use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    ffi::OsString,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex as StdMutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use parking_lot::RwLock;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    Filter, audit,
    checkpoint::{
        CollectionCheckpoint, SegmentsManifest, read_checkpoint, read_segments_manifest,
        write_checkpoint, write_segments_manifest,
    },
    data_dir_lock::DataDirLock,
    distance_soa::soa_top_k,
    error::{GaussError, Result},
    fs_util::{
        copy_dir_contents, directory_size, durable_create_dir, durable_remove_dir_all,
        durable_remove_file, durable_rename, sync_directory, sync_tree,
    },
    graph_identity::{GRAPH_IDENTITY_FILE, GraphIdentityStore},
    model::{
        ColdTierResponse, CollectionConfig, CompactResponse, CountResponse, HybridSearchRequest,
        IndexStatusResponse, MultiSearchRequest, MultiSearchResponse, PayloadType, Point,
        RecommendRequest, RerankRequest, ScrollResponse, SearchHit, SearchRequest, SearchResponse,
        SparseVector, WalArchivePruneResponse,
    },
    observability::{
        OperationGuard, observe_degraded, observe_graph_edges_orphaned_by_delete,
        observe_points_deleted, observe_points_upserted, set_storage_gauges,
    },
    restore_journal::{self, RestoreInstallMode, RestoreJournal, RestorePhase},
    segment::{
        ColdMaterializeScope, ColdObjectStoreConfig, SoASegmentCache,
        materialize_missing_cold_segments_from_object_store,
    },
    snapshot::{SnapshotCollection, SnapshotMarker, read_snapshot_marker, write_snapshot_marker},
    snapshot_journal::{self, SnapshotJournal, SnapshotPhase},
    wal::{FrozenWalArchive, Wal, WalEntry, WalRecord, prune_archives},
    wal_archive::{
        apply_wal_archive_retention, mirror_wal_archive, mirror_wal_archive_to_object_store,
        rehydrate_wal_origin_from_archives, replay_restored_wal_archives,
        restore_wal_archives_from_external, restore_wal_archives_from_object_store,
        run_wal_archive_command,
    },
};

mod build_admission;
mod build_lifecycle;
mod generation_builder;
mod graph_calibration;
mod graph_pitr;
mod graph_retrieval;
mod graph_runtime;
mod graph_shadow;
mod graph_snapshot;
mod maintenance;
#[cfg(test)]
mod tenant_isolation;
mod text_retrieval;

use generation_builder::{
    LsvecCompactionScope, StagedGraphCompaction, StagedLsvecCompaction, stage_graph_compaction,
    stage_lsvec_compaction,
};
use maintenance::CollectionCompactionGuard;

const CATALOG_FILE: &str = "catalog.json";
const CATALOG_WAL_DIR: &str = "catalog_wal";
const ASYNC_WAL_FLUSH_INTERVAL: Duration = Duration::from_millis(200);
const MAX_VECTOR_DIM: usize = 65_536;
const MAX_SEARCH_K: usize = 10_000;
const MAX_MULTI_SEARCHES: usize = 128;
const MAX_POINT_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_POINT_ID_BYTES: usize = 1024;
#[derive(Clone, Debug)]
pub struct Db {
    inner: Arc<RwLock<DbInner>>,
    data_dir: PathBuf,
    graph_identity: Arc<GraphIdentityStore>,
    maintenance_barrier: Arc<RwLock<()>>,
    audit_writer: Arc<audit::AuditWriter>,
    /// Process-exclusive lease for the resolved data-directory identity.
    /// Arc ownership keeps the OS lock held until the final `Db` clone drops.
    _data_dir_lock: Arc<DataDirLock>,
    /// PA-2c: server-side default for `SearchRequest.with_payload`. When the
    /// request leaves the field as `None`, this flag decides whether the hot
    /// scoring loop clones each `payload: serde_json::Value` or returns
    /// `Value::Null`. Set via `Db::set_default_with_payload` (CLI flag
    /// `--default-with-payload=false` / env `GAUSSDB_DEFAULT_WITH_PAYLOAD=0`).
    /// Default = `true` for back-compat.
    default_with_payload: Arc<std::sync::atomic::AtomicBool>,
    /// PA-5: live count of in-flight `Db::search` calls. Background
    /// compaction reads it to defer when search latency would be impacted
    /// (`Db::search_inflight()`). Atomic so the hot search path pays only
    /// one increment + one decrement per call.
    search_inflight: Arc<std::sync::atomic::AtomicUsize>,
    /// P2C: server-wide `intra_query_parallel` flag. When set, HNSW
    /// layer-0 beam expansion dispatches unvisited-neighbor scoring to
    /// `rayon::par_iter`. Arc-shared so the server can flip it without
    /// holding `&mut Db`. Set via CLI flag `--intra-query-parallel` /
    /// env `GAUSSDB_INTRA_QUERY_PARALLEL=1`. Default OFF to preserve
    /// the recall_golden floor and avoid the insert-phase hang the
    /// original P2C attempt hit.
    intra_query_parallel: Arc<std::sync::atomic::AtomicBool>,
    /// W1: server-wide in-beam binary cascade flag. When set, HNSW layer-0
    /// beam ranks neighbours by a rotated/norm-corrected binary proxy, keeps
    /// a widened pool, then exact-reranks. Arc-shared so the server can flip
    /// it without holding `&mut Db`. Default OFF: real measurement on
    /// sift-128 (1M, dim=128, k=10, ef=256) shows cascade ON is strictly
    /// worse than OFF on both axes — recall 0.9473 vs 0.9813, QPS 173 vs
    /// 1103 (6.4x slower) — so it does not clear the recall≥0.97 bar and
    /// costs throughput instead of saving it. Opt-in via `Db::set_cascade`.
    cascade: Arc<std::sync::atomic::AtomicBool>,
    /// Sticky process-lifetime signal for a durable I/O failure after a WAL
    /// commit. Reads remain available, but readiness and later mutations can
    /// surface that the process needs operator attention.
    durability_degraded: Arc<std::sync::atomic::AtomicBool>,
    lifecycle_gate: Arc<RwLock<()>>,
    maintenance: Arc<AtomicBool>,
    /// Process-local admission for collection compaction. All `Db` clones
    /// share this set so a scheduled sweep cannot duplicate a manual or
    /// earlier scheduled generation replacement for the same collection.
    compactions_in_flight: Arc<StdMutex<HashSet<String>>>,
    wal_flusher: Arc<WalFlushCoordinator>,
    build_lifecycle: Arc<build_lifecycle::BuildLifecycle>,
    graph_shadow_runtime: Arc<graph_shadow::GraphShadowRuntime>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "used by the following scoped graph API slice")
)]
struct GraphBatchCommitReceipt {
    graph_epoch: crate::graph::GraphEpoch,
    operation_lsn: u64,
    durable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UpsertExecutionReceipt {
    total: usize,
    operation_lsn: u64,
    unsafe_override_audited: bool,
    graph_epoch: Option<crate::graph::GraphEpoch>,
    graph_bound_endpoints: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MutationOrigin {
    Client,
    LegacyReplication,
}

struct MutationContext {
    audit: audit::AuditContext,
    origin: MutationOrigin,
}

impl MutationContext {
    fn client(audit: audit::AuditContext) -> Self {
        Self {
            audit,
            origin: MutationOrigin::Client,
        }
    }

    fn legacy_replication() -> Self {
        Self {
            audit: audit::AuditContext::embedded(),
            origin: MutationOrigin::LegacyReplication,
        }
    }
}

/// RAII counter guard for `Db.search_inflight`. Increments on construction,
/// decrements on drop — works correctly across panics and early returns.
struct SearchInflightGuard {
    counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl SearchInflightGuard {
    fn new(counter: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self { counter }
    }
}

impl Drop for SearchInflightGuard {
    fn drop(&mut self) {
        self.counter
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

struct MaintenanceGuard {
    maintenance: Arc<AtomicBool>,
    release_on_drop: bool,
}

impl MaintenanceGuard {
    fn enter(maintenance: Arc<AtomicBool>) -> Result<Self> {
        maintenance
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                GaussError::InvalidRequest(
                    "another storage maintenance operation is already active".to_string(),
                )
            })?;
        Ok(Self {
            maintenance,
            release_on_drop: true,
        })
    }

    fn latch(&mut self) {
        self.release_on_drop = false;
    }
}

impl Drop for MaintenanceGuard {
    fn drop(&mut self) {
        if self.release_on_drop {
            self.maintenance.store(false, Ordering::Release);
        }
    }
}

#[derive(Debug)]
struct WalFlushCoordinator {
    stop: Arc<AtomicBool>,
    wake: Arc<(StdMutex<()>, Condvar)>,
    handle: StdMutex<Option<JoinHandle<()>>>,
}

impl WalFlushCoordinator {
    fn spawn(
        inner: Weak<RwLock<DbInner>>,
        degraded: Arc<AtomicBool>,
        maintenance: Arc<AtomicBool>,
    ) -> Arc<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let wake = Arc::new((StdMutex::new(()), Condvar::new()));
        let worker_stop = Arc::clone(&stop);
        let worker_wake = Arc::clone(&wake);
        let handle = std::thread::Builder::new()
            .name("chirondb-wal-flusher".to_string())
            .spawn(move || {
                loop {
                    let (lock, signal) = &*worker_wake;
                    let guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    let (_iteration_guard, _) = signal
                        .wait_timeout(guard, ASYNC_WAL_FLUSH_INTERVAL)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if worker_stop.load(Ordering::Acquire) {
                        break;
                    }
                    if maintenance.load(Ordering::Acquire) {
                        continue;
                    }
                    let Some(inner) = inner.upgrade() else {
                        break;
                    };
                    if let Err(error) = flush_wals_inner(&inner) {
                        degraded.store(true, Ordering::Release);
                        metrics::counter!(
                            "chirondb_wal_durability_failures_total",
                            "operation" => "background_flush"
                        )
                        .increment(1);
                        tracing::error!(%error, "background WAL flush failed; writes degraded");
                    }
                }
            })
            .expect("spawn WAL flush coordinator");
        Arc::new(Self {
            stop,
            wake,
            handle: StdMutex::new(Some(handle)),
        })
    }

    fn shutdown(&self) {
        if self.stop.swap(true, Ordering::AcqRel) {
            return;
        }
        self.wake.1.notify_all();
        if let Some(handle) = self
            .handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = handle.join();
        }
    }

    fn quiesce(&self) {
        // The worker intentionally retains this mutex guard through each
        // flush iteration. Once maintenance is set, acquiring it proves any
        // already-started flush has finished; later iterations observe the
        // maintenance flag and skip storage access.
        drop(
            self.wake
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
    }
}

impl Drop for WalFlushCoordinator {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn flush_wals_inner(inner: &Arc<RwLock<DbInner>>) -> Result<()> {
    let (catalog_dirty, catalog_bytes, catalog_age, collections) = {
        let inner = inner.read();
        (
            inner.catalog_wal.is_dirty(),
            inner.catalog_wal.unsynced_bytes(),
            inner.catalog_wal.oldest_unsynced_age(),
            inner.collections.values().cloned().collect::<Vec<_>>(),
        )
    };
    let mut unsynced_bytes = catalog_bytes;
    let mut oldest_unsynced = catalog_age.unwrap_or_default();
    for collection in &collections {
        let collection = collection.read();
        unsynced_bytes = unsynced_bytes.saturating_add(collection.wal.unsynced_bytes());
        if let Some(age) = collection.wal.oldest_unsynced_age() {
            oldest_unsynced = oldest_unsynced.max(age);
        }
    }
    metrics::gauge!("chirondb_wal_unsynced_bytes").set(unsynced_bytes as f64);
    metrics::gauge!("chirondb_wal_oldest_unsynced_seconds").set(oldest_unsynced.as_secs_f64());

    if catalog_dirty {
        inner.read().catalog_wal.sync()?;
    }
    for collection in collections {
        let mut collection = collection.write();
        if collection.wal.is_dirty() {
            collection.wal.sync()?;
        }
        collection.overlays.publish_pending()?;
    }
    metrics::gauge!("chirondb_wal_unsynced_bytes").set(0.0);
    metrics::gauge!("chirondb_wal_oldest_unsynced_seconds").set(0.0);
    Ok(())
}

#[derive(Debug)]
struct DbInner {
    root: PathBuf,
    collections: HashMap<String, Arc<RwLock<Collection>>>,
    /// Root-level WAL for collection lifecycle changes. `catalog.json` is a
    /// checkpoint of this log, not the commit record itself.
    catalog_wal: Wal,
    wal_archive_retain_last: Option<usize>,
    wal_archive_max_bytes: Option<u64>,
    wal_archive_max_age: Option<Duration>,
    wal_external_archive_dir: Option<PathBuf>,
    wal_object_store: Option<ColdObjectStoreConfig>,
    wal_archive_command: Option<String>,
    cold_object_store: Option<ColdObjectStoreConfig>,
    max_points_per_collection: Option<usize>,
    /// P7: whether row-level tenant rules apply. `Disabled` by default, so a
    /// deployment behaves exactly as it did before this existed until an
    /// operator has finished backfilling `tenant_id`.
    tenant_enforcement: crate::tenant::TenantEnforcement,
}

#[derive(Debug)]
struct Collection {
    config: CollectionConfig,
    /// The mutable streamer: live points + their in-memory dense indexes
    /// (LS-Vec rework D1). Holds what used to be the `points` / `h2qg` /
    /// `named_h2qg` fields directly on `Collection`.
    streamer: crate::streamer::Streamer,
    /// Frozen streamer kept query-visible while its v4 segment seals off-lock.
    sealing: Option<Arc<crate::streamer::Streamer>>,
    /// Immutable sealed segments, oldest → newest (LS-Vec rework D3).
    /// Queries fan out across all of them plus the streamer; each keeps its
    /// own index, store, and tombstone set.
    searchers: Vec<crate::searcher::SegmentSearcher>,
    /// Global ID authority: which segment (streamer or searcher) currently
    /// owns each live point id. A point is live in exactly one place —
    /// upserting an existing id tombstones its old location and inserts
    /// into the streamer. `id_index.len()` is the live point count.
    id_index: HashMap<String, crate::searcher::SegLoc>,
    graph_lifecycle: crate::graph_lifecycle::GraphLifecycleState,
    /// Present only after a graph-aware WAL batch establishes point handles.
    /// Legacy/vector-only collections retain no graph resolver allocation.
    graph_resolver: Option<crate::graph_resolver::PointIncarnationResolver>,
    /// Correctness-first G0 topology for the active graph epoch. DROP GRAPH
    /// retires this state while preserving point handles in `graph_resolver`.
    graph_mutable: Option<crate::mutable_graph::MutableGraphState>,
    /// Immutable graph/vector cut pinned alongside the replayed mutable tail.
    graph_generation: Option<Arc<crate::graph_generation::GraphGeneration>>,
    /// Checked, immutable D6 planner evidence loaded from this collection's
    /// graph metadata. Absence keeps public routing on exact P1.
    graph_calibration: Option<Arc<crate::graph_estimator::GraphCalibrationStore>>,
    sparse_index: SparseIndex,
    payload_index: PayloadIndex,
    /// One atomically selected visibility bundle for all current sealed point
    /// locations and future stable EdgeIds. Collection read guards pin this
    /// Arc-backed version for the duration of each query.
    overlays: crate::overlay::OverlayStore,
    /// PA-4 / PC-1b: RaBitQ backend instance. Mutually exclusive with `h2qg`
    /// on the same vector field — populated only when
    /// `config.index_kind = Some("rabitq")`. Search dispatch picks whichever
    /// is `Some`.
    rabitq: Option<crate::index::rabitq::RabitqBackend>,
    /// PC-2: Vamana/DiskANN single-layer graph backend. Mutually exclusive
    /// with `h2qg` and `rabitq` — populated only when
    /// `config.index_kind = Some("vamana")`. Different recall-vs-QPS shape
    /// from HNSW; often faster on cosine at 50K.
    vamana: Option<crate::index::vamana::VamanaBackend>,
    /// B1.1 / P4: IVF k-means coarse-partition backend (paper §VI L0).
    /// Mutually exclusive with `h2qg`/`rabitq`/`vamana` — populated only when
    /// `config.index_kind = Some("ivf")`. See `crate::index::ivf`.
    ivf: Option<crate::index::ivf::IvfBackend>,
    wal: Wal,
    /// WAL prefix already represented by installed immutable segments.
    wal_watermark: u64,
    schema_epoch: u64,
    last_segment_id: Option<String>,
    /// PC-3: learned `(ef_search, recall)` curve for this collection. Built
    /// by `Db::calibrate_collection`; consumed by the recall-target →
    /// ef_search resolver in `Db::search`. `None` ⇒ fall back to the static
    /// step curve in `h2qg::ef_search_for_recall_target`.
    recall_curve: Option<Vec<(usize, f32)>>,
    /// PD-5: true if points were mutated since the last successful compact.
    /// When false, `compact_collection` skips the HNSW rebuild and segment
    /// write — the on-disk state is already current.
    hnsw_dirty: bool,
    /// True while a background thread is building the initial index after
    /// crossing `HNSW_THRESHOLD`. Prevents spawning a second build for the
    /// same collection while one is already in flight.
    index_build_in_flight: bool,
    /// True while an off-lock immutable generation merge owns a stable
    /// manifest snapshot. Upserts remain available, but automatic sealing is
    /// deferred so publication cannot race another generation writer.
    generation_build_in_flight: bool,
    /// One process-local worker may migrate legacy point IDs to durable Nids.
    /// Durable progress lives only in GraphBatch handle assignments, so this
    /// flag deliberately resets on open and is safe to lose on a crash.
    graph_backfill_in_flight: bool,
}

impl Collection {
    fn checkpoint(
        &self,
        last_applied_lsn: u64,
        points: usize,
        segment_id: Option<String>,
    ) -> Result<CollectionCheckpoint> {
        let mut checkpoint = CollectionCheckpoint::new(
            &self.config,
            self.schema_epoch,
            last_applied_lsn,
            points,
            segment_id,
        )?;
        checkpoint.segments = Some(
            self.searchers
                .iter()
                .map(|searcher| searcher.id.clone())
                .collect(),
        );
        checkpoint.wal_watermark = self.wal_watermark;
        Ok(checkpoint)
    }

    /// Whole-collection backend (RaBitQ / Vamana / IVF index kinds): these
    /// index every live point regardless of segment, so queries use them as
    /// a single leg instead of fanning out per searcher.
    fn global_backend(&self) -> Option<&dyn crate::index::IndexBackend> {
        if let Some(ref rb) = self.rabitq {
            return Some(rb as &dyn crate::index::IndexBackend);
        }
        if let Some(ref vm) = self.vamana {
            return Some(vm as &dyn crate::index::IndexBackend);
        }
        self.ivf
            .as_ref()
            .map(|ivf| ivf as &dyn crate::index::IndexBackend)
    }

    /// Total live points across the streamer and every searcher.
    fn live_points(&self) -> usize {
        if let Some(generation) = &self.graph_generation {
            debug_assert!(
                self.wal_watermark
                    >= generation
                        .manifest
                        .graph
                        .as_ref()
                        .expect("graph cut")
                        .graph_batch_watermark
            );
            debug_assert_eq!(
                self.overlays.current_ref().generation(),
                generation.manifest.generation
            );
        }
        if let Some(epoch) = self.graph_lifecycle.epoch() {
            // DROP GRAPH retires topology by epoch but preserves point handles
            // for a later re-enable of the same collection.
            debug_assert!(self.graph_resolver.is_some());
            if self.graph_lifecycle.is_enabled() {
                debug_assert_eq!(
                    self.graph_mutable.as_ref().map(|state| state.epoch()),
                    Some(epoch)
                );
            } else {
                debug_assert!(self.graph_mutable.is_none());
            }
        } else {
            debug_assert!(self.graph_resolver.is_none());
            debug_assert!(self.graph_mutable.is_none());
        }
        if let Some(resolver) = &self.graph_resolver {
            // Lazy backfill may leave legacy points temporarily unassigned,
            // but it can never manufacture more live graph nodes than points.
            debug_assert!(resolver.live_len() <= self.id_index.len());
        }
        self.id_index.len()
    }

    /// Once the collection is large enough to require ANN, every non-empty
    /// mutable tier needs its own HNSW even when that tier is smaller than the
    /// collection threshold. Sealed segments already carry their own indexes;
    /// leaving a recovered WAL tail unindexed would exact-scan that entire
    /// tail on every query after restart.
    fn streamer_hnsw_required(&self) -> bool {
        !self.streamer.points.is_empty() && self.live_points() >= crate::h2qg::HNSW_THRESHOLD
    }

    /// Pin the collection visibility authority once for one logical read.
    fn overlay_read_state(&self) -> crate::overlay::OverlayReadState {
        self.overlays
            .read_state(self.searchers.iter().map(|searcher| searcher.id.as_str()))
    }

    fn resolve_in_read_state<'a>(
        &'a self,
        state: &crate::overlay::OverlayReadState,
        id: &str,
    ) -> Option<Cow<'a, Point>> {
        match self.id_index.get(id)? {
            crate::searcher::SegLoc::Streamer => self.streamer.points.get(id).map(Cow::Borrowed),
            crate::searcher::SegLoc::Sealing => {
                self.sealing.as_ref()?.points.get(id).map(Cow::Borrowed)
            }
            crate::searcher::SegLoc::Searcher(i) => {
                let index = *i as usize;
                self.searchers
                    .get(index)?
                    .get_visible(id, state.point_tombstones(index))
            }
        }
    }

    fn contains_in_read_state(&self, state: &crate::overlay::OverlayReadState, id: &str) -> bool {
        match self.id_index.get(id) {
            Some(crate::searcher::SegLoc::Streamer) => self.streamer.points.contains_key(id),
            Some(crate::searcher::SegLoc::Sealing) => self
                .sealing
                .as_ref()
                .is_some_and(|streamer| streamer.points.contains_key(id)),
            Some(crate::searcher::SegLoc::Searcher(i)) => {
                let index = *i as usize;
                self.searchers.get(index).is_some_and(|searcher| {
                    searcher.contains_visible(id, state.point_tombstones(index))
                })
            }
            None => false,
        }
    }

    /// Resolve a live point by id through the ID authority.
    fn resolve(&self, id: &str) -> Option<Cow<'_, Point>> {
        match self.id_index.get(id)? {
            crate::searcher::SegLoc::Streamer => self.streamer.points.get(id).map(Cow::Borrowed),
            crate::searcher::SegLoc::Sealing => {
                self.sealing.as_ref()?.points.get(id).map(Cow::Borrowed)
            }
            crate::searcher::SegLoc::Searcher(i) => {
                let searcher = self.searchers.get(*i as usize)?;
                searcher.get_visible(
                    id,
                    self.overlays
                        .current_ref()
                        .point_tombstones()
                        .bitmap(&searcher.id),
                )
            }
        }
    }

    /// Iterate every live point (streamer first, then searchers).
    fn iter_live(&self) -> Box<dyn Iterator<Item = Cow<'_, Point>> + '_> {
        Box::new(
            self.streamer
                .points
                .values()
                .map(Cow::Borrowed)
                .chain(
                    self.sealing
                        .iter()
                        .flat_map(|streamer| streamer.points.values())
                        .filter(|point| {
                            self.id_index.get(&point.id) == Some(&crate::searcher::SegLoc::Sealing)
                        })
                        .map(Cow::Borrowed),
                )
                .chain(self.searchers.iter().flat_map(|s| {
                    s.iter_visible(self.overlays.current_ref().point_tombstones().bitmap(&s.id))
                })),
        )
    }

    fn iter_live_in_read_state<'a>(
        &'a self,
        state: &'a crate::overlay::OverlayReadState,
    ) -> Box<dyn Iterator<Item = Cow<'a, Point>> + 'a> {
        Box::new(
            self.streamer
                .points
                .values()
                .map(Cow::Borrowed)
                .chain(
                    self.sealing
                        .iter()
                        .flat_map(|streamer| streamer.points.values())
                        .filter(|point| {
                            self.id_index.get(&point.id) == Some(&crate::searcher::SegLoc::Sealing)
                        })
                        .map(Cow::Borrowed),
                )
                .chain(
                    self.searchers
                        .iter()
                        .enumerate()
                        .flat_map(|(index, searcher)| {
                            searcher.iter_visible(state.point_tombstones(index))
                        }),
                ),
        )
    }

    /// Build the P0 hybrid prefilter representation: stable ordinals for
    /// current sealed segments plus point IDs for mutable and legacy tiers.
    fn payload_candidates(
        &self,
        state: &crate::overlay::OverlayReadState,
        filter: Option<&crate::Filter>,
    ) -> Option<crate::payload_index::PayloadCandidateSet> {
        let fallback = payload_filter_candidates(&self.payload_index, filter)?;
        let mut sealed = crate::ordinal::SegmentOrdinalSet::default();
        for (index, searcher) in self.searchers.iter().enumerate() {
            if let Some(ordinals) =
                searcher.payload_ordinal_candidates(filter, state.point_tombstones(index))
            {
                sealed.insert_bitmap(searcher.id.clone(), ordinals);
            }
        }
        Some(crate::payload_index::PayloadCandidateSet { sealed, fallback })
    }

    fn payload_candidate_contains(
        &self,
        candidates: &crate::payload_index::PayloadCandidateSet,
        id: &str,
    ) -> bool {
        if candidates.fallback.contains(id) {
            return true;
        }
        let Some(crate::searcher::SegLoc::Searcher(index)) = self.id_index.get(id) else {
            return false;
        };
        let Some(searcher) = self.searchers.get(*index as usize) else {
            return false;
        };
        searcher
            .ordinal(id)
            .is_some_and(|ordinal| candidates.sealed.contains(&searcher.id, ordinal))
    }

    fn iter_payload_candidates<'a>(
        &'a self,
        state: &'a crate::overlay::OverlayReadState,
        candidates: &'a crate::payload_index::PayloadCandidateSet,
    ) -> Box<dyn Iterator<Item = Cow<'a, Point>> + 'a> {
        let fallback = candidates
            .fallback
            .iter()
            .filter_map(move |id| self.resolve_in_read_state(state, id));
        let sealed = candidates
            .sealed
            .iter()
            .filter_map(|(segment_id, ordinals)| {
                self.searchers
                    .iter()
                    .enumerate()
                    .find(|(_, searcher)| searcher.id == segment_id)
                    .map(|(index, searcher)| (index, searcher, ordinals))
            })
            .flat_map(move |(index, searcher, ordinals)| {
                ordinals.iter().filter_map(move |ordinal| {
                    searcher.get_ordinal_visible(ordinal, state.point_tombstones(index))
                })
            });
        Box::new(fallback.chain(sealed))
    }

    /// Rebuild only the permanent string fallback. Current sealed V4
    /// segments are represented by their per-segment ordinal postings.
    fn rebuild_payload_fallback(&mut self) {
        self.payload_index = crate::payload_index::build_payload_index_iter(
            self.streamer
                .points
                .values()
                .map(Cow::Borrowed)
                .chain(
                    self.sealing
                        .iter()
                        .flat_map(|streamer| streamer.points.values())
                        .filter(|point| {
                            self.id_index.get(&point.id) == Some(&crate::searcher::SegLoc::Sealing)
                        })
                        .map(Cow::Borrowed),
                )
                .chain(
                    self.searchers
                        .iter()
                        .filter(|searcher| searcher.ordinal_payload_index.is_none())
                        .flat_map(|searcher| {
                            searcher.iter_visible_aux_index_points(
                                self.overlays
                                    .current_ref()
                                    .point_tombstones()
                                    .bitmap(&searcher.id),
                            )
                        }),
                ),
        );
    }

    fn tombstone_searcher(&mut self, index: usize, id: &str) -> Result<bool> {
        let searcher = self.searchers.get_mut(index).ok_or_else(|| {
            GaussError::InvalidRequest("searcher location is out of bounds".to_string())
        })?;
        let segment = searcher.id.clone();
        let ordinal = searcher.ordinal(id);
        let inserted = searcher.tombstone(id);
        if let Some(ordinal) = ordinal {
            self.overlays.tombstone_point(&segment, ordinal)?;
        }
        Ok(inserted)
    }

    /// Propagate the server-wide W1 cascade flag to every dense graph this
    /// collection serves — the streamer's live graph and each searcher
    /// segment's loaded graph (which used to be the single collection-level
    /// `h2qg` slot).
    fn set_cascade_on_indexes(&mut self, flag: Arc<std::sync::atomic::AtomicBool>) {
        if let Some(h2qg) = self.streamer.hnsw.as_mut() {
            h2qg.set_cascade(flag.clone());
        }
        for searcher in self.searchers.iter_mut() {
            if let crate::searcher::SegmentIndex::LegacyH2qg(h2qg) = &mut searcher.index {
                h2qg.set_cascade(flag.clone());
            }
        }
    }

    /// Propagate the server-wide P2C intra-query-parallel flag, same
    /// coverage as [`Self::set_cascade_on_indexes`].
    fn set_intra_query_parallel_on_indexes(&mut self, flag: Arc<std::sync::atomic::AtomicBool>) {
        if let Some(h2qg) = self.streamer.hnsw.as_mut() {
            h2qg.set_intra_query_parallel(flag.clone());
        }
        for searcher in self.searchers.iter_mut() {
            if let crate::searcher::SegmentIndex::LegacyH2qg(h2qg) = &mut searcher.index {
                h2qg.set_intra_query_parallel(flag.clone());
            }
        }
    }
}

/// Repeatable, ID-ordered view of the collection's live points for merge
/// compaction. Only IDs are materialized; v4 plaintext vectors remain mmap-backed and
/// each point is hydrated just for the writer call that consumes it.
struct MergeInput<'a> {
    collection: &'a Collection,
    ids: Vec<String>,
}

impl<'a> MergeInput<'a> {
    fn new(collection: &'a Collection) -> Self {
        let mut ids = collection.id_index.keys().cloned().collect::<Vec<_>>();
        ids.sort();
        Self { collection, ids }
    }
}

impl crate::seal::VectorInput for MergeInput<'_> {
    fn len(&self) -> usize {
        self.ids.len()
    }

    fn point(&self, ordinal: usize) -> Result<Cow<'_, Point>> {
        let id = self.ids.get(ordinal).ok_or_else(|| {
            GaussError::InvalidRequest(format!("merge input ordinal {ordinal} is out of bounds"))
        })?;
        self.collection
            .resolve(id)
            .ok_or_else(|| GaussError::PointNotFound(id.clone()))
    }
}

impl crate::search::PointResolver for Collection {
    fn resolve_point(&self, id: &str) -> Option<Cow<'_, Point>> {
        self.resolve(id)
    }

    fn contains_point(&self, id: &str) -> bool {
        self.id_index.contains_key(id)
    }
}

struct CollectionReadResolver<'a> {
    collection: &'a Collection,
    state: &'a crate::overlay::OverlayReadState,
}

impl crate::search::PointResolver for CollectionReadResolver<'_> {
    fn resolve_point(&self, id: &str) -> Option<Cow<'_, Point>> {
        self.collection.resolve_in_read_state(self.state, id)
    }

    fn contains_point(&self, id: &str) -> bool {
        self.collection.contains_in_read_state(self.state, id)
    }
}

#[derive(Clone, Debug)]
struct SchemaRestoreState {
    config: CollectionConfig,
    schema_epoch: u64,
    graph_history: bool,
    snapshot_lsn: u64,
}

#[derive(Clone, Debug, Default)]
struct AppliedRestoreWalTargets {
    lsns: HashMap<String, u64>,
    schema_rewinds: HashMap<String, SchemaRestoreState>,
    graph_bases: HashMap<String, graph_pitr::GraphPitrBase>,
}

use crate::{
    payload_index::{
        PayloadIndex, insert_payload_point, payload_filter_candidates, remove_payload_point,
        validate_payload_field, validate_payload_schema,
    },
    search::{
        RankedPoint, add_scaled, fuse_rankings, fuse_search_responses, normalize, point_vector,
        rank_order, required_point_vector, sparse_search_ranked,
    },
    sparse_index::{SparseIndex, insert_sparse_point, remove_sparse_point},
};

#[derive(Debug, Default, Deserialize, Serialize)]
struct Catalog {
    collections: Vec<CollectionConfig>,
    #[serde(default)]
    wal_watermark: u64,
}

impl Db {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_cold_object_store(root, None)
    }

    pub fn open_with_cold_object_store(
        root: impl AsRef<Path>,
        cold_object_store_dir: Option<PathBuf>,
    ) -> Result<Self> {
        Self::open_with_cold_object_store_config(
            root,
            cold_object_store_dir.map(ColdObjectStoreConfig::LocalDir),
        )
    }

    pub fn open_with_cold_object_store_config(
        root: impl AsRef<Path>,
        cold_object_store: Option<ColdObjectStoreConfig>,
    ) -> Result<Self> {
        let data_dir_lock = Arc::new(DataDirLock::acquire(root.as_ref())?);
        let data_dir = data_dir_lock.root().to_path_buf();
        recover_interrupted_generation_restore(&data_dir, cold_object_store.as_ref())?;
        let layout = crate::storage_layout::resolve(&data_dir)?;
        let root = layout.active_root;
        recover_interrupted_restore(&root, cold_object_store.as_ref())?;
        fs::create_dir_all(collections_dir(&root))?;

        let LoadedDbRoot {
            catalog_wal,
            collections,
            catalog_replayed,
        } = load_db_root(&root, cold_object_store.as_ref())?;
        // A snapshot's first activation is an import. Once identity exists,
        // legitimate live mutations may have advanced beyond its old marker.
        if !data_dir.join(GRAPH_IDENTITY_FILE).try_exists()? {
            validate_snapshot_marker(read_snapshot_marker(&root)?.as_ref(), &collections)?;
        }
        let graph_identity = Arc::new(GraphIdentityStore::open(&data_dir)?);

        let inner = Arc::new(RwLock::new(DbInner {
            root: root.clone(),
            collections,
            catalog_wal,
            wal_archive_retain_last: None,
            wal_archive_max_bytes: None,
            wal_archive_max_age: None,
            wal_external_archive_dir: None,
            wal_object_store: None,
            wal_archive_command: None,
            cold_object_store,
            max_points_per_collection: None,
            tenant_enforcement: crate::tenant::TenantEnforcement::Disabled,
        }));
        if catalog_replayed {
            let mut recovered = inner.write();
            write_catalog(&recovered)?;
            let watermark = recovered.catalog_wal.len()?;
            recovered.catalog_wal.drop_prefix(watermark)?;
        }
        let audit_writer = audit::AuditWriter::open(&data_dir)?;
        let durability_degraded = Arc::new(AtomicBool::new(false));
        let maintenance = Arc::new(AtomicBool::new(false));
        let wal_flusher = WalFlushCoordinator::spawn(
            Arc::downgrade(&inner),
            Arc::clone(&durability_degraded),
            Arc::clone(&maintenance),
        );
        let db = Self {
            inner,
            data_dir,
            graph_identity,
            _data_dir_lock: data_dir_lock,
            maintenance_barrier: Arc::new(RwLock::new(())),
            audit_writer,
            default_with_payload: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            search_inflight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            intra_query_parallel: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            // W1 Phase 3: flipped on after the rotation + norm-correction fix
            // cleared the 0.97 recall floor at CASCADE_OVERSAMPLE=8 across the
            // 2026-06-21-session diagnostic sweep (see h2qg::CASCADE_OVERSAMPLE
            // doc). Symmetric Hamming (pre-rotation) never cleared this floor.
            cascade: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            durability_degraded,
            lifecycle_gate: Arc::new(RwLock::new(())),
            maintenance,
            compactions_in_flight: Arc::new(StdMutex::new(HashSet::new())),
            wal_flusher,
            build_lifecycle: build_lifecycle::BuildLifecycle::new(),
            graph_shadow_runtime: graph_shadow::GraphShadowRuntime::new(),
        };
        db.rebuild_recovered_streamer_indexes();
        db.resume_graph_handle_backfills();
        db.refresh_metrics();
        Ok(db)
    }

    /// WAL replay restores the live streamer points but cannot persist its
    /// mutable mini-HNSW. Rebuild that internal hot-tier index off-lock after
    /// open so a restarted LS-VEC collection does not silently exact-scan a
    /// large WAL suffix forever.
    fn rebuild_recovered_streamer_indexes(&self) {
        let collections = self
            .inner
            .read()
            .collections
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut builds = Vec::new();
        for coll in collections {
            let mut collection = coll.write();
            if !collection.streamer_hnsw_required()
                || collection.streamer.hnsw.is_some()
                || collection.index_build_in_flight
            {
                continue;
            }
            collection.index_build_in_flight = true;
            builds.push(PendingIndexBuild {
                coll: Arc::clone(&coll),
                data_dir_lock: Arc::clone(&self._data_dir_lock),
                lifecycle: Arc::clone(&self.build_lifecycle),
                streamer_base_lsn: collection.streamer.base_lsn,
                vector_dim: collection.config.vector_dim,
                hnsw_m: collection.config.hnsw_m,
                hnsw_ef_construction: collection.config.hnsw_ef_construction,
                metric: collection.config.metric,
                // The Streamer is the live f32 tier. Collection quantization
                // applies when immutable LS-VEC artifacts are sealed, not to
                // the mutable mini-HNSW rebuilt from WAL replay.
                kind: PendingIndexBuildKind::H2qg,
                cascade: self.cascade.clone(),
            });
        }
        for build in builds {
            spawn_index_build(build);
        }
    }

    /// PA-2c — set the server-side default for `SearchRequest.with_payload`
    /// when callers leave it `None`. `false` skips the per-hit
    /// `serde_json::Value` clone in the hot scoring loop — significant p99
    /// win on payload-heavy schemas (e.g. VectorDBBench, ann-benchmarks).
    /// Existing API contract is preserved for callers that explicitly send
    /// `Some(true)` or `Some(false)`.
    pub fn set_default_with_payload(&self, value: bool) {
        self.default_with_payload
            .store(value, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn default_with_payload(&self) -> bool {
        self.default_with_payload
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// P2C — set the server-wide `intra_query_parallel` flag. When set,
    /// HNSW layer-0 beam expansion dispatches unvisited-neighbor scoring
    /// to `rayon::par_iter` once the batch size hits
    /// `INTRA_QUERY_PARALLEL_THRESHOLD`. Arc-shared so callers can flip
    /// the flag without holding `&mut Db`. Default OFF to preserve the
    /// recall_golden floor and avoid the insert-phase hang the original
    /// P2C attempt hit.
    pub fn set_intra_query_parallel(&self, value: bool) {
        self.intra_query_parallel
            .store(value, std::sync::atomic::Ordering::Relaxed);
        // P2C: propagate the flag to every live H2qgIndex so the per-graph
        // AtomicBool the search hot path reads is in sync. The hot path
        // never holds the outer lock so the latency cost is bounded by
        // the number of collections, not the candidate size.
        let inner = self.inner.write();
        for (_name, coll_arc) in inner.collections.iter() {
            let mut coll = coll_arc.write();
            coll.set_intra_query_parallel_on_indexes(self.intra_query_parallel.clone());
        }
    }

    /// P2C — current value of the server-wide `intra_query_parallel` flag.
    pub fn intra_query_parallel(&self) -> bool {
        self.intra_query_parallel
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// W1 — set the server-wide in-beam binary cascade flag. When set, HNSW
    /// layer-0 beam ranks neighbours by Hamming popcount on sign codes, keeps
    /// a widened `ef * CASCADE_OVERSAMPLE` pool, then exact-reranks. Arc-shared
    /// so callers can flip it without `&mut Db`. Propagation to each live
    /// H2qgIndex builds the sign codes eagerly (when turning ON) so the search
    /// hot path stays `&self`. Default OFF until the 50K bench confirms recall.
    pub fn set_cascade(&self, value: bool) {
        self.cascade
            .store(value, std::sync::atomic::Ordering::Relaxed);
        let inner = self.inner.write();
        for (_name, coll_arc) in inner.collections.iter() {
            let mut coll = coll_arc.write();
            coll.set_cascade_on_indexes(self.cascade.clone());
        }
    }

    /// W1 — current value of the server-wide cascade flag.
    pub fn cascade(&self) -> bool {
        self.cascade.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// PA-5 — live count of in-flight `Db::search` calls. Used by the
    /// background compaction driver to defer compact work when search
    /// latency would be impacted.
    pub fn search_inflight(&self) -> usize {
        self.search_inflight
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// False after a post-commit durability/checkpoint failure. Liveness is
    /// intentionally separate: existing durable data remains readable.
    pub fn durability_ready(&self) -> bool {
        !self.durability_degraded.load(Ordering::Acquire)
            && !self.maintenance.load(Ordering::Acquire)
    }

    fn ensure_storage_mutations_available(&self) -> Result<()> {
        if self.maintenance.load(Ordering::Acquire) {
            return Err(GaussError::WalUnavailable(
                "storage maintenance is active; mutations are read-only until recovery".to_string(),
            ));
        }
        Ok(())
    }

    /// Force every dirty collection WAL (and the root catalog WAL) to stable
    /// storage. Embedded users can call this before process shutdown; the
    /// server also has a 200 ms background coordinator.
    pub fn flush_wals(&self) -> Result<()> {
        match flush_wals_inner(&self.inner) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.mark_durability_degraded("explicit_flush", &error);
                Err(error)
            }
        }
    }

    fn wait_for_storage_idle(&self) -> Result<()> {
        const STORAGE_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
        let deadline = Instant::now() + STORAGE_IDLE_TIMEOUT;
        loop {
            let collections = self
                .inner
                .read()
                .collections
                .values()
                .cloned()
                .collect::<Vec<_>>();
            let idle = collections.iter().all(|collection| {
                let collection = collection.read();
                collection.sealing.is_none()
                    && !collection.index_build_in_flight
                    && !collection.generation_build_in_flight
            });
            if idle {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(GaussError::ResourceExhausted(
                    "timed out waiting for background storage work to finish".to_string(),
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn mark_durability_degraded(&self, operation: &'static str, error: &GaussError) {
        self.durability_degraded
            .store(true, std::sync::atomic::Ordering::Release);
        metrics::counter!("chirondb_wal_durability_failures_total", "operation" => operation)
            .increment(1);
        tracing::error!(%error, operation, "durability subsystem entered degraded mode");
    }

    fn checkpoint_catalog_after_commit(&self, inner: &mut DbInner) {
        let result = write_catalog(inner).and_then(|()| {
            let watermark = inner.catalog_wal.len()?;
            inner.catalog_wal.drop_prefix(watermark)
        });
        if let Err(error) = result {
            self.mark_durability_degraded("catalog_checkpoint", &error);
        }
    }

    pub fn set_wal_archive_retain_last(&self, retain_last: Option<usize>) {
        self.inner.write().wal_archive_retain_last = retain_last;
    }

    pub fn wal_archive_retain_last(&self) -> Option<usize> {
        self.inner.read().wal_archive_retain_last
    }

    pub fn set_wal_archive_max_bytes(&self, max_bytes: Option<u64>) {
        self.inner.write().wal_archive_max_bytes = max_bytes;
    }

    pub fn wal_archive_max_bytes(&self) -> Option<u64> {
        self.inner.read().wal_archive_max_bytes
    }

    pub fn set_wal_archive_max_age(&self, max_age: Option<Duration>) {
        self.inner.write().wal_archive_max_age = max_age;
    }

    pub fn wal_archive_max_age(&self) -> Option<Duration> {
        self.inner.read().wal_archive_max_age
    }

    pub fn set_wal_external_archive_dir(&self, archive_dir: Option<PathBuf>) {
        self.inner.write().wal_external_archive_dir = archive_dir;
    }

    pub fn wal_external_archive_dir(&self) -> Option<PathBuf> {
        self.inner.read().wal_external_archive_dir.clone()
    }

    pub fn set_wal_object_store_dir(&self, archive_dir: Option<PathBuf>) {
        self.inner.write().wal_object_store = archive_dir.map(ColdObjectStoreConfig::LocalDir);
    }

    pub fn wal_object_store_dir(&self) -> Option<PathBuf> {
        match self.inner.read().wal_object_store.clone() {
            Some(ColdObjectStoreConfig::LocalDir(path)) => Some(path),
            Some(ColdObjectStoreConfig::Url(_)) | None => None,
        }
    }

    pub fn set_wal_object_store_url(&self, archive_url: Option<String>) {
        self.inner.write().wal_object_store = archive_url.map(ColdObjectStoreConfig::Url);
    }

    pub fn wal_object_store_url(&self) -> Option<String> {
        match self.inner.read().wal_object_store.clone() {
            Some(ColdObjectStoreConfig::Url(url)) => Some(url),
            Some(ColdObjectStoreConfig::LocalDir(_)) | None => None,
        }
    }

    pub fn set_wal_archive_command(&self, archive_command: Option<String>) {
        self.inner.write().wal_archive_command = archive_command;
    }

    pub fn wal_archive_command(&self) -> Option<String> {
        self.inner.read().wal_archive_command.clone()
    }

    pub fn set_cold_object_store_dir(&self, cold_object_store_dir: Option<PathBuf>) {
        self.inner.write().cold_object_store =
            cold_object_store_dir.map(ColdObjectStoreConfig::LocalDir);
    }

    pub fn cold_object_store_dir(&self) -> Option<PathBuf> {
        match self.inner.read().cold_object_store.clone() {
            Some(ColdObjectStoreConfig::LocalDir(path)) => Some(path),
            Some(ColdObjectStoreConfig::Url(_)) | None => None,
        }
    }

    pub fn set_cold_object_store_url(&self, cold_object_store_url: Option<String>) {
        self.inner.write().cold_object_store =
            cold_object_store_url.map(ColdObjectStoreConfig::Url);
    }

    pub fn cold_object_store_url(&self) -> Option<String> {
        match self.inner.read().cold_object_store.clone() {
            Some(ColdObjectStoreConfig::Url(url)) => Some(url),
            Some(ColdObjectStoreConfig::LocalDir(_)) | None => None,
        }
    }

    // -- guarded public entry points ---------------------------------------
    //
    // These carry no tenant scope, so under `TenantEnforcement::Enforced` they
    // refuse rather than run unscoped. A surface that has not been taught about
    // tenants therefore fails visibly instead of leaking rows across a
    // boundary. Use the `_scoped` variants to serve a request.

    pub fn search(&self, collection_name: &str, request: SearchRequest) -> Result<SearchResponse> {
        self.require_scoped_entry("search")?;
        if request.graph.is_some() {
            return Err(GaussError::InvalidRequest(
                "graph-constrained search requires `search_scoped`".to_string(),
            ));
        }
        self.search_unguarded(collection_name, request)
    }

    pub fn count(&self, collection_name: &str, filter: Option<Filter>) -> Result<CountResponse> {
        self.require_scoped_entry("count")?;
        self.count_unguarded(collection_name, filter)
    }

    pub fn scroll(
        &self,
        collection_name: &str,
        offset: Option<&str>,
        limit: usize,
        filter: Option<Filter>,
    ) -> Result<ScrollResponse> {
        self.require_scoped_entry("scroll")?;
        self.scroll_unguarded(collection_name, offset, limit, filter)
    }

    pub fn get_points(&self, collection_name: &str, ids: &[String]) -> Result<Vec<Point>> {
        self.require_scoped_entry("get_points")?;
        self.get_points_unguarded(collection_name, ids)
    }

    pub fn upsert_wait(
        &self,
        collection_name: &str,
        points: Vec<Point>,
        wait: bool,
    ) -> Result<usize> {
        self.require_scoped_entry("upsert")?;
        self.upsert_wait_unguarded(
            collection_name,
            points,
            wait,
            MutationContext::client(audit::AuditContext::embedded()),
            None,
            None,
        )
        .map(|receipt| receipt.total)
    }

    pub fn delete(&self, collection_name: &str, ids: &[String]) -> Result<usize> {
        self.require_scoped_entry("delete")?;
        self.delete_unguarded(
            collection_name,
            ids,
            false,
            audit::AuditContext::embedded(),
            MutationOrigin::Client,
        )
    }

    pub fn delete_with_edges(&self, collection_name: &str, ids: &[String]) -> Result<usize> {
        self.require_scoped_entry("delete_with_edges")?;
        self.delete_unguarded(
            collection_name,
            ids,
            true,
            audit::AuditContext::embedded(),
            MutationOrigin::Client,
        )
    }

    pub fn set_payload(
        &self,
        collection_name: &str,
        id: &str,
        payload: serde_json::Value,
        merge: bool,
    ) -> Result<Point> {
        self.require_scoped_entry("set_payload")?;
        self.set_payload_unguarded(
            collection_name,
            id,
            payload,
            merge,
            audit::AuditContext::embedded(),
            MutationOrigin::Client,
        )
    }

    pub fn delete_by_filter(&self, collection_name: &str, filter: &crate::Filter) -> Result<usize> {
        self.require_scoped_entry("delete_by_filter")?;
        self.delete_by_filter_unguarded(
            collection_name,
            filter,
            false,
            audit::AuditContext::embedded(),
        )
    }

    pub fn delete_by_filter_with_edges(
        &self,
        collection_name: &str,
        filter: &crate::Filter,
    ) -> Result<usize> {
        self.require_scoped_entry("delete_by_filter_with_edges")?;
        self.delete_by_filter_unguarded(
            collection_name,
            filter,
            true,
            audit::AuditContext::embedded(),
        )
    }

    pub fn set_max_points_per_collection(&self, max_points: Option<usize>) {
        self.inner.write().max_points_per_collection = max_points;
    }

    /// Turn row-level tenant rules on, off, or on-but-observing.
    ///
    /// Switching straight to `Enforced` on a database that predates this makes
    /// every existing point invisible, because a point with no `tenant_id`
    /// belongs to nobody and is therefore visible to nobody. Backfill first,
    /// confirm with `DryRun`, then enforce. See `crate::tenant`.
    pub fn set_tenant_enforcement(&self, enforcement: crate::tenant::TenantEnforcement) {
        self.inner.write().tenant_enforcement = enforcement;
    }

    pub fn tenant_enforcement(&self) -> crate::tenant::TenantEnforcement {
        self.inner.read().tenant_enforcement
    }

    /// Refuses a call that arrived through an entry point carrying no tenant
    /// scope, once enforcement is on.
    ///
    /// This is what makes omission safe. A surface that has not been taught
    /// about tenants keeps working while enforcement is off, and **denies**
    /// rather than leaks the moment it is switched on — the failure mode is an
    /// error the operator sees, not rows crossing a boundary silently.
    fn require_scoped_entry(&self, operation: &str) -> Result<()> {
        if self.tenant_enforcement().blocks() {
            return Err(GaussError::InvalidRequest(format!(
                "`{operation}` was called without a tenant scope while tenant enforcement is \
                 on; use the `_scoped` entry point"
            )));
        }
        Ok(())
    }

    // -- tenant-scoped entry points ----------------------------------------
    //
    // Each one narrows or stamps according to the caller's scope and then
    // delegates to the unscoped implementation, so there is one copy of the
    // engine logic and one copy of the tenant logic.

    pub fn search_scoped(
        &self,
        collection_name: &str,
        mut request: SearchRequest,
        scope: &crate::tenant::TenantScope,
    ) -> Result<SearchResponse> {
        let enforcement = self.tenant_enforcement();
        request.filter = scope.scope_filter(enforcement, request.filter)?;
        if request.graph.is_some() {
            let cancelled = AtomicBool::new(false);
            return self.graph_search_scoped_controlled(
                collection_name,
                request,
                scope,
                &cancelled,
            );
        }
        self.search_unguarded(collection_name, request)
    }

    pub fn search_with_cancellation_scoped(
        &self,
        collection_name: &str,
        mut request: SearchRequest,
        scope: &crate::tenant::TenantScope,
        cancelled: &AtomicBool,
    ) -> Result<SearchResponse> {
        request.filter = scope.scope_filter(self.tenant_enforcement(), request.filter.take())?;
        if request.graph.is_some() {
            return self.graph_search_scoped_controlled(collection_name, request, scope, cancelled);
        }
        self.search_controlled(collection_name, request, Some(cancelled))
    }

    pub fn count_scoped(
        &self,
        collection_name: &str,
        filter: Option<Filter>,
        scope: &crate::tenant::TenantScope,
    ) -> Result<CountResponse> {
        let enforcement = self.tenant_enforcement();
        let filter = scope.scope_filter(enforcement, filter)?;
        self.count_unguarded(collection_name, filter)
    }

    pub fn scroll_scoped(
        &self,
        collection_name: &str,
        offset: Option<&str>,
        limit: usize,
        filter: Option<Filter>,
        scope: &crate::tenant::TenantScope,
    ) -> Result<ScrollResponse> {
        let enforcement = self.tenant_enforcement();
        let filter = scope.scope_filter(enforcement, filter)?;
        self.scroll_unguarded(collection_name, offset, limit, filter)
    }

    /// Fetch by id, filtered after the fact.
    ///
    /// There is no filter to narrow here, so each point is checked against the
    /// caller instead. A point belonging to another tenant is omitted rather
    /// than reported as forbidden: telling a caller that an id exists but is
    /// not theirs is itself a leak.
    pub fn get_points_scoped(
        &self,
        collection_name: &str,
        ids: &[String],
        scope: &crate::tenant::TenantScope,
    ) -> Result<Vec<Point>> {
        let enforcement = self.tenant_enforcement();
        let points = self.get_points_unguarded(collection_name, ids)?;
        if !enforcement.blocks() {
            return Ok(points);
        }
        Ok(points
            .into_iter()
            .filter(|point| scope.may_read_payload(enforcement, &point.payload))
            .collect())
    }

    pub fn upsert_scoped(
        &self,
        collection_name: &str,
        mut points: Vec<Point>,
        wait: bool,
        scope: &crate::tenant::TenantScope,
    ) -> Result<usize> {
        let enforcement = self.tenant_enforcement();
        for point in &mut points {
            scope.stamp_payload(enforcement, &mut point.payload)?;
        }
        self.upsert_wait_unguarded(
            collection_name,
            points,
            wait,
            MutationContext::client(audit_context(scope)),
            None,
            None,
        )
        .map(|receipt| receipt.total)
    }

    /// Typed structural-node admission for protocol and SDK façades.
    ///
    /// Generic point upsert remains unchanged for legacy clients. Graph-aware
    /// callers use this scoped entry point so D18's non-zero identity-derived
    /// embedding convention is enforced and any explicit exception is written
    /// into the same durable mutation audit record as its WAL operation.
    pub fn upsert_structural_scoped(
        &self,
        collection_name: &str,
        mut points: Vec<Point>,
        wait: bool,
        scope: &crate::tenant::TenantScope,
        unsafe_reason: Option<&str>,
    ) -> Result<crate::structural_embedding::StructuralUpsertReceipt> {
        let unsafe_audit =
            crate::structural_embedding::validate_structural_points(&points, unsafe_reason)?;
        let enforcement = self.tenant_enforcement();
        for point in &mut points {
            scope.stamp_payload(enforcement, &mut point.payload)?;
        }
        self.upsert_wait_unguarded(
            collection_name,
            points,
            wait,
            MutationContext::client(audit_context(scope)),
            unsafe_audit,
            None,
        )
        .map(
            |receipt| crate::structural_embedding::StructuralUpsertReceipt {
                total: receipt.total,
                operation_lsn: receipt.operation_lsn,
                unsafe_override_audited: receipt.unsafe_override_audited,
            },
        )
    }

    /// Crate-internal G0 mutation boundary. Protocols remain unable to call
    /// this raw-ID primitive; typed scoped wrappers resolve public point/edge
    /// tokens before they reach it in later slices.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "used by the following scoped graph API slice")
    )]
    fn commit_graph_batch_scoped(
        &self,
        collection_name: &str,
        batch: crate::wal::GraphBatch,
        wait: bool,
        scope: &crate::tenant::TenantScope,
    ) -> Result<GraphBatchCommitReceipt> {
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let audit_operation = self.audit_operation_with_context(
            "graph_batch",
            Some(collection_name),
            audit_context(scope),
        )?;
        let coll = self.get_coll(collection_name)?;
        let mut collection = coll.write();
        let point_mutations = batch.point_mutations.len();
        let handle_assignments = batch.handle_assignments.len();
        let edge_mutations = batch.edge_mutations.len();
        let deferred_creates = batch.deferred_binds.len();
        let deferred_binds = batch.edge_binds.len();
        let session_mutations = batch.deferred_sessions.len();
        let receipt = self.commit_graph_batch_locked(&mut collection, batch, wait)?;
        drop(collection);

        audit_operation.success(serde_json::json!({
            "graph_epoch": receipt.graph_epoch.raw(),
            "operation_lsn": receipt.operation_lsn,
            "wait": wait,
            "point_mutations": point_mutations,
            "handle_assignments": handle_assignments,
            "edge_mutations": edge_mutations,
            "deferred_creates": deferred_creates,
            "deferred_binds": deferred_binds,
            "session_mutations": session_mutations,
        }))?;
        self.refresh_metrics();
        Ok(receipt)
    }

    fn commit_graph_batch_locked(
        &self,
        collection: &mut Collection,
        batch: crate::wal::GraphBatch,
        wait: bool,
    ) -> Result<GraphBatchCommitReceipt> {
        let record_lsn = collection.wal.len()?;
        let prepared = prepare_graph_batch(
            &collection.config,
            &collection.streamer,
            collection.sealing.as_deref(),
            &collection.searchers,
            &collection.id_index,
            record_lsn,
            collection.graph_lifecycle,
            &collection.graph_resolver,
            &collection.graph_mutable,
            &batch,
        )?;
        crate::failpoint::check("graph_batch.after_prepare")?;
        let graph_epoch = batch.graph_epoch;
        let operation_lsn = collection.wal.append_no_sync(&WalEntry::GraphBatch {
            batch: batch.clone(),
        })?;
        crate::failpoint::check("graph_batch.after_wal_append")?;
        if wait && let Err(error) = collection.wal.sync() {
            self.mark_durability_degraded("graph_batch_sync", &error);
            return Err(error);
        }
        if wait {
            crate::failpoint::check("graph_batch.after_wal_sync")?;
        }

        let Collection {
            streamer,
            sealing,
            searchers,
            id_index,
            graph_resolver,
            graph_mutable,
            sparse_index,
            payload_index,
            overlays,
            ..
        } = collection;
        if let Err(error) = apply_prepared_graph_batch(
            GraphApplyState {
                streamer,
                sealing: sealing.as_deref(),
                searchers,
                id_index,
                resolver: graph_resolver,
                mutable: graph_mutable,
                sparse_index: Some(sparse_index),
                payload_index,
            },
            batch,
            prepared,
        ) {
            let error = GaussError::WalUnavailable(format!(
                "committed GraphBatch could not publish its prevalidated state; restart required: {error}"
            ));
            self.mark_durability_degraded("graph_batch_apply", &error);
            return Err(error);
        }
        crate::failpoint::check("graph_batch.after_apply")?;
        let mut point_tombstones = crate::ordinal::SegmentOrdinalSet::new();
        for searcher in searchers.iter() {
            point_tombstones
                .insert_bitmap(searcher.id.clone(), searcher.tombstone_ordinals.clone());
        }
        let edge_tombstones = graph_mutable
            .as_ref()
            .expect("prepared GraphBatch requires mutable graph state")
            .edge_tombstones();
        if let Err(error) = overlays
            .reconcile_points(&point_tombstones)
            .and_then(|_| overlays.replace_edges(edge_tombstones))
            .and_then(|_| overlays.publish_pending())
        {
            self.mark_durability_degraded("graph_batch_overlay", &error);
            return Err(error);
        }
        crate::failpoint::check("graph_batch.after_overlay_publish")?;
        Ok(GraphBatchCommitReceipt {
            graph_epoch,
            operation_lsn,
            durable: wait,
        })
    }

    pub fn delete_scoped(
        &self,
        collection_name: &str,
        ids: &[String],
        scope: &crate::tenant::TenantScope,
    ) -> Result<usize> {
        let enforcement = self.tenant_enforcement();
        if !enforcement.blocks() {
            return self.delete_unguarded(
                collection_name,
                ids,
                false,
                audit_context(scope),
                MutationOrigin::Client,
            );
        }
        // Only delete ids this caller can actually see. An id belonging to
        // another tenant is skipped, not refused, for the same reason
        // `get_points_scoped` omits rather than reports.
        let visible: Vec<String> = self
            .get_points_scoped(collection_name, ids, scope)?
            .into_iter()
            .map(|point| point.id)
            .collect();
        if visible.is_empty() {
            return Ok(0);
        }
        self.delete_unguarded(
            collection_name,
            &visible,
            false,
            audit_context(scope),
            MutationOrigin::Client,
        )
    }

    pub fn delete_with_edges_scoped(
        &self,
        collection_name: &str,
        ids: &[String],
        scope: &crate::tenant::TenantScope,
    ) -> Result<usize> {
        let enforcement = self.tenant_enforcement();
        if !enforcement.blocks() {
            return self.delete_unguarded(
                collection_name,
                ids,
                true,
                audit_context(scope),
                MutationOrigin::Client,
            );
        }
        let visible = self
            .get_points_scoped(collection_name, ids, scope)?
            .into_iter()
            .map(|point| point.id)
            .collect::<Vec<_>>();
        if visible.is_empty() {
            return Ok(0);
        }
        self.delete_unguarded(
            collection_name,
            &visible,
            true,
            audit_context(scope),
            MutationOrigin::Client,
        )
    }

    pub fn set_payload_scoped(
        &self,
        collection_name: &str,
        id: &str,
        mut payload: serde_json::Value,
        merge: bool,
        scope: &crate::tenant::TenantScope,
    ) -> Result<Point> {
        let enforcement = self.tenant_enforcement();
        if enforcement.blocks() {
            // The point must already be the caller's before it may be changed.
            let existing =
                self.get_points_unguarded(collection_name, std::slice::from_ref(&id.to_string()))?;
            let Some(existing) = existing.first() else {
                return Err(GaussError::PointNotFound(id.to_string()));
            };
            scope.may_write_payload(enforcement, &existing.payload)?;
            // A replace must not drop the tenant stamp and orphan the row.
            scope.stamp_payload(enforcement, &mut payload)?;
        }
        self.set_payload_unguarded(
            collection_name,
            id,
            payload,
            merge,
            audit_context(scope),
            MutationOrigin::Client,
        )
    }

    pub fn delete_by_filter_scoped(
        &self,
        collection_name: &str,
        filter: &Filter,
        scope: &crate::tenant::TenantScope,
    ) -> Result<usize> {
        let enforcement = self.tenant_enforcement();
        let scoped = scope.scope_filter(enforcement, Some(filter.clone()))?;
        match scoped {
            Some(filter) => self.delete_by_filter_unguarded(
                collection_name,
                &filter,
                false,
                audit_context(scope),
            ),
            None => self.delete_by_filter_unguarded(
                collection_name,
                filter,
                false,
                audit_context(scope),
            ),
        }
    }

    pub fn delete_by_filter_with_edges_scoped(
        &self,
        collection_name: &str,
        filter: &Filter,
        scope: &crate::tenant::TenantScope,
    ) -> Result<usize> {
        let scoped = scope.scope_filter(self.tenant_enforcement(), Some(filter.clone()))?;
        self.delete_by_filter_unguarded(
            collection_name,
            scoped.as_ref().unwrap_or(filter),
            true,
            audit_context(scope),
        )
    }

    pub fn hybrid_search_scoped(
        &self,
        collection_name: &str,
        mut request: HybridSearchRequest,
        scope: &crate::tenant::TenantScope,
    ) -> Result<SearchResponse> {
        request.filter = scope.scope_filter(self.tenant_enforcement(), request.filter)?;
        if request.graph.is_some() {
            let cancelled = AtomicBool::new(false);
            return self.graph_hybrid_search_scoped_controlled(
                collection_name,
                request,
                scope,
                &cancelled,
            );
        }
        self.hybrid_search_unguarded(collection_name, request)
    }

    pub fn multi_search_scoped(
        &self,
        collection_name: &str,
        mut request: MultiSearchRequest,
        scope: &crate::tenant::TenantScope,
    ) -> Result<MultiSearchResponse> {
        let enforcement = self.tenant_enforcement();
        for search in &mut request.searches {
            search.filter = scope.scope_filter(enforcement, search.filter.take())?;
        }
        if request.searches.iter().any(|search| search.graph.is_some()) {
            return Err(GaussError::InvalidRequest(
                "graph constraints are not supported by multi_search; issue scoped searches separately"
                    .to_string(),
            ));
        }
        self.multi_search_unguarded(collection_name, request)
    }

    pub fn recommend_scoped(
        &self,
        collection_name: &str,
        mut request: RecommendRequest,
        scope: &crate::tenant::TenantScope,
    ) -> Result<SearchResponse> {
        let enforcement = self.tenant_enforcement();
        if enforcement.blocks() {
            let ids: Vec<String> = request
                .positive
                .iter()
                .chain(&request.negative)
                .cloned()
                .collect();
            let visible = self.get_points_scoped(collection_name, &ids, scope)?;
            if visible.len() != ids.len() {
                return Err(GaussError::PointNotFound(
                    "one or more recommendation source points were not found".to_string(),
                ));
            }
        }
        request.filter = scope.scope_filter(enforcement, request.filter)?;
        self.recommend_unguarded(collection_name, request)
    }

    pub fn rerank_scoped(
        &self,
        collection_name: &str,
        mut request: RerankRequest,
        scope: &crate::tenant::TenantScope,
    ) -> Result<SearchResponse> {
        request.filter = scope.scope_filter(self.tenant_enforcement(), request.filter)?;
        self.rerank_unguarded(collection_name, request)
    }

    pub fn max_points_per_collection(&self) -> Option<usize> {
        self.inner.read().max_points_per_collection
    }

    fn get_coll(&self, name: &str) -> Result<Arc<RwLock<Collection>>> {
        self.inner
            .read()
            .collections
            .get(name)
            .cloned()
            .ok_or_else(|| GaussError::CollectionNotFound(name.to_string()))
    }

    fn ensure_collection_cold_materialized(&self, collection_name: &str) -> Result<()> {
        self.ensure_collection_cold_materialized_scope(
            collection_name,
            ColdMaterializeScope::Search,
        )
    }

    fn ensure_collection_cold_materialized_scope(
        &self,
        collection_name: &str,
        _scope: ColdMaterializeScope,
    ) -> Result<()> {
        // Read-first: the common case (no cold/object-store tier configured)
        // exits here without ever taking `self.inner.write()`. Taking a
        // write lock on every search -- the previous behavior -- serialized
        // all concurrent searches across every collection through one
        // global mutex, since parking_lot write locks block all readers.
        // Only escalate to the write lock below when there's actually
        // materialization work to do.
        let (root, cold_object_store) = {
            let inner = self.inner.read();
            if !inner.collections.contains_key(collection_name) {
                return Err(GaussError::CollectionNotFound(collection_name.to_string()));
            }
            (inner.root.clone(), inner.cold_object_store.clone())
        };
        let Some(cold_object_store) = cold_object_store else {
            return Ok(());
        };
        self.ensure_storage_mutations_available()?;
        let collection_dir = collection_dir(&root, collection_name);
        let materialized = materialize_missing_cold_segments_from_object_store(
            &collection_dir.join("cold"),
            &cold_object_store,
        )?;
        if materialized == 0 {
            return Ok(());
        }

        let arc_coll = self
            .inner
            .read()
            .collections
            .get(collection_name)
            .cloned()
            .ok_or_else(|| GaussError::CollectionNotFound(collection_name.to_string()))?;
        let (config, schema_epoch, wal_watermark) = {
            let coll = arc_coll.read();
            (coll.config.clone(), coll.schema_epoch, coll.wal_watermark)
        };
        let state = load_collection_state(
            &collection_dir,
            config,
            schema_epoch,
            wal_watermark,
            Some(&cold_object_store),
            crate::overlay::OverlayOpenMode::Recover,
        )?;

        let mut col = arc_coll.write();
        col.config = state.config;
        col.schema_epoch = state.schema_epoch;
        col.streamer = state.streamer;
        col.searchers = state.searchers;
        col.id_index = state.id_index;
        col.graph_lifecycle = state.graph_lifecycle;
        col.graph_resolver = state.graph_resolver;
        col.graph_mutable = state.graph_mutable;
        col.graph_generation = state.graph_generation;
        col.wal_watermark = state.wal_watermark;
        col.payload_index = state.payload_index;
        col.sparse_index = state.sparse_index;
        col.overlays = state.overlays;
        // W1 bugfix: a freshly loaded H2qgIndex always starts with its own
        // cascade flag false (HnswGraph::new default) regardless of
        // DbInner.cascade. Without this, the server-wide default never
        // actually reaches a collection loaded from disk.
        col.set_cascade_on_indexes(self.cascade.clone());
        // PC-2 v3: rehydrate the vamana graph from the per-segment
        // `vamana.gdx` artifact when present. Read by iterating the
        // per-segment dirs under `<collection>/searchers/` (vamana is
        // per-segment, not per-collection). The reader returns
        // Ok(None) for segments without a vamana.gdx (legacy V1/V2 or
        // HNSW collections).
        if matches!(col.config.index_kind.as_deref(), Some("vamana")) {
            let vamana_searchers_dir = collection_dir.join("searchers");
            let mut vamana_backends: Vec<Option<crate::index::vamana::VamanaBackend>> = Vec::new();
            if vamana_searchers_dir.exists() {
                for entry in std::fs::read_dir(&vamana_searchers_dir)? {
                    let dir = entry?.path();
                    if dir.is_dir() {
                        let vamana_path = dir.join(crate::segment::VAMANA_FILE);
                        vamana_backends.push(crate::segment::read_vamana_index(&vamana_path)?);
                    }
                }
            }
            // P2C v3: vamana is per-segment; the in-memory `vamana` field
            // holds the first one as a stand-in until a future iteration
            // folds multiple segments into a single graph. Today this
            // matches the existing single-graph-per-collection contract.
            col.vamana = vamana_backends.into_iter().flatten().next();
        }
        Ok(())
    }

    pub fn create_collection(&self, config: CollectionConfig) -> Result<CollectionConfig> {
        let _lifecycle = self.lifecycle_gate.write();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let audit_operation =
            self.audit_operation("create_collection", Some(config.name.as_str()))?;
        let mut operation_metrics = OperationGuard::start("create_collection");
        let config = config.normalize();
        validate_config(&config)?;

        let mut inner = self.inner.write();
        if inner.collections.contains_key(&config.name) {
            return Err(GaussError::CollectionExists(config.name));
        }

        let root = inner.root.clone();
        let collection_dir = collection_dir(&root, &config.name);
        let staging_dir = collection_create_staging_dir(&root, &config.name);
        if collection_dir.exists() || staging_dir.exists() {
            return Err(GaussError::WalUnavailable(format!(
                "collection '{}' has an unresolved filesystem generation",
                config.name
            )));
        }
        fs::create_dir_all(staging_dir.join("wal"))?;
        fs::create_dir_all(staging_dir.join("searchers"))?;
        let staging_wal = Wal::open(&staging_dir.join("wal"))?;
        let schema_epoch = 1;
        let checkpoint = CollectionCheckpoint::new(&config, schema_epoch, 0, 0, None)?;
        write_checkpoint(&staging_dir, &checkpoint)?;
        let empty_segments = HashSet::new();
        drop(crate::overlay::OverlayStore::open(
            &staging_dir,
            0,
            &empty_segments,
            crate::ordinal::SegmentOrdinalSet::new(),
            crate::overlay::OverlayOpenMode::Recover,
        )?);
        drop(staging_wal);
        sync_tree(&staging_dir)?;
        inner.catalog_wal.append(&WalEntry::CreateCollection {
            config: config.clone(),
        })?;
        #[cfg(feature = "fault-injection")]
        crate::fs_util::fault_injection::crash_hook(
            crate::fs_util::fault_injection::HOOK_CATALOG_AFTER_DURABLE_COMMIT,
        )?;
        if let Err(error) = durable_rename(&staging_dir, &collection_dir) {
            let error = GaussError::WalUnavailable(format!(
                "catalog committed collection '{}' but generation install failed: {error}",
                config.name
            ));
            self.mark_durability_degraded("create_collection_install", &error);
            return Err(error);
        }
        let wal = Wal::open(&collection_dir.join("wal"))?;
        let overlays = crate::overlay::OverlayStore::open(
            &collection_dir,
            0,
            &empty_segments,
            crate::ordinal::SegmentOrdinalSet::new(),
            crate::overlay::OverlayOpenMode::Recover,
        )?;
        inner.collections.insert(
            config.name.clone(),
            Arc::new(RwLock::new(Collection {
                config: config.clone(),
                streamer: crate::streamer::Streamer::new(),
                sealing: None,
                searchers: Vec::new(),
                id_index: HashMap::new(),
                graph_lifecycle: crate::graph_lifecycle::GraphLifecycleState::default(),
                graph_resolver: None,
                graph_mutable: None,
                graph_generation: None,
                graph_calibration: None,
                sparse_index: SparseIndex::default(),
                payload_index: PayloadIndex::default(),
                overlays,
                rabitq: None,
                vamana: None,
                ivf: None,
                wal,
                wal_watermark: 0,
                schema_epoch,
                last_segment_id: None,
                recall_curve: None,
                hnsw_dirty: true,
                index_build_in_flight: false,
                generation_build_in_flight: false,
                graph_backfill_in_flight: false,
            })),
        );
        self.checkpoint_catalog_after_commit(&mut inner);
        drop(inner);
        audit_operation.success(serde_json::json!({
            "vector_dim": config.vector_dim,
            "metric": config.metric,
            "shards": config.shards,
            "replicas": config.replicas,
            "recall_sla": config.recall_sla,
        }))?;
        self.refresh_metrics();
        operation_metrics.succeed();
        Ok(config)
    }

    pub fn list_collections(&self) -> Vec<CollectionConfig> {
        let mut collections: Vec<_> = self
            .inner
            .read()
            .collections
            .values()
            .map(|c| c.read().config.clone())
            .collect();
        collections.sort_by(|left, right| left.name.cmp(&right.name));
        collections
    }

    pub fn delete_collection(&self, collection_name: &str) -> Result<String> {
        let _lifecycle = self.lifecycle_gate.write();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let audit_operation = self.audit_operation("delete_collection", Some(collection_name))?;
        let coll = self.get_coll(collection_name)?;
        while coll.read().sealing.is_some() {
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut inner = self.inner.write();
        if !inner.collections.contains_key(collection_name) {
            return Err(GaussError::CollectionNotFound(collection_name.to_string()));
        }
        let root = inner.root.clone();
        inner.catalog_wal.append(&WalEntry::DropCollection {
            name: collection_name.to_string(),
        })?;
        #[cfg(feature = "fault-injection")]
        crate::fs_util::fault_injection::crash_hook(
            crate::fs_util::fault_injection::HOOK_CATALOG_AFTER_DURABLE_COMMIT,
        )?;
        let removed = inner.collections.remove(collection_name);
        drop(removed);
        let dir = collection_dir(&root, collection_name);
        let mut trash = collection_drop_trash_dir(&root, collection_name);
        if trash.exists() {
            trash = collections_dir(&root).join(format!(
                ".chirondb-drop-{collection_name}-{}.trash",
                uuid::Uuid::new_v4()
            ));
        }
        if dir.exists()
            && let Err(error) = durable_rename(&dir, &trash)
        {
            let error = GaussError::WalUnavailable(format!(
                "catalog committed drop for '{collection_name}' but trash install failed: {error}"
            ));
            self.mark_durability_degraded("drop_collection_install", &error);
            return Err(error);
        }
        // Checkpoint and prefix pruning happen only after the live generation
        // has moved out of the catalog namespace. If a crash happens earlier,
        // replay still retains the DropCollection record needed to finish it.
        self.checkpoint_catalog_after_commit(&mut inner);
        drop(inner);
        if trash.exists()
            && let Err(error) = durable_remove_dir_all(&trash)
        {
            self.mark_durability_degraded("drop_collection_cleanup", &error);
            tracing::warn!(%error, collection = collection_name, "drop trash retained for operator cleanup");
        }
        audit_operation.success(serde_json::json!({}))?;
        self.refresh_metrics();
        Ok(collection_name.to_string())
    }

    pub fn update_payload_schema(
        &self,
        collection_name: &str,
        payload_schema: HashMap<String, PayloadType>,
    ) -> Result<CollectionConfig> {
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let audit_operation =
            self.audit_operation("update_payload_schema", Some(collection_name))?;
        let mut operation_metrics = OperationGuard::start("update_payload_schema");
        self.ensure_collection_cold_materialized(collection_name)?;
        let inner = self.inner.write();
        let root = inner.root.clone();
        let arc_coll = inner
            .collections
            .get(collection_name)
            .cloned()
            .ok_or_else(|| GaussError::CollectionNotFound(collection_name.to_string()))?;
        let (updated, checkpoint) = {
            let mut collection = arc_coll.write();
            let mut candidate = collection.config.clone();
            candidate.payload_schema = payload_schema;
            validate_config(&candidate)?;
            for point in collection.iter_live() {
                validate_payload_schema(&candidate, &point)?;
            }
            let schema_epoch = collection
                .schema_epoch
                .checked_add(1)
                .ok_or_else(|| GaussError::InvalidRequest("schema epoch overflow".to_string()))?;
            let previous_config = collection.config.clone();
            let last_applied_lsn = collection.wal.append(&WalEntry::Schema {
                schema_epoch,
                config: candidate.clone(),
                previous_config: Some(previous_config),
            })?;
            // WAL-first: once validation succeeds, make the schema durable
            // before publishing it to readers or advancing the epoch.
            collection.config = candidate.clone();
            collection.schema_epoch = schema_epoch;
            let checkpoint = collection.checkpoint(
                last_applied_lsn,
                collection.live_points(),
                collection.last_segment_id.clone(),
            )?;
            (candidate, checkpoint)
        };
        if let Err(error) = write_catalog(&inner)
            .and_then(|()| write_checkpoint(&collection_dir(&root, collection_name), &checkpoint))
        {
            // The schema record is already durable and recovery can rebuild
            // both metadata files. Do not report a false rollback to a client;
            // mark readiness degraded until an operator restarts/repairs I/O.
            self.mark_durability_degraded("schema_checkpoint", &error);
        }
        drop(inner);
        audit_operation.success(serde_json::json!({
            "fields": updated.payload_schema.len(),
        }))?;
        operation_metrics.succeed();
        Ok(updated)
    }

    pub fn upsert(&self, collection_name: &str, points: Vec<Point>) -> Result<usize> {
        self.upsert_wait_unguarded(
            collection_name,
            points,
            true,
            MutationContext::client(audit::AuditContext::embedded()),
            None,
            None,
        )
        .map(|receipt| receipt.total)
    }

    fn upsert_wait_unguarded(
        &self,
        collection_name: &str,
        points: Vec<Point>,
        wait: bool,
        mutation_context: MutationContext,
        unsafe_structural_audit: Option<
            crate::structural_embedding::UnsafeStructuralEmbeddingAudit,
        >,
        graph_deferred_session: Option<&crate::graph::GraphDeferredSessionId>,
    ) -> Result<UpsertExecutionReceipt> {
        let MutationContext {
            audit: audit_context,
            origin,
        } = mutation_context;
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        if origin == MutationOrigin::LegacyReplication {
            self.ensure_legacy_replication_available(collection_name)?;
        }
        let audit_operation =
            self.audit_operation_with_context("upsert", Some(collection_name), audit_context)?;
        let mut operation_metrics = OperationGuard::start("upsert");
        self.ensure_collection_cold_materialized(collection_name)?;
        let (root, max_points_per_collection, wal_archive_policy) = {
            let inner = self.inner.read();
            (
                inner.root.clone(),
                inner.max_points_per_collection,
                seal_wal_archive_policy(&inner, collection_name),
            )
        };
        let coll = self.get_coll(collection_name)?;
        let mut collection = coll.write();

        // A collection has exactly two mutable legs: the frozen streamer being
        // sealed and the new active streamer. If both have reached the cap,
        // wait for normal backpressure; under cgroup pressure, reject before
        // WAL mutation so the client can retry instead of risking an OOM kill.
        while streamer_admission_wait_required(
            collection.sealing.is_some(),
            collection
                .streamer
                .should_seal(collection.config.streamer_max_bytes),
            crate::streamer::memory_pressure(),
        )? {
            drop(collection);
            std::thread::sleep(Duration::from_millis(20));
            collection = coll.write();
        }
        if origin == MutationOrigin::LegacyReplication
            && collection.graph_lifecycle.epoch().is_some()
        {
            return Err(graph_replication_unavailable(collection_name));
        }

        let requested_points = points.len();
        // PB-2: parallelise typed-payload + dim validation across the batch.
        // Each `validate_point` call is independent and CPU-bound (dim check,
        // payload schema walk, regex/text checks). For small batches the rayon
        // setup cost dominates, so fall back to serial below the threshold.
        const PARALLEL_VALIDATE_THRESHOLD: usize = 256;
        let validate_one = |point: &Point| -> Result<()> {
            validate_point(&collection.config, point).map_err(|e| match e {
                GaussError::DimensionMismatch { expected, actual } => {
                    GaussError::InvalidRequest(format!(
                        "point '{}': expected vector dimension {expected}, got {actual}",
                        point.id
                    ))
                }
                other => other,
            })
        };
        if points.len() >= PARALLEL_VALIDATE_THRESHOLD {
            points.par_iter().try_for_each(validate_one)?;
        } else {
            for point in &points {
                validate_one(point)?;
            }
        }
        if let Some(max_points) = max_points_per_collection {
            let new_ids = points
                .iter()
                .filter(|point| !collection.id_index.contains_key(&point.id))
                .count();
            let projected_points = collection
                .live_points()
                .checked_add(new_ids)
                .ok_or_else(|| GaussError::ResourceExhausted("point count overflow".to_string()))?;
            if projected_points > max_points {
                return Err(GaussError::InvalidRequest(format!(
                    "collection {collection_name} would exceed max_points_per_collection {max_points}: {projected_points}"
                )));
            }
        }

        let graph_enabled = collection.graph_lifecycle.is_enabled();
        if graph_deferred_session.is_some() && !graph_enabled {
            return Err(crate::graph::GraphError::new(
                crate::graph::GraphErrorCode::GraphDisabled,
                "graph is not enabled for this collection",
            )
            .into());
        }
        // Persist one frame per request. Graph-enabled collections route point
        // mutation and any fresh handle assignments through the same
        // GraphBatch; vector-only collections retain their legacy WAL shape.
        let mut graph_epoch = None;
        let mut graph_bound_endpoints = 0;
        let operation_lsn = if graph_enabled && !points.is_empty() {
            let (receipt, bound_endpoints) = self.commit_graph_point_upserts_with_session_locked(
                &mut collection,
                points.clone(),
                wait,
                graph_deferred_session.map(crate::graph::GraphDeferredSessionId::as_str),
            )?;
            graph_epoch = Some(receipt.graph_epoch);
            graph_bound_endpoints = bound_endpoints;
            receipt.operation_lsn
        } else if !points.is_empty() {
            collection.wal.append_no_sync(&WalEntry::UpsertBatch {
                points: points.clone(),
            })?;
            if wait {
                collection.wal.sync()?;
            }
            collection.wal.len()?
        } else {
            collection.wal.len()?
        };
        // Phase 3a: when an HNSW graph already exists, append each new point
        // into the live graph alongside sparse/payload updates. Removes the gap
        // where points upserted between compactions fell through to flat scan.
        let h2qg_present_before = collection.streamer.hnsw.is_some();
        let rabitq_present_before = collection.rabitq.is_some();
        let vamana_present_before = collection.vamana.is_some();
        let ivf_present_before = collection.ivf.is_some();
        let collection_vector_dim = collection.config.vector_dim;
        if !graph_enabled {
            for point in points {
                // Route the old copy through the ID authority: an id living in a
                // sealed searcher is tombstoned there (never mutated in place);
                // an id already in the streamer is replaced as before.
                match collection.id_index.get(&point.id).copied() {
                    Some(crate::searcher::SegLoc::Sealing) => {
                        if let Some(old_point) = collection
                            .sealing
                            .as_ref()
                            .and_then(|streamer| streamer.points.get(&point.id))
                            .cloned()
                        {
                            remove_sparse_point(&mut collection.sparse_index, &old_point);
                            remove_payload_point(&mut collection.payload_index, &old_point);
                        }
                        collection.streamer.insert(point.clone());
                    }
                    Some(crate::searcher::SegLoc::Searcher(i)) => {
                        let old_point = collection.searchers[i as usize]
                            .store
                            .get(&point.id)
                            .map(Cow::into_owned);
                        if let Some(old_point) = old_point {
                            remove_sparse_point(&mut collection.sparse_index, &old_point);
                            remove_payload_point(&mut collection.payload_index, &old_point);
                        }
                        collection.tombstone_searcher(i as usize, &point.id)?;
                        collection.streamer.insert(point.clone());
                    }
                    _ => {
                        if let Some(old_point) = collection.streamer.insert(point.clone()) {
                            remove_sparse_point(&mut collection.sparse_index, &old_point);
                            remove_payload_point(&mut collection.payload_index, &old_point);
                        }
                    }
                }
                collection
                    .id_index
                    .insert(point.id.clone(), crate::searcher::SegLoc::Streamer);
                insert_sparse_point(&mut collection.sparse_index, &point);
                insert_payload_point(&mut collection.payload_index, &point);
                if h2qg_present_before
                    && let Some(h2qg) = collection.streamer.hnsw.as_mut()
                    && !h2qg.contains(&point.id)
                {
                    let _ = h2qg.insert_point(&point, collection_vector_dim);
                }
                // PC-1b: inline insert for RaBitQ too. `IndexBackend::insert_point`
                // is a trait method so the call shape is identical.
                if rabitq_present_before && let Some(rb) = collection.rabitq.as_mut() {
                    use crate::index::IndexBackend;
                    if !IndexBackend::contains(rb, &point.id) {
                        let _ = IndexBackend::insert_point(rb, &point, collection_vector_dim);
                    }
                }
                // PC-2: same inline-insert shape for Vamana.
                if vamana_present_before && let Some(vm) = collection.vamana.as_mut() {
                    use crate::index::IndexBackend;
                    if !IndexBackend::contains(vm, &point.id) {
                        let _ = IndexBackend::insert_point(vm, &point, collection_vector_dim);
                    }
                }
                // B1.1: same inline-insert shape for IVF.
                if ivf_present_before && let Some(ivf) = collection.ivf.as_mut() {
                    use crate::index::IndexBackend;
                    if !IndexBackend::contains(ivf, &point.id) {
                        let _ = IndexBackend::insert_point(ivf, &point, collection_vector_dim);
                    }
                }
                collection.hnsw_dirty = true;
            }
        }

        let mut pending_seal = None;
        if collection.sealing.is_none()
            && !collection.generation_build_in_flight
            && collection
                .streamer
                .should_seal(collection.config.streamer_max_bytes)
        {
            // The seal marker may cover this WAL prefix only after the prefix
            // itself is durable, including wait=false batches.
            collection.wal.sync()?;
            match collection.overlays.publish_pending() {
                Ok(()) => {
                    let end_lsn = collection.wal.len()?;
                    let graph = capture_graph_seal(
                        &mut collection,
                        &collection_dir(&root, collection_name),
                        end_lsn,
                    )?;
                    let wal_archive_cut = if graph.is_some() {
                        collection.wal.freeze_archive_cut(end_lsn)?
                    } else {
                        None
                    };
                    let frozen = freeze_streamer_for_seal(&mut collection, end_lsn);
                    pending_seal = Some(PendingSeal {
                        coll: Arc::clone(&coll),
                        data_dir_lock: Arc::clone(&self._data_dir_lock),
                        lifecycle: Arc::clone(&self.build_lifecycle),
                        collection_dir: collection_dir(&root, collection_name),
                        frozen,
                        end_lsn,
                        graph,
                        wal_archive_cut,
                        wal_archive_policy,
                        vector_dim: collection.config.vector_dim,
                        metric: collection.config.metric,
                        hnsw_m: collection.config.hnsw_m,
                        hnsw_ef_construction: collection.config.hnsw_ef_construction,
                        index_kind: crate::seal::SealIndexKind::Algorithm2,
                        cascade: self.cascade.clone(),
                        intra_query_parallel: self.intra_query_parallel.clone(),
                    });
                }
                Err(error) => self.mark_durability_degraded("visibility_overlay", &error),
            }
        }

        // Phase 3a: if the collection just crossed the HNSW threshold, stage
        // the initial graph build to run on a background thread, off the
        // collection write lock. Building inline (the old behavior) stalls
        // every read/write against this collection for the entire build --
        // measured 26s/55s/109s at 768/1536/3072-dim on a 20k-point corpus.
        // The build functions only need an owned point snapshot + scalar
        // params, so they don't need the lock held; `spawn_index_build`
        // reconciles points inserted during the build window on completion.
        let mut pending_build: Option<PendingIndexBuild> = None;
        if pending_seal.is_none()
            && !h2qg_present_before
            && !rabitq_present_before
            && !vamana_present_before
            && !ivf_present_before
            && !collection.index_build_in_flight
            && collection.streamer_hnsw_required()
            && collection.streamer.hnsw.is_none()
            && collection.rabitq.is_none()
            && collection.vamana.is_none()
            && collection.ivf.is_none()
        {
            collection.index_build_in_flight = true;
            let vector_dim = collection.config.vector_dim;
            let hnsw_m = collection.config.hnsw_m;
            let hnsw_ef_construction = collection.config.hnsw_ef_construction;
            let metric = collection.config.metric;

            // PC-1b: `CollectionConfig.index_kind = Some("rabitq")` routes the
            // build to the binary cascade backend. PC-2: `Some("vamana")` routes
            // to the DiskANN-style single-layer graph. Otherwise fall through
            // to the internal f32 HNSW dispatch. Collection quantization is
            // a sealed-tier policy; the mutable Streamer remains the live f32
            // tier so hot candidates do not pay a second proxy-distance path.
            let index_kind = collection
                .config
                .index_kind
                .as_deref()
                .map(str::to_ascii_lowercase);
            let kind = if index_kind.as_deref() == Some("rabitq") {
                PendingIndexBuildKind::Rabitq
            } else if index_kind.as_deref() == Some("vamana") {
                PendingIndexBuildKind::Vamana
            } else if index_kind.as_deref() == Some("ivf") {
                PendingIndexBuildKind::Ivf
            } else {
                PendingIndexBuildKind::H2qg
            };
            pending_build = Some(PendingIndexBuild {
                coll: Arc::clone(&coll),
                data_dir_lock: Arc::clone(&self._data_dir_lock),
                lifecycle: Arc::clone(&self.build_lifecycle),
                streamer_base_lsn: collection.streamer.base_lsn,
                vector_dim,
                hnsw_m,
                hnsw_ef_construction,
                metric,
                kind,
                cascade: self.cascade.clone(),
            });
        }

        if wait && let Err(error) = collection.overlays.publish_pending() {
            self.mark_durability_degraded("visibility_overlay", &error);
        }
        let total = collection.live_points();
        drop(collection);
        if let Some(seal) = pending_seal {
            spawn_segment_seal(seal);
        }
        if let Some(build) = pending_build {
            spawn_index_build(build);
        }
        let mut audit_details = serde_json::json!({
            "requested_points": requested_points,
            "total_points": total,
            "wait": wait,
            "operation_lsn": operation_lsn,
        });
        if graph_deferred_session.is_some() {
            audit_details["deferred_graph_session"] = serde_json::json!(true);
            audit_details["bound_endpoints"] = serde_json::json!(graph_bound_endpoints);
        }
        if let Some(unsafe_audit) = &unsafe_structural_audit {
            audit_details["unsafe_structural_embedding"] = serde_json::json!({
                "reason": unsafe_audit.reason,
                "point_count": unsafe_audit.point_count,
                "zero_vector_points": unsafe_audit.zero_vector_points,
                "point_id_sha256": unsafe_audit.point_id_sha256,
            });
        }
        audit_operation.success(audit_details)?;
        crate::failpoint::check("db.after_upsert_durable")?;
        observe_points_upserted(requested_points);
        self.refresh_metrics();
        operation_metrics.succeed();
        Ok(UpsertExecutionReceipt {
            total,
            operation_lsn,
            unsafe_override_audited: unsafe_structural_audit.is_some(),
            graph_epoch,
            graph_bound_endpoints,
        })
    }

    fn delete_unguarded(
        &self,
        collection_name: &str,
        ids: &[String],
        with_edges_acknowledged: bool,
        audit_context: audit::AuditContext,
        origin: MutationOrigin,
    ) -> Result<usize> {
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        if origin == MutationOrigin::LegacyReplication {
            self.ensure_legacy_replication_available(collection_name)?;
        }
        let audit_operation =
            self.audit_operation_with_context("delete", Some(collection_name), audit_context)?;
        let mut operation_metrics = OperationGuard::start("delete");
        self.ensure_collection_cold_materialized(collection_name)?;
        let coll = self.get_coll(collection_name)?;
        let mut collection = coll.write();
        if origin == MutationOrigin::LegacyReplication
            && collection.graph_lifecycle.epoch().is_some()
        {
            return Err(graph_replication_unavailable(collection_name));
        }

        if collection.graph_lifecycle.is_enabled() {
            let (receipt, deleted, orphaned_edges) = self.commit_graph_point_deletes_locked(
                &mut collection,
                ids,
                with_edges_acknowledged,
            )?;
            drop(collection);
            audit_operation.success(serde_json::json!({
                "requested_ids": ids.len(),
                "deleted": deleted,
                "graph_epoch": receipt.map(|receipt| receipt.graph_epoch.raw()),
                "operation_lsn": receipt.map(|receipt| receipt.operation_lsn),
                "with_edges_acknowledged": with_edges_acknowledged,
            }))?;
            observe_points_deleted(deleted);
            observe_graph_edges_orphaned_by_delete(orphaned_edges);
            self.refresh_metrics();
            operation_metrics.succeed();
            return Ok(deleted);
        }

        if !ids.is_empty() {
            collection
                .wal
                .append(&WalEntry::DeleteBatch { ids: ids.to_vec() })?;
        }
        let mut deleted = 0;
        for id in ids {
            match collection.id_index.get(id).copied() {
                Some(crate::searcher::SegLoc::Streamer) => {
                    if let Some(point) = collection.streamer.remove(id) {
                        remove_sparse_point(&mut collection.sparse_index, &point);
                        remove_payload_point(&mut collection.payload_index, &point);
                        if let Some(h2qg) = collection.streamer.hnsw.as_mut() {
                            h2qg.remove_from_indexed(id);
                        }
                        for named in collection.streamer.named_hnsw.values_mut() {
                            named.remove_from_indexed(id);
                        }
                        collection.id_index.remove(id);
                        collection.hnsw_dirty = true;
                        deleted += 1;
                    }
                }
                Some(crate::searcher::SegLoc::Sealing) => {
                    if let Some(point) = collection
                        .sealing
                        .as_ref()
                        .and_then(|streamer| streamer.points.get(id))
                        .cloned()
                    {
                        remove_sparse_point(&mut collection.sparse_index, &point);
                        remove_payload_point(&mut collection.payload_index, &point);
                    }
                    collection.id_index.remove(id);
                    collection.hnsw_dirty = true;
                    deleted += 1;
                }
                Some(crate::searcher::SegLoc::Searcher(i)) => {
                    // Sealed point: tombstone in place, never mutate the
                    // segment. Reclaimed at the next compact.
                    let point = collection.searchers[i as usize]
                        .store
                        .get(id)
                        .map(Cow::into_owned);
                    if let Some(point) = point {
                        remove_sparse_point(&mut collection.sparse_index, &point);
                        remove_payload_point(&mut collection.payload_index, &point);
                    }
                    collection.tombstone_searcher(i as usize, id)?;
                    collection.id_index.remove(id);
                    collection.hnsw_dirty = true;
                    deleted += 1;
                }
                None => {}
            }
            // DROP GRAPH preserves surviving handles, not deleted incarnations.
            if let Some(resolver) = &mut collection.graph_resolver {
                resolver.retire(id);
            }
        }
        if let Err(error) = collection.overlays.publish_pending() {
            self.mark_durability_degraded("visibility_overlay", &error);
        }
        drop(collection);
        audit_operation.success(serde_json::json!({
            "requested_ids": ids.len(),
            "deleted": deleted,
        }))?;
        observe_points_deleted(deleted);
        self.refresh_metrics();
        operation_metrics.succeed();
        Ok(deleted)
    }

    fn get_points_unguarded(&self, collection_name: &str, ids: &[String]) -> Result<Vec<Point>> {
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_collection_cold_materialized(collection_name)?;
        let coll = self.get_coll(collection_name)?;
        let collection = coll.read();
        let points = ids
            .iter()
            .filter_map(|id| collection.resolve(id).map(Cow::into_owned))
            .collect();
        Ok(points)
    }

    fn set_payload_unguarded(
        &self,
        collection_name: &str,
        id: &str,
        payload: serde_json::Value,
        merge: bool,
        audit_context: audit::AuditContext,
        origin: MutationOrigin,
    ) -> Result<Point> {
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        if origin == MutationOrigin::LegacyReplication {
            self.ensure_legacy_replication_available(collection_name)?;
        }
        let audit_operation =
            self.audit_operation_with_context("set_payload", Some(collection_name), audit_context)?;
        let mut operation_metrics = OperationGuard::start("set_payload");
        self.ensure_collection_cold_materialized(collection_name)?;
        let coll = self.get_coll(collection_name)?;
        let mut collection = coll.write();
        if origin == MutationOrigin::LegacyReplication
            && collection.graph_lifecycle.epoch().is_some()
        {
            return Err(graph_replication_unavailable(collection_name));
        }

        if !collection.id_index.contains_key(id) {
            return Err(GaussError::PointNotFound(id.to_string()));
        }

        // Validate the resulting point before the WAL commit. This is
        // especially important for follower apply: an invalid replicated
        // payload must not become a durable record that fails every restart.
        let mut candidate = collection
            .resolve(id)
            .map(Cow::into_owned)
            .ok_or_else(|| GaussError::PointNotFound(id.to_string()))?;
        if merge {
            if let (Some(existing_obj), Some(new_obj)) =
                (candidate.payload.as_object_mut(), payload.as_object())
            {
                for (key, value) in new_obj {
                    existing_obj.insert(key.clone(), value.clone());
                }
            } else {
                candidate.payload = payload.clone();
            }
        } else {
            candidate.payload = payload.clone();
        }
        validate_payload_schema(&collection.config, &candidate)?;

        if collection.graph_lifecycle.is_enabled() {
            let receipt = self.commit_graph_point_upserts_locked(
                &mut collection,
                vec![candidate.clone()],
                true,
            )?;
            drop(collection);
            audit_operation.success(serde_json::json!({
                "merge": merge,
                "graph_epoch": receipt.graph_epoch.raw(),
                "operation_lsn": receipt.operation_lsn,
            }))?;
            operation_metrics.succeed();
            return Ok(candidate);
        }

        collection.wal.append(&WalEntry::SetPayload {
            id: id.to_string(),
            payload: payload.clone(),
            merge,
        })?;

        // A payload update on a sealed point is an update: move the point
        // into the streamer and tombstone the old location, then mutate the
        // streamer copy in place.
        match collection.id_index.get(id).copied() {
            Some(crate::searcher::SegLoc::Sealing) => {
                if let Some(point) = collection
                    .sealing
                    .as_ref()
                    .and_then(|streamer| streamer.points.get(id))
                    .cloned()
                {
                    collection.streamer.insert(point);
                    collection
                        .id_index
                        .insert(id.to_string(), crate::searcher::SegLoc::Streamer);
                }
            }
            Some(crate::searcher::SegLoc::Searcher(i)) => {
                let point = collection.searchers[i as usize]
                    .store
                    .get(id)
                    .map(Cow::into_owned);
                if let Some(point) = point {
                    collection.tombstone_searcher(i as usize, id)?;
                    collection.streamer.insert(point);
                    collection
                        .id_index
                        .insert(id.to_string(), crate::searcher::SegLoc::Streamer);
                }
            }
            _ => {}
        }
        let col: &mut Collection = &mut collection;
        let old_bytes = crate::streamer::point_bytes(col.streamer.points.get(id).unwrap());
        let updated_point = {
            let point = col.streamer.points.get_mut(id).unwrap();
            remove_payload_point(&mut col.payload_index, point);
            col.sparse_index.text.remove(point);
            if merge {
                if let (Some(existing_obj), Some(new_obj)) =
                    (point.payload.as_object_mut(), payload.as_object())
                {
                    for (k, v) in new_obj {
                        existing_obj.insert(k.clone(), v.clone());
                    }
                } else {
                    point.payload = payload;
                }
            } else {
                point.payload = payload;
            }
            insert_payload_point(&mut col.payload_index, point);
            col.sparse_index.text.insert(point);
            point.clone()
        };
        col.streamer.refresh_point_bytes(old_bytes, id);
        if let Err(error) = col.overlays.publish_pending() {
            self.mark_durability_degraded("visibility_overlay", &error);
        }

        drop(collection);
        audit_operation.success(serde_json::json!({ "merge": merge }))?;
        operation_metrics.succeed();
        Ok(updated_point)
    }

    fn delete_by_filter_unguarded(
        &self,
        collection_name: &str,
        filter: &crate::Filter,
        with_edges_acknowledged: bool,
        audit_context: audit::AuditContext,
    ) -> Result<usize> {
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        validate_filter_complexity(Some(filter))?;
        let _admission = self.maintenance_barrier.read();
        let audit_operation = self.audit_operation_with_context(
            "delete_by_filter",
            Some(collection_name),
            audit_context,
        )?;
        let mut operation_metrics = OperationGuard::start("delete_by_filter");
        self.ensure_collection_cold_materialized(collection_name)?;
        let coll = self.get_coll(collection_name)?;
        let mut collection = coll.write();
        let visibility = collection.overlay_read_state();

        let matching_ids: Vec<String> =
            if let Some(candidates) = collection.payload_candidates(&visibility, Some(filter)) {
                collection
                    .iter_payload_candidates(&visibility, &candidates)
                    .filter(|point| filter.matches(&point.payload))
                    .map(|point| point.id.clone())
                    .collect()
            } else {
                collection
                    .iter_live_in_read_state(&visibility)
                    .filter(|point| filter.matches(&point.payload))
                    .map(|point| point.id.clone())
                    .collect()
            };

        if collection.graph_lifecycle.is_enabled() {
            let (receipt, deleted, orphaned_edges) = self.commit_graph_point_deletes_locked(
                &mut collection,
                &matching_ids,
                with_edges_acknowledged,
            )?;
            drop(collection);
            audit_operation.success(serde_json::json!({
                "deleted": deleted,
                "graph_epoch": receipt.map(|receipt| receipt.graph_epoch.raw()),
                "operation_lsn": receipt.map(|receipt| receipt.operation_lsn),
                "with_edges_acknowledged": with_edges_acknowledged,
            }))?;
            observe_points_deleted(deleted);
            observe_graph_edges_orphaned_by_delete(orphaned_edges);
            self.refresh_metrics();
            operation_metrics.succeed();
            return Ok(deleted);
        }

        if !matching_ids.is_empty() {
            collection.wal.append(&WalEntry::DeleteBatch {
                ids: matching_ids.clone(),
            })?;
        }
        let mut deleted = 0;
        for id in &matching_ids {
            match collection.id_index.get(id).copied() {
                Some(crate::searcher::SegLoc::Streamer) => {
                    if let Some(point) = collection.streamer.remove(id) {
                        remove_sparse_point(&mut collection.sparse_index, &point);
                        remove_payload_point(&mut collection.payload_index, &point);
                        if let Some(h2qg) = collection.streamer.hnsw.as_mut() {
                            h2qg.remove_from_indexed(id);
                        }
                        for named in collection.streamer.named_hnsw.values_mut() {
                            named.remove_from_indexed(id);
                        }
                        collection.id_index.remove(id);
                        collection.hnsw_dirty = true;
                        deleted += 1;
                    }
                }
                Some(crate::searcher::SegLoc::Sealing) => {
                    if let Some(point) = collection
                        .sealing
                        .as_ref()
                        .and_then(|streamer| streamer.points.get(id))
                        .cloned()
                    {
                        remove_sparse_point(&mut collection.sparse_index, &point);
                        remove_payload_point(&mut collection.payload_index, &point);
                    }
                    collection.id_index.remove(id);
                    collection.hnsw_dirty = true;
                    deleted += 1;
                }
                Some(crate::searcher::SegLoc::Searcher(i)) => {
                    let point = collection.searchers[i as usize]
                        .store
                        .get(id)
                        .map(Cow::into_owned);
                    if let Some(point) = point {
                        remove_sparse_point(&mut collection.sparse_index, &point);
                        remove_payload_point(&mut collection.payload_index, &point);
                    }
                    collection.tombstone_searcher(i as usize, id)?;
                    collection.id_index.remove(id);
                    collection.hnsw_dirty = true;
                    deleted += 1;
                }
                None => {}
            }
            if let Some(resolver) = &mut collection.graph_resolver {
                resolver.retire(id);
            }
        }
        if let Err(error) = collection.overlays.publish_pending() {
            self.mark_durability_degraded("visibility_overlay", &error);
        }
        drop(collection);
        audit_operation.success(serde_json::json!({ "deleted": deleted }))?;
        observe_points_deleted(deleted);
        self.refresh_metrics();
        operation_metrics.succeed();
        Ok(deleted)
    }

    fn search_unguarded(
        &self,
        collection_name: &str,
        request: SearchRequest,
    ) -> Result<SearchResponse> {
        let _lifecycle = self.lifecycle_gate.read();
        self.search_controlled_unguarded(collection_name, request, None)
    }

    /// Execute a search that can be cooperatively stopped by an upstream
    /// coordinator after its response deadline expires.
    pub fn search_with_cancellation(
        &self,
        collection_name: &str,
        request: SearchRequest,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<SearchResponse> {
        if request.graph.is_some() {
            return Err(GaussError::InvalidRequest(
                "graph-constrained cancellation requires `search_with_cancellation_scoped`"
                    .to_string(),
            ));
        }
        self.search_controlled(collection_name, request, Some(cancelled))
    }

    fn search_controlled(
        &self,
        collection_name: &str,
        request: SearchRequest,
        cancelled: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<SearchResponse> {
        let _lifecycle = self.lifecycle_gate.read();
        self.search_controlled_unguarded(collection_name, request, cancelled)
    }

    fn search_controlled_unguarded(
        &self,
        collection_name: &str,
        request: SearchRequest,
        cancelled: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<SearchResponse> {
        debug_assert!(request.graph.is_none());
        let _inflight = SearchInflightGuard::new(self.search_inflight.clone());
        let mut operation_metrics = OperationGuard::start("search");
        #[cfg(feature = "search-metrics")]
        let expected_k = request.k;
        let response = self.search_excluding(
            collection_name,
            request,
            &std::collections::HashSet::new(),
            cancelled,
        )?;
        if response.degraded {
            observe_degraded("search");
        }
        crate::index::search_metrics::record_search_metric!(ReturnedCount, response.hits.len());
        crate::index::search_metrics::record_search_metric!(
            UnderfilledCount,
            usize::from(response.hits.len() != expected_k)
        );
        crate::index::search_metrics::record_search_metric!(
            DegradedCount,
            usize::from(response.degraded)
        );
        crate::index::search_metrics::record_search_metric!(
            CancelledCount,
            usize::from(
                cancelled.is_some_and(|flag| { flag.load(std::sync::atomic::Ordering::Relaxed) })
            )
        );
        operation_metrics.succeed();
        Ok(response)
    }

    pub fn multi_search(
        &self,
        collection_name: &str,
        request: MultiSearchRequest,
    ) -> Result<MultiSearchResponse> {
        self.require_scoped_entry("multi_search")?;
        self.multi_search_unguarded(collection_name, request)
    }

    fn multi_search_unguarded(
        &self,
        collection_name: &str,
        request: MultiSearchRequest,
    ) -> Result<MultiSearchResponse> {
        let _lifecycle = self.lifecycle_gate.read();
        let mut operation_metrics = OperationGuard::start("multi_search");
        if request.searches.iter().any(|search| search.graph.is_some()) {
            return Err(GaussError::InvalidRequest(
                "graph constraints are not supported by multi_search".to_string(),
            ));
        }
        if request.searches.len() > MAX_MULTI_SEARCHES {
            return Err(GaussError::ResourceExhausted(format!(
                "multi_search contains {} queries; maximum is {MAX_MULTI_SEARCHES}",
                request.searches.len()
            )));
        }
        let started = Instant::now();
        if request.weights.len() > request.searches.len() {
            return Err(GaussError::InvalidRequest(
                "multi_search weights must not outnumber searches".to_string(),
            ));
        }
        if request.weights.iter().any(|weight| *weight < 0.0) {
            return Err(GaussError::InvalidRequest(
                "multi_search weights must be non-negative".to_string(),
            ));
        }
        let default_fused_k = request
            .searches
            .iter()
            .map(|search| search.k)
            .max()
            .unwrap_or_default();
        let results = {
            let _span = tracing::info_span!(
                "gaussdb.search.multi.branches",
                collection = collection_name,
                searches = request.searches.len()
            )
            .entered();
            // PA-5: independent search branches in parallel via rayon. Each
            // branch takes its own per-collection read lock (multiple readers
            // allowed) and internally fans out via M4-002 par_iter on its own
            // candidate set. Nested rayon — handled by rayon's thread pool.
            // First error short-circuits the batch. Branch dispatch uses its
            // own pool because each branch can fan out internally on the
            // dedicated search pool while holding a collection read guard.
            // See `search_pool` module doc for the writer-preference deadlock
            // this separation prevents.
            if request.searches.len() >= 2 {
                crate::search_pool::MULTI_SEARCH_POOL.install(|| {
                    request
                        .searches
                        .into_par_iter()
                        .map(|search| {
                            self.search_controlled_unguarded(collection_name, search, None)
                        })
                        .collect::<Result<Vec<_>>>()
                })?
            } else {
                let mut results = Vec::with_capacity(request.searches.len());
                for search in request.searches {
                    results.push(self.search_controlled_unguarded(
                        collection_name,
                        search,
                        None,
                    )?);
                }
                results
            }
        };
        let fused = {
            let _span = tracing::info_span!(
                "gaussdb.search.multi.fuse",
                collection = collection_name,
                enabled = request.fusion.is_some()
            )
            .entered();
            request.fusion.map(|fusion| {
                fuse_search_responses(
                    &results,
                    fusion,
                    request.fused_k.unwrap_or(default_fused_k),
                    &request.weights,
                    started,
                )
            })
        };
        operation_metrics.succeed();
        Ok(MultiSearchResponse { results, fused })
    }

    pub fn hybrid_search(
        &self,
        collection_name: &str,
        request: HybridSearchRequest,
    ) -> Result<SearchResponse> {
        self.require_scoped_entry("hybrid_search")?;
        if request.graph.is_some() {
            return Err(GaussError::InvalidRequest(
                "graph-constrained hybrid search requires `hybrid_search_scoped`".to_string(),
            ));
        }
        self.hybrid_search_unguarded(collection_name, request)
    }

    fn hybrid_search_unguarded(
        &self,
        collection_name: &str,
        request: HybridSearchRequest,
    ) -> Result<SearchResponse> {
        debug_assert!(request.graph.is_none());
        let _lifecycle = self.lifecycle_gate.read();
        let mut operation_metrics = OperationGuard::start("hybrid_search");
        validate_k(request.k, "k")?;
        validate_filter_complexity(request.filter.as_ref())?;
        {
            let _span = tracing::info_span!(
                "gaussdb.search.materialize_cold",
                collection = collection_name
            )
            .entered();
            self.ensure_collection_cold_materialized_scope(
                collection_name,
                ColdMaterializeScope::HybridSearch,
            )?;
        }
        let started = Instant::now();
        let budget = Some(Duration::from_millis(request.budget_ms.unwrap_or(30_000)));
        if request.vector.is_none() && request.sparse_vector.is_none() {
            return Err(GaussError::InvalidRequest(
                "hybrid search requires a dense vector, sparse vector, or both".to_string(),
            ));
        }
        if request.k == 0 {
            operation_metrics.succeed();
            return Ok(SearchResponse {
                hits: Vec::new(),
                degraded: false,
                searched: 0,
                elapsed_ms: started.elapsed().as_millis(),
                graph: None,
            });
        }
        if request.dense_weight < 0.0 || request.sparse_weight < 0.0 {
            return Err(GaussError::InvalidRequest(
                "hybrid search weights must be non-negative".to_string(),
            ));
        }

        let coll = self.get_coll(collection_name)?;
        let collection = coll.read();

        if let Some(vector) = &request.vector
            && vector.len() != collection.config.vector_dim
        {
            return Err(GaussError::DimensionMismatch {
                expected: collection.config.vector_dim,
                actual: vector.len(),
            });
        }
        if request
            .vector
            .as_ref()
            .is_some_and(|vector| vector.iter().any(|value| !value.is_finite()))
        {
            return Err(GaussError::InvalidRequest(
                "dense vector values must be finite".to_string(),
            ));
        }
        if let Some(vector_name) = &request.vector_name {
            validate_vector_name(vector_name)?;
        }
        let visibility = collection.overlay_read_state();
        let resolver = CollectionReadResolver {
            collection: &collection,
            state: &visibility,
        };
        if let Some(sparse_vector) = &request.sparse_vector {
            validate_sparse_vector(sparse_vector)?;
        }

        let branch_limit = request.k.saturating_mul(4).max(request.k);
        let payload_candidates = {
            let _span = tracing::info_span!(
                "gaussdb.search.payload_candidates",
                collection = collection_name,
                has_filter = request.filter.is_some()
            )
            .entered();
            collection.payload_candidates(&visibility, request.filter.as_ref())
        };
        let payload_string_filter = |id: &str| {
            payload_candidates
                .as_ref()
                .is_none_or(|candidates| collection.payload_candidate_contains(candidates, id))
        };
        let mut searched = 0;
        let mut degraded = false;
        let mut dense_ranked = Vec::new();
        if let Some(vector) = &request.vector {
            let _span = tracing::info_span!(
                "gaussdb.search.hybrid.dense_branch",
                collection = collection_name,
                k = request.k,
                branch_limit,
                vector_name = request.vector_name.as_deref().unwrap_or("default")
            )
            .entered();
            let recall_target = collection
                .config
                .recall_sla
                .unwrap_or(crate::h2qg::DEFAULT_RECALL_TARGET);
            let coll_ef_search = collection
                .config
                .hnsw_ef_search
                .map(|x| (x as usize).max(branch_limit))
                .or_else(|| {
                    collection.config.recall_sla.map(|recall_sla| {
                        crate::h2qg::ef_search_for_recall_target(
                            branch_limit,
                            recall_sla,
                            collection.live_points(),
                            collection.config.vector_dim,
                        )
                    })
                });
            // P2F: feed the prefilter candidate set into the HNSW beam so it
            // skips filtered-out neighbours during expansion. Closes the gap
            // to the Filtered50K benchmark case.
            let filter_pred = payload_candidates
                .as_ref()
                .map(|_| &payload_string_filter as &dyn crate::index::FilterPredicate);
            let ordinal_filter = payload_candidates
                .as_ref()
                .map(|set| &set.sealed as &dyn crate::index::OrdinalFilterPredicate);
            for point in crate::search::fan_out_candidates(
                collection.global_backend(),
                &collection.streamer,
                collection.sealing.as_deref(),
                &collection.searchers,
                &visibility,
                &resolver,
                collection.live_points(),
                vector,
                branch_limit,
                request.vector_name.as_deref(),
                coll_ef_search,
                recall_target,
                filter_pred,
                ordinal_filter,
                None,
            ) {
                if budget.is_some_and(|budget| started.elapsed() >= budget) {
                    degraded = true;
                    break;
                }
                if payload_candidates.as_ref().is_some_and(|candidates| {
                    !collection.payload_candidate_contains(candidates, &point.id)
                }) {
                    continue;
                }
                if request
                    .filter
                    .as_ref()
                    .is_some_and(|filter| !filter.matches(&point.payload))
                {
                    continue;
                }
                searched += 1;
                let Some(point_vector) = point_vector(&point, request.vector_name.as_deref())
                else {
                    continue;
                };
                dense_ranked.push(RankedPoint {
                    id: point.id.clone(),
                    score: collection.config.metric.score(vector, point_vector)?,
                });
            }
            dense_ranked.sort_by(rank_order);
            dense_ranked.truncate(branch_limit);
        }

        let mut sparse_ranked = Vec::new();
        if !degraded && let Some(query_sparse) = &request.sparse_vector {
            let _span = tracing::info_span!(
                "gaussdb.search.hybrid.sparse_branch",
                collection = collection_name,
                k = request.k,
                branch_limit,
                terms = query_sparse.indices.len()
            )
            .entered();
            // The sparse engine is still ID-keyed. Materialize only at this
            // compatibility boundary; dense and exact sealed paths retain
            // ordinals through candidate exchange.
            let sparse_payload_candidates = payload_candidates.as_ref().map(|candidates| {
                collection
                    .iter_payload_candidates(&visibility, candidates)
                    .map(|point| point.id.clone())
                    .collect::<HashSet<_>>()
            });
            let sparse = sparse_search_ranked(
                &collection.sparse_index,
                &resolver,
                crate::search::SparseSearchParams {
                    query: query_sparse,
                    limit: branch_limit,
                    payload_candidates: sparse_payload_candidates.as_ref(),
                    filter: request.filter.as_ref(),
                    budget,
                    started,
                    cancelled: None,
                },
            );
            searched += sparse.searched;
            degraded = sparse.degraded;
            sparse_ranked = sparse.ranked;
        }

        let fused = {
            let _span = tracing::info_span!(
                "gaussdb.search.hybrid.fuse",
                collection = collection_name,
                dense_hits = dense_ranked.len(),
                sparse_hits = sparse_ranked.len()
            )
            .entered();
            fuse_rankings(
                &dense_ranked,
                &sparse_ranked,
                request.fusion,
                request.dense_weight,
                request.sparse_weight,
            )
        };
        let mut hits = Vec::with_capacity(request.k.min(fused.len()));
        for ranked in fused.into_iter().take(request.k) {
            if let Some(point) = collection.resolve(&ranked.id) {
                hits.push(SearchHit {
                    id: point.id.clone(),
                    score: ranked.score,
                    payload: point.payload.clone(),
                });
            }
        }

        let response = SearchResponse {
            hits,
            degraded,
            searched,
            elapsed_ms: started.elapsed().as_millis(),
            graph: None,
        };
        if response.degraded {
            observe_degraded("hybrid_search");
        }
        operation_metrics.succeed();
        Ok(response)
    }

    pub fn recommend(
        &self,
        collection_name: &str,
        request: RecommendRequest,
    ) -> Result<SearchResponse> {
        self.require_scoped_entry("recommend")?;
        self.recommend_unguarded(collection_name, request)
    }

    fn recommend_unguarded(
        &self,
        collection_name: &str,
        request: RecommendRequest,
    ) -> Result<SearchResponse> {
        let _lifecycle = self.lifecycle_gate.read();
        let mut operation_metrics = OperationGuard::start("recommend");
        validate_k(request.k, "k")?;
        {
            let _span = tracing::info_span!(
                "gaussdb.search.materialize_cold",
                collection = collection_name
            )
            .entered();
            self.ensure_collection_cold_materialized(collection_name)?;
        }
        if request.positive.is_empty() {
            return Err(GaussError::InvalidRequest(
                "recommend requires at least one positive point id".to_string(),
            ));
        }

        let coll = self.get_coll(collection_name)?;
        let collection = coll.read();

        let mut vector = vec![0.0_f32; collection.config.vector_dim];
        {
            let _span = tracing::info_span!(
                "gaussdb.search.recommend.vector_synthesis",
                collection = collection_name,
                positive = request.positive.len(),
                negative = request.negative.len(),
                vector_name = request.vector_name.as_deref().unwrap_or("default")
            )
            .entered();
            for id in &request.positive {
                let point = collection
                    .resolve(id)
                    .ok_or_else(|| GaussError::PointNotFound(id.clone()))?;
                add_scaled(
                    &mut vector,
                    required_point_vector(&point, request.vector_name.as_deref())?,
                    1.0,
                );
            }
            for id in &request.negative {
                let point = collection
                    .resolve(id)
                    .ok_or_else(|| GaussError::PointNotFound(id.clone()))?;
                add_scaled(
                    &mut vector,
                    required_point_vector(&point, request.vector_name.as_deref())?,
                    -1.0,
                );
            }
            normalize(&mut vector);
        }
        drop(collection);

        let excluded = request
            .positive
            .iter()
            .chain(&request.negative)
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        let response = self.search_excluding(
            collection_name,
            SearchRequest {
                graph: None,
                vector,
                vector_name: request.vector_name,
                k: request.k,
                filter: request.filter,
                budget_ms: request.budget_ms,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: None,
            },
            &excluded,
            None,
        )?;
        if response.degraded {
            observe_degraded("recommend");
        }
        operation_metrics.succeed();
        Ok(response)
    }

    /// Retrieve `prefetch_k` ANN candidates then re-score by applying
    /// `request.score_boosts` (payload-field equality → multiplicative factor)
    /// before returning the top `k` results.
    pub fn rerank(&self, collection_name: &str, request: RerankRequest) -> Result<SearchResponse> {
        self.require_scoped_entry("rerank")?;
        self.rerank_unguarded(collection_name, request)
    }

    fn rerank_unguarded(
        &self,
        collection_name: &str,
        request: RerankRequest,
    ) -> Result<SearchResponse> {
        let _lifecycle = self.lifecycle_gate.read();
        let mut operation_metrics = OperationGuard::start("rerank");
        validate_k(request.k, "k")?;
        let prefetch_k = request
            .prefetch_k
            .unwrap_or(request.k.saturating_mul(3).max(1));
        validate_k(prefetch_k, "prefetch_k")?;
        let prefetch_response = self.search_excluding(
            collection_name,
            SearchRequest {
                graph: None,
                vector: request.vector,
                vector_name: request.vector_name,
                k: prefetch_k,
                filter: request.filter,
                budget_ms: request.budget_ms,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: None,
            },
            &std::collections::HashSet::new(),
            None,
        )?;

        let mut hits = prefetch_response.hits;
        if !request.score_boosts.is_empty() {
            let _span = tracing::info_span!(
                "gaussdb.rerank.apply_boosts",
                collection = collection_name,
                candidates = hits.len(),
                boosts = request.score_boosts.len()
            )
            .entered();
            for hit in &mut hits {
                for boost in &request.score_boosts {
                    if let Some(field_val) = hit.payload.get(&boost.field)
                        && field_val == &boost.value
                    {
                        hit.score *= boost.boost;
                    }
                }
            }
            hits.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
        }
        hits.truncate(request.k);

        if prefetch_response.degraded {
            observe_degraded("rerank");
        }
        operation_metrics.succeed();
        Ok(SearchResponse {
            hits,
            degraded: prefetch_response.degraded,
            searched: prefetch_response.searched,
            elapsed_ms: prefetch_response.elapsed_ms,
            graph: None,
        })
    }

    fn search_excluding(
        &self,
        collection_name: &str,
        request: SearchRequest,
        excluded: &std::collections::HashSet<String>,
        cancelled: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<SearchResponse> {
        validate_k(request.k, "k")?;
        validate_filter_complexity(request.filter.as_ref())?;
        if request.vector.iter().any(|value| !value.is_finite()) {
            return Err(GaussError::InvalidRequest(
                "dense vector values must be finite".to_string(),
            ));
        }
        if let Some(recall_target) = request.recall_target
            && (!recall_target.is_finite() || !(0.5..=1.0).contains(&recall_target))
        {
            return Err(GaussError::InvalidRequest(format!(
                "recall_target must be finite and in [0.5, 1.0], got {recall_target}"
            )));
        }
        let started = Instant::now();
        let read_budget_ms = request.budget_ms.unwrap_or(30_000);
        let should_stop = || {
            cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
                || started.elapsed() >= Duration::from_millis(read_budget_ms)
        };
        if should_stop() {
            return Ok(SearchResponse {
                hits: Vec::new(),
                degraded: true,
                searched: 0,
                elapsed_ms: started.elapsed().as_millis(),
                graph: None,
            });
        }
        {
            let _span = tracing::info_span!(
                "gaussdb.search.materialize_cold",
                collection = collection_name
            )
            .entered();
            self.ensure_collection_cold_materialized(collection_name)?;
        }
        let budget = request.budget_ms.map(Duration::from_millis);
        let coll = self.get_coll(collection_name)?;
        let collection = coll.read();
        if request.vector.len() != collection.config.vector_dim {
            return Err(GaussError::DimensionMismatch {
                expected: collection.config.vector_dim,
                actual: request.vector.len(),
            });
        }
        if let Some(vector_name) = &request.vector_name {
            validate_vector_name(vector_name)?;
        }
        let visibility = collection.overlay_read_state();
        let resolver = CollectionReadResolver {
            collection: &collection,
            state: &visibility,
        };

        // PA-2: callers that don't need payload (e.g. id+score-only agentic
        // re-ranking) opt out by sending `with_payload: false`. PA-2c: the
        // server-side default (set via `Db::set_default_with_payload`) flips
        // this for benchmark / id-only deployments without breaking the
        // explicit-`Some(true)` callers.
        let with_payload = request
            .with_payload
            .unwrap_or_else(|| self.default_with_payload());
        // PA-4: pre-size hits Vec to roughly the maximum we may push before
        // top-k truncation. Saves a few mid-loop grow allocations.
        let mut hits: Vec<SearchHit> = Vec::with_capacity(request.k.saturating_mul(2).max(16));
        let mut searched = 0;
        let mut degraded = false;
        let payload_candidates = {
            let _span = tracing::info_span!(
                "gaussdb.search.payload_candidates",
                collection = collection_name,
                has_filter = request.filter.is_some()
            )
            .entered();
            collection.payload_candidates(&visibility, request.filter.as_ref())
        };
        let payload_string_filter = |id: &str| {
            payload_candidates
                .as_ref()
                .is_none_or(|candidates| collection.payload_candidate_contains(candidates, id))
        };

        // Scale k upward when the filter is restrictive so the ANN fetches enough
        // candidates to still return k valid results after post-filtering.
        let effective_k = if let Some(ref candidates) = payload_candidates {
            let total = collection.live_points().max(1);
            let matching = candidates.len();
            if matching < total {
                let needed =
                    (request.k as f64 * total as f64 / matching.max(1) as f64).ceil() as usize;
                needed.max(request.k).min(total)
            } else {
                request.k
            }
        } else {
            request.k
        };

        // Phase 3b (ACORN-lite): cardinality-aware filter dispatch.
        // When the filter is highly selective, skip the HNSW graph and do an
        // exact scan over the matching point set — trivially recall=1.0, and
        // avoids inflating `ef_search` to the point where HNSW degrades to a
        // graph-wide walk. Reference: Patel et al., "ACORN", arXiv:2403.04871.
        // Threshold: filter matches ≤ 5% of the collection AND ≤ 5_000 points.
        // These bounds keep the brute-force pass tractable while covering the
        // restrictive-filter regime where post-filter HNSW behaves worst.
        let total_points = collection.live_points();
        let use_prefilter_exact = payload_candidates.as_ref().is_some_and(|candidates| {
            let cap = (total_points / 20).min(5_000);
            candidates.len() <= cap
        });

        if use_prefilter_exact {
            let _span = tracing::info_span!(
                "gaussdb.search.prefilter_exact",
                collection = collection_name,
                k = request.k,
                matching = payload_candidates.as_ref().map(|c| c.len()).unwrap_or(0),
                vector_name = request.vector_name.as_deref().unwrap_or("default")
            )
            .entered();
            let candidates_set = payload_candidates.as_ref().unwrap();
            for point in collection.iter_payload_candidates(&visibility, candidates_set) {
                if excluded.contains(&point.id) {
                    continue;
                }
                if should_stop() {
                    degraded = true;
                    break;
                }
                if request
                    .filter
                    .as_ref()
                    .is_some_and(|filter| !filter.matches(&point.payload))
                {
                    continue;
                }
                searched += 1;
                let Some(point_vector) = point_vector(&point, request.vector_name.as_deref())
                else {
                    continue;
                };
                let score = collection
                    .config
                    .metric
                    .score(&request.vector, point_vector)?;
                hits.push(SearchHit {
                    id: point.id.clone(),
                    score,
                    payload: if with_payload {
                        point.payload.clone()
                    } else {
                        Value::Null
                    },
                });
            }
        } else {
            // Recommendation queries exclude their positive/negative seed
            // IDs after ANN selection. Over-fetch by that exact count so
            // excluded top hits cannot consume the entire candidate budget.
            let candidate_k = effective_k.saturating_add(excluded.len());
            let _span = tracing::info_span!(
                "gaussdb.search.exact_rescore",
                collection = collection_name,
                k = request.k,
                effective_k,
                candidate_k,
                vector_name = request.vector_name.as_deref().unwrap_or("default")
            )
            .entered();
            // PA-1 + PC-3 + W0: explicit ef_search wins; else resolve an
            // effective recall target and map it through the calibration curve
            // (learned via Db::calibrate_collection when available, otherwise
            // the static step curve). The target precedence is:
            //   request.recall_target  (caller opt-in)
            //   → config.recall_sla    (P3 contract — e.g. 1.0 keeps exact recall)
            //   → DEFAULT_RECALL_TARGET (W0: 0.97 throughput default)
            // so an unconfigured collection runs at 0.97 while a contracted
            // collection still meets its SLA.
            // Qdrant semantics: an explicit ef below k under-fills the beam
            // and returns fewer than k hits, so clamp to at least effective_k.
            let resolved_recall_target = request
                .recall_target
                .or(collection.config.recall_sla)
                .unwrap_or(crate::h2qg::DEFAULT_RECALL_TARGET);
            let resolved_ef_search = request
                .ef_search
                .or(collection.config.hnsw_ef_search)
                .map(|x| (x as usize).max(candidate_k))
                .or_else(|| {
                    let ef = if let Some(curve) = collection.recall_curve.as_ref() {
                        ef_search_from_curve(curve, resolved_recall_target).unwrap_or_else(|| {
                            crate::h2qg::ef_search_for_recall_target(
                                candidate_k,
                                resolved_recall_target,
                                collection.live_points(),
                                collection.config.vector_dim,
                            )
                        })
                    } else {
                        crate::h2qg::ef_search_for_recall_target(
                            candidate_k,
                            resolved_recall_target,
                            collection.live_points(),
                            collection.config.vector_dim,
                        )
                    };
                    Some(ef)
                });

            let candidates = crate::search::fan_out_candidates(
                collection.global_backend(),
                &collection.streamer,
                collection.sealing.as_deref(),
                &collection.searchers,
                &visibility,
                &resolver,
                collection.live_points(),
                &request.vector,
                candidate_k,
                request.vector_name.as_deref(),
                resolved_ef_search,
                resolved_recall_target,
                // P2F: feed the prefilter candidate set into the HNSW beam so it
                // skips filtered-out neighbours during expansion. The prefilter
                // set is built from the payload index — it's the same set the
                // post-filter rescore below checks, so the inline + post-filter
                // paths agree on the candidate pool. With the inline path active
                // we no longer need `effective_k` inflation to compensate for
                // filtered-out points; we keep the inflation for the post-filter
                // path (defense in depth) but the beam already returned only
                // passing candidates.
                payload_candidates
                    .as_ref()
                    .map(|_| &payload_string_filter as &dyn crate::index::FilterPredicate),
                payload_candidates
                    .as_ref()
                    .map(|set| &set.sealed as &dyn crate::index::OrdinalFilterPredicate),
                cancelled,
            );
            if cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
                degraded = true;
            }

            // M4-002 / PA-3: data-parallel candidate scoring via rayon when
            // the candidate set is wide enough to amortise the work-stealing
            // setup cost (~5-10 µs). Below the threshold serial scoring wins.
            // With a budget, fall back to serial so we can respect it per-
            // candidate. Acceptance test: `rayon_parallel_scoring`.
            //
            // PA-3 (2026-06-12): threshold lowered 256 → 128. After M3-004
            // SIMD distance kernels and PA-2 slim hits, per-candidate cost
            // dropped to ~0.5-0.8 µs, so the crossover point shifts down.
            const PARALLEL_RESCORE_THRESHOLD: usize = 128;
            let parallel = budget.is_none() && candidates.len() >= PARALLEL_RESCORE_THRESHOLD;

            if parallel {
                let vector_name = request.vector_name.as_deref();
                let filter = request.filter.as_ref();
                let metric = collection.config.metric;
                let query = request.vector.as_slice();

                // W3: dedicated search pool, not rayon's global pool — see
                // `search_pool` module doc.
                let scored: Vec<SearchHit> = crate::search_pool::SEARCH_POOL.install(|| {
                    candidates
                        .par_iter()
                        .filter_map(|point| {
                            if excluded.contains(&point.id) {
                                return None;
                            }
                            if payload_candidates.as_ref().is_some_and(|candidates| {
                                !collection.payload_candidate_contains(candidates, &point.id)
                            }) {
                                return None;
                            }
                            if filter.is_some_and(|f| !f.matches(&point.payload)) {
                                return None;
                            }
                            let pv = point_vector(point, vector_name)?;
                            let score = metric.score(query, pv).ok()?;
                            Some(SearchHit {
                                id: point.id.clone(),
                                score,
                                payload: if with_payload {
                                    point.payload.clone()
                                } else {
                                    Value::Null
                                },
                            })
                        })
                        .collect()
                });
                searched += scored.len();
                hits.extend(scored);
            } else {
                for point in candidates {
                    if excluded.contains(&point.id) {
                        continue;
                    }
                    if should_stop() {
                        degraded = true;
                        break;
                    }
                    if payload_candidates.as_ref().is_some_and(|candidates| {
                        !collection.payload_candidate_contains(candidates, &point.id)
                    }) {
                        continue;
                    }
                    if request
                        .filter
                        .as_ref()
                        .is_some_and(|filter| !filter.matches(&point.payload))
                    {
                        continue;
                    }
                    searched += 1;
                    let Some(point_vector) = point_vector(&point, request.vector_name.as_deref())
                    else {
                        continue;
                    };
                    let score = collection
                        .config
                        .metric
                        .score(&request.vector, point_vector)?;
                    hits.push(SearchHit {
                        id: point.id.clone(),
                        score,
                        payload: if with_payload {
                            point.payload.clone()
                        } else {
                            Value::Null
                        },
                    });
                }
            }
        }

        {
            let _span = tracing::info_span!(
                "gaussdb.search.topk",
                collection = collection_name,
                scored = hits.len(),
                k = request.k
            )
            .entered();
            hits.sort_by(|left, right| {
                right
                    .score
                    .total_cmp(&left.score)
                    .then_with(|| left.id.cmp(&right.id))
            });
            hits.truncate(request.k);
        }
        Ok(SearchResponse {
            hits,
            degraded,
            searched,
            elapsed_ms: started.elapsed().as_millis(),
            graph: None,
        })
    }

    fn count_unguarded(
        &self,
        collection_name: &str,
        filter: Option<Filter>,
    ) -> Result<CountResponse> {
        let _lifecycle = self.lifecycle_gate.read();
        let mut operation_metrics = OperationGuard::start("count");
        validate_filter_complexity(filter.as_ref())?;
        self.ensure_collection_cold_materialized_scope(
            collection_name,
            ColdMaterializeScope::Scroll,
        )?;
        let coll = self.get_coll(collection_name)?;
        let collection = coll.read();
        let visibility = collection.overlay_read_state();
        let count =
            if let Some(candidates) = collection.payload_candidates(&visibility, filter.as_ref()) {
                collection
                    .iter_payload_candidates(&visibility, &candidates)
                    .filter(|point| {
                        filter
                            .as_ref()
                            .is_none_or(|filter| filter.matches(&point.payload))
                    })
                    .count()
            } else {
                collection
                    .iter_live_in_read_state(&visibility)
                    .filter(|point| {
                        filter
                            .as_ref()
                            .is_none_or(|filter| filter.matches(&point.payload))
                    })
                    .count()
            };
        operation_metrics.succeed();
        Ok(CountResponse { count })
    }

    /// Index build readiness for a collection: whether a background HNSW
    /// build is currently in flight (see `spawn_index_build`) and how many
    /// of the collection's points are actually indexed vs. total. While a
    /// build is in flight, `search` falls back to an `O(N)` linear scan for
    /// points the index hasn't caught up to yet (`search::search_point_candidates`)
    /// -- this lets callers with latency/recall expectations (benchmark
    /// harnesses, production clients with a `recall_sla` contract) wait for
    /// the index to catch up instead of silently eating that cost.
    pub fn index_status(&self, collection_name: &str) -> Result<IndexStatusResponse> {
        let coll = self.get_coll(collection_name)?;
        let collection = coll.read();
        let indexed_points = match collection.global_backend() {
            Some(backend) => backend.indexed_points(),
            None => {
                let streamer_indexed = collection
                    .streamer
                    .hnsw
                    .as_ref()
                    .map(crate::index::IndexBackend::indexed_points)
                    .unwrap_or(0);
                let searcher_indexed: usize = collection
                    .searchers
                    .iter()
                    .filter_map(|s| s.index.as_backend())
                    .map(|b| b.indexed_points())
                    .sum();
                streamer_indexed + searcher_indexed
            }
        };
        Ok(IndexStatusResponse {
            build_in_flight: collection.index_build_in_flight
                || collection.generation_build_in_flight,
            indexed_points,
            total_points: collection.live_points(),
        })
    }

    /// Return whether the collection currently has a frozen streamer being
    /// installed. This is primarily useful to lifecycle and shutdown tooling
    /// that must wait for the durable checkpoint before exiting.
    pub fn seal_in_progress(&self, collection_name: &str) -> Result<bool> {
        let coll = self.get_coll(collection_name)?;
        Ok(coll.read().sealing.is_some())
    }

    fn scroll_unguarded(
        &self,
        collection_name: &str,
        offset: Option<&str>,
        limit: usize,
        filter: Option<Filter>,
    ) -> Result<ScrollResponse> {
        let _lifecycle = self.lifecycle_gate.read();
        let mut operation_metrics = OperationGuard::start("scroll");
        validate_filter_complexity(filter.as_ref())?;
        self.ensure_collection_cold_materialized_scope(
            collection_name,
            ColdMaterializeScope::Scroll,
        )?;
        let coll = self.get_coll(collection_name)?;
        let collection = coll.read();
        let visibility = collection.overlay_read_state();
        let mut points: Vec<_> =
            if let Some(candidates) = collection.payload_candidates(&visibility, filter.as_ref()) {
                collection
                    .iter_payload_candidates(&visibility, &candidates)
                    .filter(|point| {
                        filter
                            .as_ref()
                            .is_none_or(|filter| filter.matches(&point.payload))
                    })
                    .map(Cow::into_owned)
                    .collect()
            } else {
                collection
                    .iter_live_in_read_state(&visibility)
                    .filter(|point| {
                        filter
                            .as_ref()
                            .is_none_or(|filter| filter.matches(&point.payload))
                    })
                    .map(Cow::into_owned)
                    .collect()
            };
        // Sort by ID for stable, deterministic pagination
        points.sort_by(|left, right| left.id.cmp(&right.id));

        // Skip all points whose ID is <= the cursor (exclusive lower-bound)
        let start_pos = if let Some(cursor) = offset {
            points
                .iter()
                .position(|point| point.id.as_str() > cursor)
                .unwrap_or(points.len())
        } else {
            0
        };

        let page: Vec<_> = points[start_pos..].iter().take(limit).cloned().collect();
        let has_more = start_pos + page.len() < points.len();
        let next_offset = if has_more {
            page.last().map(|point| point.id.clone())
        } else {
            None
        };
        operation_metrics.succeed();
        Ok(ScrollResponse {
            points: page,
            next_offset,
        })
    }

    /// PC-3: build the per-collection `(ef_search, recall)` curve.
    ///
    /// Strategy: sample `samples` query vectors uniformly from the collection's
    /// existing points (so the data distribution matches production). For each
    /// query, compute exact brute-force top-`k` as ground truth, then run the
    /// HNSW search at each candidate `ef_search`. Recall at each ef_search is
    /// the fraction of exact hits recovered.
    ///
    /// Output: the curve is cached on the collection (in-memory only, not
    /// persisted — recompute on restart). Subsequent search calls with a
    /// `recall_target` pick the smallest `ef_search` that meets the target.
    ///
    /// Returns the curve as `Vec<(ef_search, recall)>` sorted ascending by
    /// ef_search. No-op on flat collections (recall is always 1.0 there).
    pub fn calibrate_collection(
        &self,
        collection_name: &str,
        k: usize,
        samples: usize,
    ) -> Result<Vec<(usize, f32)>> {
        let _lifecycle = self.lifecycle_gate.read();
        self.calibrate_collection_unguarded(collection_name, k, samples)
    }

    fn calibrate_collection_unguarded(
        &self,
        collection_name: &str,
        k: usize,
        samples: usize,
    ) -> Result<Vec<(usize, f32)>> {
        let _admission = self.maintenance_barrier.read();
        let mut operation_metrics = OperationGuard::start("calibrate");
        let coll = self.get_coll(collection_name)?;

        // Snapshot collection state under read lock.
        let (config, points_snapshot, h2qg_present) = {
            let collection = coll.read();
            (
                collection.config.clone(),
                collection
                    .iter_live()
                    .map(Cow::into_owned)
                    .collect::<Vec<Point>>(),
                collection.streamer.hnsw.is_some()
                    || collection
                        .searchers
                        .iter()
                        .any(|s| s.index.as_backend().is_some()),
            )
        };

        if !h2qg_present || points_snapshot.len() < k {
            // Flat path → recall is always 1.0 regardless of ef_search.
            let curve = vec![(k.max(1), 1.0_f32)];
            let mut collection = coll.write();
            collection.recall_curve = Some(curve.clone());
            operation_metrics.succeed();
            return Ok(curve);
        }

        // Candidate ef_search values: cover the same grid as the step calibrator.
        let efs: Vec<usize> = [k, k * 2, k * 4, k * 8, k * 16]
            .into_iter()
            .map(|v| v.max(16))
            .collect();

        // Sample queries from the point set (deterministic via stride).
        let stride = (points_snapshot.len() / samples.max(1)).max(1);
        let sample_points: Vec<&Point> = points_snapshot
            .iter()
            .enumerate()
            .filter(|(i, _)| i % stride == 0)
            .map(|(_, p)| p)
            .take(samples)
            .collect();

        // The exact top-k ground truth doesn't depend on `ef` — computing it
        // once per query (instead of once per (ef, query) pair) drops 5
        // redundant O(N) passes down to 1. The pass itself is now a
        // contiguous SoA batch scan (`soa_top_k`) instead of a scattered
        // per-`Point` walk — the genuine full-scan use case the SoA kernel
        // was built for (P2E).
        let soa_cache = SoASegmentCache::from_points(&points_snapshot)?;
        let exact_ids_per_query: Vec<std::collections::HashSet<String>> = sample_points
            .iter()
            .map(|q| {
                soa_top_k(&soa_cache, &q.vector, k, config.metric)
                    .map(|hits| {
                        hits.iter()
                            .map(|hit| soa_cache.ids()[hit.index].clone())
                            .collect()
                    })
                    .unwrap_or_default()
            })
            .collect();

        let mut curve: Vec<(usize, f32)> = Vec::with_capacity(efs.len());
        for ef in &efs {
            let mut total = 0.0_f64;
            for (q, exact_ids) in sample_points.iter().zip(exact_ids_per_query.iter()) {
                let req = SearchRequest {
                    graph: None,
                    vector: q.vector.clone(),
                    vector_name: None,
                    k,
                    filter: None,
                    budget_ms: None,
                    consistency: None,
                    ef_search: Some(*ef as u32),
                    recall_target: None,
                    with_payload: Some(false),
                };
                let result = self.search_excluding(
                    collection_name,
                    req,
                    &std::collections::HashSet::new(),
                    None,
                )?;
                let hits = result
                    .hits
                    .iter()
                    .filter(|h| exact_ids.contains(h.id.as_str()))
                    .count();
                total += hits as f64 / k.max(1) as f64;
            }
            let avg = (total / sample_points.len().max(1) as f64) as f32;
            curve.push((*ef, avg));
        }

        {
            let mut collection = coll.write();
            collection.recall_curve = Some(curve.clone());
        }
        operation_metrics.succeed();
        Ok(curve)
    }

    /// P3 — run a fresh calibration and decide whether the collection's
    /// contracted `recall_sla` is still being met at the engine's active
    /// `ef_search` choice. Emits a `recall_sla_breach` audit event when a
    /// drift is detected so the audit chain has a durable record of the
    /// violation.
    ///
    /// Returns `Ok(None)` when:
    /// - the collection has no `recall_sla` (monitoring disabled)
    /// - the collection is below the HNSW threshold (flat path → recall=1.0)
    /// - the SLA is being met at the active ef
    ///
    /// Returns `Ok(Some(report))` and writes the audit event when a breach is
    /// detected. The drift monitor in `chirondb-server::main::spawn_drift_monitor`
    /// calls this on every collection on a fixed cadence.
    pub fn check_recall_drift(&self, collection_name: &str) -> Result<Option<RecallDriftReport>> {
        let _lifecycle = self.lifecycle_gate.read();
        let coll = self.get_coll(collection_name)?;
        let (recall_sla, configured_ef, point_count, vector_dim) = {
            let collection = coll.read();
            (
                collection.config.recall_sla,
                collection.config.hnsw_ef_search,
                collection.live_points(),
                collection.config.vector_dim,
            )
        };
        let Some(sla) = recall_sla else {
            return Ok(None);
        };
        // k=10 / samples=32 matches the operating point used by VectorDBBench
        // and the ann-benchmarks Recall@10 metric. Cheap enough to run every
        // few minutes; the calibrator already short-circuits flat-mode.
        let calibration_k: usize = 10;
        let curve = self.calibrate_collection_unguarded(collection_name, calibration_k, 32)?;
        let active_ef = configured_ef.map(|v| v as usize).unwrap_or_else(|| {
            crate::h2qg::default_ef_search(calibration_k, point_count, vector_dim)
        });
        let Some(report) = evaluate_recall_drift(&curve, sla, active_ef) else {
            return Ok(None);
        };
        self.ensure_storage_mutations_available()?;
        self.audit_success(
            "recall_sla_breach",
            Some(collection_name),
            serde_json::json!({
                "sla": report.sla,
                "active_ef": report.active_ef,
                "observed_recall_at_active_ef": report.observed_recall_at_active_ef,
                "ef_search_needed": report.ef_search_needed,
                "k": calibration_k,
            }),
        )?;
        Ok(Some(report))
    }

    /// P3 — sweep every collection with a contracted `recall_sla`. Used by the
    /// background drift monitor in `chirondb-server::main`. Returns the list of
    /// (collection, report) breaches detected this sweep. Errors on individual
    /// collections are logged via tracing and do not halt the sweep.
    pub fn check_recall_drift_all(&self) -> Vec<(String, RecallDriftReport)> {
        let candidates: Vec<String> = self
            .inner
            .read()
            .collections
            .iter()
            .filter_map(|(name, coll)| {
                let collection = coll.read();
                collection.config.recall_sla.map(|_| name.clone())
            })
            .collect();
        let mut breaches = Vec::new();
        for name in candidates {
            match self.check_recall_drift(&name) {
                Ok(Some(report)) => breaches.push((name, report)),
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(%error, collection = %name, "recall drift check failed");
                }
            }
        }
        breaches
    }

    pub fn compact_collection(&self, collection_name: &str) -> Result<CompactResponse> {
        self.compact_collection_with_scope(collection_name, LsvecCompactionScope::SizeTiered)
    }

    /// Inspect the immutable graph debt selected by the current collection
    /// generation. Mutable topology remains a tail and is not misreported as
    /// another persisted fragment. The current unified edge overlay supplies
    /// visibility while the collection lock pins all three inputs together.
    pub fn graph_maintenance_stats(
        &self,
        collection_name: &str,
    ) -> Result<Option<crate::compaction::GraphMaintenanceStats>> {
        let _lifecycle = self.lifecycle_gate.read();
        let coll = self.get_coll(collection_name)?;
        let Some((generation, resolver, edge_tombstones)) = ({
            let collection = coll.read();
            collection.graph_generation.as_ref().map(|generation| {
                (
                    Arc::clone(generation),
                    collection.graph_resolver.clone(),
                    collection.overlays.current_ref().edge_tombstones().clone(),
                )
            })
        }) else {
            return Ok(None);
        };
        let resolver = resolver
            .ok_or_else(|| GaussError::InvalidRequest("graph generation has no resolver".into()))?;
        generation
            .maintenance_stats(&resolver, &edge_tombstones)
            .map(Some)
    }

    /// Freeze one coherent graph-compaction input and prepare its D3b
    /// location/merge plan off-lock. D3c will consume this private boundary
    /// from the graph-aware publisher; it is intentionally not a public admin
    /// operation on its own.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "D3b plan is consumed by the following D3c publisher slice"
        )
    )]
    fn prepare_graph_compaction_plan(
        &self,
        collection_name: &str,
    ) -> Result<Option<crate::graph_generation::compaction::GraphCompactionPlan>> {
        let _lifecycle = self.lifecycle_gate.read();
        let coll = self.get_coll(collection_name)?;
        let Some((generation, resolver, overlay, mutable, enabled)) = ({
            let collection = coll.read();
            collection.graph_generation.as_ref().map(|generation| {
                (
                    Arc::clone(generation),
                    collection.graph_resolver.clone(),
                    collection.overlays.current(),
                    collection.graph_mutable.clone(),
                    collection.graph_lifecycle.is_enabled(),
                )
            })
        }) else {
            return Ok(None);
        };
        let resolver = resolver
            .ok_or_else(|| GaussError::InvalidRequest("graph generation has no resolver".into()))?;
        crate::graph_generation::compaction::GraphCompactionPlan::prepare(
            generation, resolver, overlay, mutable, enabled,
        )
        .map(Some)
    }

    /// Prepare an offline data directory for plaintext-to-encrypted migration.
    /// Vector-only collections retain the established compaction path. Any
    /// collection with graph history advances through the normal unified seal
    /// path so graph/vector publication identity is preserved and its active
    /// WAL can be encrypted only after it is empty.
    pub fn prepare_encryption_migration(&self) -> Result<()> {
        self.flush_wals()?;
        self.wait_for_storage_idle()?;
        let mut collections = self
            .inner
            .read()
            .collections
            .iter()
            .map(|(name, collection)| {
                (
                    name.clone(),
                    collection.read().graph_lifecycle.epoch().is_some(),
                )
            })
            .collect::<Vec<_>>();
        collections.sort_by(|left, right| left.0.cmp(&right.0));
        for (name, has_graph_history) in collections {
            if has_graph_history {
                self.seal_graph_for_encryption_migration(&name)?;
            } else {
                self.compact_collection(&name).map_err(|error| {
                    GaussError::InvalidRequest(format!(
                        "failed to compact vector-only collection '{name}' before encryption: {error}"
                    ))
                })?;
            }
        }
        self.wait_for_storage_idle()?;
        {
            let mut inner = self.inner.write();
            write_catalog(&inner)?;
            let watermark = inner.catalog_wal.len()?;
            inner.catalog_wal.drop_prefix(watermark)?;
            if !inner.catalog_wal.is_empty()? {
                return Err(GaussError::InvalidRequest(
                    "catalog WAL is not empty after encryption preparation".into(),
                ));
            }
            for (name, collection) in &inner.collections {
                if !collection.read().wal.is_empty()? {
                    return Err(GaussError::InvalidRequest(format!(
                        "collection '{name}' WAL is not empty after encryption preparation"
                    )));
                }
            }
        }
        self.audit_success(
            "prepare_encryption_migration",
            None,
            serde_json::json!({"status": "ready"}),
        )
    }

    fn seal_graph_for_encryption_migration(&self, collection_name: &str) -> Result<()> {
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        self.ensure_collection_cold_materialized_scope(
            collection_name,
            ColdMaterializeScope::Full,
        )?;
        self.wait_for_storage_idle()?;
        let (root, wal_archive_policy) = {
            let inner = self.inner.read();
            (
                inner.root.clone(),
                seal_wal_archive_policy(&inner, collection_name),
            )
        };
        let coll = self.get_coll(collection_name)?;
        let collection_dir = collection_dir(&root, collection_name);
        let seal = {
            let mut collection = coll.write();
            collection.wal.sync()?;
            collection.overlays.publish_pending()?;
            if collection.wal.is_empty()? {
                return Ok(());
            }
            let end_lsn = collection.wal.len()?;
            let installed_watermark = collection
                .graph_generation
                .as_ref()
                .and_then(|generation| generation.manifest.graph.as_ref())
                .map_or(0, |graph| graph.graph_batch_watermark);
            if end_lsn <= installed_watermark {
                return Err(GaussError::InvalidRequest(format!(
                    "collection '{collection_name}' retains WAL bytes without advancing beyond graph watermark {installed_watermark}"
                )));
            }
            let graph = capture_graph_seal(&mut collection, &collection_dir, end_lsn)?
                .ok_or_else(|| graph_publication_unavailable(collection_name))?;
            let wal_archive_cut = collection.wal.freeze_archive_cut(end_lsn)?;
            let frozen = freeze_streamer_for_seal(&mut collection, end_lsn);
            let index_kind = if frozen.points.is_empty() {
                // Algorithm-2's trained IVF has no meaningful empty model.
                // A zero-row H2QG marker is a format-valid internal carrier
                // for the graph-only cut and exposes no backend choice.
                crate::seal::SealIndexKind::Hnsw
            } else {
                crate::seal::SealIndexKind::Algorithm2
            };
            PendingSeal {
                coll: Arc::clone(&coll),
                data_dir_lock: Arc::clone(&self._data_dir_lock),
                lifecycle: Arc::clone(&self.build_lifecycle),
                collection_dir,
                frozen,
                end_lsn,
                graph: Some(graph),
                wal_archive_cut,
                wal_archive_policy,
                vector_dim: collection.config.vector_dim,
                metric: collection.config.metric,
                hnsw_m: collection.config.hnsw_m,
                hnsw_ef_construction: collection.config.hnsw_ef_construction,
                index_kind,
                cascade: Arc::clone(&self.cascade),
                intra_query_parallel: Arc::clone(&self.intra_query_parallel),
            }
        };
        let _build_permit = build_admission::acquire(build_admission::estimated_build_bytes(
            seal.frozen.points.len(),
            seal.vector_dim,
            3,
        ));
        if let Err(error) = run_segment_seal(&seal) {
            if seal_generation_is_published(&seal) {
                return Err(error);
            }
            cleanup_unpublished_seal(&seal);
            restore_failed_seal(Arc::clone(&seal.coll), Arc::clone(&seal.frozen));
            return Err(error);
        }
        let collection = coll.read();
        if !collection.wal.is_empty()? {
            return Err(GaussError::InvalidRequest(format!(
                "collection '{collection_name}' WAL remained non-empty after graph seal"
            )));
        }
        Ok(())
    }

    /// Evidence-only major compaction for a sealed-topology benchmark. This is
    /// absent from default production builds and is not a customer index knob.
    #[cfg(feature = "benchmark-internals")]
    #[doc(hidden)]
    pub fn compact_collection_full_for_benchmark(
        &self,
        collection_name: &str,
    ) -> Result<CompactResponse> {
        self.compact_collection_with_scope(collection_name, LsvecCompactionScope::Full)
    }

    fn compact_collection_with_scope(
        &self,
        collection_name: &str,
        scope: LsvecCompactionScope,
    ) -> Result<CompactResponse> {
        let _compaction = CollectionCompactionGuard::try_enter(
            Arc::clone(&self.compactions_in_flight),
            collection_name,
        )
        .ok_or_else(|| {
            GaussError::ResourceExhausted(format!(
                "collection '{collection_name}' already has compaction in flight"
            ))
        })?;
        self.compact_collection_with_scope_admitted(collection_name, scope)
    }

    fn compact_collection_with_scope_admitted(
        &self,
        collection_name: &str,
        scope: LsvecCompactionScope,
    ) -> Result<CompactResponse> {
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let audit_operation = self.audit_operation("compact", Some(collection_name))?;
        let mut operation_metrics = OperationGuard::start("compact");
        self.flush_wals()?;
        self.ensure_collection_cold_materialized_scope(
            collection_name,
            ColdMaterializeScope::Full,
        )?;
        let (
            root,
            wal_external_archive_dir,
            wal_object_store,
            wal_archive_command_cfg,
            wal_archive_retain_last,
            wal_archive_max_bytes,
            wal_archive_max_age,
        ) = {
            let inner = self.inner.read();
            (
                inner.root.clone(),
                inner.wal_external_archive_dir.clone(),
                inner.wal_object_store.clone(),
                inner.wal_archive_command.clone(),
                inner.wal_archive_retain_last,
                inner.wal_archive_max_bytes,
                inner.wal_archive_max_age,
            )
        };
        let coll = self.get_coll(collection_name)?;
        let collection_dir = collection_dir(&root, collection_name);

        let graph_history = coll.read().graph_lifecycle.epoch().is_some();
        // Normalize any pre-existing mutable prefix through the ordinary G1
        // sealer first. D3 then replaces that complete generation while newer
        // writes remain a WAL/overlay tail during the off-lock build.
        if graph_history {
            self.seal_graph_for_encryption_migration(collection_name)?;
        }

        // A threshold-crossing upsert may have staged a background index
        // build (see `spawn_index_build`) that hasn't landed yet. Compaction
        // also rebuilds the index from `collection.streamer.points` when dirty, so
        // running both at once would race two independent builds against the
        // same `collection.streamer.hnsw` slot -- whichever finishes last silently
        // wins, and HNSW's construction-order sensitivity means the loser's
        // (perfectly valid) graph can simply have different recall. Wait for
        // the background build to land first so compaction always rebuilds
        // from a settled state.
        while {
            let collection = coll.read();
            collection.index_build_in_flight
                || collection.sealing.is_some()
                || collection.generation_build_in_flight
        } {
            std::thread::sleep(Duration::from_millis(20));
        }

        // Validate/establish manifest authority before freezing any mutable
        // input or marking a generation build in flight. A corrupt manifest
        // must fail without leaving `sealing` or generation ownership set.
        {
            let collection = coll.read();
            ensure_segments_manifest(&collection_dir, &collection)?;
        }

        let build_permit = {
            let collection = coll.read();
            let estimated = build_admission::estimated_build_bytes(
                collection.live_points(),
                collection.config.vector_dim,
                3,
            );
            build_admission::acquire(estimated)
        };

        // LS-VEC generations are built from a WAL-watermarked frozen view
        // while readers continue to serve the old immutable generation plus
        // the frozen/new streamers. Legacy heap segments fall back to the
        // compatibility path below and migrate on their next successful seal.
        let mut staged_graph = if graph_history {
            Some(
                stage_graph_compaction(&coll, &collection_dir, collection_name)?.ok_or_else(
                    || GaussError::InvalidRequest("graph compaction produced no frozen cut".into()),
                )?,
            )
        } else {
            None
        };
        let mut staged_lsvec = if graph_history {
            None
        } else {
            stage_lsvec_compaction(&coll, &collection_dir, scope)?
        };
        let mut completed_build_workspace = None;
        let mut completed_graph_manifest = None;

        // PB-1 (2026-06-12): hold the write lock only across the in-memory
        // state swap + WAL archive_and_reset. The off-disk mirror/retention/
        // archive-command operations touch external files (and may do network
        // I/O on object-store mirrors), so we release the lock before them.
        // Reduces contention on the per-collection RwLock during a slow
        // compaction so concurrent searches don't block on the mirror tail.
        //
        // Note: the compact_searchers_with_params + load_searchers calls still
        // run under write lock because they read `collection.streamer.points` and swap
        // `collection.streamer.hnsw` / `collection.streamer.named_hnsw` in place. A fully lock-
        // free compaction needs a WAL truncation API that keeps records that
        // landed during the disk-write window (out of scope for PB-1 — would
        // ship as PB-1b).
        // PD-5: track (segment_id, points, index stats) for the response so
        // both the full-rebuild and the no-op path use the same post-lock code.
        #[allow(clippy::type_complexity)]
        let (
            compact_segment_id,
            compact_points,
            compact_h2qg_cells,
            compact_named_h2qg_fields,
            compact_sparse_dim,
            compact_sparse_postings,
            compact_payload_fields,
            compact_payload_values,
            compact_payload_postings,
            compact_tombstones,
            wal_archive,
        ): (
            String,
            usize,
            usize,
            usize,
            usize,
            usize,
            usize,
            usize,
            usize,
            usize,
            Option<crate::wal::WalArchive>,
        ) = {
            let mut collection = loop {
                let collection = coll.write();
                let staged_owns_sealing = staged_graph
                    .as_ref()
                    .map(|staged| &staged.input)
                    .or_else(|| staged_lsvec.as_ref().map(|staged| &staged.input))
                    .is_some_and(|input| {
                        input.frozen.as_ref().is_some_and(|staged_frozen| {
                            collection
                                .sealing
                                .as_ref()
                                .is_some_and(|frozen| Arc::ptr_eq(frozen, staged_frozen))
                        })
                    });
                let staged_owns_generation = (staged_graph.is_some() || staged_lsvec.is_some())
                    && collection.generation_build_in_flight;
                if !collection.index_build_in_flight
                    && (collection.sealing.is_none() || staged_owns_sealing)
                    && (!collection.generation_build_in_flight || staged_owns_generation)
                {
                    break collection;
                }
                drop(collection);
                std::thread::sleep(Duration::from_millis(20));
            };
            let last_applied_lsn = collection.wal.len()?;
            // Establish an authoritative generation even for a legacy or
            // never-compacted collection. A crash after publishing a new
            // segment but before switching the next manifest can then remove
            // that unreferenced directory instead of loading it as legacy
            // state alongside the old generation.
            let current_manifest_generation =
                ensure_segments_manifest(&collection_dir, &collection)?;
            let exact_vectors_current = collection.searchers.iter().all(|searcher| {
                matches!(
                    &searcher.store,
                    crate::searcher::SegmentStore::V4(store)
                        if store.segment_format_version() >= 6
                            && (searcher.named_index.is_empty()
                                || store.segment_format_version() >= 8)
                )
            });

            if let Some(staged) = staged_graph.take() {
                let StagedGraphCompaction {
                    input,
                    plan,
                    segment_id,
                    final_dir,
                    store,
                    mut index,
                    named_index,
                    marker_points,
                    end_lsn,
                    generation,
                    build_workspace,
                    expected,
                    prepared_graph,
                    enabled,
                } = staged;
                debug_assert_eq!(marker_points, input.entries.len());
                if current_manifest_generation != expected.generation
                    || collection
                        .graph_generation
                        .as_ref()
                        .is_none_or(|current| current.manifest.as_ref() != &expected)
                    || collection.graph_lifecycle.epoch() != Some(plan.graph_epoch)
                    || collection.graph_lifecycle.is_enabled() != enabled
                {
                    collection.generation_build_in_flight = false;
                    let frozen = input.frozen.as_ref().map(Arc::clone);
                    drop(collection);
                    if let Some(frozen) = frozen {
                        restore_failed_seal(Arc::clone(&coll), frozen);
                    }
                    let _ = remove_seal_candidate(&final_dir);
                    return Err(GaussError::InvalidRequest(
                        "graph compaction cut became stale before publication".into(),
                    ));
                }
                let live_points = collection.live_points();
                let tombstones = input
                    .entries
                    .iter()
                    .filter(|(id, snapshot_location)| {
                        collection.id_index.get(id) != Some(snapshot_location)
                    })
                    .map(|(id, _)| id.clone())
                    .collect::<HashSet<_>>();
                let tombstone_ordinals: roaring::RoaringBitmap = tombstones
                    .iter()
                    .filter_map(|id| store.ordinal(id))
                    .filter_map(|ordinal| u32::try_from(ordinal).ok())
                    .collect();
                let mut point_tombstones = crate::ordinal::SegmentOrdinalSet::new();
                point_tombstones.insert_bitmap(segment_id.clone(), tombstone_ordinals.clone());
                let mut tail_edge_tombstones =
                    collection.overlays.current_ref().edge_tombstones().clone();
                for raw in plan.overlay.edge_tombstones().iter() {
                    tail_edge_tombstones.remove(raw);
                }
                let candidate_manifest = prepared_graph.manifest.as_ref().clone();
                let commit_result = (|| -> Result<_> {
                    crate::seal::write_tombstones(&final_dir, &store, &tombstones)?;
                    for searcher in &collection.searchers {
                        persist_searcher_tombstones(searcher)?;
                    }
                    collection.wal.append_no_sync(&WalEntry::Compact {
                        generation,
                        segments: vec![segment_id.clone()],
                    })?;
                    collection.wal.sync()?;
                    crate::failpoint::check("compaction.after_wal_sync")?;
                    let compact_lsn = collection.wal.len()?;
                    let tail_overlay = collection.overlays.prepare_replacement_generation(
                        generation,
                        point_tombstones.clone(),
                        tail_edge_tombstones.clone(),
                    )?;
                    let published = crate::graph_generation::GraphGeneration::publish_prepared(
                        &collection_dir,
                        Some(&expected),
                        prepared_graph,
                    )?;
                    Ok((compact_lsn, published, tail_overlay))
                })();
                let (compact_lsn, published, tail_overlay) = match commit_result {
                    Ok(committed) => committed,
                    Err(error) => {
                        let committed = read_segments_manifest(&collection_dir)
                            .ok()
                            .flatten()
                            .as_ref()
                            == Some(&candidate_manifest);
                        collection.generation_build_in_flight = false;
                        let frozen = input.frozen.as_ref().map(Arc::clone);
                        drop(collection);
                        if let Some(frozen) = frozen {
                            restore_failed_seal(Arc::clone(&coll), frozen);
                        }
                        if !committed {
                            let _ = remove_seal_candidate(&final_dir);
                        }
                        return Err(error);
                    }
                };
                let published = Arc::new(published);
                collection.wal_watermark = end_lsn;
                collection.graph_generation = Some(Arc::clone(&published));
                collection.overlays.install_prepared(tail_overlay);
                if let Some(mutable) = &mut collection.graph_mutable {
                    mutable.acknowledge_seal(plan.graph_epoch, end_lsn);
                    mutable.install_compaction_tail_tombstones(tail_edge_tombstones);
                    mutable.attach_sealed_adjacency(Arc::clone(&published));
                }
                if let crate::searcher::SegmentIndex::LegacyH2qg(h2qg) = &mut index {
                    h2qg.set_cascade(Arc::clone(&self.cascade));
                    h2qg.set_intra_query_parallel(Arc::clone(&self.intra_query_parallel));
                }
                let compact_h2qg_cells = index
                    .as_backend()
                    .map_or(0, crate::index::IndexBackend::cells);
                let compact_named_h2qg_fields = named_index.len();
                let compact_sparse_dim = collection.sparse_index.dimensions.len();
                let compact_sparse_postings = collection
                    .sparse_index
                    .dimensions
                    .values()
                    .map(|posting| posting.postings.len())
                    .sum();
                let compact_payload_fields = collection.payload_index.equality.len();
                let compact_payload_values = collection
                    .payload_index
                    .equality
                    .values()
                    .map(HashMap::len)
                    .sum();
                let compact_payload_postings = collection
                    .payload_index
                    .equality
                    .values()
                    .flat_map(HashMap::values)
                    .map(HashSet::len)
                    .sum();
                let new_searcher = crate::searcher::SegmentSearcher::new(
                    segment_id.clone(),
                    final_dir,
                    index,
                    named_index,
                    crate::searcher::SegmentStore::V4(store),
                    tombstones.clone(),
                    tombstone_ordinals,
                );
                for (id, snapshot_location) in &input.entries {
                    if collection.id_index.get(id) == Some(snapshot_location) {
                        collection
                            .id_index
                            .insert(id.clone(), crate::searcher::SegLoc::Searcher(0));
                    }
                }
                collection.searchers = vec![new_searcher];
                collection.rebuild_payload_fallback();
                if input.frozen.is_some() {
                    collection.sealing = None;
                }
                collection.generation_build_in_flight = false;
                collection.last_segment_id = Some(segment_id.clone());
                collection.hnsw_dirty = !collection.streamer.points.is_empty();
                collection.overlays.publish_pending()?;
                collection.streamer.base_lsn = end_lsn;
                let checkpoint =
                    collection.checkpoint(compact_lsn, live_points, Some(segment_id.clone()))?;
                write_checkpoint(&collection_dir, &checkpoint)?;
                // Keep the absolute WAL base at or below the graph watermark.
                // The Compact lifecycle record (and any concurrent suffix)
                // remains replayable; the preceding graph seal already
                // archived the durable mutation prefix.
                collection.wal.drop_prefix(end_lsn)?;
                let wal_archive = None;
                remove_unlisted_segment_dirs(
                    &collection_dir,
                    &HashSet::from([segment_id.clone()]),
                )?;
                completed_build_workspace = Some(build_workspace);
                completed_graph_manifest = Some(candidate_manifest);
                drop(plan);
                (
                    segment_id,
                    marker_points,
                    compact_h2qg_cells,
                    compact_named_h2qg_fields,
                    compact_sparse_dim,
                    compact_sparse_postings,
                    compact_payload_fields,
                    compact_payload_values,
                    compact_payload_postings,
                    tombstones.len(),
                    wal_archive,
                )
            // PD-5: skip the full rebuild when no mutations have landed since
            // the last successful compact. The on-disk segment and in-memory
            // index are already current — just advance the checkpoint LSN and
            // archive the (empty) WAL. A legacy f32 segment deliberately
            // bypasses this path so ordinary compaction atomically migrates it
            // to the current scaled-f16 exact-row format.
            } else if staged_lsvec.is_none()
                && collection.last_segment_id.is_some()
                && collection.streamer.points.is_empty()
                && collection.wal.is_empty()?
                && exact_vectors_current
            {
                let segment_id = collection.last_segment_id.clone().unwrap();
                let n_points = collection.live_points();
                collection.wal_watermark = 0;
                collection.streamer.base_lsn = 0;
                let checkpoint =
                    collection.checkpoint(last_applied_lsn, n_points, Some(segment_id.clone()))?;
                write_checkpoint(&collection_dir, &checkpoint)?;
                #[cfg(feature = "fault-injection")]
                crate::fs_util::fault_injection::crash_hook(
                    crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_CHECKPOINT_PUBLISH,
                )?;
                let wal_archive = collection
                    .wal
                    .archive_and_reset(&collection_dir.join("wal/archive"))?;
                (segment_id, n_points, 0, 0, 0, 0, 0, 0, 0, 0, wal_archive)
            } else if collection.live_points() == 0 {
                let generation = current_manifest_generation.checked_add(1).ok_or_else(|| {
                    GaussError::InvalidRequest("segment manifest generation overflow".into())
                })?;
                collection.wal.append_no_sync(&WalEntry::Compact {
                    generation,
                    segments: Vec::new(),
                })?;
                collection.wal.sync()?;
                #[cfg(feature = "fault-injection")]
                crate::fs_util::fault_injection::crash_hook(
                    crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_WAL_FSYNC,
                )?;
                let compact_lsn = collection.wal.len()?;
                write_segments_manifest(
                    &collection_dir,
                    &SegmentsManifest {
                        generation,
                        segments: Vec::new(),
                        graph: None,
                    },
                )?;
                #[cfg(feature = "fault-injection")]
                crate::fs_util::fault_injection::crash_hook(
                    crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_MANIFEST_PUBLISH,
                )?;
                collection.searchers.clear();
                collection.id_index.clear();
                collection.streamer = crate::streamer::Streamer::with_base_lsn(0);
                collection.payload_index = PayloadIndex::default();
                collection.wal_watermark = 0;
                collection.last_segment_id = None;
                collection.hnsw_dirty = false;
                collection
                    .overlays
                    .replace_generation(generation, crate::ordinal::SegmentOrdinalSet::new())?;
                collection.overlays.publish_pending()?;
                let checkpoint = collection.checkpoint(compact_lsn, 0, None)?;
                write_checkpoint(&collection_dir, &checkpoint)?;
                #[cfg(feature = "fault-injection")]
                crate::fs_util::fault_injection::crash_hook(
                    crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_CHECKPOINT_PUBLISH,
                )?;
                let wal_archive = collection
                    .wal
                    .archive_and_reset(&collection_dir.join("wal/archive"))?;
                remove_unlisted_segment_dirs(&collection_dir, &HashSet::new())?;
                ("empty".to_string(), 0, 0, 0, 0, 0, 0, 0, 0, 0, wal_archive)
            } else if let Some(staged) = staged_lsvec.take() {
                let StagedLsvecCompaction {
                    input,
                    segment_id,
                    final_dir,
                    store,
                    index,
                    named_index,
                    marker_points,
                    end_lsn,
                    generation,
                    build_workspace,
                    selected_segment_ids,
                } = staged;
                debug_assert_eq!(marker_points, input.entries.len());
                let live_points = collection.live_points();
                let tail_present = collection.wal.len()? > end_lsn;
                let tombstones = input
                    .entries
                    .iter()
                    .filter(|(id, snapshot_location)| {
                        collection.id_index.get(id) != Some(snapshot_location)
                    })
                    .map(|(id, _)| id.clone())
                    .collect::<HashSet<_>>();
                let installed_segment_ids = if let Some(selected) = &selected_segment_ids {
                    let mut installed = Vec::with_capacity(
                        collection
                            .searchers
                            .len()
                            .saturating_sub(selected.len())
                            .saturating_add(1),
                    );
                    let mut inserted = false;
                    for searcher in &collection.searchers {
                        if selected.contains(&searcher.id) {
                            if !inserted {
                                installed.push(segment_id.clone());
                                inserted = true;
                            }
                        } else {
                            installed.push(searcher.id.clone());
                        }
                    }
                    if !inserted {
                        installed.push(segment_id.clone());
                    }
                    installed
                } else {
                    vec![segment_id.clone()]
                };
                let tombstone_ordinals: roaring::RoaringBitmap = tombstones
                    .iter()
                    .filter_map(|id| store.ordinal(id))
                    .filter_map(|ordinal| u32::try_from(ordinal).ok())
                    .collect();
                let previous_overlay = collection.overlays.current();
                let mut next_point_tombstones = previous_overlay.point_tombstones().clone();
                next_point_tombstones.retain_segments(|segment| {
                    installed_segment_ids.iter().any(|id| id == segment)
                });
                next_point_tombstones.insert_bitmap(segment_id.clone(), tombstone_ordinals.clone());

                // Complete every fallible candidate write before changing the
                // in-memory generation. If manifest publication fails before
                // rename, the frozen snapshot is restored and the old
                // generation remains the sole serveable one.
                let commit_result = (|| -> Result<u64> {
                    crate::seal::write_tombstones(&final_dir, &store, &tombstones)?;
                    if selected_segment_ids.is_some() {
                        for searcher in &collection.searchers {
                            persist_searcher_tombstones(searcher)?;
                        }
                    }
                    collection.wal.append_no_sync(&WalEntry::Compact {
                        generation,
                        segments: installed_segment_ids.clone(),
                    })?;
                    collection.wal.sync()?;
                    crate::failpoint::check("compaction.after_wal_sync")?;
                    #[cfg(feature = "fault-injection")]
                    crate::fs_util::fault_injection::crash_hook(
                        crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_WAL_FSYNC,
                    )?;
                    let compact_lsn = collection.wal.len()?;
                    collection
                        .overlays
                        .advance_generation(generation, next_point_tombstones.clone())?;
                    collection.overlays.publish_pending()?;
                    write_segments_manifest(
                        &collection_dir,
                        &SegmentsManifest {
                            generation,
                            segments: installed_segment_ids.clone(),
                            graph: None,
                        },
                    )?;
                    crate::failpoint::check("compaction.after_manifest")?;
                    #[cfg(feature = "fault-injection")]
                    crate::fs_util::fault_injection::crash_hook(
                        crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_MANIFEST_PUBLISH,
                    )?;
                    Ok(compact_lsn)
                })();
                let compact_lsn = match commit_result {
                    Ok(lsn) => lsn,
                    Err(error) => {
                        // A directory fsync may report an error after rename.
                        // Re-read the manifest to distinguish a committed
                        // generation from a safely abortable candidate.
                        let committed = read_segments_manifest(&collection_dir)
                            .ok()
                            .flatten()
                            .is_some_and(|manifest| {
                                manifest.generation == generation
                                    && manifest.segments == installed_segment_ids
                            });
                        if committed {
                            tracing::warn!(
                                %error,
                                generation,
                                "segment manifest was renamed but final sync reported an error"
                            );
                            collection.wal.len()?
                        } else {
                            collection.overlays.restore_snapshot(&previous_overlay)?;
                            let frozen = input.frozen.as_ref().map(Arc::clone);
                            drop(input);
                            drop(index);
                            drop(named_index);
                            drop(store);
                            drop(collection);
                            let mut failed = coll.write();
                            failed.generation_build_in_flight = false;
                            drop(failed);
                            if let Some(frozen) = frozen {
                                restore_failed_seal(Arc::clone(&coll), frozen);
                            }
                            let _ = remove_seal_candidate(&final_dir);
                            return Err(error);
                        }
                    }
                };

                let compact_h2qg_cells = index
                    .as_backend()
                    .map_or(0, crate::index::IndexBackend::cells);
                let compact_named_h2qg_fields = named_index.len();
                let compact_sparse_dim = collection.sparse_index.dimensions.len();
                let compact_sparse_postings = collection
                    .sparse_index
                    .dimensions
                    .values()
                    .map(|posting| posting.postings.len())
                    .sum();
                let compact_payload_fields = collection.payload_index.equality.len();
                let compact_payload_values = collection
                    .payload_index
                    .equality
                    .values()
                    .map(HashMap::len)
                    .sum();
                let compact_payload_postings = collection
                    .payload_index
                    .equality
                    .values()
                    .flat_map(HashMap::values)
                    .map(HashSet::len)
                    .sum();
                let included_frozen = input.frozen.is_some();
                let compact_tombstones = tombstones.len();
                let merged_searcher = crate::searcher::SegmentSearcher::new(
                    segment_id.clone(),
                    final_dir,
                    index,
                    named_index,
                    crate::searcher::SegmentStore::V4(store),
                    tombstones,
                    tombstone_ordinals,
                );
                if let Some(selected) = &selected_segment_ids {
                    let old_searchers = std::mem::take(&mut collection.searchers);
                    let selected_positions = old_searchers
                        .iter()
                        .enumerate()
                        .filter(|(_, searcher)| selected.contains(&searcher.id))
                        .map(|(position, _)| position)
                        .collect::<HashSet<_>>();
                    let first_selected = selected_positions.iter().min().copied();
                    let mut old_to_new = vec![None; old_searchers.len()];
                    let mut merged = Some(merged_searcher);
                    let mut merged_position = None;
                    let mut replacement = Vec::with_capacity(installed_segment_ids.len());
                    for (old_position, searcher) in old_searchers.into_iter().enumerate() {
                        if selected_positions.contains(&old_position) {
                            if first_selected == Some(old_position) {
                                merged_position = Some(replacement.len() as u32);
                                replacement
                                    .push(merged.take().expect("merged searcher inserted once"));
                            }
                        } else {
                            old_to_new[old_position] = Some(replacement.len() as u32);
                            replacement.push(searcher);
                        }
                    }
                    if let Some(merged) = merged.take() {
                        merged_position = Some(replacement.len() as u32);
                        replacement.push(merged);
                    }
                    let merged_position = merged_position.expect("partial merge installs segment");
                    for location in collection.id_index.values_mut() {
                        match *location {
                            crate::searcher::SegLoc::Sealing => {
                                *location = crate::searcher::SegLoc::Searcher(merged_position);
                            }
                            crate::searcher::SegLoc::Searcher(old_position)
                                if selected_positions.contains(&(old_position as usize)) =>
                            {
                                *location = crate::searcher::SegLoc::Searcher(merged_position);
                            }
                            crate::searcher::SegLoc::Searcher(old_position) => {
                                *location = crate::searcher::SegLoc::Searcher(
                                    old_to_new[old_position as usize]
                                        .expect("retained searcher has replacement position"),
                                );
                            }
                            crate::searcher::SegLoc::Streamer => {}
                        }
                    }
                    collection.searchers = replacement;
                } else {
                    for (id, snapshot_location) in &input.entries {
                        if collection.id_index.get(id) == Some(snapshot_location) {
                            collection
                                .id_index
                                .insert(id.clone(), crate::searcher::SegLoc::Searcher(0));
                        }
                    }
                    collection.searchers = vec![merged_searcher];
                }
                collection.rebuild_payload_fallback();
                if included_frozen {
                    collection.sealing = None;
                }
                collection.generation_build_in_flight = false;
                collection.last_segment_id = Some(segment_id.clone());
                collection.hnsw_dirty = !collection.streamer.points.is_empty();

                let wal_archive = if tail_present {
                    // The immutable generation owns only the snapshot prefix;
                    // concurrent mutations stay in the active streamer and
                    // WAL suffix, with absolute LSNs preserved.
                    collection.wal_watermark = end_lsn;
                    collection.streamer.base_lsn = end_lsn;
                    let checkpoint = collection.checkpoint(
                        compact_lsn,
                        live_points,
                        Some(segment_id.clone()),
                    )?;
                    write_checkpoint(&collection_dir, &checkpoint)?;
                    collection.wal.drop_prefix(end_lsn)?;
                    None
                } else {
                    // Preserve existing archive behavior when no tail raced
                    // the build; the new segment contains the entire state.
                    collection.wal_watermark = 0;
                    collection.streamer.base_lsn = 0;
                    let checkpoint = collection.checkpoint(
                        compact_lsn,
                        live_points,
                        Some(segment_id.clone()),
                    )?;
                    write_checkpoint(&collection_dir, &checkpoint)?;
                    collection
                        .wal
                        .archive_and_reset(&collection_dir.join("wal/archive"))?
                };
                crate::failpoint::check("compaction.after_checkpoint")?;
                #[cfg(feature = "fault-injection")]
                crate::fs_util::fault_injection::crash_hook(
                    crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_CHECKPOINT_PUBLISH,
                )?;
                crate::failpoint::check("compaction.after_archive")?;
                remove_unlisted_segment_dirs(
                    &collection_dir,
                    &installed_segment_ids
                        .iter()
                        .cloned()
                        .collect::<HashSet<_>>(),
                )?;
                completed_build_workspace = Some(build_workspace);
                (
                    segment_id,
                    live_points,
                    compact_h2qg_cells,
                    compact_named_h2qg_fields,
                    compact_sparse_dim,
                    compact_sparse_postings,
                    compact_payload_fields,
                    compact_payload_values,
                    compact_payload_postings,
                    compact_tombstones,
                    wal_archive,
                )
            } else if collection
                .config
                .index_kind
                .as_deref()
                .is_none_or(|kind| kind.eq_ignore_ascii_case("lsvec"))
                && !exact_vectors_current
            {
                let generation = current_manifest_generation.checked_add(1).ok_or_else(|| {
                    GaussError::InvalidRequest("segment manifest generation overflow".into())
                })?;
                let segment_id = format!("sg-v6-merge-{last_applied_lsn:020}-{generation:020}");
                let searchers_dir = collection_dir.join("searchers");
                fs::create_dir_all(&searchers_dir)?;
                let final_dir = searchers_dir.join(&segment_id);
                let tmp_dir =
                    searchers_dir.join(format!(".{segment_id}.tmp-{}", std::process::id()));
                let marker = {
                    let input = MergeInput::new(&collection);
                    crate::seal::build_segment(
                        &input,
                        &tmp_dir,
                        crate::seal::SealConfig {
                            vector_dim: collection.config.vector_dim,
                            metric: collection.config.metric,
                            hnsw_m: collection.config.hnsw_m,
                            hnsw_ef_construction: collection.config.hnsw_ef_construction,
                            index_kind: crate::seal::SealIndexKind::Algorithm2,
                            base_lsn: 0,
                            end_lsn: last_applied_lsn,
                        },
                    )?
                    .marker
                };
                #[cfg(feature = "fault-injection")]
                crate::fs_util::fault_injection::crash_hook(
                    crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_SEGMENT_TREE_SYNC,
                )?;
                durable_rename(&tmp_dir, &final_dir)?;
                crate::failpoint::check("compaction.after_segment_sync")?;
                #[cfg(feature = "fault-injection")]
                crate::fs_util::fault_injection::crash_hook(
                    crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_SEGMENT_PUBLISH,
                )?;

                let store = Arc::new(crate::seal::V4Store::open(&final_dir)?);
                let index = crate::searcher::SegmentIndex::Ivf(Box::new(
                    crate::index::ivf_segment::IvfSegmentIndex::open(
                        &final_dir,
                        Arc::clone(&store),
                        collection.config.metric,
                    )?,
                ));
                let named_index = crate::searcher::load_named_algorithm2_indexes(
                    &final_dir,
                    collection.config.metric,
                )?;
                let compact_h2qg_cells = index
                    .as_backend()
                    .map_or(0, crate::index::IndexBackend::cells);
                let compact_named_h2qg_fields = named_index.len();
                let compact_sparse_dim = collection.sparse_index.dimensions.len();
                let compact_sparse_postings = collection
                    .sparse_index
                    .dimensions
                    .values()
                    .map(|posting| posting.postings.len())
                    .sum();
                let compact_payload_fields = collection.payload_index.equality.len();
                let compact_payload_values = collection
                    .payload_index
                    .equality
                    .values()
                    .map(HashMap::len)
                    .sum();
                let compact_payload_postings = collection
                    .payload_index
                    .equality
                    .values()
                    .flat_map(HashMap::values)
                    .map(HashSet::len)
                    .sum();
                let id_index = store
                    .ids()
                    .iter()
                    .cloned()
                    .map(|id| (id, crate::searcher::SegLoc::Searcher(0)))
                    .collect();
                let new_searcher = crate::searcher::SegmentSearcher::new(
                    segment_id.clone(),
                    final_dir,
                    index,
                    named_index,
                    crate::searcher::SegmentStore::V4(store),
                    HashSet::new(),
                    roaring::RoaringBitmap::new(),
                );

                // The manifest is the atomic generation switch. Until it
                // lands, recovery keeps serving the old segment set and
                // replays the untouched WAL.
                collection.wal.append_no_sync(&WalEntry::Compact {
                    generation,
                    segments: vec![segment_id.clone()],
                })?;
                collection.wal.sync()?;
                crate::failpoint::check("compaction.after_wal_sync")?;
                #[cfg(feature = "fault-injection")]
                crate::fs_util::fault_injection::crash_hook(
                    crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_WAL_FSYNC,
                )?;
                let compact_lsn = collection.wal.len()?;
                write_segments_manifest(
                    &collection_dir,
                    &SegmentsManifest {
                        generation,
                        segments: vec![segment_id.clone()],
                        graph: None,
                    },
                )?;
                crate::failpoint::check("compaction.after_manifest")?;
                #[cfg(feature = "fault-injection")]
                crate::fs_util::fault_injection::crash_hook(
                    crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_MANIFEST_PUBLISH,
                )?;
                collection.searchers = vec![new_searcher];
                collection.id_index = id_index;
                collection.streamer = crate::streamer::Streamer::with_base_lsn(0);
                collection.payload_index = PayloadIndex::default();
                collection.wal_watermark = 0;
                collection.last_segment_id = Some(segment_id.clone());
                collection.hnsw_dirty = false;
                collection
                    .overlays
                    .replace_generation(generation, crate::ordinal::SegmentOrdinalSet::new())?;
                collection.overlays.publish_pending()?;
                let checkpoint =
                    collection.checkpoint(compact_lsn, marker.points, Some(segment_id.clone()))?;
                write_checkpoint(&collection_dir, &checkpoint)?;
                crate::failpoint::check("compaction.after_checkpoint")?;
                #[cfg(feature = "fault-injection")]
                crate::fs_util::fault_injection::crash_hook(
                    crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_CHECKPOINT_PUBLISH,
                )?;
                let wal_archive = collection
                    .wal
                    .archive_and_reset(&collection_dir.join("wal/archive"))?;
                crate::failpoint::check("compaction.after_archive")?;
                remove_unlisted_segment_dirs(
                    &collection_dir,
                    &HashSet::from([segment_id.clone()]),
                )?;
                (
                    segment_id,
                    marker.points,
                    compact_h2qg_cells,
                    compact_named_h2qg_fields,
                    compact_sparse_dim,
                    compact_sparse_postings,
                    compact_payload_fields,
                    compact_payload_values,
                    compact_payload_postings,
                    0,
                    wal_archive,
                )
            } else {
                // Drop the old graphs before the rebuild: the write lock is
                // held across the whole rebuild + reload, so no reader can see
                // the gap, and holding the old graph (which embeds a full copy
                // of every vector) alongside the new one doubles graph-phase
                // peak memory — the difference between compacting and OOMing
                // on memory-capped hosts. If the rebuild errors out mid-way,
                // searches fall back to the (correct, slower) flat path until
                // the next compact; `hnsw_dirty` stays true so one is due.
                collection.streamer.hnsw = None;
                collection.streamer.named_hnsw.clear();
                // Gather the union of every live point (streamer + all
                // searcher stores, tombstones excluded) into one map. Phase 1
                // keeps the monolithic single-segment rebuild — the map is
                // moved out and back by the compactor, then becomes the new
                // searcher's store — so peak memory matches the old merged-
                // map behavior. The chunked multi-segment seal replaces this
                // in Phase 2.
                let mut union_points = collection.streamer.take_points();
                for searcher in collection.searchers.drain(..) {
                    let tombstones = searcher.tombstones;
                    match searcher.store {
                        crate::searcher::SegmentStore::Heap(points) => {
                            for (id, point) in points {
                                if !tombstones.contains(&id) {
                                    union_points.entry(id).or_insert(point);
                                }
                            }
                        }
                        crate::searcher::SegmentStore::V4(store) => {
                            for ordinal in 0..store.len() {
                                if let Some(point) = store.get_ordinal(ordinal)
                                    && !tombstones.contains(&point.id)
                                {
                                    union_points.entry(point.id.clone()).or_insert(point);
                                }
                            }
                        }
                    }
                }
                let write = crate::segment::compact_searchers_with_params(
                    &collection_dir.join("searchers"),
                    &mut union_points,
                    collection.config.vector_dim,
                    &collection.config.named_vector_dims,
                    collection.config.hnsw_m,
                    collection.config.hnsw_ef_construction,
                    collection.config.metric,
                )?;
                #[cfg(feature = "fault-injection")]
                crate::fs_util::fault_injection::crash_hook(
                    crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_SEGMENT_TREE_SYNC,
                )?;
                #[cfg(feature = "fault-injection")]
                crate::fs_util::fault_injection::crash_hook(
                    crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_SEGMENT_PUBLISH,
                )?;
                // PC-2 v3: also persist the vamana index when this is a
                // vamana collection. The writer is a no-op (writes a
                // VAMANA_MAGIC file alongside h2qg.gdx) so the vamana graph
                // survives a restart. Non-vamana collections skip the
                // branch via the `is_some()` guard.
                if let Some(ref vamana) = collection.vamana {
                    let vamana_path = collection_dir
                        .join("searchers")
                        .join(&write.id)
                        .join(crate::segment::VAMANA_FILE);
                    let _vamana_write = crate::segment::write_vamana_index(&vamana_path, vamana)?;
                }
                // Install the rewritten segment as the collection's single
                // searcher: the graph + named indexes reload from disk, but
                // the point store reuses the union map already in memory —
                // no second full read of vec.gdx.
                let new_segment_dir = collection_dir.join("searchers").join(&write.id);
                let new_index = {
                    let h2qg_path = new_segment_dir.join(crate::h2qg::INDEX_FILE);
                    if h2qg_path.exists() {
                        crate::searcher::SegmentIndex::LegacyH2qg(Box::new(
                            crate::h2qg::read_index_paged(&new_segment_dir)?,
                        ))
                    } else {
                        crate::searcher::SegmentIndex::None
                    }
                };
                let mut new_named = HashMap::new();
                for (name, path) in crate::segment::named_h2qg_paths(&new_segment_dir)? {
                    new_named.insert(
                        name,
                        crate::searcher::SegmentIndex::LegacyH2qg(Box::new(
                            crate::h2qg::read_index(&path)?,
                        )),
                    );
                }
                let mut new_searcher = crate::searcher::SegmentSearcher::new(
                    write.id.clone(),
                    new_segment_dir,
                    new_index,
                    new_named,
                    crate::searcher::SegmentStore::Heap(union_points),
                    std::collections::HashSet::new(),
                    roaring::RoaringBitmap::new(),
                );
                // W1 bugfix: compaction reloads a fresh H2qgIndex from the
                // rewritten segment; wire the server-wide cascade flag same
                // as the other two build/load sites.
                if let crate::searcher::SegmentIndex::LegacyH2qg(h2qg) = &mut new_searcher.index {
                    h2qg.set_cascade(self.cascade.clone());
                }
                let mut id_index = HashMap::with_capacity(new_searcher.store.len());
                for point in new_searcher.store.iter_points() {
                    id_index.insert(point.id.clone(), crate::searcher::SegLoc::Searcher(0));
                }
                collection.searchers = vec![new_searcher];
                collection.id_index = id_index;
                collection.rebuild_payload_fallback();
                let generation = current_manifest_generation.checked_add(1).ok_or_else(|| {
                    GaussError::InvalidRequest("segment manifest generation overflow".into())
                })?;
                let installed = collection
                    .searchers
                    .iter()
                    .map(|searcher| searcher.id.clone())
                    .collect::<Vec<_>>();
                collection.wal.append_no_sync(&WalEntry::Compact {
                    generation,
                    segments: installed.clone(),
                })?;
                collection.wal.sync()?;
                #[cfg(feature = "fault-injection")]
                crate::fs_util::fault_injection::crash_hook(
                    crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_WAL_FSYNC,
                )?;
                let compact_lsn = collection.wal.len()?;
                write_segments_manifest(
                    &collection_dir,
                    &SegmentsManifest {
                        generation,
                        segments: installed,
                        graph: None,
                    },
                )?;
                #[cfg(feature = "fault-injection")]
                crate::fs_util::fault_injection::crash_hook(
                    crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_MANIFEST_PUBLISH,
                )?;
                collection
                    .overlays
                    .replace_generation(generation, crate::ordinal::SegmentOrdinalSet::new())?;
                collection.overlays.publish_pending()?;
                collection.wal_watermark = 0;
                collection.streamer.base_lsn = 0;
                let checkpoint =
                    collection.checkpoint(compact_lsn, write.points, Some(write.id.clone()))?;
                write_checkpoint(&collection_dir, &checkpoint)?;
                #[cfg(feature = "fault-injection")]
                crate::fs_util::fault_injection::crash_hook(
                    crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_CHECKPOINT_PUBLISH,
                )?;
                collection.last_segment_id = Some(write.id.clone());
                collection.hnsw_dirty = false;
                let wal_archive = collection
                    .wal
                    .archive_and_reset(&collection_dir.join("wal/archive"))?;
                (
                    write.id,
                    write.points,
                    write.h2qg_cells,
                    write.named_h2qg_fields,
                    write.sparse_dimensions,
                    write.sparse_postings,
                    write.payload_fields,
                    write.payload_values,
                    write.payload_postings,
                    write.tombstones,
                    wal_archive,
                )
            }
        };
        // Critical section over — readers can resume.
        if let Some(workspace) = completed_build_workspace
            && let Err(error) = crate::build_progress::remove_workspace(&workspace)
        {
            tracing::warn!(
                %error,
                path = %workspace.display(),
                "published LS-VEC compaction retained completed build workspace"
            );
        }
        if let Some(manifest) = completed_graph_manifest
            && let Err(error) = remove_unlisted_graph_artifacts(&collection_dir, &manifest)
        {
            // The replacement manifest is already authoritative. A reader on
            // a platform that prevents unlinking an open mapped file may keep
            // an old run alive until the next maintenance pass.
            tracing::warn!(
                %error,
                generation = manifest.generation,
                "published graph compaction retained superseded artifacts"
            );
        }
        drop(build_permit);

        let wal_external_archive = match (&wal_external_archive_dir, &wal_archive) {
            (Some(external_root), Some(archive)) => {
                Some(mirror_wal_archive(external_root, collection_name, archive)?)
            }
            _ => None,
        };
        let wal_object_archive = match (&wal_object_store, &wal_archive) {
            (Some(object_store), Some(archive)) => Some(mirror_wal_archive_to_object_store(
                object_store,
                collection_name,
                archive,
            )?),
            _ => None,
        };
        let wal_archive_command = match (&wal_archive_command_cfg, &wal_archive) {
            (Some(command), Some(archive)) => {
                Some(run_wal_archive_command(command, collection_name, archive)?)
            }
            _ => None,
        };
        let wal_auto_prune = apply_wal_archive_retention(
            &collection_dir.join("wal/archive"),
            wal_archive_retain_last,
            wal_archive_max_bytes,
            wal_archive_max_age,
        )?;
        let response = CompactResponse {
            collection: collection_name.to_string(),
            segment_id: compact_segment_id,
            points: compact_points,
            h2qg_cells: compact_h2qg_cells,
            named_h2qg_fields: compact_named_h2qg_fields,
            sparse_dimensions: compact_sparse_dim,
            sparse_postings: compact_sparse_postings,
            payload_fields: compact_payload_fields,
            payload_values: compact_payload_values,
            payload_postings: compact_payload_postings,
            tombstones: compact_tombstones,
            wal_archived_segments: wal_archive.as_ref().map_or(0, |archive| archive.segments),
            wal_archived_bytes: wal_archive.as_ref().map_or(0, |archive| archive.bytes),
            wal_external_archived_segments: wal_external_archive
                .as_ref()
                .map_or(0, |archive| archive.segments),
            wal_external_archived_bytes: wal_external_archive
                .as_ref()
                .map_or(0, |archive| archive.bytes),
            wal_object_archived_segments: wal_object_archive
                .as_ref()
                .map_or(0, |archive| archive.segments),
            wal_object_archived_bytes: wal_object_archive
                .as_ref()
                .map_or(0, |archive| archive.bytes),
            wal_archive_command_executed: wal_archive_command
                .as_ref()
                .is_some_and(|archive_command| archive_command.executed),
            wal_auto_retained_archives: wal_auto_prune
                .as_ref()
                .map_or(0, |prune| prune.retained_archives),
            wal_auto_pruned_archives: wal_auto_prune
                .as_ref()
                .map_or(0, |prune| prune.pruned_archives),
            wal_auto_pruned_bytes: wal_auto_prune
                .as_ref()
                .map_or(0, |prune| prune.pruned_bytes),
        };
        // PB-1: `collection` write guard already dropped at end of inner block.
        audit_operation.success(serde_json::json!({
            "segment_id": &response.segment_id,
            "points": response.points,
            "h2qg_cells": response.h2qg_cells,
            "named_h2qg_fields": response.named_h2qg_fields,
            "sparse_dimensions": response.sparse_dimensions,
            "sparse_postings": response.sparse_postings,
            "payload_fields": response.payload_fields,
            "payload_values": response.payload_values,
            "payload_postings": response.payload_postings,
            "tombstones": response.tombstones,
            "wal_archived_segments": response.wal_archived_segments,
            "wal_archived_bytes": response.wal_archived_bytes,
            "wal_external_archived_segments": response.wal_external_archived_segments,
            "wal_external_archived_bytes": response.wal_external_archived_bytes,
            "wal_object_archived_segments": response.wal_object_archived_segments,
            "wal_object_archived_bytes": response.wal_object_archived_bytes,
            "wal_archive_command_executed": response.wal_archive_command_executed,
            "wal_auto_retained_archives": response.wal_auto_retained_archives,
            "wal_auto_pruned_archives": response.wal_auto_pruned_archives,
            "wal_auto_pruned_bytes": response.wal_auto_pruned_bytes,
        }))?;
        self.refresh_metrics();
        operation_metrics.succeed();
        Ok(response)
    }

    pub fn tier_collection_to_cold(&self, collection_name: &str) -> Result<ColdTierResponse> {
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let audit_operation = self.audit_operation("tier_cold", Some(collection_name))?;
        let mut operation_metrics = OperationGuard::start("tier_cold");
        let (root, cold_object_store) = {
            let inner = self.inner.read();
            (inner.root.clone(), inner.cold_object_store.clone())
        };
        let coll = self.get_coll(collection_name)?;
        let collection = loop {
            let collection = coll.read();
            if collection.sealing.is_none() {
                break collection;
            }
            drop(collection);
            std::thread::sleep(Duration::from_millis(20));
        };
        if collection.graph_lifecycle.epoch().is_some() && collection.graph_generation.is_none() {
            return Err(graph_publication_unavailable(collection_name));
        }
        let collection_dir = collection_dir(&root, collection_name);
        if let Some(pinned) = &collection.graph_generation {
            let manifest = read_segments_manifest(&collection_dir)?.ok_or_else(|| {
                GaussError::SegmentCorruption {
                    path: collection_dir
                        .join(crate::checkpoint::SEGMENTS_MANIFEST_FILE)
                        .display()
                        .to_string(),
                    message: "graph cold tier requires the selected segments manifest".into(),
                }
            })?;
            if manifest != *pinned.manifest {
                return Err(GaussError::SegmentCorruption {
                    path: collection_dir
                        .join(crate::checkpoint::SEGMENTS_MANIFEST_FILE)
                        .display()
                        .to_string(),
                    message: "selected graph manifest changed after collection admission".into(),
                });
            }
            let installed = manifest.segments.iter().cloned().collect::<HashSet<_>>();
            let remote_diskann = if let Some(object_store) = cold_object_store.as_ref() {
                materialize_missing_cold_segments_from_object_store(
                    &collection_dir.join("cold"),
                    object_store,
                )?;
                crate::segment::remote_diskann_artifacts(
                    &collection_dir.join("cold"),
                    object_store,
                    Some(&installed),
                )?
            } else {
                HashMap::new()
            };
            crate::graph_generation::GraphGeneration::load_candidate_with_remote_diskann(
                &collection_dir,
                manifest,
                &remote_diskann,
            )?;
        }
        let points = collection
            .searchers
            .iter()
            .map(|searcher| searcher.live_len())
            .sum();
        let write = crate::segment::tier_searchers_to_cold(
            &collection_dir.join("searchers"),
            &collection_dir.join("cold"),
            collection_name,
            points,
            cold_object_store.as_ref(),
        )?;
        drop(collection);
        let response = ColdTierResponse {
            collection: collection_name.to_string(),
            segments: write.segments,
            files: write.files,
            bytes: write.bytes,
            points: write.points,
        };
        audit_operation.success(serde_json::json!({
            "segments": response.segments,
            "files": response.files,
            "bytes": response.bytes,
            "points": response.points,
        }))?;
        operation_metrics.succeed();
        Ok(response)
    }

    /// Aggregate page-I/O evidence from cold LS-VEC segments. Hot segments
    /// and non-LS-VEC indexes contribute zero.
    pub fn diskann_io_stats(
        &self,
        collection_name: &str,
    ) -> Result<crate::index::diskann::DiskAnnIoStats> {
        let _lifecycle = self.lifecycle_gate.read();
        let coll = self.get_coll(collection_name)?;
        let collection = coll.read();
        let mut stats = crate::index::diskann::DiskAnnIoStats::default();
        for searcher in &collection.searchers {
            if let crate::searcher::SegmentIndex::Ivf(index) = &searcher.index {
                stats += index.diskann_io_stats();
            }
        }
        Ok(stats)
    }

    /// Reset cold-page counters and evict the bounded userspace page cache so
    /// the next query phase starts from an observable cold baseline.
    pub fn reset_diskann_io_stats(&self, collection_name: &str) -> Result<()> {
        let _lifecycle = self.lifecycle_gate.read();
        let coll = self.get_coll(collection_name)?;
        let collection = coll.read();
        for searcher in &collection.searchers {
            if let crate::searcher::SegmentIndex::Ivf(index) = &searcher.index {
                index.reset_diskann_io_stats();
            }
        }
        Ok(())
    }

    pub fn compact_collections_over_wal_bytes(
        &self,
        threshold_bytes: u64,
    ) -> Result<Vec<CompactResponse>> {
        if threshold_bytes == 0 {
            return Err(GaussError::InvalidRequest(
                "auto-compaction WAL threshold must be greater than zero".to_string(),
            ));
        }

        let collection_names = {
            let inner = self.inner.read();
            let mut names = Vec::new();
            for (name, arc_coll) in &inner.collections {
                let collection = arc_coll.read();
                if collection.wal.retained_bytes()? >= threshold_bytes {
                    names.push(name.clone());
                }
            }
            names
        };

        collection_names
            .into_iter()
            .map(|name| self.compact_collection(&name))
            .collect()
    }

    /// Compact all collections whose multi-factor compaction score meets or
    /// exceeds `min_score`, ordered by descending urgency.
    ///
    /// The score combines WAL-to-segment byte ratio and WAL deletion density.
    /// A score of 0.0 compacts every collection above the minimum WAL
    /// threshold; 1.0 compacts nothing.  A threshold around 0.4–0.6 is
    /// suitable for routine background maintenance.
    pub fn compact_collections_by_score(
        &self,
        min_score: f32,
        weights: Option<crate::compaction::CompactionWeights>,
    ) -> Result<Vec<CompactResponse>> {
        let weights = weights.unwrap_or_default();

        let candidates = {
            let inner = self.inner.read();
            let mut stats_vec = Vec::new();
            let mut forced = HashSet::new();
            for (name, arc_coll) in &inner.collections {
                let collection = arc_coll.read();
                let wal_bytes = collection.wal.retained_bytes()?;
                let mut wal_entry_count = 0usize;
                let mut wal_delete_count = 0usize;
                Wal::scan_from(
                    &collection_dir(&inner.root, name).join("wal"),
                    collection.wal_watermark,
                    |record| {
                        let (entries, deletes) = match record.entry {
                            WalEntry::Upsert { .. } | WalEntry::SetPayload { .. } => (1, 0),
                            WalEntry::UpsertBatch { points } => (points.len(), 0),
                            WalEntry::Delete { .. } => (1, 1),
                            WalEntry::DeleteBatch { ids } => (ids.len(), ids.len()),
                            WalEntry::GraphBatch { batch } => {
                                let entries = batch.point_mutations.len();
                                let deletes = batch
                                    .point_mutations
                                    .iter()
                                    .filter(|mutation| {
                                        matches!(
                                            mutation,
                                            crate::wal::GraphPointMutation::Delete { .. }
                                        )
                                    })
                                    .count();
                                (entries, deletes)
                            }
                            WalEntry::CreateCollection { .. }
                            | WalEntry::DropCollection { .. }
                            | WalEntry::Schema { .. }
                            | WalEntry::GraphEpochAdvance { .. }
                            | WalEntry::Compact { .. } => (0, 0),
                        };
                        wal_entry_count = wal_entry_count.saturating_add(entries);
                        wal_delete_count = wal_delete_count.saturating_add(deletes);
                        Ok(())
                    },
                )?;
                let segment_bytes = collection
                    .searchers
                    .iter()
                    .filter_map(|searcher| directory_size(&searcher.dir).ok())
                    .sum();
                let stored_points = collection
                    .searchers
                    .iter()
                    .map(|searcher| searcher.store.len())
                    .sum::<usize>();
                let tombstones = collection
                    .searchers
                    .iter()
                    .map(|searcher| searcher.tombstones.len())
                    .sum::<usize>();
                if collection.searchers.len() > 8
                    || (stored_points > 0 && tombstones.saturating_mul(5) > stored_points)
                {
                    forced.insert(name.clone());
                }
                stats_vec.push(crate::compaction::CollectionCompactionStats {
                    name: name.clone(),
                    wal_bytes,
                    segment_bytes,
                    live_points: collection.live_points(),
                    compacted_point_count: collection.live_points(),
                    wal_entry_count,
                    wal_delete_count,
                });
            }
            let mut ranked = crate::compaction::ranked_candidates(&stats_vec, min_score, &weights);
            for name in forced {
                if !ranked.iter().any(|(candidate, _)| candidate == &name) {
                    ranked.push((name, 1.0));
                }
            }
            ranked.sort_by(|left, right| right.1.total_cmp(&left.1));
            ranked
        };

        candidates
            .into_iter()
            .map(|(name, _score)| self.compact_collection(&name))
            .collect()
    }

    pub fn prune_wal_archive(
        &self,
        collection_name: &str,
        retain_last: usize,
    ) -> Result<WalArchivePruneResponse> {
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let audit_operation = self.audit_operation("prune_wal_archive", Some(collection_name))?;
        let mut operation_metrics = OperationGuard::start("prune_wal_archive");
        // Validate collection exists before proceeding
        self.get_coll(collection_name)?;
        let root = self.inner.read().root.clone();
        let prune = prune_archives(
            &collection_dir(&root, collection_name).join("wal/archive"),
            retain_last,
        )?;
        audit_operation.success(serde_json::json!({
            "retain_last": retain_last,
            "retained_archives": prune.retained_archives,
            "pruned_archives": prune.pruned_archives,
            "pruned_bytes": prune.pruned_bytes,
        }))?;
        operation_metrics.succeed();
        Ok(WalArchivePruneResponse {
            collection: collection_name.to_string(),
            retained_archives: prune.retained_archives,
            pruned_archives: prune.pruned_archives,
            pruned_bytes: prune.pruned_bytes,
        })
    }

    pub fn snapshot(&self, destination: impl AsRef<Path>) -> Result<()> {
        let _lifecycle = self.lifecycle_gate.write();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let audit_operation = self.audit_operation("snapshot", None)?;
        let mut operation_metrics = OperationGuard::start("snapshot");
        self.wait_for_storage_idle()?;
        self.flush_wals()?;
        let inner = self.inner.read();
        let destination = destination.as_ref();
        reject_storage_path_overlap("snapshot destination", destination, &inner.root)?;
        let snapshot_destination_lock = DataDirLock::acquire(destination)?;
        let destination = snapshot_destination_lock.root();
        recover_snapshot_control(destination)?;
        cleanup_snapshot_staging(destination)?;
        let destination_was_empty = if destination.exists() {
            if !destination.is_dir() || fs::read_dir(destination)?.next().is_some() {
                return Err(GaussError::InvalidRequest(format!(
                    "snapshot destination is not an empty directory: {}",
                    destination.display()
                )));
            }
            true
        } else {
            false
        };
        let mut marker_collections = Vec::with_capacity(inner.collections.len());
        for arc_coll in inner.collections.values() {
            let collection = arc_coll.read();
            marker_collections.push(collection.snapshot_collection()?);
        }
        marker_collections.sort_by(|left, right| left.collection.cmp(&right.collection));
        let marker = SnapshotMarker::new(marker_collections);
        let operation_id = uuid::Uuid::new_v4();
        let staging = snapshot_staging_path(destination, operation_id)?;
        let parent = destination.parent().ok_or_else(|| {
            GaussError::InvalidRequest("snapshot target must have a parent directory".to_string())
        })?;
        let identity = snapshot_staging_identity(destination)?;
        let journal = SnapshotJournal::new(
            operation_id,
            SnapshotPhase::Prepared,
            sibling_file_name(&staging)?,
            sibling_file_name(destination)?,
        )?;
        snapshot_journal::write(parent, &identity, &journal)?;
        snapshot_dir_all(&inner.root, &staging)?;
        // Check the copied generation and WAL tail, not just in-memory source
        // counters. An incomplete graph snapshot must never publish success.
        let staged = load_db_root(&staging, inner.cold_object_store.as_ref())?;
        validate_snapshot_marker(Some(&marker), &staged.collections)?;
        drop(staged);
        sync_tree(&staging)?;
        crate::failpoint::check("snapshot.after_tree_sync")?;
        write_snapshot_marker(&staging, &marker)?;
        crate::failpoint::check("snapshot.after_marker_sync")?;
        sync_tree(&staging)?;
        #[cfg(feature = "fault-injection")]
        crate::fs_util::fault_injection::crash_hook(
            crate::fs_util::fault_injection::HOOK_SNAPSHOT_AFTER_STAGING_SYNC,
        )?;
        if destination_was_empty {
            durable_remove_dir_all(destination)?;
        }
        if let Err(error) = durable_rename(&staging, destination) {
            if staging.exists() {
                let _ = durable_remove_dir_all(&staging);
            }
            if destination_was_empty && !destination.exists() {
                let _ = fs::create_dir_all(destination);
                if let Some(parent) = destination.parent() {
                    let _ = sync_directory(parent);
                }
            }
            return Err(error);
        }
        crate::failpoint::check("snapshot.after_publish_sync")?;
        snapshot_journal::write(
            parent,
            &identity,
            &journal.with_phase(SnapshotPhase::Published),
        )?;
        #[cfg(feature = "fault-injection")]
        crate::fs_util::fault_injection::crash_hook(
            crate::fs_util::fault_injection::HOOK_SNAPSHOT_AFTER_DESTINATION_PUBLISH,
        )?;
        snapshot_journal::remove(parent, &identity)?;
        drop(inner);
        audit_operation.success(serde_json::json!({
            "destination": destination.display().to_string(),
            "collections": marker.collections.len(),
        }))?;
        operation_metrics.succeed();
        Ok(())
    }

    pub fn restore(&self, source: impl AsRef<Path>) -> Result<()> {
        self.restore_to_wal_targets(source, &HashMap::new(), &HashMap::new())
    }

    pub fn restore_to_wal_lsns(
        &self,
        source: impl AsRef<Path>,
        target_wal_lsns: &HashMap<String, u64>,
    ) -> Result<()> {
        self.restore_to_wal_targets(source, target_wal_lsns, &HashMap::new())
    }

    pub fn restore_to_wal_targets(
        &self,
        source: impl AsRef<Path>,
        target_wal_lsns: &HashMap<String, u64>,
        target_wal_unix_ms: &HashMap<String, u64>,
    ) -> Result<()> {
        self.restore_to_wal_targets_with_archive_dir(
            source,
            target_wal_lsns,
            target_wal_unix_ms,
            None,
        )
    }

    pub fn restore_to_wal_targets_with_archive_dir(
        &self,
        source: impl AsRef<Path>,
        target_wal_lsns: &HashMap<String, u64>,
        target_wal_unix_ms: &HashMap<String, u64>,
        wal_restore_archive_dir: Option<&Path>,
    ) -> Result<()> {
        self.restore_to_wal_targets_with_archive_sources(
            source,
            target_wal_lsns,
            target_wal_unix_ms,
            wal_restore_archive_dir,
            None,
        )
    }

    pub fn restore_to_wal_targets_with_archive_sources(
        &self,
        source: impl AsRef<Path>,
        target_wal_lsns: &HashMap<String, u64>,
        target_wal_unix_ms: &HashMap<String, u64>,
        wal_restore_archive_dir: Option<&Path>,
        wal_restore_object_store: Option<&ColdObjectStoreConfig>,
    ) -> Result<()> {
        if let Some(previous_generation) = self.active_generation() {
            return self.restore_generation_to_wal_targets_with_archive_sources(
                source.as_ref(),
                target_wal_lsns,
                target_wal_unix_ms,
                wal_restore_archive_dir,
                wal_restore_object_store,
                &previous_generation,
            );
        }
        let _maintenance = self.maintenance_barrier.write();
        let audit_operation = self.audit_operation("restore", None)?;
        let mut operation_metrics = OperationGuard::start("restore");
        let source = source.as_ref();
        let (root, cold_object_store) = {
            let inner = self.inner.read();
            (inner.root.clone(), inner.cold_object_store.clone())
        };
        self.ensure_storage_mutations_available()?;
        reject_storage_path_overlap("restore source", source, &root)?;
        if let Some(archive_dir) = wal_restore_archive_dir {
            reject_storage_path_overlap("WAL restore archive directory", archive_dir, &root)?;
        }
        if let Some(ColdObjectStoreConfig::LocalDir(object_store_dir)) = wal_restore_object_store {
            reject_storage_path_overlap(
                "WAL restore object-store directory",
                object_store_dir,
                &root,
            )?;
        }

        let snapshot_marker = read_snapshot_marker(source)?;
        validate_restore_wal_targets(
            snapshot_marker.as_ref(),
            target_wal_lsns,
            target_wal_unix_ms,
            wal_restore_archive_dir.is_some() || wal_restore_object_store.is_some(),
        )?;
        let graph_allocator_epoch = self.graph_identity.reserve_new_epoch()?;
        let journal_parent = restore_control_dir(&root)?;
        match fs::create_dir(&journal_parent) {
            Ok(()) => {
                if let Some(parent) = journal_parent.parent() {
                    sync_directory(parent)?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(GaussError::InvalidRequest(format!(
                    "restore control directory already exists: {}",
                    journal_parent.display()
                )));
            }
            Err(error) => return Err(error.into()),
        }
        let operation_id = uuid::Uuid::new_v4();
        let operation_target = journal_parent.join("generation");
        let (staging, backup) = operation_siblings(&operation_target, "restore", operation_id)?;
        let journal = RestoreJournal::new(
            operation_id,
            RestorePhase::Prepared,
            sibling_file_name(&staging)?,
            sibling_file_name(&backup)?,
        )?;

        let prepared = (|| -> Result<_> {
            fs::create_dir_all(&staging)?;
            copy_dir_contents(source, &staging)?;
            GraphIdentityStore::discard_imported_from(&staging)?;
            sync_tree(&staging)?;

            let LoadedDbRoot {
                mut catalog_wal,
                collections,
                catalog_replayed,
            } = load_db_root(&staging, cold_object_store.as_ref())?;
            if catalog_replayed {
                write_catalog_state(&staging, &collections, &catalog_wal)?;
                let watermark = catalog_wal.len()?;
                catalog_wal.drop_prefix(watermark)?;
            }
            validate_snapshot_marker(snapshot_marker.as_ref(), &collections)?;
            let restored_collection_names = collections.keys().cloned().collect::<Vec<_>>();
            let restored_configs = collections
                .values()
                .map(|collection| collection.read().config.clone())
                .collect::<Vec<_>>();
            let restored_schema_states = collections
                .iter()
                .map(|(name, collection)| {
                    let collection = collection.read();
                    Ok((
                        name.clone(),
                        SchemaRestoreState {
                            config: collection.config.clone(),
                            schema_epoch: collection.schema_epoch,
                            graph_history: collection.graph_lifecycle.epoch().is_some(),
                            snapshot_lsn: collection.wal.len()?,
                        },
                    ))
                })
                .collect::<Result<HashMap<_, _>>>()?;
            drop(collections);
            drop(catalog_wal);

            let wal_archive_restore = wal_restore_archive_dir
                .map(|archive_dir| {
                    restore_wal_archives_from_external(
                        &staging,
                        archive_dir,
                        &restored_collection_names,
                    )
                })
                .transpose()?;
            let wal_object_restore = wal_restore_object_store
                .map(|object_store| {
                    restore_wal_archives_from_object_store(
                        &staging,
                        object_store,
                        &restored_collection_names,
                    )
                })
                .transpose()?;
            let wal_rehydrated_origins =
                rehydrate_restore_wal_origins(&staging, target_wal_lsns, target_wal_unix_ms)?;
            let wal_archive_replay = replay_restored_wal_archives(
                &staging,
                [&wal_archive_restore, &wal_object_restore],
            )?;
            let applied_target_wal = apply_restore_wal_targets(
                &staging,
                target_wal_lsns,
                target_wal_unix_ms,
                &restored_schema_states,
            )?;
            let collections = load_restore_collections(
                &staging,
                &restored_configs,
                &applied_target_wal,
                cold_object_store.as_ref(),
            )?;
            let catalog_wal = Wal::open(&staging.join(CATALOG_WAL_DIR))?;
            let rewrite_restore_metadata = !target_wal_lsns.is_empty()
                || !target_wal_unix_ms.is_empty()
                || wal_archive_replay.records > 0;
            write_restore_metadata(
                &staging,
                &collections,
                &catalog_wal,
                rewrite_restore_metadata,
            )?;
            catalog_wal.sync()?;
            for collection in collections.values() {
                collection.read().wal.sync()?;
            }
            let restored_collection_count = collections.len();
            drop(collections);
            drop(catalog_wal);
            sync_tree(&staging)?;

            // Re-open every persisted structure after PITR/archive rewrites.
            // Nothing is installed unless this final read-only validation
            // succeeds against the exact staged generation.
            let validated = load_db_root(&staging, cold_object_store.as_ref())?;
            if validated.catalog_replayed {
                return Err(GaussError::WalCorruption {
                    path: staging.join(CATALOG_WAL_DIR).display().to_string(),
                    message: "staged restore catalog WAL was not checkpointed".to_string(),
                });
            }
            drop(validated);
            sync_tree(&staging)?;
            Ok((
                wal_archive_restore,
                wal_object_restore,
                wal_rehydrated_origins,
                wal_archive_replay,
                applied_target_wal,
                restored_collection_count,
            ))
        })();
        let (
            wal_archive_restore,
            wal_object_restore,
            wal_rehydrated_origins,
            wal_archive_replay,
            applied_target_wal,
            restored_collection_count,
        ) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                if staging.exists() {
                    let _ = durable_remove_dir_all(&staging);
                }
                let _ = durable_remove_dir_all(&journal_parent);
                return Err(error);
            }
        };

        let maintenance_guard = match MaintenanceGuard::enter(Arc::clone(&self.maintenance)) {
            Ok(guard) => guard,
            Err(error) => {
                let _ = durable_remove_dir_all(&journal_parent);
                return Err(error);
            }
        };
        let _lifecycle = self.lifecycle_gate.write();
        // Declared after the lifecycle guard so ordinary exits clear
        // maintenance before queued operations can acquire the shared gate.
        let mut maintenance_guard = maintenance_guard;
        self.wal_flusher.quiesce();
        let preinstall = self
            .wait_for_storage_idle()
            .and_then(|()| self.flush_wals())
            .and_then(|()| preserve_audit_log(&root, &staging))
            .and_then(|()| self.graph_identity.preserve_for_root_swap(&staging))
            .and_then(|()| sync_tree(&staging));
        if let Err(error) = preinstall {
            let _ = durable_remove_dir_all(&journal_parent);
            return Err(error);
        }

        if let Err(error) = restore_journal::write(&journal_parent, &journal) {
            let _ = durable_remove_dir_all(&staging);
            let _ = restore_journal::remove(&journal_parent);
            let _ = durable_remove_dir_all(&journal_parent);
            return Err(error);
        }
        #[cfg(feature = "fault-injection")]
        crate::fs_util::fault_injection::crash_hook(
            crate::fs_util::fault_injection::HOOK_RESTORE_AFTER_PREPARED,
        )?;

        let install_result = (|| -> Result<LoadedDbRoot> {
            durable_rename(&root, &backup)?;
            restore_journal::write(&journal_parent, &journal.with_phase(RestorePhase::OldMoved))?;
            #[cfg(feature = "fault-injection")]
            crate::fs_util::fault_injection::crash_hook(
                crate::fs_util::fault_injection::HOOK_RESTORE_AFTER_OLD_MOVED,
            )?;
            durable_rename(&staging, &root)?;
            restore_journal::write(
                &journal_parent,
                &journal.with_phase(RestorePhase::NewInstalled),
            )?;
            #[cfg(feature = "fault-injection")]
            crate::fs_util::fault_injection::crash_hook(
                crate::fs_util::fault_injection::HOOK_RESTORE_AFTER_NEW_INSTALLED,
            )?;
            let mut loaded = load_db_root(&root, cold_object_store.as_ref())?;
            if loaded.catalog_replayed {
                write_catalog_state(&root, &loaded.collections, &loaded.catalog_wal)?;
                let watermark = loaded.catalog_wal.len()?;
                loaded.catalog_wal.drop_prefix(watermark)?;
            }
            sync_tree(&root)?;
            Ok(loaded)
        })();
        let loaded = match install_result {
            Ok(loaded) => loaded,
            Err(error) => {
                if let Err(rollback_error) =
                    rollback_restore_generation(&root, &staging, &backup, &journal_parent)
                {
                    maintenance_guard.latch();
                    self.mark_durability_degraded("restore_rollback", &rollback_error);
                    return Err(GaussError::WalCorruption {
                        path: journal_parent
                            .join(restore_journal::RESTORE_JOURNAL_FILE)
                            .display()
                            .to_string(),
                        message: format!(
                            "restore failed ({error}); rollback also failed ({rollback_error})"
                        ),
                    });
                }
                return Err(error);
            }
        };

        let LoadedDbRoot {
            catalog_wal,
            collections,
            catalog_replayed: _,
        } = loaded;
        let (old_catalog_wal, old_collections) = {
            let mut inner = self.inner.write();
            let old_catalog_wal = std::mem::replace(&mut inner.catalog_wal, catalog_wal);
            let old_collections = std::mem::replace(&mut inner.collections, collections);
            (old_catalog_wal, old_collections)
        };
        drop(old_collections);
        drop(old_catalog_wal);

        // Remove the control directory with the journal still inside it. This
        // avoids a crash window where startup sees an empty control directory
        // after the journal was unlinked but before the directory itself was
        // removed.
        let cleanup_result =
            durable_remove_dir_all(&backup).and_then(|()| durable_remove_dir_all(&journal_parent));
        if let Err(error) = cleanup_result {
            self.mark_durability_degraded("restore_cleanup", &error);
            tracing::error!(%error, "atomic restore committed but cleanup requires startup recovery");
        }
        audit_operation.success(serde_json::json!({
                "source": source.display().to_string(),
                "collections": restored_collection_count,
                "snapshot_marker": snapshot_marker.is_some(),
                "target_wal_lsns": target_wal_lsns,
                "target_wal_unix_ms": target_wal_unix_ms,
                "applied_target_wal_lsns": applied_target_wal.lsns,
                "graph_allocator_epoch": graph_allocator_epoch,
                "wal_restore_archive_dir": wal_restore_archive_dir.map(|path| path.display().to_string()),
                "wal_restored_archives": wal_archive_restore.as_ref().map_or(0, |restore| restore.archives),
                "wal_restored_archive_segments": wal_archive_restore.as_ref().map_or(0, |restore| restore.segments),
                "wal_restored_archive_bytes": wal_archive_restore.as_ref().map_or(0, |restore| restore.bytes),
                "wal_restore_object_store": wal_restore_object_store.is_some(),
                "wal_object_restored_archives": wal_object_restore.as_ref().map_or(0, |restore| restore.archives),
                "wal_object_restored_archive_segments": wal_object_restore.as_ref().map_or(0, |restore| restore.segments),
                "wal_object_restored_archive_bytes": wal_object_restore.as_ref().map_or(0, |restore| restore.bytes),
                "wal_rehydrated_origins": wal_rehydrated_origins,
                "wal_replayed_archives": wal_archive_replay.archives,
                "wal_replayed_archive_records": wal_archive_replay.records,
                "wal_replayed_archive_schema_records": wal_archive_replay.schema_records,
            }))?;
        self.rebuild_recovered_streamer_indexes();
        self.refresh_metrics();
        operation_metrics.succeed();
        Ok(())
    }

    pub fn data_dir(&self) -> PathBuf {
        self.data_dir.clone()
    }

    pub fn graph_database_id(&self) -> uuid::Uuid {
        self.graph_identity.snapshot().database_id
    }

    pub fn graph_allocator_epoch(&self) -> u32 {
        self.graph_identity.snapshot().allocator_epoch
    }

    pub fn active_generation(&self) -> Option<String> {
        crate::storage_layout::resolve(&self.data_dir)
            .ok()
            .and_then(|layout| layout.generation)
    }

    #[allow(clippy::too_many_arguments)]
    fn restore_generation_to_wal_targets_with_archive_sources(
        &self,
        source: &Path,
        target_wal_lsns: &HashMap<String, u64>,
        target_wal_unix_ms: &HashMap<String, u64>,
        wal_restore_archive_dir: Option<&Path>,
        wal_restore_object_store: Option<&ColdObjectStoreConfig>,
        previous_generation: &str,
    ) -> Result<()> {
        let _maintenance = self.maintenance_barrier.write();
        let audit_operation = self.audit_operation("restore", None)?;
        let mut operation_metrics = OperationGuard::start("restore");
        let (_, cold_object_store) = {
            let inner = self.inner.read();
            (inner.root.clone(), inner.cold_object_store.clone())
        };
        self.ensure_storage_mutations_available()?;
        reject_storage_path_overlap("restore source", source, &self.data_dir)?;
        if let Some(archive_dir) = wal_restore_archive_dir {
            reject_storage_path_overlap(
                "WAL restore archive directory",
                archive_dir,
                &self.data_dir,
            )?;
        }
        if let Some(ColdObjectStoreConfig::LocalDir(object_store_dir)) = wal_restore_object_store {
            reject_storage_path_overlap(
                "WAL restore object-store directory",
                object_store_dir,
                &self.data_dir,
            )?;
        }

        let snapshot_marker = read_snapshot_marker(source)?;
        validate_restore_wal_targets(
            snapshot_marker.as_ref(),
            target_wal_lsns,
            target_wal_unix_ms,
            wal_restore_archive_dir.is_some() || wal_restore_object_store.is_some(),
        )?;
        let graph_allocator_epoch = self.graph_identity.reserve_new_epoch()?;

        let generations = self.data_dir.join(crate::storage_layout::GENERATIONS_DIR);
        durable_create_dir(&generations)?;
        let next_generation = crate::storage_layout::new_generation_id();
        let staging_name = format!(".{next_generation}.restore-staging");
        let staging = generations.join(&staging_name);
        let destination = generations.join(&next_generation);
        if staging.exists()
            || destination.exists()
            || restore_journal::read(&self.data_dir)?.is_some()
        {
            return Err(GaussError::InvalidRequest(
                "a generation restore is already pending recovery".to_string(),
            ));
        }
        let journal = RestoreJournal::new_generation(
            uuid::Uuid::new_v4(),
            RestorePhase::Prepared,
            &staging_name,
            previous_generation,
            &next_generation,
        )?;
        restore_journal::write(&self.data_dir, &journal)?;
        crate::failpoint::check("restore.after_copy_journal")?;
        let prepared = (|| -> Result<_> {
            durable_create_dir(&staging)?;
            copy_dir_contents(source, &staging)?;
            GraphIdentityStore::discard_imported_from(&staging)?;
            sync_tree(&staging)?;
            crate::failpoint::check("restore.after_snapshot_copy")?;

            let LoadedDbRoot {
                mut catalog_wal,
                collections,
                catalog_replayed,
            } = load_db_root(&staging, cold_object_store.as_ref())?;
            if catalog_replayed {
                write_catalog_state(&staging, &collections, &catalog_wal)?;
                let watermark = catalog_wal.len()?;
                catalog_wal.drop_prefix(watermark)?;
            }
            validate_snapshot_marker(snapshot_marker.as_ref(), &collections)?;
            let restored_collection_names = collections.keys().cloned().collect::<Vec<_>>();
            let restored_configs = collections
                .values()
                .map(|collection| collection.read().config.clone())
                .collect::<Vec<_>>();
            let restored_schema_states = collections
                .iter()
                .map(|(name, collection)| {
                    let collection = collection.read();
                    Ok((
                        name.clone(),
                        SchemaRestoreState {
                            config: collection.config.clone(),
                            schema_epoch: collection.schema_epoch,
                            graph_history: collection.graph_lifecycle.epoch().is_some(),
                            snapshot_lsn: collection.wal.len()?,
                        },
                    ))
                })
                .collect::<Result<HashMap<_, _>>>()?;
            drop(collections);
            drop(catalog_wal);

            let wal_archive_restore = wal_restore_archive_dir
                .map(|archive_dir| {
                    restore_wal_archives_from_external(
                        &staging,
                        archive_dir,
                        &restored_collection_names,
                    )
                })
                .transpose()?;
            let wal_object_restore = wal_restore_object_store
                .map(|object_store| {
                    restore_wal_archives_from_object_store(
                        &staging,
                        object_store,
                        &restored_collection_names,
                    )
                })
                .transpose()?;
            let wal_rehydrated_origins =
                rehydrate_restore_wal_origins(&staging, target_wal_lsns, target_wal_unix_ms)?;
            let wal_archive_replay = replay_restored_wal_archives(
                &staging,
                [&wal_archive_restore, &wal_object_restore],
            )?;
            let applied_target_wal = apply_restore_wal_targets(
                &staging,
                target_wal_lsns,
                target_wal_unix_ms,
                &restored_schema_states,
            )?;
            let collections = load_restore_collections(
                &staging,
                &restored_configs,
                &applied_target_wal,
                cold_object_store.as_ref(),
            )?;
            let catalog_wal = Wal::open(&staging.join(CATALOG_WAL_DIR))?;
            let rewrite_restore_metadata = !target_wal_lsns.is_empty()
                || !target_wal_unix_ms.is_empty()
                || wal_archive_replay.records > 0;
            write_restore_metadata(
                &staging,
                &collections,
                &catalog_wal,
                rewrite_restore_metadata,
            )?;
            catalog_wal.sync()?;
            for collection in collections.values() {
                collection.read().wal.sync()?;
            }
            let restored_collection_count = collections.len();
            drop(collections);
            drop(catalog_wal);
            sync_tree(&staging)?;

            let validated = load_db_root(&staging, cold_object_store.as_ref())?;
            if validated.catalog_replayed {
                return Err(GaussError::WalCorruption {
                    path: staging.join(CATALOG_WAL_DIR).display().to_string(),
                    message: "staged restore catalog WAL was not checkpointed".to_string(),
                });
            }
            drop(validated);
            Ok((
                wal_archive_restore,
                wal_object_restore,
                wal_rehydrated_origins,
                wal_archive_replay,
                applied_target_wal,
                restored_collection_count,
            ))
        })();
        let (
            wal_archive_restore,
            wal_object_restore,
            wal_rehydrated_origins,
            wal_archive_replay,
            applied_target_wal,
            restored_collection_count,
        ) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                if staging.exists() {
                    let _ = durable_remove_dir_all(&staging);
                }
                let _ = restore_journal::remove(&self.data_dir);
                return Err(error);
            }
        };

        let maintenance_guard = MaintenanceGuard::enter(Arc::clone(&self.maintenance))?;
        let _lifecycle = self.lifecycle_gate.write();
        let mut maintenance_guard = maintenance_guard;
        self.wal_flusher.quiesce();
        self.wait_for_storage_idle()?;
        self.flush_wals()?;

        fs::rename(&staging, &destination)?;
        sync_directory(&generations)?;
        restore_journal::write(&self.data_dir, &journal.with_phase(RestorePhase::OldMoved))?;
        #[cfg(feature = "fault-injection")]
        crate::fs_util::fault_injection::crash_hook(
            crate::fs_util::fault_injection::HOOK_RESTORE_AFTER_OLD_MOVED,
        )?;
        crate::failpoint::check("restore.after_generation_sync")?;
        crate::failpoint::check("restore.before_current_switch")?;
        if let Err(error) = crate::storage_layout::switch_current(&self.data_dir, &next_generation)
        {
            let _ = durable_remove_dir_all(&destination);
            let _ = restore_journal::remove(&self.data_dir);
            return Err(error);
        }
        crate::failpoint::check("restore.after_current_switch")?;
        restore_journal::write(
            &self.data_dir,
            &journal.with_phase(RestorePhase::NewInstalled),
        )?;
        #[cfg(feature = "fault-injection")]
        crate::fs_util::fault_injection::crash_hook(
            crate::fs_util::fault_injection::HOOK_RESTORE_AFTER_NEW_INSTALLED,
        )?;
        crate::failpoint::check("restore.after_current_switch")?;

        let loaded = match load_db_root(&destination, cold_object_store.as_ref()) {
            Ok(loaded) if !loaded.catalog_replayed => loaded,
            Ok(_) => {
                let error = GaussError::WalCorruption {
                    path: destination.join(CATALOG_WAL_DIR).display().to_string(),
                    message: "installed restore catalog WAL was not checkpointed".to_string(),
                };
                crate::storage_layout::switch_current(&self.data_dir, previous_generation)?;
                let _ = durable_remove_dir_all(&destination);
                let _ = restore_journal::remove(&self.data_dir);
                maintenance_guard.latch();
                return Err(error);
            }
            Err(error) => {
                crate::storage_layout::switch_current(&self.data_dir, previous_generation)?;
                let _ = durable_remove_dir_all(&destination);
                let _ = restore_journal::remove(&self.data_dir);
                maintenance_guard.latch();
                return Err(error);
            }
        };
        let LoadedDbRoot {
            catalog_wal,
            collections,
            catalog_replayed: _,
        } = loaded;
        let (old_catalog_wal, old_collections) = {
            let mut inner = self.inner.write();
            inner.root = destination.clone();
            let old_catalog_wal = std::mem::replace(&mut inner.catalog_wal, catalog_wal);
            let old_collections = std::mem::replace(&mut inner.collections, collections);
            (old_catalog_wal, old_collections)
        };
        drop(old_collections);
        drop(old_catalog_wal);

        restore_journal::remove(&self.data_dir)?;
        let previous_root = generations.join(previous_generation);
        if let Err(error) = durable_remove_dir_all(&previous_root) {
            self.mark_durability_degraded("restore_generation_cleanup", &error);
            tracing::error!(%error, "generation restore committed but old generation cleanup failed");
        }
        sync_directory(&generations)?;
        audit_operation.success(serde_json::json!({
            "source": source.display().to_string(),
            "collections": restored_collection_count,
            "snapshot_marker": snapshot_marker.is_some(),
            "install_mode": "generation_switch",
            "previous_generation": previous_generation,
            "active_generation": next_generation,
            "target_wal_lsns": target_wal_lsns,
            "target_wal_unix_ms": target_wal_unix_ms,
            "applied_target_wal_lsns": applied_target_wal.lsns,
            "graph_allocator_epoch": graph_allocator_epoch,
            "wal_restore_archive_dir": wal_restore_archive_dir.map(|path| path.display().to_string()),
            "wal_restored_archives": wal_archive_restore.as_ref().map_or(0, |restore| restore.archives),
            "wal_restored_archive_segments": wal_archive_restore.as_ref().map_or(0, |restore| restore.segments),
            "wal_restored_archive_bytes": wal_archive_restore.as_ref().map_or(0, |restore| restore.bytes),
            "wal_restore_object_store": wal_restore_object_store.is_some(),
            "wal_object_restored_archives": wal_object_restore.as_ref().map_or(0, |restore| restore.archives),
            "wal_object_restored_archive_segments": wal_object_restore.as_ref().map_or(0, |restore| restore.segments),
            "wal_object_restored_archive_bytes": wal_object_restore.as_ref().map_or(0, |restore| restore.bytes),
            "wal_rehydrated_origins": wal_rehydrated_origins,
            "wal_replayed_archives": wal_archive_replay.archives,
            "wal_replayed_archive_records": wal_archive_replay.records,
            "wal_replayed_archive_schema_records": wal_archive_replay.schema_records,
        }))?;
        self.rebuild_recovered_streamer_indexes();
        self.refresh_metrics();
        operation_metrics.succeed();
        Ok(())
    }

    // ── Replication helpers ───────────────────────────────────────────────────

    /// Returns the WAL directory for a collection, used by WAL streaming replication.
    pub fn collection_wal_dir(&self, name: &str) -> Option<std::path::PathBuf> {
        let _lifecycle = self.lifecycle_gate.read();
        let inner = self.inner.read();
        if inner.collections.contains_key(name) {
            let root = inner.root.clone();
            drop(inner);
            Some(collection_dir(&root, name).join("wal"))
        } else {
            None
        }
    }

    fn ensure_legacy_replication_available(&self, collection_name: &str) -> Result<()> {
        let coll = self.get_coll(collection_name)?;
        if coll.read().graph_lifecycle.epoch().is_some() {
            return Err(graph_replication_unavailable(collection_name));
        }
        Ok(())
    }

    /// Durably apply a legacy replicated point batch. The graph-history check
    /// is performed while holding the same collection write lock as the WAL
    /// append and publication, so graph activation is ordered wholly before
    /// (reject) or after (accept and backfill) this mutation.
    pub(crate) fn apply_legacy_replicated_upsert(
        &self,
        collection_name: &str,
        points: Vec<Point>,
    ) -> Result<()> {
        self.upsert_wait_unguarded(
            collection_name,
            points,
            true,
            MutationContext::legacy_replication(),
            None,
            None,
        )?;
        Ok(())
    }

    /// Durably apply a legacy replicated point-delete batch under the atomic
    /// graph-history refusal boundary.
    pub(crate) fn apply_legacy_replicated_delete(
        &self,
        collection_name: &str,
        ids: &[String],
    ) -> Result<()> {
        self.delete_unguarded(
            collection_name,
            ids,
            false,
            audit::AuditContext::embedded(),
            MutationOrigin::LegacyReplication,
        )?;
        Ok(())
    }

    /// Durably apply a legacy replicated payload update under the atomic
    /// graph-history refusal boundary.
    pub(crate) fn apply_legacy_replicated_payload(
        &self,
        collection_name: &str,
        id: &str,
        payload: Value,
        merge: bool,
    ) -> Result<()> {
        self.set_payload_unguarded(
            collection_name,
            id,
            payload,
            merge,
            audit::AuditContext::embedded(),
            MutationOrigin::LegacyReplication,
        )?;
        Ok(())
    }

    /// Apply a replicated upsert WITHOUT writing to the local WAL.
    pub fn upsert_replicated(&self, collection_name: &str, point: Point) -> Result<()> {
        let _admission = self.maintenance_barrier.read();
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let coll = self.get_coll(collection_name)?;
        let mut collection = coll.write();
        if collection.graph_lifecycle.epoch().is_some() {
            return Err(graph_replication_unavailable(collection_name));
        }
        match collection.id_index.get(&point.id).copied() {
            Some(crate::searcher::SegLoc::Sealing) => {
                if let Some(old_point) = collection
                    .sealing
                    .as_ref()
                    .and_then(|streamer| streamer.points.get(&point.id))
                    .cloned()
                {
                    crate::sparse_index::remove_sparse_point(
                        &mut collection.sparse_index,
                        &old_point,
                    );
                    crate::payload_index::remove_payload_point(
                        &mut collection.payload_index,
                        &old_point,
                    );
                }
                collection.streamer.insert(point.clone());
            }
            Some(crate::searcher::SegLoc::Searcher(i)) => {
                let old_point = collection.searchers[i as usize]
                    .store
                    .get(&point.id)
                    .map(Cow::into_owned);
                if let Some(old_point) = old_point {
                    crate::sparse_index::remove_sparse_point(
                        &mut collection.sparse_index,
                        &old_point,
                    );
                    crate::payload_index::remove_payload_point(
                        &mut collection.payload_index,
                        &old_point,
                    );
                }
                collection.tombstone_searcher(i as usize, &point.id)?;
                collection.streamer.insert(point.clone());
            }
            _ => {
                if let Some(old_point) = collection.streamer.insert(point.clone()) {
                    crate::sparse_index::remove_sparse_point(
                        &mut collection.sparse_index,
                        &old_point,
                    );
                    crate::payload_index::remove_payload_point(
                        &mut collection.payload_index,
                        &old_point,
                    );
                }
            }
        }
        collection
            .id_index
            .insert(point.id.clone(), crate::searcher::SegLoc::Streamer);
        crate::sparse_index::insert_sparse_point(&mut collection.sparse_index, &point);
        crate::payload_index::insert_payload_point(&mut collection.payload_index, &point);
        collection.overlays.publish_pending()?;
        Ok(())
    }

    /// Apply a replicated delete WITHOUT writing to the local WAL.
    pub fn delete_replicated(&self, collection_name: &str, id: &str) -> Result<()> {
        let _admission = self.maintenance_barrier.read();
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let coll = self.get_coll(collection_name)?;
        let mut collection = coll.write();
        if collection.graph_lifecycle.epoch().is_some() {
            return Err(graph_replication_unavailable(collection_name));
        }
        match collection.id_index.get(id).copied() {
            Some(crate::searcher::SegLoc::Streamer) => {
                if let Some(old_point) = collection.streamer.remove(id) {
                    crate::sparse_index::remove_sparse_point(
                        &mut collection.sparse_index,
                        &old_point,
                    );
                    crate::payload_index::remove_payload_point(
                        &mut collection.payload_index,
                        &old_point,
                    );
                    if let Some(h2qg) = collection.streamer.hnsw.as_mut() {
                        h2qg.remove_from_indexed(id);
                    }
                    for named in collection.streamer.named_hnsw.values_mut() {
                        named.remove_from_indexed(id);
                    }
                    collection.id_index.remove(id);
                }
            }
            Some(crate::searcher::SegLoc::Sealing) => {
                if let Some(old_point) = collection
                    .sealing
                    .as_ref()
                    .and_then(|streamer| streamer.points.get(id))
                    .cloned()
                {
                    crate::sparse_index::remove_sparse_point(
                        &mut collection.sparse_index,
                        &old_point,
                    );
                    crate::payload_index::remove_payload_point(
                        &mut collection.payload_index,
                        &old_point,
                    );
                }
                collection.id_index.remove(id);
            }
            Some(crate::searcher::SegLoc::Searcher(i)) => {
                let old_point = collection.searchers[i as usize]
                    .store
                    .get(id)
                    .map(Cow::into_owned);
                if let Some(old_point) = old_point {
                    crate::sparse_index::remove_sparse_point(
                        &mut collection.sparse_index,
                        &old_point,
                    );
                    crate::payload_index::remove_payload_point(
                        &mut collection.payload_index,
                        &old_point,
                    );
                }
                collection.tombstone_searcher(i as usize, id)?;
                collection.id_index.remove(id);
            }
            None => {}
        }
        collection.overlays.publish_pending()?;
        Ok(())
    }

    /// Durably apply a replicated payload-schema change. Schema replication is
    /// intentionally narrower than collection creation/update: physical and
    /// index configuration changes require catalog consensus and fail closed.
    pub fn apply_schema_replicated(
        &self,
        collection_name: &str,
        config: CollectionConfig,
        schema_epoch: u64,
    ) -> Result<()> {
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        self.ensure_legacy_replication_available(collection_name)?;
        self.ensure_collection_cold_materialized(collection_name)?;
        let coll = self.get_coll(collection_name)?;
        let mut collection = coll.write();
        if collection.graph_lifecycle.epoch().is_some() {
            return Err(graph_replication_unavailable(collection_name));
        }
        if schema_epoch <= collection.schema_epoch {
            return Ok(());
        }

        if config.name != collection.config.name {
            return Err(GaussError::InvalidRequest(format!(
                "replicated schema for collection '{}' cannot apply to '{}'",
                config.name, collection.config.name
            )));
        }
        validate_config(&config)?;

        let mut current_without_payload = collection.config.clone();
        current_without_payload.payload_schema.clear();
        let mut next_without_payload = config.clone();
        next_without_payload.payload_schema.clear();
        if serde_json::to_value(&current_without_payload)?
            != serde_json::to_value(&next_without_payload)?
        {
            return Err(GaussError::InvalidRequest(
                "experimental WAL replication supports payload-schema changes only".to_string(),
            ));
        }
        for point in collection.iter_live() {
            validate_payload_schema(&config, &point)?;
        }

        let previous_config = collection.config.clone();
        collection.wal.append(&WalEntry::Schema {
            schema_epoch,
            config: config.clone(),
            previous_config: Some(previous_config),
        })?;
        collection.config = config;
        collection.schema_epoch = schema_epoch;
        Ok(())
    }

    pub fn audit_admin_event(&self, operation: &'static str, details: Value) -> Result<()> {
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        self.audit_success(operation, None, details)
    }

    pub fn audit_read_operation(
        &self,
        operation: &str,
        collection: Option<&str>,
        context: audit::AuditContext,
    ) -> Result<audit::AuditOperation> {
        self.audit_writer
            .operation_in_category("access", operation, collection, context)
    }

    pub fn audit_network_operation(
        &self,
        operation: &str,
        collection: Option<&str>,
        principal_id: &str,
        tenant_id: Option<&str>,
        transport: &str,
        request_id: Option<&str>,
    ) -> Result<audit::AuditOperation> {
        self.audit_operation_with_context(
            operation,
            collection,
            audit::AuditContext {
                principal_id: principal_id.to_string(),
                tenant_id: tenant_id.map(str::to_string),
                transport: transport.to_string(),
                request_id: request_id.map(str::to_string),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn audit_access_event(
        &self,
        category: &str,
        operation: &str,
        outcome: &str,
        collection: Option<&str>,
        principal_id: &str,
        tenant_id: Option<&str>,
        transport: &str,
        request_id: Option<&str>,
        error_code: Option<&str>,
    ) -> Result<()> {
        self.audit_writer
            .record(audit::AuditEvent {
                category,
                operation,
                outcome,
                collection,
                context: &audit::AuditContext {
                    principal_id: principal_id.to_string(),
                    tenant_id: tenant_id.map(str::to_string),
                    transport: transport.to_string(),
                    request_id: request_id.map(str::to_string),
                },
                error_code,
                details: Value::Null,
                durable: false,
            })
            .map_err(|error| GaussError::AuditUnavailable(error.to_string()))
    }

    fn audit_success(
        &self,
        operation: &str,
        collection: Option<&str>,
        details: Value,
    ) -> Result<()> {
        self.audit_writer
            .record(audit::AuditEvent {
                category: "mutation",
                operation,
                outcome: "success",
                collection,
                context: &audit::AuditContext::embedded(),
                error_code: None,
                details,
                durable: true,
            })
            .map_err(|error| GaussError::AuditUnavailable(error.to_string()))
    }

    fn audit_operation(
        &self,
        operation: &str,
        collection: Option<&str>,
    ) -> Result<audit::AuditOperation> {
        self.audit_operation_with_context(operation, collection, audit::AuditContext::embedded())
    }

    fn audit_operation_with_context(
        &self,
        operation: &str,
        collection: Option<&str>,
        context: audit::AuditContext,
    ) -> Result<audit::AuditOperation> {
        self.audit_writer
            .operation(operation, collection, context)
            .map_err(|error| GaussError::AuditUnavailable(error.to_string()))
    }

    fn audit_query_operation_with_context(
        &self,
        operation: &str,
        collection: Option<&str>,
        context: audit::AuditContext,
    ) -> Result<audit::AuditOperation> {
        self.audit_writer
            .operation_in_category("query", operation, collection, context)
            .map_err(|error| GaussError::AuditUnavailable(error.to_string()))
    }

    /// Encode a text string as a BM25-weighted sparse vector using the current
    /// corpus statistics of the given collection.  Call this before upserting
    /// a point or before issuing a hybrid search query so the query and indexed
    /// documents use the same vocabulary.
    ///
    /// `text_fields` constrains which payload fields contribute to the IDF
    /// statistics.  Pass an empty slice to use all top-level string fields.
    pub fn bm25_encode(
        &self,
        collection_name: &str,
        text: &str,
        text_fields: &[String],
    ) -> Result<crate::model::SparseVector> {
        let _lifecycle = self.lifecycle_gate.read();
        let coll = self.get_coll(collection_name)?;
        let collection = coll.read();
        let live: Vec<Point> = collection.iter_live().map(Cow::into_owned).collect();
        let live_refs: Vec<&Point> = live.iter().collect();
        let corpus = crate::sparse_index::build_bm25_corpus_from_points(&live_refs, text_fields);
        Ok(crate::sparse_index::encode_bm25(&corpus, text))
    }

    pub fn refresh_metrics(&self) {
        let inner = self.inner.read();
        let collections = inner.collections.len();
        let points = inner
            .collections
            .values()
            .map(|c| c.read().live_points())
            .sum();
        let sparse_postings = inner
            .collections
            .values()
            .flat_map(|c| {
                let coll = c.read();
                coll.sparse_index
                    .dimensions
                    .values()
                    .map(|list| list.postings.len())
                    .collect::<Vec<_>>()
            })
            .sum();
        set_storage_gauges(collections, points, sparse_postings);
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        // The worker keeps only a Weak reference to `inner`, so this is the
        // final externally-owned handle. Flush first, then stop and join the
        // coordinator while the collection files are still alive.
        if Arc::strong_count(&self.inner) == 1 {
            if !self
                .build_lifecycle
                .cancel_and_drain(Duration::from_secs(300))
            {
                tracing::error!(
                    "timed out draining background index builds during Db drop; data-directory lease remains held by unfinished tasks"
                );
            }
            if let Err(error) = flush_wals_inner(&self.inner) {
                tracing::error!(%error, "final WAL flush failed during Db drop");
            }
            self.wal_flusher.shutdown();
        }
    }
}

fn streamer_admission_wait_required(
    sealing: bool,
    active_full: bool,
    memory_pressure: bool,
) -> Result<bool> {
    if sealing && active_full && memory_pressure {
        return Err(GaussError::ResourceExhausted(
            "both mutable streamers are full under cgroup memory pressure; retry after the background segment seal completes".to_string(),
        ));
    }
    Ok(sealing && active_full)
}

fn validate_config(config: &CollectionConfig) -> Result<()> {
    if config.name.is_empty()
        || config.name.len() > 255
        || !config
            .name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err(GaussError::InvalidCollectionName(config.name.clone()));
    }
    if config.vector_dim == 0 || config.vector_dim > MAX_VECTOR_DIM {
        return Err(GaussError::InvalidRequest(format!(
            "vector_dim must be in 1..={MAX_VECTOR_DIM}"
        )));
    }
    for field in config.payload_schema.keys() {
        validate_payload_field(field)?;
    }
    for (name, &dim) in &config.named_vector_dims {
        validate_vector_name(name)?;
        if dim == 0 || dim > MAX_VECTOR_DIM {
            return Err(GaussError::InvalidRequest(format!(
                "named vector '{name}' dimension must be in 1..={MAX_VECTOR_DIM}"
            )));
        }
    }
    if let Some(sla) = config.recall_sla
        && (!(0.5..=1.0).contains(&sla) || sla.is_nan())
    {
        return Err(GaussError::InvalidRequest(format!(
            "recall_sla {sla} out of range; must be in 0.5..=1.0"
        )));
    }
    if config
        .index_kind
        .as_deref()
        .is_some_and(|kind| !kind.eq_ignore_ascii_case("lsvec"))
    {
        return Err(GaussError::InvalidRequest(format!(
            "index_kind '{}' is unsupported; LS-VEC is the sole index (omit index_kind or use 'lsvec')",
            config.index_kind.as_deref().unwrap_or_default()
        )));
    }
    Ok(())
}

fn validate_snapshot_marker(
    marker: Option<&SnapshotMarker>,
    collections: &HashMap<String, Arc<RwLock<Collection>>>,
) -> Result<()> {
    let Some(marker) = marker else {
        return Ok(());
    };
    if marker.collections.len() != collections.len() {
        return Err(GaussError::InvalidRequest(
            "snapshot marker collection count does not match snapshot catalog".to_string(),
        ));
    }
    let mut seen = HashSet::new();
    for marked in &marker.collections {
        if !seen.insert(&marked.collection) {
            return Err(GaussError::InvalidRequest(
                "snapshot marker repeats a collection".into(),
            ));
        }
        let arc_coll = collections.get(&marked.collection).ok_or_else(|| {
            GaussError::InvalidRequest(format!(
                "snapshot marker references missing collection '{}'",
                marked.collection
            ))
        })?;
        let collection = arc_coll.read();
        if marker.version == 2 && marked.graph != collection.snapshot_graph()? {
            return Err(GaussError::InvalidRequest(format!(
                "snapshot marker graph binding mismatch for collection '{}'",
                marked.collection
            )));
        }
        if marked.schema_epoch != collection.schema_epoch {
            return Err(GaussError::InvalidRequest(format!(
                "snapshot marker schema epoch mismatch for collection '{}'",
                marked.collection
            )));
        }
        if marked.points != collection.live_points() {
            return Err(GaussError::InvalidRequest(format!(
                "snapshot marker point count mismatch for collection '{}'",
                marked.collection
            )));
        }
        if marked.segment_id != collection.last_segment_id {
            return Err(GaussError::InvalidRequest(format!(
                "snapshot marker segment mismatch for collection '{}'",
                marked.collection
            )));
        }
        if marked.config_crc
            != SnapshotCollection::new(
                &collection.config,
                collection.schema_epoch,
                marked.wal_lsn,
                marked.points,
                marked.segment_id.clone(),
            )?
            .config_crc
        {
            return Err(GaussError::InvalidRequest(format!(
                "snapshot marker config checksum mismatch for collection '{}'",
                marked.collection
            )));
        }
        if marked.wal_lsn != collection.wal.len()? {
            return Err(GaussError::InvalidRequest(format!(
                "snapshot marker WAL LSN mismatch for collection '{}'",
                marked.collection
            )));
        }
    }
    Ok(())
}

fn validate_restore_wal_targets(
    marker: Option<&SnapshotMarker>,
    target_wal_lsns: &HashMap<String, u64>,
    target_wal_unix_ms: &HashMap<String, u64>,
    allow_archive_extension: bool,
) -> Result<()> {
    if target_wal_lsns.is_empty() && target_wal_unix_ms.is_empty() {
        return Ok(());
    }
    let Some(marker) = marker else {
        return Err(GaussError::InvalidRequest(
            "target WAL restore requires a snapshot marker".to_string(),
        ));
    };
    for collection in target_wal_lsns.keys() {
        if target_wal_unix_ms.contains_key(collection) {
            return Err(GaussError::InvalidRequest(format!(
                "collection '{collection}' cannot use both target WAL LSN and target WAL Unix ms"
            )));
        }
    }
    for (collection, target_lsn) in target_wal_lsns {
        let marked = marker
            .collections
            .iter()
            .find(|marked| marked.collection == *collection)
            .ok_or_else(|| {
                GaussError::InvalidRequest(format!(
                    "target WAL LSN references missing collection '{collection}'"
                ))
            })?;
        if !allow_archive_extension && *target_lsn > marked.wal_lsn {
            return Err(GaussError::InvalidRequest(format!(
                "target WAL LSN {target_lsn} exceeds snapshot WAL LSN {} for collection '{}'",
                marked.wal_lsn, collection
            )));
        }
    }
    for collection in target_wal_unix_ms.keys() {
        if !marker
            .collections
            .iter()
            .any(|marked| marked.collection == *collection)
        {
            return Err(GaussError::InvalidRequest(format!(
                "target WAL Unix ms references missing collection '{collection}'"
            )));
        }
    }
    Ok(())
}

fn apply_restore_wal_targets(
    root: &Path,
    target_wal_lsns: &HashMap<String, u64>,
    target_wal_unix_ms: &HashMap<String, u64>,
    latest_schema_states: &HashMap<String, SchemaRestoreState>,
) -> Result<AppliedRestoreWalTargets> {
    let mut applied = AppliedRestoreWalTargets::default();
    for (collection, target_lsn) in target_wal_lsns {
        let directory = collection_dir(root, collection);
        let source = latest_schema_states
            .get(collection)
            .ok_or_else(|| GaussError::CollectionNotFound(collection.clone()))?;
        let graph_base = graph_pitr::prepare(
            &directory,
            *target_lsn,
            false,
            source.graph_history,
            source.snapshot_lsn,
        )?;
        let wal_dir = directory.join("wal");
        let mut schema_records = Vec::new();
        Wal::scan_from(&wal_dir, *target_lsn, |record| {
            if matches!(&record.entry, WalEntry::Schema { .. }) {
                schema_records.push(record);
            }
            Ok(())
        })?;
        Wal::truncate_to_lsn(&wal_dir, *target_lsn)?;
        graph_pitr::apply_staged(&directory, graph_base)?;
        if let Some(base) = graph_base {
            applied.graph_bases.insert(collection.clone(), base);
        }
        applied.lsns.insert(collection.clone(), *target_lsn);
        if let Some(schema_state) = schema_state_before_wal_target(
            collection,
            *target_lsn,
            &schema_records,
            latest_schema_states,
        )? {
            applied
                .schema_rewinds
                .insert(collection.clone(), schema_state);
        }
    }
    for (collection, target_unix_ms) in target_wal_unix_ms {
        let directory = collection_dir(root, collection);
        let wal_dir = directory.join("wal");
        let target_lsn = Wal::lsn_for_unix_ms(&wal_dir, *target_unix_ms)?;
        let source = latest_schema_states
            .get(collection)
            .ok_or_else(|| GaussError::CollectionNotFound(collection.clone()))?;
        let graph_base = graph_pitr::prepare(
            &directory,
            target_lsn,
            true,
            source.graph_history,
            source.snapshot_lsn,
        )?;
        let mut schema_records = Vec::new();
        Wal::scan_from(&wal_dir, 0, |record| {
            if matches!(&record.entry, WalEntry::Schema { .. }) {
                schema_records.push(record);
            }
            Ok(())
        })?;
        Wal::truncate_to_lsn(&wal_dir, target_lsn)?;
        graph_pitr::apply_staged(&directory, graph_base)?;
        if let Some(base) = graph_base {
            applied.graph_bases.insert(collection.clone(), base);
        }
        applied.lsns.insert(collection.clone(), target_lsn);
        if let Some(schema_state) = schema_state_before_wal_target(
            collection,
            target_lsn,
            &schema_records,
            latest_schema_states,
        )? {
            applied
                .schema_rewinds
                .insert(collection.clone(), schema_state);
        }
    }
    Ok(applied)
}

fn rehydrate_restore_wal_origins(
    root: &Path,
    target_wal_lsns: &HashMap<String, u64>,
    target_wal_unix_ms: &HashMap<String, u64>,
) -> Result<usize> {
    let mut rehydrated = 0_usize;
    let mut collections = target_wal_lsns
        .keys()
        .chain(target_wal_unix_ms.keys())
        .cloned()
        .collect::<Vec<_>>();
    collections.sort();
    collections.dedup();
    for collection in collections {
        let wal_dir = collection_dir(root, &collection).join("wal");
        let retained = Wal::retained_base_lsn(&wal_dir)?;
        if retained == 0 {
            continue;
        }
        let needs_origin = target_wal_lsns
            .get(&collection)
            .is_some_and(|target| *target < retained)
            || target_wal_unix_ms
                .get(&collection)
                .map(|target| Wal::lsn_for_unix_ms(&wal_dir, *target))
                .transpose()?
                .is_some_and(|target| target == retained);
        if needs_origin && rehydrate_wal_origin_from_archives(&wal_dir)? {
            rehydrated += 1;
        }
    }
    Ok(rehydrated)
}

fn load_restore_collections(
    root: &Path,
    restored_configs: &[CollectionConfig],
    applied_target_wal: &AppliedRestoreWalTargets,
    cold_object_store: Option<&ColdObjectStoreConfig>,
) -> Result<HashMap<String, Arc<RwLock<Collection>>>> {
    let mut collections = HashMap::with_capacity(restored_configs.len());
    for restored_config in restored_configs {
        let collection_name = restored_config.name.clone();
        let config = applied_target_wal
            .schema_rewinds
            .get(&collection_name)
            .map_or_else(|| restored_config.clone(), |state| state.config.clone());
        let collection_dir = collection_dir(root, &collection_name);
        let checkpoint = read_checkpoint(&collection_dir)?;
        let mut schema_epoch = checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.schema_epoch)
            .unwrap_or(1);
        let wal_watermark = checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.wal_watermark)
            .unwrap_or(0);
        if let Some(schema_state) = applied_target_wal.schema_rewinds.get(&collection_name) {
            schema_epoch = schema_state.schema_epoch;
        }
        let state = load_collection_state(
            &collection_dir,
            config,
            schema_epoch,
            wal_watermark,
            cold_object_store,
            if matches!(
                applied_target_wal.graph_bases.get(&collection_name),
                Some(graph_pitr::GraphPitrBase::Checkpoint | graph_pitr::GraphPitrBase::Snapshot)
            ) {
                crate::overlay::OverlayOpenMode::Recover
            } else if applied_target_wal.lsns.contains_key(&collection_name) {
                crate::overlay::OverlayOpenMode::ResetToSegmentBase
            } else {
                crate::overlay::OverlayOpenMode::Recover
            },
        )?;
        let LoadedCollectionState {
            config,
            schema_epoch,
            streamer,
            searchers,
            id_index,
            graph_lifecycle,
            graph_resolver,
            graph_mutable,
            graph_generation,
            wal_watermark,
            payload_index,
            sparse_index,
            overlays,
        } = state;
        let wal = Wal::open(&collection_dir.join("wal"))?;
        let graph_calibration =
            crate::graph_estimator::GraphCalibrationStore::open(&collection_dir)?.map(Arc::new);
        collections.insert(
            collection_name,
            Arc::new(RwLock::new(Collection {
                config,
                streamer,
                sealing: None,
                searchers,
                id_index,
                graph_lifecycle,
                graph_resolver,
                graph_mutable,
                graph_generation,
                graph_calibration,
                sparse_index,
                payload_index,
                overlays,
                rabitq: None,
                vamana: None,
                ivf: None,
                wal,
                wal_watermark,
                schema_epoch,
                last_segment_id: checkpoint
                    .as_ref()
                    .and_then(|checkpoint| checkpoint.segment_id.clone()),
                recall_curve: None,
                hnsw_dirty: true,
                index_build_in_flight: false,
                generation_build_in_flight: false,
                graph_backfill_in_flight: false,
            })),
        );
    }
    Ok(collections)
}

fn write_restore_metadata(
    root: &Path,
    collections: &HashMap<String, Arc<RwLock<Collection>>>,
    catalog_wal: &Wal,
    rewrite_restore_metadata: bool,
) -> Result<()> {
    if rewrite_restore_metadata {
        let mut marker_collections = Vec::with_capacity(collections.len());
        for collection in collections.values() {
            let collection = collection.read();
            marker_collections.push(collection.snapshot_collection()?);
        }
        marker_collections.sort_by(|left, right| left.collection.cmp(&right.collection));
        write_snapshot_marker(root, &SnapshotMarker::new(marker_collections))?;
    }
    write_catalog_state(root, collections, catalog_wal)?;
    if rewrite_restore_metadata {
        for collection in collections.values() {
            let collection = collection.read();
            let checkpoint = collection.checkpoint(
                collection.wal.len()?,
                collection.live_points(),
                collection.last_segment_id.clone(),
            )?;
            write_checkpoint(&collection_dir(root, &collection.config.name), &checkpoint)?;
        }
    }
    Ok(())
}

fn schema_state_before_wal_target(
    collection: &str,
    target_lsn: u64,
    records: &[WalRecord],
    latest_schema_states: &HashMap<String, SchemaRestoreState>,
) -> Result<Option<SchemaRestoreState>> {
    let mut schema_state = latest_schema_states
        .get(collection)
        .cloned()
        .ok_or_else(|| GaussError::CollectionNotFound(collection.to_string()))?;
    let mut rewound = false;
    for record in records
        .iter()
        .rev()
        .filter(|record| record.lsn >= target_lsn)
    {
        if let WalEntry::Schema {
            schema_epoch,
            previous_config,
            ..
        } = &record.entry
        {
            let previous_config = previous_config.clone().ok_or_else(|| {
                GaussError::InvalidRequest(format!(
                    "target WAL restore before schema record at LSN {} for collection '{}' requires WAL records written with previous schema metadata",
                    record.lsn, collection
                ))
            })?;
            if previous_config.name != collection {
                return Err(GaussError::InvalidRequest(format!(
                    "schema WAL previous config for collection '{}' cannot apply to collection '{}'",
                    previous_config.name, collection
                )));
            }
            validate_config(&previous_config)?;
            schema_state.config = previous_config;
            schema_state.schema_epoch = schema_epoch.saturating_sub(1).max(1);
            rewound = true;
        }
    }
    Ok(rewound.then_some(schema_state))
}

/// PC-3: from a learned `(ef_search, recall)` curve sorted ascending by
/// ef_search, pick the smallest ef_search whose measured recall meets
/// `target`. Returns `None` if no point on the curve meets the target —
/// caller falls back to the static step calibrator.
fn ef_search_from_curve(curve: &[(usize, f32)], target: f32) -> Option<usize> {
    curve
        .iter()
        .find(|(_, recall)| *recall >= target)
        .map(|(ef, _)| *ef)
}

/// P3 — pure helper: given a fresh `(ef_search, recall)` curve, the contracted
/// `recall_sla`, and the `active_ef` the engine would pick today, decide
/// whether a drift has occurred. Returns `Some` when the SLA is no longer
/// reachable at `active_ef`, including which ef the curve says we now need.
///
/// Definitions:
/// - `observed_recall_at_active_ef` is the curve's recall at the highest
///   curve-ef that is `<= active_ef`. If `active_ef` is below the curve's
///   smallest ef, we use the smallest ef's recall.
/// - `ef_search_needed` is the smallest ef in the curve whose recall meets
///   `recall_sla`, or `None` if no ef on the curve meets the SLA (catastrophic
///   drift — the report still fires).
pub fn evaluate_recall_drift(
    curve: &[(usize, f32)],
    recall_sla: f32,
    active_ef: usize,
) -> Option<RecallDriftReport> {
    if curve.is_empty() || !(0.5..=1.0).contains(&recall_sla) || recall_sla.is_nan() {
        return None;
    }
    let observed_recall_at_active_ef = curve
        .iter()
        .rev()
        .find(|(ef, _)| *ef <= active_ef)
        .or_else(|| curve.first())
        .map(|(_, r)| *r)
        .unwrap_or(0.0);
    if observed_recall_at_active_ef >= recall_sla {
        return None;
    }
    let ef_search_needed = ef_search_from_curve(curve, recall_sla);
    Some(RecallDriftReport {
        sla: recall_sla,
        active_ef,
        observed_recall_at_active_ef,
        ef_search_needed,
    })
}

/// P3 — payload for a `recall_sla_breach` audit event. Emitted by
/// [`Db::check_recall_drift`] when a collection with a contracted
/// `recall_sla` no longer hits its SLA at the active `ef_search`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RecallDriftReport {
    pub sla: f32,
    pub active_ef: usize,
    pub observed_recall_at_active_ef: f32,
    pub ef_search_needed: Option<usize>,
}

#[cfg(test)]
mod evaluate_recall_drift_tests {
    use super::{RecallDriftReport, evaluate_recall_drift};

    #[test]
    fn no_drift_when_active_ef_meets_sla() {
        let curve = vec![(50, 0.90), (100, 0.95), (200, 0.99)];
        assert_eq!(evaluate_recall_drift(&curve, 0.95, 100), None);
        assert_eq!(evaluate_recall_drift(&curve, 0.95, 200), None);
    }

    #[test]
    fn drift_when_active_ef_below_sla_step() {
        let curve = vec![(50, 0.80), (100, 0.92), (200, 0.96)];
        let report = evaluate_recall_drift(&curve, 0.95, 100).expect("should breach");
        assert_eq!(
            report,
            RecallDriftReport {
                sla: 0.95,
                active_ef: 100,
                observed_recall_at_active_ef: 0.92,
                ef_search_needed: Some(200),
            }
        );
    }

    #[test]
    fn drift_when_curve_below_sla_everywhere() {
        let curve = vec![(50, 0.70), (100, 0.80), (200, 0.85)];
        let report = evaluate_recall_drift(&curve, 0.95, 200).expect("should breach");
        assert_eq!(report.observed_recall_at_active_ef, 0.85);
        assert_eq!(report.ef_search_needed, None);
    }

    #[test]
    fn empty_curve_returns_none() {
        assert_eq!(evaluate_recall_drift(&[], 0.95, 100), None);
    }

    #[test]
    fn sla_out_of_range_returns_none() {
        let curve = vec![(50, 0.90), (100, 0.95)];
        assert_eq!(evaluate_recall_drift(&curve, 0.4, 100), None);
        assert_eq!(evaluate_recall_drift(&curve, 1.5, 100), None);
        assert_eq!(evaluate_recall_drift(&curve, f32::NAN, 100), None);
    }

    #[test]
    fn active_ef_below_curve_minimum_uses_lowest_recall() {
        let curve = vec![(100, 0.92), (200, 0.96)];
        let report = evaluate_recall_drift(&curve, 0.95, 50).expect("should breach");
        assert_eq!(report.observed_recall_at_active_ef, 0.92);
        assert_eq!(report.ef_search_needed, Some(200));
    }
}

#[cfg(test)]
mod ef_search_from_curve_tests {
    use super::ef_search_from_curve;

    #[test]
    fn picks_smallest_ef_that_meets_target() {
        let curve = vec![(10, 0.80), (20, 0.92), (40, 0.96), (80, 0.99), (160, 1.00)];
        assert_eq!(ef_search_from_curve(&curve, 0.95), Some(40));
        assert_eq!(ef_search_from_curve(&curve, 0.92), Some(20));
        assert_eq!(ef_search_from_curve(&curve, 0.99), Some(80));
    }

    #[test]
    fn returns_none_when_curve_too_weak() {
        let curve = vec![(10, 0.50), (20, 0.60), (40, 0.70)];
        assert_eq!(ef_search_from_curve(&curve, 0.95), None);
    }

    #[test]
    fn empty_curve_returns_none() {
        assert_eq!(ef_search_from_curve(&[], 0.95), None);
    }
}

/// Which backend `spawn_index_build` should construct. Mirrors the
/// mutually-exclusive `h2qg` / `rabitq` / `vamana` dispatch in `upsert_wait`.
fn freeze_streamer_for_seal(
    collection: &mut Collection,
    end_lsn: u64,
) -> Arc<crate::streamer::Streamer> {
    let frozen = Arc::new(std::mem::replace(
        &mut collection.streamer,
        crate::streamer::Streamer::with_base_lsn(end_lsn),
    ));
    for id in frozen.points.keys() {
        if collection.id_index.get(id) == Some(&crate::searcher::SegLoc::Streamer) {
            collection
                .id_index
                .insert(id.clone(), crate::searcher::SegLoc::Sealing);
        }
    }
    collection.sealing = Some(Arc::clone(&frozen));
    frozen
}

struct SealInput {
    frozen: Arc<crate::streamer::Streamer>,
    ids: Vec<String>,
}

impl crate::seal::VectorInput for SealInput {
    fn len(&self) -> usize {
        self.ids.len()
    }

    fn point(&self, ordinal: usize) -> Result<Cow<'_, Point>> {
        let id = self.ids.get(ordinal).ok_or_else(|| {
            GaussError::InvalidRequest(format!("seal input ordinal {ordinal} is out of bounds"))
        })?;
        self.frozen
            .points
            .get(id)
            .map(Cow::Borrowed)
            .ok_or_else(|| GaussError::PointNotFound(id.clone()))
    }
}

struct PendingSeal {
    coll: Arc<RwLock<Collection>>,
    data_dir_lock: Arc<DataDirLock>,
    lifecycle: Arc<build_lifecycle::BuildLifecycle>,
    collection_dir: PathBuf,
    frozen: Arc<crate::streamer::Streamer>,
    end_lsn: u64,
    graph: Option<crate::mutable_graph::seal::GraphSealSnapshot>,
    wal_archive_cut: Option<FrozenWalArchive>,
    wal_archive_policy: SealWalArchivePolicy,
    vector_dim: usize,
    metric: crate::DistanceMetric,
    hnsw_m: Option<u32>,
    hnsw_ef_construction: Option<u32>,
    index_kind: crate::seal::SealIndexKind,
    cascade: Arc<std::sync::atomic::AtomicBool>,
    intra_query_parallel: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Clone, Debug)]
struct SealWalArchivePolicy {
    collection_name: String,
    external_dir: Option<PathBuf>,
    object_store: Option<ColdObjectStoreConfig>,
    command: Option<String>,
    retain_last: Option<usize>,
    max_bytes: Option<u64>,
    max_age: Option<Duration>,
}

fn seal_wal_archive_policy(inner: &DbInner, collection_name: &str) -> SealWalArchivePolicy {
    SealWalArchivePolicy {
        collection_name: collection_name.to_string(),
        external_dir: inner.wal_external_archive_dir.clone(),
        object_store: inner.wal_object_store.clone(),
        command: inner.wal_archive_command.clone(),
        retain_last: inner.wal_archive_retain_last,
        max_bytes: inner.wal_archive_max_bytes,
        max_age: inner.wal_archive_max_age,
    }
}

fn archive_graph_seal_wal(seal: &PendingSeal) -> Result<()> {
    let Some(cut) = &seal.wal_archive_cut else {
        return Ok(());
    };
    let archive = cut
        .publish(&seal.collection_dir.join("wal/archive"))
        .map_err(|error| graph_seal_archive_error("local_publish", error))?;
    metrics::counter!(
        "chirondb_graph_seal_wal_archive_stage_total",
        "stage" => "local_publish"
    )
    .increment(1);
    if let Some(external_dir) = &seal.wal_archive_policy.external_dir {
        mirror_wal_archive(
            external_dir,
            &seal.wal_archive_policy.collection_name,
            &archive,
        )
        .map_err(|error| graph_seal_archive_error("external_mirror", error))?;
        metrics::counter!(
            "chirondb_graph_seal_wal_archive_stage_total",
            "stage" => "external_mirror"
        )
        .increment(1);
    }
    if let Some(object_store) = &seal.wal_archive_policy.object_store {
        mirror_wal_archive_to_object_store(
            object_store,
            &seal.wal_archive_policy.collection_name,
            &archive,
        )
        .map_err(|error| graph_seal_archive_error("object_mirror", error))?;
        metrics::counter!(
            "chirondb_graph_seal_wal_archive_stage_total",
            "stage" => "object_mirror"
        )
        .increment(1);
    }
    if let Some(command) = &seal.wal_archive_policy.command {
        run_wal_archive_command(command, &seal.wal_archive_policy.collection_name, &archive)
            .map_err(|error| graph_seal_archive_error("command", error))?;
        metrics::counter!(
            "chirondb_graph_seal_wal_archive_stage_total",
            "stage" => "command"
        )
        .increment(1);
    }
    metrics::counter!("chirondb_graph_seal_wal_archives_total").increment(1);
    metrics::counter!("chirondb_graph_seal_wal_archived_segments_total")
        .increment(archive.segments as u64);
    metrics::counter!("chirondb_graph_seal_wal_archived_bytes_total").increment(archive.bytes);
    tracing::info!(
        collection = %seal.wal_archive_policy.collection_name,
        end_lsn = seal.end_lsn,
        segments = archive.segments,
        bytes = archive.bytes,
        "published graph seal WAL archive before prefix retirement"
    );
    Ok(())
}

fn graph_seal_archive_error(stage: &'static str, error: GaussError) -> GaussError {
    metrics::counter!(
        "chirondb_graph_seal_wal_archive_failures_total",
        "stage" => stage
    )
    .increment(1);
    tracing::error!(%error, stage, "graph seal WAL archive stage failed before publication");
    error
}

fn apply_graph_seal_archive_retention(seal: &PendingSeal) {
    if let Err(error) = apply_wal_archive_retention(
        &seal.collection_dir.join("wal/archive"),
        seal.wal_archive_policy.retain_last,
        seal.wal_archive_policy.max_bytes,
        seal.wal_archive_policy.max_age,
    ) {
        metrics::counter!("chirondb_graph_seal_wal_archive_retention_failures_total").increment(1);
        tracing::error!(
            %error,
            collection = %seal.wal_archive_policy.collection_name,
            end_lsn = seal.end_lsn,
            "published graph seal could not apply local WAL archive retention"
        );
    }
}

fn capture_graph_seal(
    collection: &mut Collection,
    directory: &Path,
    cut: u64,
) -> Result<Option<crate::mutable_graph::seal::GraphSealSnapshot>> {
    if collection.graph_lifecycle.epoch().is_none() {
        return Ok(None);
    }
    crate::mutable_graph::seal::GraphSealSnapshot::capture(
        directory,
        &collection.config.name,
        cut,
        collection.graph_lifecycle,
        collection
            .graph_resolver
            .as_ref()
            .expect("graph history preserves resolver"),
        collection.graph_mutable.as_ref(),
        collection.searchers.iter().map(|s| s.id.clone()).collect(),
        &mut collection.overlays,
    )
    .map(Some)
}

fn spawn_segment_seal(seal: PendingSeal) {
    let Some(task_guard) = seal.lifecycle.register() else {
        restore_failed_seal(seal.coll, seal.frozen);
        return;
    };
    build_admission::BUILD_POOL.spawn(move || {
        let _task_guard = task_guard;
        let estimated =
            build_admission::estimated_build_bytes(seal.frozen.points.len(), seal.vector_dim, 3);
        let _permit = match build_admission::acquire_cancellable(
            estimated,
            seal.lifecycle.cancellation(),
        ) {
            Ok(permit) => permit,
            Err(error) => {
                tracing::debug!(%error, "background LS-Vec seal cancelled before admission");
                restore_failed_seal(seal.coll, seal.frozen);
                return;
            }
        };
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_segment_seal(&seal))) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::error!(%error, "background LS-Vec segment seal failed");
                if seal_generation_is_published(&seal) {
                    tracing::error!(
                        end_lsn = seal.end_lsn,
                        "failed seal generation is already manifest-authoritative; refusing rollback"
                    );
                } else {
                    cleanup_unpublished_seal(&seal);
                    restore_failed_seal(seal.coll, seal.frozen);
                }
            }
            Err(_) => {
                tracing::error!("background LS-Vec segment seal panicked");
                if seal_generation_is_published(&seal) {
                    tracing::error!(
                        end_lsn = seal.end_lsn,
                        "panicked seal generation is already manifest-authoritative; refusing rollback"
                    );
                } else {
                    cleanup_unpublished_seal(&seal);
                    restore_failed_seal(seal.coll, seal.frozen);
                }
            }
        }
    });
}

fn run_segment_seal(seal: &PendingSeal) -> Result<()> {
    let mut ids = seal.frozen.points.keys().cloned().collect::<Vec<_>>();
    ids.sort();
    let input = SealInput {
        frozen: Arc::clone(&seal.frozen),
        ids,
    };
    let searchers_dir = seal.collection_dir.join("searchers");
    fs::create_dir_all(&searchers_dir)?;
    let segment_id = format!("sg-v6-{:020}", seal.end_lsn);
    let final_dir = searchers_dir.join(&segment_id);
    let workspace = crate::build_progress::workspace(&searchers_dir, &segment_id);
    let candidate_dir = crate::build_progress::BuildProgress::candidate_dir(&workspace);
    if seal_generation_is_published(seal) {
        return Err(GaussError::InvalidRequest(format!(
            "refusing to replace installed segment generation {segment_id}"
        )));
    }
    // Graph generations may retire the live prefix only after the exact cut
    // has durable local archive authority and every configured mirror agrees.
    // `wal_archive_cut` references rotated immutable segments, so this I/O is
    // deliberately outside the collection lock while successor WAL appends run.
    archive_graph_seal_wal(seal)?;
    remove_seal_candidate(&final_dir)?;
    crate::seal::build_segment_resumable_controlled(
        &input,
        &workspace,
        &segment_id,
        crate::seal::SealConfig {
            vector_dim: seal.vector_dim,
            metric: seal.metric,
            hnsw_m: seal.hnsw_m,
            hnsw_ef_construction: seal.hnsw_ef_construction,
            index_kind: seal.index_kind,
            base_lsn: seal.frozen.base_lsn,
            end_lsn: seal.end_lsn,
        },
        Some(seal.lifecycle.cancellation()),
    )?;
    if seal.lifecycle.is_cancelled() {
        return Err(GaussError::ResourceExhausted(
            "background seal cancelled before publication".to_string(),
        ));
    }
    let graph_base = seal
        .graph
        .as_ref()
        .map(|graph| graph.write_base(&candidate_dir))
        .transpose()?
        .unwrap_or(false);
    durable_rename(&candidate_dir, &final_dir)?;
    if seal.lifecycle.is_cancelled() {
        return Err(GaussError::ResourceExhausted(
            "background seal cancelled before manifest publication".to_string(),
        ));
    }

    let prepared_graph = seal
        .graph
        .as_ref()
        .map(|graph| {
            let manifest = graph.write_manifest(&seal.collection_dir, graph_base)?;
            let mut prepared = crate::graph_generation::GraphGeneration::prepare_publication(
                &seal.collection_dir,
                manifest,
            )?;
            // Validation reconstructs a cut; the live graph already owns the newer
            // tail. Do not install or permanently retain a duplicate mutable graph.
            prepared.recovered.take();
            Ok::<_, GaussError>(prepared)
        })
        .transpose()?;
    let store = Arc::new(if graph_base {
        crate::seal::V4Store::open_graph_base(&final_dir)?
    } else {
        crate::seal::V4Store::open(&final_dir)?
    });
    let index = match seal.index_kind {
        crate::seal::SealIndexKind::Hnsw => {
            let mut h2qg = crate::h2qg::read_index_paged(&final_dir)?;
            h2qg.set_cascade(seal.cascade.clone());
            h2qg.set_intra_query_parallel(seal.intra_query_parallel.clone());
            crate::searcher::SegmentIndex::LegacyH2qg(Box::new(h2qg))
        }
        crate::seal::SealIndexKind::Algorithm2 => crate::searcher::SegmentIndex::Ivf(Box::new(
            crate::index::ivf_segment::IvfSegmentIndex::open(
                &final_dir,
                Arc::clone(&store),
                seal.metric,
            )?,
        )),
    };
    let named_index = match seal.index_kind {
        crate::seal::SealIndexKind::Algorithm2 => {
            crate::searcher::load_named_algorithm2_indexes(&final_dir, seal.metric)?
        }
        crate::seal::SealIndexKind::Hnsw => HashMap::new(),
    };

    let mut collection = seal.coll.write();
    if !collection
        .sealing
        .as_ref()
        .is_some_and(|frozen| Arc::ptr_eq(frozen, &seal.frozen))
    {
        return Err(GaussError::InvalidRequest(
            "completed seal no longer owns the frozen streamer".to_string(),
        ));
    }
    // Graph enable may occur after a vector-only freeze. That build has no
    // graph cut and must retain the earlier WAL prefix for ordered replay.
    let retain_graph_wal = seal.graph.is_none() && collection.graph_lifecycle.epoch().is_some();
    let searcher_index = collection.searchers.len() as u32;
    let tombstones = seal
        .frozen
        .points
        .keys()
        .filter(|id| collection.id_index.get(*id) != Some(&crate::searcher::SegLoc::Sealing))
        .cloned()
        .collect();
    for searcher in &collection.searchers {
        persist_searcher_tombstones(searcher)?;
    }
    crate::seal::write_tombstones(&final_dir, &store, &tombstones)?;
    let tombstone_ordinals: roaring::RoaringBitmap = tombstones
        .iter()
        .filter_map(|id| store.ordinal(id))
        .filter_map(|ordinal| u32::try_from(ordinal).ok())
        .collect();
    let new_searcher = crate::searcher::SegmentSearcher::new(
        segment_id.clone(),
        final_dir,
        index,
        named_index,
        crate::searcher::SegmentStore::V4(store),
        tombstones,
        tombstone_ordinals.clone(),
    );
    let previous_overlay = collection.overlays.current();
    let generation = if let Some(graph) = &seal.graph {
        graph.generation
    } else {
        next_searcher_manifest_generation(&seal.collection_dir)?
    };
    let mut point_tombstones = previous_overlay.point_tombstones().clone();
    point_tombstones.insert_bitmap(segment_id.clone(), tombstone_ordinals);
    if prepared_graph.is_none() {
        if let Err(error) = collection
            .overlays
            .advance_generation(generation, point_tombstones)
            .and_then(|()| collection.overlays.publish_pending())
        {
            collection.overlays.restore_snapshot(&previous_overlay)?;
            return Err(error);
        }
        let mut installed_segments = collection
            .searchers
            .iter()
            .map(|searcher| searcher.id.clone())
            .collect::<Vec<_>>();
        installed_segments.push(segment_id.clone());
        let manifest = SegmentsManifest {
            generation,
            segments: installed_segments,
            graph: None,
        };
        if let Err(error) = write_segments_manifest(&seal.collection_dir, &manifest) {
            let committed = read_segments_manifest(&seal.collection_dir)
                .ok()
                .flatten()
                .as_ref()
                == Some(&manifest);
            if !committed {
                collection.overlays.restore_snapshot(&previous_overlay)?;
                return Err(error);
            }
            tracing::warn!(
                %error,
                generation,
                "seal manifest was renamed but final directory sync reported an error"
            );
        }
    } else if let Some(prepared_graph) = prepared_graph {
        let graph = seal.graph.as_ref().expect("prepared graph snapshot");
        let tail_overlay = collection
            .overlays
            .prepare_generation(generation, point_tombstones)?;
        let published = crate::graph_generation::GraphGeneration::publish_prepared(
            &seal.collection_dir,
            graph.expected.as_ref(),
            prepared_graph,
        )?;
        let published = Arc::new(published);
        collection.graph_generation = Some(Arc::clone(&published));
        collection.overlays.install_prepared(tail_overlay);
        if let Some(mutable) = &mut collection.graph_mutable
            && mutable.epoch() == graph.epoch
        {
            mutable.acknowledge_seal(graph.epoch, seal.end_lsn);
            mutable.attach_sealed_adjacency(published);
        }
    }
    collection.searchers.push(new_searcher);
    for id in seal.frozen.points.keys() {
        if collection.id_index.get(id) == Some(&crate::searcher::SegLoc::Sealing) {
            collection.id_index.insert(
                id.clone(),
                crate::searcher::SegLoc::Searcher(searcher_index),
            );
        }
    }
    collection.rebuild_payload_fallback();
    collection.last_segment_id = Some(segment_id.clone());
    if !retain_graph_wal {
        collection.wal_watermark = seal.end_lsn;
    }
    // A committed generation must not leave a frozen streamer installed if
    // checkpoint/CURRENT/prefix retirement subsequently reports an I/O error.
    collection.sealing = None;
    collection.overlays.publish_pending()?;
    if seal.graph.is_some() {
        crate::failpoint::check("graph_generation.after_install")?;
    }
    let checkpoint = collection.checkpoint(
        collection.wal.len()?,
        collection.live_points(),
        Some(segment_id.clone()),
    )?;
    write_checkpoint(&seal.collection_dir, &checkpoint)?;
    if !retain_graph_wal {
        collection.wal.drop_prefix(seal.end_lsn)?;
    }
    drop(collection);
    if seal.graph.is_some() {
        // Retention is cleanup, not publication authority. A cleanup failure
        // is observable but cannot roll back the committed generation.
        apply_graph_seal_archive_retention(seal);
    }
    if let Err(error) = crate::build_progress::remove_workspace(&workspace) {
        tracing::warn!(
            %error,
            path = %workspace.display(),
            "published LS-VEC seal retained completed build workspace"
        );
    }

    let mut collection = seal.coll.write();
    // The upsert that triggered this seal deliberately skipped staging a
    // mutable HNSW build: its source streamer was frozen in the same call.
    // Ingest may then fill the replacement streamer past the ANN threshold
    // while the immutable build runs. Once the seal installs, start exactly
    // one build for that current generation so queries and benchmark
    // readiness cannot remain on an ANN-sized flat tail indefinitely.
    let pending_build = if collection.streamer.points.len() >= crate::h2qg::HNSW_THRESHOLD
        && collection.sealing.is_none()
        && collection.streamer.hnsw.is_none()
        && !collection.index_build_in_flight
    {
        collection.index_build_in_flight = true;
        Some(PendingIndexBuild {
            coll: Arc::clone(&seal.coll),
            data_dir_lock: Arc::clone(&seal.data_dir_lock),
            lifecycle: Arc::clone(&seal.lifecycle),
            streamer_base_lsn: collection.streamer.base_lsn,
            vector_dim: collection.config.vector_dim,
            hnsw_m: collection.config.hnsw_m,
            hnsw_ef_construction: collection.config.hnsw_ef_construction,
            metric: collection.config.metric,
            kind: PendingIndexBuildKind::H2qg,
            cascade: Arc::clone(&seal.cascade),
        })
    } else {
        None
    };
    drop(collection);
    if let Some(build) = pending_build {
        spawn_index_build(build);
    }
    Ok(())
}

fn next_searcher_manifest_generation(collection_dir: &Path) -> Result<u64> {
    read_segments_manifest(collection_dir)?
        .map_or(0, |manifest| manifest.generation)
        .checked_add(1)
        .ok_or_else(|| GaussError::InvalidRequest("segment manifest generation overflow".into()))
}

fn seal_segment_id(seal: &PendingSeal) -> String {
    format!("sg-v6-{:020}", seal.end_lsn)
}

fn seal_generation_is_published(seal: &PendingSeal) -> bool {
    let segment_id = seal_segment_id(seal);
    read_segments_manifest(&seal.collection_dir)
        .ok()
        .flatten()
        .is_some_and(|manifest| manifest.segments.contains(&segment_id))
}

fn cleanup_unpublished_seal(seal: &PendingSeal) {
    let segment_id = seal_segment_id(seal);
    let searchers_dir = seal.collection_dir.join("searchers");
    for path in [
        searchers_dir.join(format!(".{segment_id}.tmp-{}", std::process::id())),
        searchers_dir.join(segment_id),
    ] {
        if let Err(error) = remove_seal_candidate(&path) {
            tracing::error!(%error, path = %path.display(), "failed to clean unpublished seal candidate");
        }
    }
}

fn remove_seal_candidate(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_dir() {
        durable_remove_dir_all(path)
    } else {
        Err(GaussError::InvalidRequest(format!(
            "refusing to remove non-directory segment candidate {}",
            path.display()
        )))
    }
}

/// Validate installed generation authority, or publish generation zero for a
/// legacy vector-only collection before creating a compaction candidate.
fn ensure_segments_manifest(collection_dir: &Path, collection: &Collection) -> Result<u64> {
    if let Some(manifest) = read_segments_manifest(collection_dir)? {
        if manifest.graph.is_some()
            && collection
                .graph_generation
                .as_ref()
                .is_none_or(|generation| generation.manifest.as_ref() != &manifest)
        {
            return Err(GaussError::SegmentCorruption {
                path: collection_dir
                    .join(crate::checkpoint::SEGMENTS_MANIFEST_FILE)
                    .display()
                    .to_string(),
                message: "installed graph generation disagrees with manifest authority".into(),
            });
        }
        return Ok(manifest.generation);
    }
    let manifest = SegmentsManifest {
        generation: 0,
        segments: collection
            .searchers
            .iter()
            .map(|searcher| searcher.id.clone())
            .collect(),
        graph: None,
    };
    write_segments_manifest(collection_dir, &manifest)?;
    Ok(manifest.generation)
}

fn remove_unlisted_segment_dirs(collection_dir: &Path, installed: &HashSet<String>) -> Result<()> {
    for parent in [
        collection_dir.join("searchers"),
        collection_dir.join("cold"),
    ] {
        if !parent.exists() {
            continue;
        }
        for entry in fs::read_dir(&parent)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let id = entry.file_name().to_string_lossy().into_owned();
            if parent.ends_with("searchers") && id == crate::build_progress::BUILDS_DIR {
                continue;
            }
            if !installed.contains(&id) {
                durable_remove_dir_all(&entry.path())?;
            }
        }
        crate::seal::sync_directory(&parent)?;
    }
    Ok(())
}

fn remove_unlisted_graph_artifacts(
    collection_dir: &Path,
    manifest: &SegmentsManifest,
) -> Result<()> {
    let Some(graph) = &manifest.graph else {
        return Ok(());
    };
    let retained = [
        (
            "topology",
            graph
                .topology_deltas
                .iter()
                .map(|run| run.id.clone())
                .collect::<HashSet<_>>(),
        ),
        (
            "ledger",
            std::iter::once(&graph.edge_ledger.base)
                .chain(&graph.edge_ledger.runs)
                .map(|run| run.id.clone())
                .collect::<HashSet<_>>(),
        ),
        (
            "properties",
            std::iter::once(&graph.edge_properties.base)
                .chain(&graph.edge_properties.runs)
                .map(|run| run.id.clone())
                .collect::<HashSet<_>>(),
        ),
        (
            "fragments",
            match &graph.fragment_directory {
                crate::checkpoint::FragmentDirectoryManifest::Absent => HashSet::new(),
                crate::checkpoint::FragmentDirectoryManifest::Present { base, overlays } => {
                    std::iter::once(base)
                        .chain(overlays)
                        .map(|run| run.id.clone())
                        .collect()
                }
            },
        ),
        (
            "recovery",
            graph
                .recovery
                .iter()
                .map(|run| run.id.clone())
                .collect::<HashSet<_>>(),
        ),
    ];
    for (family, retained) in retained {
        let parent = collection_dir.join("graph").join(family);
        if !parent.exists() {
            continue;
        }
        for entry in fs::read_dir(&parent)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let id = entry.file_name().to_string_lossy().into_owned();
            if !retained.contains(&id) {
                durable_remove_dir_all(&entry.path())?;
            }
        }
        crate::seal::sync_directory(&parent)?;
    }
    Ok(())
}

fn remove_installed_build_workspaces(
    collection_dir: &Path,
    installed: &HashSet<String>,
) -> Result<()> {
    let builds = collection_dir
        .join("searchers")
        .join(crate::build_progress::BUILDS_DIR);
    match fs::symlink_metadata(&builds) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(GaussError::InvalidRequest(format!(
                "build workspace root is not a directory: {}",
                builds.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    for build in fs::read_dir(&builds)? {
        let build = build?;
        if build.file_type()?.is_dir()
            && installed.contains(&build.file_name().to_string_lossy().into_owned())
        {
            durable_remove_dir_all(&build.path())?;
        }
    }
    if fs::read_dir(&builds)?.next().is_none() {
        durable_remove_dir_all(&builds)?;
    } else {
        crate::seal::sync_directory(&builds)?;
    }
    Ok(())
}

fn persist_searcher_tombstones(searcher: &crate::searcher::SegmentSearcher) -> Result<()> {
    if searcher.tombstones.is_empty() {
        return Ok(());
    }
    match &searcher.store {
        crate::searcher::SegmentStore::Heap(_) => {
            let ids = searcher.tombstones.iter().cloned().collect::<Vec<_>>();
            crate::segment::apply_incremental_tombstone(&searcher.dir, &ids)?;
        }
        crate::searcher::SegmentStore::V4(_) => {}
    }
    Ok(())
}

fn restore_failed_seal(coll: Arc<RwLock<Collection>>, frozen: Arc<crate::streamer::Streamer>) {
    let mut collection = coll.write();
    if !collection
        .sealing
        .as_ref()
        .is_some_and(|active| Arc::ptr_eq(active, &frozen))
    {
        return;
    }
    drop(collection.sealing.take());
    let base_lsn = frozen.base_lsn;
    let points = match Arc::try_unwrap(frozen) {
        Ok(mut frozen) => frozen.take_points(),
        // Existing readers may pin the old snapshot. Copy only still-owned
        // points, not its ANN indexes, and leave those readers' state intact.
        Err(frozen) => frozen
            .points
            .iter()
            .filter(|(id, _)| {
                collection.id_index.get(*id) == Some(&crate::searcher::SegLoc::Sealing)
            })
            .map(|(id, point)| (id.clone(), point.clone()))
            .collect(),
    };
    collection.streamer.hnsw = None;
    collection.streamer.named_hnsw.clear();
    collection.streamer.base_lsn = base_lsn;
    for (id, point) in points {
        if collection.id_index.get(&id) == Some(&crate::searcher::SegLoc::Sealing) {
            collection.streamer.insert(point);
            collection
                .id_index
                .insert(id, crate::searcher::SegLoc::Streamer);
        }
    }
}

#[derive(Clone, Copy)]
enum PendingIndexBuildKind {
    Rabitq,
    Vamana,
    Ivf,
    H2qg,
}

/// Maximum HNSW catch-up tail inserted while holding the collection write
/// lock. Larger tails are cloned under a read lock and indexed off-lock first.
const INDEX_BUILD_LOCK_BACKFILL_MAX: usize = 1024;

/// Captured inputs for an initial index build staged by `upsert_wait` after
/// a collection crosses `HNSW_THRESHOLD`. The point snapshot is materialized
/// only after build admission, so queued collections do not duplicate their
/// vector corpus while waiting for memory capacity.
struct PendingIndexBuild {
    coll: Arc<RwLock<Collection>>,
    /// Keep the process-exclusive data-directory lease alive until queued or
    /// running maintenance has finished touching persisted state.
    data_dir_lock: Arc<DataDirLock>,
    lifecycle: Arc<build_lifecycle::BuildLifecycle>,
    /// Generation token for mutable-tier HNSW builds. A seal replaces the
    /// streamer and advances `base_lsn`; an older build must never install
    /// its graph into that replacement streamer.
    streamer_base_lsn: u64,
    vector_dim: usize,
    hnsw_m: Option<u32>,
    hnsw_ef_construction: Option<u32>,
    metric: crate::DistanceMetric,
    kind: PendingIndexBuildKind,
    cascade: Arc<std::sync::atomic::AtomicBool>,
}

/// Builds the staged index off the collection write lock, then re-acquires
/// it just long enough to backfill points inserted during the build window
/// (same `contains` + `insert_point` shape as the live-graph insert path
/// above) and install the result. Deletes need no special handling here --
/// `Db::delete` never touches the index synchronously either; both rely on
/// the next compaction to drop stale entries.
fn spawn_index_build(build: PendingIndexBuild) {
    let cleanup_coll = Arc::clone(&build.coll);
    let Some(task_guard) = build.lifecycle.register() else {
        cleanup_coll.write().index_build_in_flight = false;
        return;
    };
    build_admission::BUILD_POOL.spawn(move || {
        let _task_guard = task_guard;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            let PendingIndexBuild {
                coll,
                data_dir_lock,
                lifecycle,
                streamer_base_lsn,
                vector_dim,
                hnsw_m,
                hnsw_ef_construction,
                metric,
                kind,
                cascade,
            } = build;
            let _data_dir_lock = data_dir_lock;
            if lifecycle.is_cancelled() {
                return Err(GaussError::ResourceExhausted(
                    "mutable index build cancelled during shutdown".to_string(),
                ));
            }
            let point_count = {
                let collection = coll.read();
                match kind {
                    PendingIndexBuildKind::H2qg => collection.streamer.points.len(),
                    _ => collection.live_points(),
                }
            };
            let weight = match kind {
                PendingIndexBuildKind::Rabitq | PendingIndexBuildKind::Ivf => 2,
                PendingIndexBuildKind::Vamana => 3,
                PendingIndexBuildKind::H2qg => 3,
            };
            let estimated = build_admission::estimated_build_bytes(point_count, vector_dim, weight);
            let _permit =
                build_admission::acquire_cancellable(estimated, lifecycle.cancellation())?;
            let owned_points: Vec<Point> = {
                let collection = coll.read();
                if matches!(kind, PendingIndexBuildKind::H2qg)
                    && collection.streamer.base_lsn != streamer_base_lsn
                {
                    drop(collection);
                    restart_h2qg_build_for_current_streamer(
                        coll,
                        streamer_base_lsn,
                        cascade,
                        Arc::clone(&_data_dir_lock),
                        Arc::clone(&lifecycle),
                    );
                    return Ok(());
                }
                match kind {
                    PendingIndexBuildKind::H2qg => {
                        collection.streamer.points.values().cloned().collect()
                    }
                    _ => collection.iter_live().map(Cow::into_owned).collect(),
                }
            };
            if lifecycle.is_cancelled() {
                return Err(GaussError::ResourceExhausted(
                    "mutable index build cancelled after snapshot".to_string(),
                ));
            }
            match kind {
                PendingIndexBuildKind::Rabitq => {
                    let mut backend =
                        crate::index::rabitq::RabitqBackend::build(&owned_points, vector_dim);
                    if lifecycle.is_cancelled() {
                        return Err(GaussError::ResourceExhausted(
                            "mutable RaBitQ build cancelled during shutdown".to_string(),
                        ));
                    }
                    let mut collection = coll.write();
                    for point in collection.iter_live() {
                        use crate::index::IndexBackend;
                        if !IndexBackend::contains(&backend, &point.id) {
                            IndexBackend::insert_point(&mut backend, &point, vector_dim)?;
                        }
                    }
                    collection.rabitq = Some(backend);
                    collection.index_build_in_flight = false;
                }
                PendingIndexBuildKind::Vamana => {
                    let mut backend =
                        crate::index::vamana::VamanaBackend::build(&owned_points, vector_dim);
                    if lifecycle.is_cancelled() {
                        return Err(GaussError::ResourceExhausted(
                            "mutable Vamana build cancelled during shutdown".to_string(),
                        ));
                    }
                    let mut collection = coll.write();
                    for point in collection.iter_live() {
                        use crate::index::IndexBackend;
                        if !IndexBackend::contains(&backend, &point.id) {
                            IndexBackend::insert_point(&mut backend, &point, vector_dim)?;
                        }
                    }
                    collection.vamana = Some(backend);
                    collection.index_build_in_flight = false;
                }
                PendingIndexBuildKind::Ivf => {
                    let mut backend = crate::index::ivf::IvfBackend::build_with_metric(
                        &owned_points,
                        vector_dim,
                        metric,
                    );
                    if lifecycle.is_cancelled() {
                        return Err(GaussError::ResourceExhausted(
                            "mutable IVF build cancelled during shutdown".to_string(),
                        ));
                    }
                    let mut collection = coll.write();
                    for point in collection.iter_live() {
                        use crate::index::IndexBackend;
                        if !IndexBackend::contains(&backend, &point.id) {
                            IndexBackend::insert_point(&mut backend, &point, vector_dim)?;
                        }
                    }
                    collection.ivf = Some(backend);
                    collection.index_build_in_flight = false;
                }
                PendingIndexBuildKind::H2qg => {
                    let mut index =
                        crate::h2qg::H2qgIndex::build_mutable_hnsw_with_params_cancellable(
                            &owned_points,
                            vector_dim,
                            hnsw_m,
                            hnsw_ef_construction,
                            metric,
                            false,
                            lifecycle.cancellation(),
                        )
                        .ok_or_else(|| {
                            GaussError::ResourceExhausted(
                                "mutable HNSW build cancelled during shutdown".to_string(),
                            )
                        })?;
                    if !streamer_generation_is_current(&coll, streamer_base_lsn) {
                        drop(index);
                        restart_h2qg_build_for_current_streamer(
                            coll,
                            streamer_base_lsn,
                            cascade,
                            Arc::clone(&_data_dir_lock),
                            Arc::clone(&lifecycle),
                        );
                        return Ok(());
                    }
                    // W1 bugfix: a freshly built index's own cascade flag
                    // defaults false independent of DbInner.cascade; wire it
                    // explicitly so the server-wide default reaches this build.
                    index.set_cascade(cascade.clone());

                    // A bulk ingest can add hundreds of thousands of points while
                    // the initial graph builds. Replaying that entire tail under
                    // the collection write lock stalls reads, writes, and segment
                    // installation for minutes. Catch up large snapshots off-lock;
                    // only the final bounded tail is reconciled atomically.
                    loop {
                        let missing = {
                            let collection = coll.read();
                            if collection.streamer.base_lsn != streamer_base_lsn {
                                drop(collection);
                                drop(index);
                                restart_h2qg_build_for_current_streamer(
                                    coll,
                                    streamer_base_lsn,
                                    cascade,
                                    Arc::clone(&_data_dir_lock),
                                    Arc::clone(&lifecycle),
                                );
                                return Ok(());
                            }
                            collection
                                .streamer
                                .points
                                .iter()
                                .filter(|(id, _)| !index.contains(id))
                                .map(|(_, point)| point.clone())
                                .collect::<Vec<_>>()
                        };
                        if missing.len() <= INDEX_BUILD_LOCK_BACKFILL_MAX {
                            break;
                        }
                        for (position, point) in missing.into_iter().enumerate() {
                            if lifecycle.is_cancelled() {
                                return Err(GaussError::ResourceExhausted(
                                    "mutable HNSW catch-up cancelled during shutdown".to_string(),
                                ));
                            }
                            if position % INDEX_BUILD_LOCK_BACKFILL_MAX == 0
                                && !streamer_generation_is_current(&coll, streamer_base_lsn)
                            {
                                drop(index);
                                restart_h2qg_build_for_current_streamer(
                                    coll,
                                    streamer_base_lsn,
                                    cascade,
                                    Arc::clone(&_data_dir_lock),
                                    Arc::clone(&lifecycle),
                                );
                                return Ok(());
                            }
                            index.insert_point(&point, vector_dim)?;
                        }
                    }
                    let mut collection = coll.write();
                    if lifecycle.is_cancelled() {
                        return Err(GaussError::ResourceExhausted(
                            "mutable HNSW install cancelled during shutdown".to_string(),
                        ));
                    }
                    if collection.streamer.base_lsn != streamer_base_lsn {
                        drop(collection);
                        drop(index);
                        restart_h2qg_build_for_current_streamer(
                            coll,
                            streamer_base_lsn,
                            cascade,
                            Arc::clone(&_data_dir_lock),
                            Arc::clone(&lifecycle),
                        );
                        return Ok(());
                    }
                    for (id, point) in collection.streamer.points.iter() {
                        if !index.contains(id) {
                            index.insert_point(point, vector_dim)?;
                        }
                    }
                    collection.streamer.hnsw = Some(index);
                    collection.index_build_in_flight = false;
                }
            }
            Ok(())
        }));
        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                cleanup_coll.write().index_build_in_flight = false;
                tracing::error!(%error, "background mutable index build failed");
            }
            Err(_) => {
                cleanup_coll.write().index_build_in_flight = false;
                tracing::error!("background mutable index build panicked");
            }
        }
    });
}

fn streamer_generation_is_current(coll: &Arc<RwLock<Collection>>, expected_base_lsn: u64) -> bool {
    coll.read().streamer.base_lsn == expected_base_lsn
}

/// Retire a mutable-tier HNSW build whose source streamer was frozen, then
/// stage a replacement for the current streamer when it is ANN-sized.
///
/// Keeping `index_build_in_flight = true` across the hand-off prevents a
/// concurrent upsert from starting a second build for the same generation.
fn restart_h2qg_build_for_current_streamer(
    coll: Arc<RwLock<Collection>>,
    stale_base_lsn: u64,
    cascade: Arc<std::sync::atomic::AtomicBool>,
    data_dir_lock: Arc<DataDirLock>,
    lifecycle: Arc<build_lifecycle::BuildLifecycle>,
) {
    let replacement = {
        let mut collection = coll.write();
        if collection.streamer.base_lsn == stale_base_lsn {
            return;
        }
        if !collection.streamer_hnsw_required() || collection.streamer.hnsw.is_some() {
            collection.index_build_in_flight = false;
            None
        } else {
            Some(PendingIndexBuild {
                coll: Arc::clone(&coll),
                data_dir_lock,
                lifecycle,
                streamer_base_lsn: collection.streamer.base_lsn,
                vector_dim: collection.config.vector_dim,
                hnsw_m: collection.config.hnsw_m,
                hnsw_ef_construction: collection.config.hnsw_ef_construction,
                metric: collection.config.metric,
                kind: PendingIndexBuildKind::H2qg,
                cascade,
            })
        }
    };
    if let Some(replacement) = replacement {
        spawn_index_build(replacement);
    }
}

fn validate_point(config: &CollectionConfig, point: &Point) -> Result<()> {
    if point.vector.len() != config.vector_dim {
        return Err(GaussError::DimensionMismatch {
            expected: config.vector_dim,
            actual: point.vector.len(),
        });
    }
    if point.vector.iter().any(|value| !value.is_finite()) {
        return Err(GaussError::InvalidRequest(
            "dense vector values must be finite".to_string(),
        ));
    }
    for (name, vector) in &point.vectors {
        validate_vector_name(name)?;
        let expected = config
            .named_vector_dims
            .get(name)
            .copied()
            .unwrap_or(config.vector_dim);
        if vector.len() != expected {
            return Err(GaussError::DimensionMismatch {
                expected,
                actual: vector.len(),
            });
        }
        if vector.iter().any(|value| !value.is_finite()) {
            return Err(GaussError::InvalidRequest(format!(
                "named vector '{name}' values must be finite"
            )));
        }
    }
    if point.id.is_empty() || point.id.len() > MAX_POINT_ID_BYTES {
        return Err(GaussError::InvalidRequest(format!(
            "point id must contain 1..={MAX_POINT_ID_BYTES} bytes"
        )));
    }
    if let Some(sparse_vector) = &point.sparse_vector {
        validate_sparse_vector(sparse_vector)?;
    }
    validate_payload_schema(config, point)?;
    let payload_bytes = serde_json::to_vec(&point.payload)?.len();
    if payload_bytes > MAX_POINT_PAYLOAD_BYTES {
        return Err(GaussError::ResourceExhausted(format!(
            "serialized point payload is {payload_bytes} bytes; maximum is {MAX_POINT_PAYLOAD_BYTES}"
        )));
    }
    Ok(())
}

fn validate_k(k: usize, field: &str) -> Result<()> {
    if k > MAX_SEARCH_K {
        return Err(GaussError::ResourceExhausted(format!(
            "{field} is {k}; maximum is {MAX_SEARCH_K}"
        )));
    }
    Ok(())
}

fn validate_filter_complexity(filter: Option<&Filter>) -> Result<()> {
    if let Some(filter) = filter {
        filter
            .validate_complexity()
            .map_err(GaussError::InvalidRequest)?;
    }
    Ok(())
}

fn validate_vector_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err(GaussError::InvalidRequest(
            "vector_name must be non-empty ASCII alphanumeric, '_' or '-'".to_string(),
        ));
    }
    Ok(())
}

fn validate_sparse_vector(sparse_vector: &SparseVector) -> Result<()> {
    if sparse_vector.indices.len() != sparse_vector.values.len() {
        return Err(GaussError::InvalidRequest(
            "sparse vector indices and values must have the same length".to_string(),
        ));
    }
    if sparse_vector.values.iter().any(|value| !value.is_finite()) {
        return Err(GaussError::InvalidRequest(
            "sparse vector values must be finite".to_string(),
        ));
    }
    let mut seen = HashSet::with_capacity(sparse_vector.indices.len());
    for index in &sparse_vector.indices {
        if !seen.insert(*index) {
            return Err(GaussError::InvalidRequest(
                "sparse vector indices must be unique".to_string(),
            ));
        }
    }
    Ok(())
}

/// Apply one WAL record to the multi-segment collection state.
///
/// Mutations route through the ID authority (`id_index`): an id living in a
/// sealed searcher is never mutated in place — it is tombstoned there and
/// (for upsert/set-payload) re-inserted into the streamer, preserving
/// "a point id is live in exactly one segment".
fn apply_wal_upsert(
    streamer: &mut crate::streamer::Streamer,
    sealing: Option<&crate::streamer::Streamer>,
    searchers: &mut [crate::searcher::SegmentSearcher],
    id_index: &mut HashMap<String, crate::searcher::SegLoc>,
    mut sparse_index: Option<&mut SparseIndex>,
    payload_index: &mut PayloadIndex,
    point: Point,
) -> Result<()> {
    use crate::searcher::SegLoc;
    match id_index.get(&point.id) {
        Some(SegLoc::Streamer) => {
            if let Some(existing) = streamer.points.get(&point.id) {
                if let Some(sparse_index) = sparse_index.as_deref_mut() {
                    remove_sparse_point(sparse_index, existing);
                }
                remove_payload_point(payload_index, existing);
            }
        }
        Some(SegLoc::Sealing) => {
            let existing = sealing
                .and_then(|frozen| frozen.points.get(&point.id))
                .ok_or_else(|| {
                    GaussError::InvalidRequest(
                        "WAL replay encountered transient sealing ownership".to_string(),
                    )
                })?;
            if let Some(sparse_index) = sparse_index.as_deref_mut() {
                remove_sparse_point(sparse_index, existing);
            }
            remove_payload_point(payload_index, existing);
        }
        Some(SegLoc::Searcher(i)) => {
            let searcher = &mut searchers[*i as usize];
            if let Some(existing) = searcher.store.get(&point.id) {
                if let Some(sparse_index) = sparse_index.as_deref_mut() {
                    remove_sparse_point(sparse_index, &existing);
                }
                remove_payload_point(payload_index, &existing);
            }
            searcher.tombstone(&point.id);
        }
        None => {}
    }
    if let Some(sparse_index) = sparse_index {
        insert_sparse_point(sparse_index, &point);
    }
    insert_payload_point(payload_index, &point);
    id_index.insert(point.id.clone(), SegLoc::Streamer);
    streamer.insert(point);
    Ok(())
}

fn apply_wal_delete(
    streamer: &mut crate::streamer::Streamer,
    sealing: Option<&crate::streamer::Streamer>,
    searchers: &mut [crate::searcher::SegmentSearcher],
    id_index: &mut HashMap<String, crate::searcher::SegLoc>,
    mut sparse_index: Option<&mut SparseIndex>,
    payload_index: &mut PayloadIndex,
    id: String,
) -> Result<()> {
    use crate::searcher::SegLoc;
    match id_index.remove(&id) {
        Some(SegLoc::Streamer) => {
            if let Some(existing) = streamer.remove(&id) {
                if let Some(sparse_index) = sparse_index.as_deref_mut() {
                    remove_sparse_point(sparse_index, &existing);
                }
                remove_payload_point(payload_index, &existing);
            }
        }
        Some(SegLoc::Sealing) => {
            let existing = sealing
                .and_then(|frozen| frozen.points.get(&id))
                .ok_or_else(|| {
                    GaussError::InvalidRequest(
                        "WAL replay encountered transient sealing ownership".to_string(),
                    )
                })?;
            if let Some(sparse_index) = sparse_index.as_deref_mut() {
                remove_sparse_point(sparse_index, existing);
            }
            remove_payload_point(payload_index, existing);
        }
        Some(SegLoc::Searcher(i)) => {
            let searcher = &mut searchers[i as usize];
            if let Some(existing) = searcher.store.get(&id) {
                if let Some(sparse_index) = sparse_index {
                    remove_sparse_point(sparse_index, &existing);
                }
                remove_payload_point(payload_index, &existing);
            }
            searcher.tombstone(&id);
        }
        None => {}
    }
    Ok(())
}

struct GraphReplayState<'a> {
    record_lsn: u64,
    lifecycle: crate::graph_lifecycle::GraphLifecycleState,
    resolver: &'a mut Option<crate::graph_resolver::PointIncarnationResolver>,
    mutable: &'a mut Option<crate::mutable_graph::MutableGraphState>,
}

fn replay_point_tenant(
    nid: crate::graph::Nid,
    resolver: &crate::graph_resolver::PointIncarnationResolver,
    staged_upsert_tenants: &HashMap<crate::graph::Nid, Option<String>>,
    streamer: &crate::streamer::Streamer,
    sealing: Option<&crate::streamer::Streamer>,
    searchers: &[crate::searcher::SegmentSearcher],
    id_index: &HashMap<String, crate::searcher::SegLoc>,
) -> Option<String> {
    use crate::searcher::SegLoc;

    if let Some(tenant) = staged_upsert_tenants.get(&nid) {
        return tenant.clone();
    }
    let point_id = resolver.live_point_id(nid)?;
    match id_index.get(point_id)? {
        SegLoc::Streamer => streamer
            .points
            .get(point_id)
            .and_then(|point| point.payload.get(crate::tenant::TENANT_FIELD))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        SegLoc::Searcher(index) => searchers
            .get(*index as usize)?
            .store
            .get(point_id)
            .and_then(|point| {
                point
                    .payload
                    .get(crate::tenant::TENANT_FIELD)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            }),
        SegLoc::Sealing => sealing
            .and_then(|frozen| frozen.points.get(point_id))
            .and_then(|point| point.payload.get(crate::tenant::TENANT_FIELD))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
    }
}

struct PreparedGraphBatch {
    record_lsn: u64,
    staged_resolver: crate::graph_resolver::PointIncarnationResolver,
    staged_types: crate::mutable_graph::GraphTypeCatalog,
    deferred_plan: crate::mutable_graph::DeferredMutationPlan,
    edge_mutations: Vec<crate::graph::EdgeMutation>,
}

struct GraphApplyState<'a> {
    streamer: &'a mut crate::streamer::Streamer,
    sealing: Option<&'a crate::streamer::Streamer>,
    searchers: &'a mut [crate::searcher::SegmentSearcher],
    id_index: &'a mut HashMap<String, crate::searcher::SegLoc>,
    resolver: &'a mut Option<crate::graph_resolver::PointIncarnationResolver>,
    mutable: &'a mut Option<crate::mutable_graph::MutableGraphState>,
    sparse_index: Option<&'a mut SparseIndex>,
    payload_index: &'a mut PayloadIndex,
}

#[allow(clippy::too_many_arguments)]
fn prepare_graph_batch(
    config: &CollectionConfig,
    streamer: &crate::streamer::Streamer,
    sealing: Option<&crate::streamer::Streamer>,
    searchers: &[crate::searcher::SegmentSearcher],
    id_index: &HashMap<String, crate::searcher::SegLoc>,
    record_lsn: u64,
    lifecycle: crate::graph_lifecycle::GraphLifecycleState,
    resolver: &Option<crate::graph_resolver::PointIncarnationResolver>,
    mutable: &Option<crate::mutable_graph::MutableGraphState>,
    batch: &crate::wal::GraphBatch,
) -> Result<PreparedGraphBatch> {
    use crate::{searcher::SegLoc, wal::GraphPointMutation};

    batch.validate()?;
    if !lifecycle.is_enabled() {
        return Err(crate::graph::GraphError::new(
            crate::graph::GraphErrorCode::GraphDisabled,
            "GraphBatch requires an enabled graph lifecycle",
        )
        .into());
    }
    let active_epoch = lifecycle.epoch().ok_or_else(|| {
        GaussError::InvalidRequest("enabled graph lifecycle has no active epoch".to_string())
    })?;
    if batch.graph_epoch != active_epoch {
        return Err(crate::graph::GraphError::new(
            crate::graph::GraphErrorCode::EpochMismatch,
            format!(
                "GraphBatch epoch {} does not match active graph epoch {}",
                batch.graph_epoch.raw(),
                active_epoch.raw()
            ),
        )
        .into());
    }
    let current_mutable = mutable.as_ref().ok_or_else(|| {
        GaussError::InvalidRequest("enabled graph lifecycle has no mutable graph state".to_string())
    })?;
    if current_mutable.epoch() != active_epoch {
        return Err(crate::graph::GraphError::new(
            crate::graph::GraphErrorCode::EpochMismatch,
            format!(
                "mutable graph epoch {} does not match active graph epoch {}",
                current_mutable.epoch().raw(),
                active_epoch.raw()
            ),
        )
        .into());
    }
    current_mutable.validate_idempotency(batch.idempotency.as_ref())?;

    let upsert_ids = batch
        .point_mutations
        .iter()
        .filter_map(|mutation| match mutation {
            GraphPointMutation::Upsert { point } => Some(point.id.as_str()),
            GraphPointMutation::Delete { .. } => None,
        })
        .collect::<HashSet<_>>();
    let current_resolver = resolver.clone().unwrap_or_default();
    let mut staged_resolver = current_resolver.clone();
    for assignment in &batch.handle_assignments {
        if !id_index.contains_key(&assignment.point_id)
            && !upsert_ids.contains(assignment.point_id.as_str())
        {
            return Err(GaussError::InvalidRequest(format!(
                "handle assignment references missing point '{}'",
                assignment.point_id
            )));
        }
        staged_resolver.bind_live(assignment.point_id.clone(), assignment.nid)?;
    }

    for mutation in &batch.point_mutations {
        let point_id = match mutation {
            GraphPointMutation::Upsert { point } => {
                validate_point(config, point)?;
                if staged_resolver.live_nid(&point.id).is_none() {
                    return Err(GaussError::InvalidRequest(format!(
                        "upsert for '{}' has no live Nid assignment",
                        point.id
                    )));
                }
                point.id.as_str()
            }
            GraphPointMutation::Delete { point_id, nid } => {
                if staged_resolver.live_nid(point_id) != Some(*nid) {
                    return Err(GaussError::InvalidRequest(format!(
                        "delete for '{point_id}' does not match its live Nid"
                    )));
                }
                if !id_index.contains_key(point_id) {
                    return Err(GaussError::InvalidRequest(format!(
                        "delete references missing point '{point_id}'"
                    )));
                }
                point_id.as_str()
            }
        };
        match id_index.get(point_id) {
            Some(SegLoc::Sealing)
                if sealing.is_none_or(|frozen| !frozen.points.contains_key(point_id)) =>
            {
                return Err(GaussError::InvalidRequest(
                    "GraphBatch sealing ownership has no frozen point".to_string(),
                ));
            }
            Some(SegLoc::Searcher(index)) if (*index as usize) >= searchers.len() => {
                return Err(GaussError::InvalidRequest(
                    "point location references a missing searcher".to_string(),
                ));
            }
            _ => {}
        }
    }

    let removed_edges = batch
        .edge_mutations
        .iter()
        .filter_map(|mutation| match mutation {
            crate::graph::EdgeMutation::Unrelate(unrelate) => Some(unrelate.edge_id),
            crate::graph::EdgeMutation::Relate(_) | crate::graph::EdgeMutation::Properties(_) => {
                None
            }
        })
        .collect::<HashSet<_>>();
    let no_staged_tenants = HashMap::new();
    for mutation in &batch.point_mutations {
        let GraphPointMutation::Upsert { point } = mutation else {
            // Point deletion retires the Nid in O(1). Incident edges stay in
            // the ledger and become invisible through endpoint liveness; the
            // public WITH EDGES acknowledgement is a later degree guard, not
            // a degree-proportional cascade.
            continue;
        };
        let Some(nid) = current_resolver.live_nid(&point.id) else {
            continue;
        };
        let next_tenant = point
            .payload
            .get(crate::tenant::TENANT_FIELD)
            .and_then(serde_json::Value::as_str);
        let current_tenant = replay_point_tenant(
            nid,
            &current_resolver,
            &no_staged_tenants,
            streamer,
            sealing,
            searchers,
            id_index,
        );
        if current_tenant.as_deref() != next_tenant
            && current_mutable.has_live_incident_edge_excluding(
                nid,
                current_tenant.as_deref(),
                &removed_edges,
            )?
        {
            return Err(crate::graph::GraphError::new(
                crate::graph::GraphErrorCode::TenantMoveHasEdges,
                format!(
                    "tenant change for Nid {} requires every incident edge to be removed with UNRELATE in the same GraphBatch",
                    nid.raw()
                ),
            )
            .into());
        }
    }

    for mutation in &batch.point_mutations {
        if let GraphPointMutation::Delete { point_id, nid } = mutation {
            let retired = staged_resolver.retire(point_id);
            debug_assert_eq!(retired, Some(*nid));
        }
    }

    let mut staged_types = current_mutable.types().clone();
    for configuration in &batch.type_configurations {
        staged_types.configure(
            configuration.type_id,
            configuration.name.clone(),
            configuration.weight_property.clone(),
        )?;
    }
    let staged_upsert_tenants = batch
        .point_mutations
        .iter()
        .filter_map(|mutation| match mutation {
            GraphPointMutation::Upsert { point } => {
                staged_resolver.live_nid(&point.id).map(|nid| {
                    (
                        nid,
                        point
                            .payload
                            .get(crate::tenant::TENANT_FIELD)
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string),
                    )
                })
            }
            GraphPointMutation::Delete { .. } => None,
        })
        .collect::<HashMap<_, _>>();
    let assignments = batch
        .handle_assignments
        .iter()
        .map(|assignment| (assignment.point_id.clone(), assignment.nid))
        .collect::<HashSet<_>>();
    let deferred_plan = current_mutable.plan_deferred(
        &staged_resolver,
        crate::mutable_graph::DeferredMutationInput {
            record_lsn,
            assignments: &assignments,
            creates: &batch.deferred_binds,
            endpoint_binds: &batch.edge_binds,
            session_mutations: &batch.deferred_sessions,
        },
        &staged_types,
    )?;
    let mut edge_mutations = batch.edge_mutations.clone();
    edge_mutations.extend_from_slice(deferred_plan.promoted());
    let promoted_pending_ids = deferred_plan
        .promoted()
        .iter()
        .filter_map(|mutation| match mutation {
            crate::graph::EdgeMutation::Relate(relate) => Some(relate.edge_id),
            crate::graph::EdgeMutation::Unrelate(_) | crate::graph::EdgeMutation::Properties(_) => {
                None
            }
        })
        .collect::<HashSet<_>>();
    current_mutable.validate_edge_mutations_with_types_and_promotions(
        &staged_resolver,
        &edge_mutations,
        |nid| {
            replay_point_tenant(
                nid,
                &staged_resolver,
                &staged_upsert_tenants,
                streamer,
                sealing,
                searchers,
                id_index,
            )
        },
        &staged_types,
        &promoted_pending_ids,
    )?;
    let edge_mutations = current_mutable.prepare_property_mutations(&edge_mutations)?;

    Ok(PreparedGraphBatch {
        record_lsn,
        staged_resolver,
        staged_types,
        deferred_plan,
        edge_mutations,
    })
}

fn apply_prepared_graph_batch(
    state: GraphApplyState<'_>,
    batch: crate::wal::GraphBatch,
    prepared: PreparedGraphBatch,
) -> Result<()> {
    use crate::wal::GraphPointMutation;

    let GraphApplyState {
        streamer,
        sealing,
        searchers,
        id_index,
        resolver,
        mutable,
        mut sparse_index,
        payload_index,
    } = state;
    let PreparedGraphBatch {
        record_lsn,
        staged_resolver,
        staged_types,
        deferred_plan,
        edge_mutations,
    } = prepared;
    let crate::wal::GraphBatch {
        point_mutations,
        idempotency,
        ..
    } = batch;

    for mutation in point_mutations {
        match mutation {
            GraphPointMutation::Upsert { point } => {
                apply_wal_upsert(
                    streamer,
                    sealing,
                    searchers,
                    id_index,
                    sparse_index.as_deref_mut(),
                    payload_index,
                    point,
                )?;
            }
            GraphPointMutation::Delete { point_id, .. } => {
                apply_wal_delete(
                    streamer,
                    sealing,
                    searchers,
                    id_index,
                    sparse_index.as_deref_mut(),
                    payload_index,
                    point_id,
                )?;
            }
        }
    }
    *resolver = Some(staged_resolver);
    let mutable = mutable.as_mut().expect("validated mutable graph state");
    mutable.track_persist_changes(record_lsn, &edge_mutations, &deferred_plan);
    mutable.replace_types(staged_types);
    mutable.apply_validated_edge_mutations(&edge_mutations);
    mutable.apply_deferred_plan(deferred_plan);
    mutable.apply_validated_idempotency(idempotency.as_ref());
    Ok(())
}

fn apply_wal_graph_batch(
    config: &CollectionConfig,
    streamer: &mut crate::streamer::Streamer,
    searchers: &mut [crate::searcher::SegmentSearcher],
    id_index: &mut HashMap<String, crate::searcher::SegLoc>,
    graph: GraphReplayState<'_>,
    payload_index: &mut PayloadIndex,
    batch: crate::wal::GraphBatch,
) -> Result<()> {
    let GraphReplayState {
        record_lsn,
        lifecycle,
        resolver,
        mutable,
    } = graph;
    let prepared = prepare_graph_batch(
        config, streamer, None, searchers, id_index, record_lsn, lifecycle, resolver, mutable,
        &batch,
    )
    .map_err(|error| graph_batch_corruption(&config.name, error.to_string()))?;
    apply_prepared_graph_batch(
        GraphApplyState {
            streamer,
            sealing: None,
            searchers,
            id_index,
            resolver,
            mutable,
            sparse_index: None,
            payload_index,
        },
        batch,
        prepared,
    )
    .map_err(|error| graph_batch_corruption(&config.name, error.to_string()))
}

fn graph_batch_corruption(collection: &str, message: impl Into<String>) -> GaussError {
    GaussError::WalCorruption {
        path: collection.to_string(),
        message: format!("invalid GraphBatch: {}", message.into()),
    }
}

fn graph_publication_unavailable(collection: &str) -> GaussError {
    GaussError::InvalidRequest(format!(
        "collection '{collection}' has WAL-only G0 graph state; vector seal/compaction/cold tiering is disabled until G1 publishes graph and vector artifacts atomically"
    ))
}

fn graph_replication_unavailable(collection: &str) -> GaussError {
    GaussError::InvalidRequest(format!(
        "collection '{collection}' has graph history; legacy point-only replication, including payload and schema records, is disabled until graph artifacts and vector mutations replicate atomically"
    ))
}

struct WalReplayIndexes<'a> {
    id_index: &'a mut HashMap<String, crate::searcher::SegLoc>,
    graph_lifecycle: &'a mut crate::graph_lifecycle::GraphLifecycleState,
    graph_resolver: &'a mut Option<crate::graph_resolver::PointIncarnationResolver>,
    graph_mutable: &'a mut Option<crate::mutable_graph::MutableGraphState>,
    payload_index: &'a mut PayloadIndex,
}

fn apply_wal_record(
    config: &mut CollectionConfig,
    schema_epoch: &mut u64,
    streamer: &mut crate::streamer::Streamer,
    searchers: &mut [crate::searcher::SegmentSearcher],
    indexes: WalReplayIndexes<'_>,
    record: WalRecord,
) -> Result<()> {
    use crate::searcher::SegLoc;
    let record_lsn = record.lsn;
    match record.entry {
        WalEntry::Upsert { point } => {
            apply_wal_upsert(
                streamer,
                None,
                searchers,
                indexes.id_index,
                None,
                indexes.payload_index,
                point,
            )?;
        }
        WalEntry::UpsertBatch { points } => {
            for point in points {
                apply_wal_upsert(
                    streamer,
                    None,
                    searchers,
                    indexes.id_index,
                    None,
                    indexes.payload_index,
                    point,
                )?;
            }
        }
        WalEntry::Delete { id } => {
            if let Some(resolver) = indexes.graph_resolver.as_mut() {
                resolver.retire(&id);
            }
            apply_wal_delete(
                streamer,
                None,
                searchers,
                indexes.id_index,
                None,
                indexes.payload_index,
                id,
            )?;
        }
        WalEntry::DeleteBatch { ids } => {
            for id in ids {
                if let Some(resolver) = indexes.graph_resolver.as_mut() {
                    resolver.retire(&id);
                }
                apply_wal_delete(
                    streamer,
                    None,
                    searchers,
                    indexes.id_index,
                    None,
                    indexes.payload_index,
                    id,
                )?;
            }
        }
        WalEntry::SetPayload { id, payload, merge } => {
            // A payload update on a sealed point is an update: move the
            // point into the streamer and tombstone the old location.
            let moved = match indexes.id_index.get(&id) {
                Some(SegLoc::Sealing) => {
                    return Err(GaussError::InvalidRequest(
                        "WAL replay encountered transient sealing ownership".to_string(),
                    ));
                }
                Some(SegLoc::Searcher(i)) => {
                    let searcher = &mut searchers[*i as usize];
                    let taken = searcher.store.get(&id).map(Cow::into_owned);
                    if taken.is_some() {
                        searcher.tombstone(&id);
                    }
                    taken
                }
                _ => None,
            };
            if let Some(point) = moved {
                indexes.id_index.insert(id.clone(), SegLoc::Streamer);
                streamer.insert(point);
            }
            if streamer.points.contains_key(&id) {
                let old_bytes = crate::streamer::point_bytes(&streamer.points[&id]);
                {
                    let point = streamer.points.get_mut(&id).unwrap();
                    remove_payload_point(indexes.payload_index, point);
                    if merge {
                        if let (Some(existing_obj), Some(new_obj)) =
                            (point.payload.as_object_mut(), payload.as_object())
                        {
                            for (k, v) in new_obj {
                                existing_obj.insert(k.clone(), v.clone());
                            }
                        } else {
                            point.payload = payload;
                        }
                    } else {
                        point.payload = payload;
                    }
                    insert_payload_point(indexes.payload_index, point);
                }
                streamer.refresh_point_bytes(old_bytes, &id);
            }
        }
        WalEntry::Schema {
            schema_epoch: next_epoch,
            config: next_config,
            ..
        } => {
            if next_config.name != config.name {
                return Err(GaussError::InvalidRequest(format!(
                    "schema WAL record for collection '{}' cannot apply to collection '{}'",
                    next_config.name, config.name
                )));
            }
            validate_config(&next_config)?;
            for point in streamer
                .points
                .values()
                .map(Cow::Borrowed)
                .chain(searchers.iter().flat_map(|s| s.iter_live()))
            {
                validate_payload_schema(&next_config, &point)?;
            }
            *config = next_config;
            *schema_epoch = next_epoch;
        }
        WalEntry::Compact { .. } => {}
        WalEntry::GraphEpochAdvance { epoch, enabled } => {
            let mut staged = *indexes.graph_lifecycle;
            staged
                .apply_advance(epoch, enabled)
                .map_err(|error| graph_batch_corruption(&config.name, error.to_string()))?;
            *indexes.graph_lifecycle = staged;
            if enabled && indexes.graph_resolver.is_none() {
                *indexes.graph_resolver =
                    Some(crate::graph_resolver::PointIncarnationResolver::default());
            }
            *indexes.graph_mutable =
                enabled.then(|| crate::mutable_graph::MutableGraphState::new(epoch));
        }
        WalEntry::GraphBatch { batch } => {
            apply_wal_graph_batch(
                config,
                streamer,
                searchers,
                indexes.id_index,
                GraphReplayState {
                    record_lsn,
                    lifecycle: *indexes.graph_lifecycle,
                    resolver: indexes.graph_resolver,
                    mutable: indexes.graph_mutable,
                },
                indexes.payload_index,
                batch,
            )?;
        }
        WalEntry::CreateCollection { .. } | WalEntry::DropCollection { .. } => {
            return Err(GaussError::WalCorruption {
                path: config.name.clone(),
                message: "catalog WAL entry found in collection WAL".to_string(),
            });
        }
    }
    Ok(())
}

/// Everything `Db::open` / cold-materialize / restore need to (re)build a
/// collection's in-memory state from its directory: sealed segments as
/// independent searchers, WAL tail replayed into the streamer, and the
/// global indexes over the union.
struct LoadedCollectionState {
    config: CollectionConfig,
    schema_epoch: u64,
    streamer: crate::streamer::Streamer,
    searchers: Vec<crate::searcher::SegmentSearcher>,
    id_index: HashMap<String, crate::searcher::SegLoc>,
    graph_lifecycle: crate::graph_lifecycle::GraphLifecycleState,
    graph_resolver: Option<crate::graph_resolver::PointIncarnationResolver>,
    graph_mutable: Option<crate::mutable_graph::MutableGraphState>,
    graph_generation: Option<Arc<crate::graph_generation::GraphGeneration>>,
    wal_watermark: u64,
    payload_index: PayloadIndex,
    sparse_index: SparseIndex,
    overlays: crate::overlay::OverlayStore,
}

struct LoadedDbRoot {
    catalog_wal: Wal,
    collections: HashMap<String, Arc<RwLock<Collection>>>,
    catalog_replayed: bool,
}

#[derive(Default)]
struct CatalogReplayResult {
    replayed: bool,
    dropped: HashSet<String>,
}

fn load_db_root(
    root: &Path,
    cold_object_store: Option<&ColdObjectStoreConfig>,
) -> Result<LoadedDbRoot> {
    fs::create_dir_all(collections_dir(root))?;
    let mut catalog = read_catalog(root)?;
    let catalog_wal = Wal::open(&root.join(CATALOG_WAL_DIR))?;
    let catalog_replay = replay_catalog_wal(root, &mut catalog, &catalog_wal)?;
    reconcile_catalog_generations(root, &catalog.collections, &catalog_replay.dropped)?;
    let catalog_replayed = catalog_replay.replayed;
    let mut collections = HashMap::new();
    for config in catalog.collections {
        validate_config(&config)?;
        let collection_name = config.name.clone();
        let collection_dir = collection_dir(root, &collection_name);
        fs::create_dir_all(collection_dir.join("wal"))?;
        fs::create_dir_all(collection_dir.join("searchers"))?;
        let checkpoint = read_checkpoint(&collection_dir)?;
        let schema_epoch = checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.schema_epoch)
            .unwrap_or(1);
        let wal_watermark = checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.wal_watermark)
            .unwrap_or(0);
        let state = load_collection_state(
            &collection_dir,
            config,
            schema_epoch,
            wal_watermark,
            cold_object_store,
            crate::overlay::OverlayOpenMode::Recover,
        )?;
        let LoadedCollectionState {
            config,
            schema_epoch,
            streamer,
            searchers,
            id_index,
            graph_lifecycle,
            graph_resolver,
            graph_mutable,
            graph_generation,
            wal_watermark,
            payload_index,
            sparse_index,
            overlays,
        } = state;
        let wal = Wal::open(&collection_dir.join("wal"))?;
        let graph_calibration =
            crate::graph_estimator::GraphCalibrationStore::open(&collection_dir)?.map(Arc::new);
        collections.insert(
            collection_name,
            Arc::new(RwLock::new(Collection {
                config,
                streamer,
                sealing: None,
                searchers,
                id_index,
                graph_lifecycle,
                graph_resolver,
                graph_mutable,
                graph_generation,
                graph_calibration,
                sparse_index,
                payload_index,
                overlays,
                rabitq: None,
                vamana: None,
                ivf: None,
                wal,
                wal_watermark,
                schema_epoch,
                last_segment_id: checkpoint
                    .as_ref()
                    .and_then(|checkpoint| checkpoint.segment_id.clone()),
                recall_curve: None,
                hnsw_dirty: true,
                index_build_in_flight: false,
                generation_build_in_flight: false,
                graph_backfill_in_flight: false,
            })),
        );
    }
    Ok(LoadedDbRoot {
        catalog_wal,
        collections,
        catalog_replayed,
    })
}

fn load_collection_state(
    collection_dir: &Path,
    mut config: CollectionConfig,
    mut schema_epoch: u64,
    wal_watermark: u64,
    cold_object_store: Option<&ColdObjectStoreConfig>,
    overlay_mode: crate::overlay::OverlayOpenMode,
) -> Result<LoadedCollectionState> {
    let manifest = read_segments_manifest(collection_dir)?;
    if let Some(manifest) = manifest
        .as_ref()
        .filter(|manifest| manifest.graph.is_some())
    {
        let graph = manifest.graph.as_ref().expect("selected graph");
        if Wal::retained_base_lsn(&collection_dir.join("wal"))? > graph.graph_batch_watermark {
            return Err(GaussError::InvalidRequest(
                "retained WAL does not cover the selected graph checkpoint".into(),
            ));
        }
        if graph.recovery.is_none() {
            manifest.require_vector_only(collection_dir)?;
        }
        if matches!(
            overlay_mode,
            crate::overlay::OverlayOpenMode::ResetToSegmentBase
        ) {
            return Err(GaussError::InvalidRequest(
                "graph generation cannot use a vector-only visibility reset".into(),
            ));
        }
    }
    let mut remote_graph_diskann = HashMap::new();
    if manifest
        .as_ref()
        .is_some_and(|manifest| manifest.graph.is_some())
        && let Some(object_store) = cold_object_store
    {
        let installed = manifest
            .as_ref()
            .expect("selected graph manifest")
            .segments
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        materialize_missing_cold_segments_from_object_store(
            &collection_dir.join("cold"),
            object_store,
        )?;
        remote_graph_diskann = crate::segment::remote_diskann_artifacts(
            &collection_dir.join("cold"),
            object_store,
            Some(&installed),
        )?;
    }
    let mut graph_generation = match manifest
        .as_ref()
        .filter(|manifest| manifest.graph.is_some())
    {
        Some(manifest) => {
            let generation =
                crate::graph_generation::GraphGeneration::load_candidate_with_remote_diskann(
                    collection_dir,
                    manifest.clone(),
                    &remote_graph_diskann,
                )?;
            if generation.recovered.is_none() {
                return Err(GaussError::SegmentCorruption {
                    path: collection_dir.display().to_string(),
                    message: "graph generation has no complete recovery catalog".into(),
                });
            }
            Some(generation)
        }
        None => None,
    };
    let wal_watermark = if let Some(generation) = &graph_generation {
        let graph_watermark = generation
            .manifest
            .graph
            .as_ref()
            .expect("graph manifest")
            .graph_batch_watermark;
        if wal_watermark > graph_watermark {
            return Err(GaussError::SegmentCorruption {
                path: collection_dir.display().to_string(),
                message: "checkpoint WAL watermark exceeds the selected graph cut".into(),
            });
        }
        graph_watermark
    } else {
        wal_watermark
    };
    let manifest_generation = manifest.as_ref().map_or(0, |manifest| manifest.generation);
    let installed_segments = match manifest.as_ref() {
        Some(manifest) => Some(manifest.segments.iter().cloned().collect::<HashSet<_>>()),
        None => read_checkpoint(collection_dir)?
            .and_then(|checkpoint| checkpoint.segments)
            .map(|segments| segments.into_iter().collect::<HashSet<_>>()),
    };
    if let Some(installed) = &installed_segments {
        remove_unlisted_segment_dirs(collection_dir, installed)?;
        remove_installed_build_workspaces(collection_dir, installed)?;
    }
    let mut searchers = if let Some(generation) = &graph_generation {
        generation.searchers(config.metric)?
    } else {
        let loaded_segments = crate::segment::load_segments_with_cold_object_store(
            &collection_dir.join("searchers"),
            &collection_dir.join("cold"),
            cold_object_store,
            installed_segments.as_ref(),
        )?;
        if let Some(installed) = &installed_segments {
            let mut loaded = HashSet::with_capacity(loaded_segments.len());
            for segment in &loaded_segments {
                if !loaded.insert(segment.id.clone()) {
                    return Err(GaussError::SegmentCorruption {
                        path: collection_dir
                            .join(crate::checkpoint::SEGMENTS_MANIFEST_FILE)
                            .display()
                            .to_string(),
                        message: format!(
                            "installed segment '{}' exists in more than one storage tier",
                            segment.id
                        ),
                    });
                }
            }
            if let Some(object_store) = cold_object_store {
                loaded.extend(crate::segment::validated_remote_cold_segment_ids(
                    &collection_dir.join("cold"),
                    object_store,
                )?);
            }
            if &loaded != installed {
                let missing = installed.difference(&loaded).cloned().collect::<Vec<_>>();
                return Err(GaussError::SegmentCorruption {
                    path: collection_dir
                        .join(crate::checkpoint::SEGMENTS_MANIFEST_FILE)
                        .display()
                        .to_string(),
                    message: format!("installed segment directories are missing: {missing:?}"),
                });
            }
        }
        loaded_segments
            .into_iter()
            .map(|loaded| crate::searcher::SegmentSearcher::from_loaded(loaded, config.metric))
            .collect::<Result<Vec<_>>>()?
    };
    let installed_for_overlay = installed_segments.clone().unwrap_or_else(|| {
        searchers
            .iter()
            .map(|searcher| searcher.id.clone())
            .collect()
    });
    let mut segment_base = crate::ordinal::SegmentOrdinalSet::new();
    for searcher in &searchers {
        segment_base.insert_bitmap(searcher.id.clone(), searcher.tombstone_ordinals.clone());
    }
    let mut overlays = if let Some(generation) = &graph_generation {
        crate::overlay::OverlayStore::from_graph_manifest(
            collection_dir,
            Arc::clone(&generation.overlay),
        )?
    } else {
        crate::overlay::OverlayStore::open(
            collection_dir,
            manifest_generation,
            &installed_for_overlay,
            segment_base,
            overlay_mode,
        )?
    };
    for searcher in &mut searchers {
        if let Some(tombstones) = overlays
            .current_ref()
            .point_tombstones()
            .bitmap(&searcher.id)
        {
            searcher.install_point_tombstones(tombstones);
        }
    }
    let mut id_index: HashMap<String, crate::searcher::SegLoc> = HashMap::new();
    for (i, searcher) in searchers.iter().enumerate() {
        // Legacy WAL replay needs checkpoint-era ID authority, including points
        // hidden by a newer persisted overlay. In particular, an enabled
        // graph may assign a sealed point's Nid and delete it in later WAL
        // records; starting from final visibility would make that historical
        // assignment look like corruption. Final overlay visibility is
        // imposed after the ordered WAL replay below. A graph manifest already
        // supplies the exact cut, so its hidden locations must stay absent.
        for id in searcher.store.iter_ids() {
            if graph_generation.is_some()
                && !searcher.contains_visible(
                    id,
                    overlays
                        .current_ref()
                        .point_tombstones()
                        .bitmap(&searcher.id),
                )
            {
                continue;
            }
            id_index.insert(id.to_string(), crate::searcher::SegLoc::Searcher(i as u32));
        }
    }
    let mut streamer = crate::streamer::Streamer::with_base_lsn(wal_watermark);
    let recovered = graph_generation
        .as_mut()
        .and_then(|generation| generation.recovered.take());
    let (mut graph_lifecycle, mut graph_resolver, mut graph_mutable) = match recovered {
        Some(recovered) => (
            recovered.lifecycle,
            Some(recovered.resolver),
            recovered
                .lifecycle
                .is_enabled()
                .then_some(recovered.mutable),
        ),
        None => (
            crate::graph_lifecycle::GraphLifecycleState::default(),
            None,
            None,
        ),
    };
    let graph_generation = graph_generation.map(Arc::new);
    if let (Some(mutable), Some(generation)) = (&mut graph_mutable, &graph_generation) {
        mutable.attach_sealed_adjacency(Arc::clone(generation));
    }
    let mut payload_index = crate::payload_index::build_payload_index_iter(
        searchers
            .iter()
            .filter(|searcher| searcher.ordinal_payload_index.is_none())
            .flat_map(|searcher| searcher.store.iter_aux_index_points()),
    );
    Wal::recover_from(&collection_dir.join("wal"), wal_watermark, |record| {
        apply_wal_record(
            &mut config,
            &mut schema_epoch,
            &mut streamer,
            &mut searchers,
            WalReplayIndexes {
                id_index: &mut id_index,
                graph_lifecycle: &mut graph_lifecycle,
                graph_resolver: &mut graph_resolver,
                graph_mutable: &mut graph_mutable,
                payload_index: &mut payload_index,
            },
            record,
        )
    })?;
    // Overlay records whose originating WAL prefix has already been covered
    // by the checkpoint are not replayed. Remove those final hidden sealed
    // locations now, without removing a later WAL upsert that moved the same
    // public ID into the Streamer.
    for (searcher_index, searcher) in searchers.iter().enumerate() {
        let tombstones = overlays
            .current_ref()
            .point_tombstones()
            .bitmap(&searcher.id);
        let hidden_ids = searcher
            .store
            .iter_ids()
            .filter(|id| !searcher.contains_visible(id, tombstones))
            .map(str::to_string)
            .collect::<Vec<_>>();
        for id in hidden_ids {
            if id_index.get(&id) == Some(&crate::searcher::SegLoc::Searcher(searcher_index as u32))
            {
                if let Some(point) = searcher.store.get(&id) {
                    remove_payload_point(&mut payload_index, &point);
                }
                id_index.remove(&id);
            }
        }
    }
    let mut recovered_tombstones = crate::ordinal::SegmentOrdinalSet::new();
    for searcher in &searchers {
        recovered_tombstones
            .insert_bitmap(searcher.id.clone(), searcher.tombstone_ordinals.clone());
    }
    overlays.reconcile_points(&recovered_tombstones)?;
    let empty_edge_tombstones = roaring::RoaringTreemap::new();
    overlays.replace_edges(
        graph_mutable
            .as_ref()
            .map_or(&empty_edge_tombstones, |graph| graph.edge_tombstones()),
    )?;
    overlays.publish_pending()?;
    let sparse_index = crate::sparse_index::build_sparse_index_iter(
        streamer
            .points
            .values()
            .map(Cow::Borrowed)
            .chain(searchers.iter().flat_map(|searcher| {
                searcher.iter_visible_aux_index_points(
                    overlays
                        .current_ref()
                        .point_tombstones()
                        .bitmap(&searcher.id),
                )
            })),
    );
    Ok(LoadedCollectionState {
        config,
        schema_epoch,
        streamer,
        searchers,
        id_index,
        graph_lifecycle,
        graph_resolver,
        graph_mutable,
        graph_generation,
        wal_watermark,
        payload_index,
        sparse_index,
        overlays,
    })
}

fn audit_context(scope: &crate::tenant::TenantScope) -> audit::AuditContext {
    audit::AuditContext {
        principal_id: scope.actor().to_string(),
        tenant_id: scope.tenant_id().map(str::to_string),
        transport: "network".to_string(),
        request_id: None,
    }
}

fn recover_interrupted_generation_restore(
    data_dir: &Path,
    cold_object_store: Option<&ColdObjectStoreConfig>,
) -> Result<()> {
    let Some(journal) = restore_journal::read(data_dir)? else {
        return Ok(());
    };
    if journal.install_mode != RestoreInstallMode::GenerationSwitch {
        return Err(GaussError::WalCorruption {
            path: data_dir
                .join(restore_journal::RESTORE_JOURNAL_FILE)
                .display()
                .to_string(),
            message: "legacy restore journal found in generation control location".to_string(),
        });
    }
    let next_generation =
        journal
            .installed_name
            .as_deref()
            .ok_or_else(|| GaussError::WalCorruption {
                path: data_dir
                    .join(restore_journal::RESTORE_JOURNAL_FILE)
                    .display()
                    .to_string(),
                message: "generation restore journal does not name the installed generation"
                    .to_string(),
            })?;
    let previous_generation = &journal.backup_name;
    let generations = data_dir.join(crate::storage_layout::GENERATIONS_DIR);
    let staging = generations.join(&journal.staging_name);
    let destination = generations.join(next_generation);
    let previous = generations.join(previous_generation);
    let current = crate::storage_layout::resolve(data_dir)?.generation;

    if journal.phase == RestorePhase::Prepared && !destination.exists() {
        if current.as_deref() != Some(previous_generation) || !previous.is_dir() {
            return Err(GaussError::WalCorruption {
                path: data_dir
                    .join(restore_journal::RESTORE_JOURNAL_FILE)
                    .display()
                    .to_string(),
                message: "prepared generation restore has no recoverable previous generation"
                    .to_string(),
            });
        }
        if staging.exists() {
            durable_remove_dir_all(&staging)?;
        }
        restore_journal::remove(data_dir)?;
        tracing::warn!(
            data_dir = %data_dir.display(),
            "rolled back interrupted generation restore before publish"
        );
        return Ok(());
    }

    if !destination.is_dir() || !previous.is_dir() {
        return Err(GaussError::WalCorruption {
            path: data_dir
                .join(restore_journal::RESTORE_JOURNAL_FILE)
                .display()
                .to_string(),
            message: "generation restore journal references a missing generation".to_string(),
        });
    }
    match current.as_deref() {
        Some(current) if current == next_generation => {}
        Some(current) if current == previous_generation => {
            crate::storage_layout::switch_current(data_dir, next_generation)?;
            restore_journal::write(data_dir, &journal.with_phase(RestorePhase::NewInstalled))?;
        }
        _ => {
            return Err(GaussError::WalCorruption {
                path: data_dir
                    .join(restore_journal::RESTORE_JOURNAL_FILE)
                    .display()
                    .to_string(),
                message: "generation restore CURRENT value is ambiguous".to_string(),
            });
        }
    }

    match load_db_root(&destination, cold_object_store) {
        Ok(loaded) if !loaded.catalog_replayed => drop(loaded),
        Ok(loaded) => {
            drop(loaded);
            crate::storage_layout::switch_current(data_dir, previous_generation)?;
            durable_remove_dir_all(&destination)?;
            if staging.exists() {
                durable_remove_dir_all(&staging)?;
            }
            restore_journal::remove(data_dir)?;
            tracing::error!(
                data_dir = %data_dir.display(),
                "rolled back generation restore whose catalog checkpoint was incomplete"
            );
            return Ok(());
        }
        Err(error) => {
            crate::storage_layout::switch_current(data_dir, previous_generation)?;
            durable_remove_dir_all(&destination)?;
            if staging.exists() {
                durable_remove_dir_all(&staging)?;
            }
            restore_journal::remove(data_dir)?;
            tracing::error!(%error, data_dir = %data_dir.display(), "rolled back invalid installed generation restore");
            return Ok(());
        }
    }

    if staging.exists() {
        durable_remove_dir_all(&staging)?;
    }
    restore_journal::remove(data_dir)?;
    durable_remove_dir_all(&previous)?;
    sync_directory(&generations)?;
    tracing::warn!(
        data_dir = %data_dir.display(),
        generation = next_generation,
        "completed interrupted generation restore"
    );
    Ok(())
}

fn recover_interrupted_restore(
    root: &Path,
    cold_object_store: Option<&ColdObjectStoreConfig>,
) -> Result<()> {
    let journal_parent = restore_control_dir(root)?;
    let Some(journal) = restore_journal::read(&journal_parent)? else {
        if journal_parent.exists() {
            // Db::open owns the process-exclusive sibling data lock before it
            // reaches this recovery path. A control directory without a
            // published journal therefore cannot belong to a live preparer;
            // it is an uncommitted staging generation from a crashed process.
            tracing::warn!(
                control = %journal_parent.display(),
                "removing interrupted restore staging without a published journal"
            );
            durable_remove_dir_all(&journal_parent)?;
        }
        return Ok(());
    };
    let staging = journal_parent.join(&journal.staging_name);
    let backup = journal_parent.join(&journal.backup_name);
    let journal_path = journal_parent.join(restore_journal::RESTORE_JOURNAL_FILE);
    let layout_error = |message: &str| GaussError::WalCorruption {
        path: journal_path.display().to_string(),
        message: message.to_string(),
    };

    let committed = match journal.phase {
        RestorePhase::Prepared => match (root.exists(), staging.exists(), backup.exists()) {
            (true, true, false) => false,
            (false, true, true) => {
                durable_rename(&backup, root)?;
                false
            }
            _ => {
                return Err(layout_error(
                    "prepared restore journal has an ambiguous generation layout",
                ));
            }
        },
        RestorePhase::OldMoved => match (root.exists(), staging.exists(), backup.exists()) {
            (false, true, true) => {
                durable_rename(&staging, root)?;
                restore_journal::write(
                    &journal_parent,
                    &journal.with_phase(RestorePhase::NewInstalled),
                )?;
                true
            }
            (true, false, true) => {
                restore_journal::write(
                    &journal_parent,
                    &journal.with_phase(RestorePhase::NewInstalled),
                )?;
                true
            }
            _ => {
                return Err(layout_error(
                    "old_moved restore journal has an ambiguous generation layout",
                ));
            }
        },
        RestorePhase::NewInstalled => {
            if !root.exists() || staging.exists() {
                return Err(layout_error(
                    "new_installed restore journal has an ambiguous generation layout",
                ));
            }
            true
        }
    };

    if committed {
        // Never delete the rollback generation until the installed root has
        // passed the same full persisted-format load used during normal open.
        let validated = load_db_root(root, cold_object_store)?;
        drop(validated);
    }
    if staging.exists() {
        durable_remove_dir_all(&staging)?;
    }
    if backup.exists() {
        durable_remove_dir_all(&backup)?;
    }
    durable_remove_dir_all(&journal_parent)?;
    tracing::warn!(data_dir = %root.display(), "recovered interrupted atomic restore");
    Ok(())
}

fn read_catalog(root: &Path) -> Result<Catalog> {
    let path = root.join(CATALOG_FILE);
    if !path.exists() {
        return Ok(Catalog::default());
    }
    Ok(serde_json::from_slice(
        &crate::encryption::read_persistent(&path)?,
    )?)
}

fn replay_catalog_wal(
    root: &Path,
    catalog: &mut Catalog,
    wal: &Wal,
) -> Result<CatalogReplayResult> {
    let mut replay = CatalogReplayResult::default();
    Wal::recover_from(
        &root.join(CATALOG_WAL_DIR),
        catalog.wal_watermark,
        |record| {
            replay.replayed = true;
            match record.entry {
                WalEntry::CreateCollection { config } => {
                    validate_config(&config)?;
                    replay.dropped.remove(&config.name);
                    catalog
                        .collections
                        .retain(|existing| existing.name != config.name);
                    catalog.collections.push(config);
                }
                WalEntry::DropCollection { name } => {
                    catalog.collections.retain(|config| config.name != name);
                    replay.dropped.insert(name);
                }
                _ => {
                    return Err(GaussError::WalCorruption {
                        path: root.join(CATALOG_WAL_DIR).display().to_string(),
                        message: "collection mutation found in catalog WAL".to_string(),
                    });
                }
            }
            Ok(())
        },
    )?;
    if !replay.replayed {
        return Ok(replay);
    }
    catalog.wal_watermark = wal.len()?;
    catalog
        .collections
        .sort_by(|left, right| left.name.cmp(&right.name));
    Ok(replay)
}

fn write_catalog(inner: &DbInner) -> Result<()> {
    write_catalog_state(&inner.root, &inner.collections, &inner.catalog_wal)
}

fn write_catalog_state(
    root: &Path,
    collections: &HashMap<String, Arc<RwLock<Collection>>>,
    catalog_wal: &Wal,
) -> Result<()> {
    let mut collection_configs: Vec<_> = collections
        .values()
        .map(|collection| collection.read().config.clone())
        .collect();
    collection_configs.sort_by(|left, right| left.name.cmp(&right.name));
    let catalog = Catalog {
        collections: collection_configs,
        wal_watermark: catalog_wal.len()?,
    };
    let path = root.join(CATALOG_FILE);
    let bytes = serde_json::to_vec_pretty(&catalog)?;
    crate::encryption::atomic_write_persistent(&path, crate::encryption::FileType::Metadata, &bytes)
}

fn collections_dir(root: &Path) -> PathBuf {
    root.join("collections")
}

fn reject_storage_path_overlap(label: &str, candidate: &Path, root: &Path) -> Result<()> {
    let resolved_root = fs::canonicalize(root)?;
    let resolved_candidate = resolve_path_for_containment(candidate)?;
    if resolved_candidate.starts_with(&resolved_root)
        || resolved_root.starts_with(&resolved_candidate)
    {
        return Err(GaussError::InvalidRequest(format!(
            "{label} must be outside and must not contain the live data directory"
        )));
    }
    Ok(())
}

/// Resolve symlinks in the nearest existing ancestor while retaining a
/// not-yet-created suffix. This closes the containment bypass where a snapshot
/// destination such as `<symlink-to-live>/new` does not itself exist yet and
/// therefore cannot be canonicalized directly.
fn resolve_path_for_containment(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let normalized = normalize_absolute_path(&absolute)?;
    let mut existing = normalized.as_path();
    let mut missing = Vec::<OsString>::new();
    while !existing.exists() {
        let name = existing.file_name().ok_or_else(|| {
            GaussError::InvalidRequest(format!("cannot resolve storage path {}", path.display()))
        })?;
        missing.push(name.to_os_string());
        existing = existing.parent().ok_or_else(|| {
            GaussError::InvalidRequest(format!("cannot resolve storage path {}", path.display()))
        })?;
    }
    let mut resolved = fs::canonicalize(existing)?;
    for component in missing.into_iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

fn normalize_absolute_path(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => normalized.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    return Err(GaussError::InvalidRequest(format!(
                        "storage path escapes its filesystem root: {}",
                        path.display()
                    )));
                }
            }
            std::path::Component::Normal(value) => normalized.push(value),
        }
    }
    Ok(normalized)
}

fn collection_dir(root: &Path, name: &str) -> PathBuf {
    collections_dir(root).join(name)
}

fn collection_create_staging_dir(root: &Path, name: &str) -> PathBuf {
    collections_dir(root).join(format!(".chirondb-create-{name}.staging"))
}

fn collection_drop_trash_dir(root: &Path, name: &str) -> PathBuf {
    collections_dir(root).join(format!(".chirondb-drop-{name}.trash"))
}

fn quarantine_known_generation(root: &Path, path: &Path) -> Result<()> {
    let quarantine = collections_dir(root).join(format!(
        ".chirondb-known-orphan-{}.quarantine",
        uuid::Uuid::new_v4()
    ));
    durable_rename(path, &quarantine)
}

fn reconcile_catalog_generations(
    root: &Path,
    configs: &[CollectionConfig],
    dropped: &HashSet<String>,
) -> Result<()> {
    let collections_root = collections_dir(root);
    let active = configs
        .iter()
        .map(|config| config.name.as_str())
        .collect::<HashSet<_>>();

    for config in configs {
        let live = collection_dir(root, &config.name);
        let staging = collection_create_staging_dir(root, &config.name);
        match (live.exists(), staging.exists()) {
            (false, true) => durable_rename(&staging, &live)?,
            (true, true) => quarantine_known_generation(root, &staging)?,
            (true, false) => {}
            (false, false) => {
                return Err(GaussError::WalCorruption {
                    path: collections_root.display().to_string(),
                    message: format!(
                        "catalog references collection '{}' without a durable generation",
                        config.name
                    ),
                });
            }
        }
    }

    // Only act on names proven by catalog WAL or by ChironDB's own staging
    // convention. Unrelated directories are preserved untouched.
    for name in dropped {
        let live = collection_dir(root, name);
        if live.exists() {
            let mut trash = collection_drop_trash_dir(root, name);
            if trash.exists() {
                trash = collections_root.join(format!(
                    ".chirondb-drop-{name}-{}.trash",
                    uuid::Uuid::new_v4()
                ));
            }
            durable_rename(&live, &trash)?;
        }
    }
    for entry in fs::read_dir(&collections_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.starts_with(".chirondb-create-")
            && name.ends_with(".staging")
            && !configs
                .iter()
                .any(|config| collection_create_staging_dir(root, &config.name) == entry.path())
        {
            tracing::warn!(
                generation = name,
                "quarantining uncommitted collection staging"
            );
            quarantine_known_generation(root, &entry.path())?;
        }
    }
    debug_assert!(
        active
            .iter()
            .all(|name| collection_dir(root, name).exists())
    );
    Ok(())
}

fn restore_control_dir(root: &Path) -> Result<PathBuf> {
    let root_name = root.file_name().ok_or_else(|| {
        GaussError::InvalidRequest("restore data directory must name a directory".to_string())
    })?;
    let parent = root
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let digest = Sha256::digest(root_name.as_encoded_bytes());
    let identity = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(parent.join(format!(".chirondb-restore-{identity}")))
}

fn operation_siblings(
    target: &Path,
    operation: &str,
    operation_id: uuid::Uuid,
) -> Result<(PathBuf, PathBuf)> {
    let parent = target.parent().ok_or_else(|| {
        GaussError::InvalidRequest(format!("{operation} target must have a parent directory"))
    })?;
    if target.file_name().is_none() {
        return Err(GaussError::InvalidRequest(format!(
            "{operation} target must name a directory"
        )));
    }
    fs::create_dir_all(parent)?;
    let staging = parent.join(format!(".chirondb-{operation}-{operation_id}.staging"));
    let backup = parent.join(format!(".chirondb-{operation}-{operation_id}.backup"));
    if staging.exists() || backup.exists() {
        return Err(GaussError::InvalidRequest(format!(
            "{operation} operation path collision for id {operation_id}"
        )));
    }
    Ok((staging, backup))
}

fn snapshot_staging_identity(destination: &Path) -> Result<String> {
    let name = destination.file_name().ok_or_else(|| {
        GaussError::InvalidRequest("snapshot target must name a directory".to_string())
    })?;
    let digest = Sha256::digest(name.as_encoded_bytes());
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn snapshot_staging_path(destination: &Path, operation_id: uuid::Uuid) -> Result<PathBuf> {
    let parent = destination.parent().ok_or_else(|| {
        GaussError::InvalidRequest("snapshot target must have a parent directory".to_string())
    })?;
    Ok(parent.join(format!(
        ".chirondb-snapshot-{}-{operation_id}.staging",
        snapshot_staging_identity(destination)?
    )))
}

fn recover_snapshot_control(destination: &Path) -> Result<()> {
    let parent = destination.parent().ok_or_else(|| {
        GaussError::InvalidRequest("snapshot target must have a parent directory".to_string())
    })?;
    let identity = snapshot_staging_identity(destination)?;
    let Some(journal) = snapshot_journal::read(parent, &identity)? else {
        return Ok(());
    };
    if destination.file_name().and_then(|name| name.to_str())
        != Some(journal.destination_name.as_str())
    {
        return Err(GaussError::WalCorruption {
            path: parent.display().to_string(),
            message: "snapshot journal destination does not match the locked target".to_string(),
        });
    }
    let staging = parent.join(&journal.staging_name);
    let destination_has_contents =
        destination.is_dir() && fs::read_dir(destination)?.next().transpose()?.is_some();
    if destination_has_contents {
        if read_snapshot_marker(destination)?.is_none() {
            return Err(GaussError::WalCorruption {
                path: destination.display().to_string(),
                message: "published snapshot lacks its final marker".to_string(),
            });
        }
    } else if journal.phase == SnapshotPhase::Published {
        return Err(GaussError::WalCorruption {
            path: destination.display().to_string(),
            message: "published snapshot journal references a missing destination".to_string(),
        });
    }
    if staging.exists() {
        durable_remove_dir_all(&staging)?;
    }
    snapshot_journal::remove(parent, &identity)?;
    tracing::warn!(
        destination = %destination.display(),
        published = destination_has_contents,
        "recovered interrupted snapshot publication"
    );
    Ok(())
}

/// A destination lock excludes a concurrent publisher, so matching staging
/// directories can only be remnants of an interrupted earlier attempt.
fn cleanup_snapshot_staging(destination: &Path) -> Result<()> {
    let parent = destination.parent().ok_or_else(|| {
        GaussError::InvalidRequest("snapshot target must have a parent directory".to_string())
    })?;
    let prefix = format!(
        ".chirondb-snapshot-{}-",
        snapshot_staging_identity(destination)?
    );
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&prefix) && name.ends_with(".staging") {
            tracing::warn!(
                staging = %entry.path().display(),
                "removing interrupted snapshot staging directory"
            );
            durable_remove_dir_all(&entry.path())?;
        }
    }
    Ok(())
}

fn sibling_file_name(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            GaussError::InvalidRequest(format!(
                "restore operation path is not a UTF-8 sibling name: {}",
                path.display()
            ))
        })
}

fn preserve_audit_log(live_root: &Path, staged_root: &Path) -> Result<()> {
    let live_path = audit::audit_log_path(live_root);
    let staged_path = audit::audit_log_path(staged_root);
    let current = match fs::read(&live_path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    match current {
        Some(bytes) => {
            let parent = staged_path.parent().ok_or_else(|| {
                GaussError::InvalidRequest("staged audit log has no parent directory".to_string())
            })?;
            fs::create_dir_all(parent)?;
            let mut file = File::create(&staged_path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            sync_directory(parent)?;
        }
        None if staged_path.exists() => durable_remove_file(&staged_path)?,
        None => {}
    }
    Ok(())
}

fn rollback_restore_generation(
    root: &Path,
    staging: &Path,
    backup: &Path,
    journal_parent: &Path,
) -> Result<()> {
    if backup.exists() {
        if root.exists() {
            if staging.exists() {
                return Err(GaussError::WalCorruption {
                    path: journal_parent
                        .join(restore_journal::RESTORE_JOURNAL_FILE)
                        .display()
                        .to_string(),
                    message: "ambiguous restore rollback: live, staging, and backup all exist"
                        .to_string(),
                });
            }
            durable_rename(root, staging)?;
        }
        durable_rename(backup, root)?;
    } else if !root.exists() {
        return Err(GaussError::WalCorruption {
            path: journal_parent
                .join(restore_journal::RESTORE_JOURNAL_FILE)
                .display()
                .to_string(),
            message: "restore rollback has neither a live nor backup generation".to_string(),
        });
    }
    if staging.exists() {
        durable_remove_dir_all(staging)?;
    }
    durable_remove_dir_all(journal_parent)?;
    Ok(())
}

fn snapshot_dir_all(source: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        if !destination.is_dir() || fs::read_dir(destination)?.next().is_some() {
            return Err(GaussError::InvalidRequest(format!(
                "snapshot staging directory is not empty: {}",
                destination.display()
            )));
        }
        durable_remove_dir_all(destination)?;
    }
    fs::create_dir_all(destination)?;
    if let Some(parent) = destination.parent() {
        sync_directory(parent)?;
    }
    snapshot_dir_contents(source, source, destination)
}

fn snapshot_dir_contents(root: &Path, source: &Path, destination: &Path) -> Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let source_path = entry.path();
        if source == root
            && matches!(
                entry.file_name().to_str(),
                Some(".chirondb.lock" | "audit" | GRAPH_IDENTITY_FILE)
            )
        {
            continue;
        }
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            fs::create_dir_all(&target)?;
            snapshot_dir_contents(root, &source_path, &target)?;
        } else if should_hard_link_snapshot_file(root, &source_path) {
            if fs::hard_link(&source_path, &target).is_err() {
                fs::copy(&source_path, &target)?;
            }
        } else {
            fs::copy(source_path, target)?;
        }
    }
    Ok(())
}

fn should_hard_link_snapshot_file(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    let parts = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>();
    parts
        .iter()
        .any(|part| part.as_ref() == "searchers" || part.as_ref() == "cold")
        || parts
            .windows(2)
            .any(|window| window[0].as_ref() == "wal" && window[1].as_ref() == "archive")
}

#[cfg(test)]
mod tests {
    mod encryption_lifecycle;
    mod graph_archive;
    mod graph_compaction;
    mod graph_maintenance;
    mod graph_pitr;
    mod graph_retrieval;
    mod graph_snapshot;
    mod partitioned_delta;

    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    #[cfg(all(unix, feature = "fault-injection"))]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(all(unix, feature = "fault-injection"))]
    use std::process::{Command, Stdio};
    use std::{
        collections::{HashMap, HashSet},
        fs,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        path::{Path, PathBuf},
        sync::{
            Arc, Barrier,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    use parking_lot::RwLock;
    use serde_json::json;
    use tempfile::TempDir;

    use crate::{
        CollectionConfig, DistanceMetric, Filter, GaussError, HybridSearchRequest,
        MultiSearchRequest, PayloadType, Point, RecommendRequest, RerankRequest, ScoreBoost,
        SearchRequest, SparseVector, audit, checkpoint,
        graph_identity::GRAPH_IDENTITY_FILE,
        segment::ColdObjectStoreConfig,
        snapshot,
        wal::{GraphBatch, GraphPointMutation, Wal, WalEntry},
    };

    #[test]
    fn memory_pressure_rejects_only_when_both_streamers_are_full() {
        assert!(super::streamer_admission_wait_required(true, true, false).unwrap());
        assert!(!super::streamer_admission_wait_required(false, true, true).unwrap());
        assert!(matches!(
            super::streamer_admission_wait_required(true, true, true),
            Err(GaussError::ResourceExhausted(_))
        ));
    }

    #[test]
    fn recovery_preserves_pending_builds_and_removes_installed_build_workspace() {
        let temp = TempDir::new().unwrap();
        let collection_dir = temp.path().join("collection");
        let searchers = collection_dir.join("searchers");
        let builds = searchers.join(crate::build_progress::BUILDS_DIR);
        fs::create_dir_all(builds.join("installed")).unwrap();
        fs::create_dir_all(builds.join("pending")).unwrap();
        fs::create_dir_all(searchers.join("unpublished-segment")).unwrap();

        let installed = HashSet::from(["installed".to_string()]);
        super::remove_unlisted_segment_dirs(&collection_dir, &installed).unwrap();
        assert!(builds.join("installed").exists());
        super::remove_installed_build_workspaces(&collection_dir, &installed).unwrap();

        assert!(!builds.join("installed").exists());
        assert!(builds.join("pending").exists());
        assert!(!searchers.join("unpublished-segment").exists());
    }

    #[test]
    fn collection_index_kind_defaults_to_lsvec_and_rejects_legacy_choices() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let created = db.create_collection(ls_vec_config("default")).unwrap();
        assert_eq!(created.index_kind.as_deref(), Some("lsvec"));

        for kind in ["hnsw", "ivf", "rabitq", "vamana", "unknown"] {
            let mut config = ls_vec_config(&format!("rejected_{kind}"));
            config.index_kind = Some(kind.to_string());
            let error = db.create_collection(config).unwrap_err();
            assert!(
                matches!(error, GaussError::InvalidRequest(ref message)
                    if message.contains("LS-VEC is the sole index")),
                "unexpected error for {kind}: {error}"
            );
        }
    }

    use super::{
        Collection, Db, PendingSeal, freeze_streamer_for_seal, restore_failed_seal,
        run_segment_seal,
    };
    use crate::payload_index::{build_payload_index, payload_filter_candidates};

    #[derive(Debug, Default)]
    struct RangeHttpStats {
        total_requests: AtomicU64,
        diskann_full_gets: AtomicU64,
        diskann_range_gets: AtomicU64,
        diskann_range_bytes: AtomicU64,
    }

    struct RangeHttpFixture {
        url: String,
        stats: Arc<RangeHttpStats>,
        shutdown: Arc<AtomicBool>,
        worker: Option<thread::JoinHandle<()>>,
    }

    impl RangeHttpFixture {
        fn start(root: PathBuf) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let stats = Arc::new(RangeHttpStats::default());
            let shutdown = Arc::new(AtomicBool::new(false));
            let worker_stats = Arc::clone(&stats);
            let worker_shutdown = Arc::clone(&shutdown);
            let worker = thread::spawn(move || {
                while !worker_shutdown.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            serve_range_http_request(stream, &root, &worker_stats);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => panic!("range HTTP fixture accept failed: {error}"),
                    }
                }
            });
            Self {
                url: format!("http://{address}/"),
                stats,
                shutdown,
                worker: Some(worker),
            }
        }
    }

    impl Drop for RangeHttpFixture {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Relaxed);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    fn serve_range_http_request(mut stream: TcpStream, root: &Path, stats: &RangeHttpStats) {
        stats.total_requests.fetch_add(1, Ordering::Relaxed);
        let mut request = [0_u8; 16 * 1024];
        let read = stream.read(&mut request).unwrap();
        let request = String::from_utf8_lossy(&request[..read]);
        let mut lines = request.lines();
        let Some(request_line) = lines.next() else {
            return;
        };
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let raw_path = parts.next().unwrap_or_default();
        let relative = raw_path
            .split('?')
            .next()
            .unwrap_or_default()
            .trim_start_matches('/');
        let relative_path = Path::new(relative);
        if relative_path.is_absolute()
            || relative_path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            write_http_response(&mut stream, "400 Bad Request", &[], &[]);
            return;
        }
        let path = root.join(relative_path);
        let Ok(bytes) = fs::read(&path) else {
            write_http_response(&mut stream, "404 Not Found", &[], &[]);
            return;
        };
        let range = lines.find_map(|line| {
            line.strip_prefix("Range: bytes=")
                .or_else(|| line.strip_prefix("range: bytes="))
                .and_then(|range| range.split_once('-'))
                .and_then(|(start, end)| {
                    Some((
                        start.parse::<usize>().ok()?,
                        end.trim().parse::<usize>().ok()?,
                    ))
                })
        });
        let is_diskann = path
            .file_name()
            .is_some_and(|name| name == crate::index::diskann::DISKANN_FILE);
        match (method, range) {
            ("HEAD", _) => {
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                    bytes.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
            ("GET", Some((start, end))) if start <= end && end < bytes.len() => {
                let body = &bytes[start..=end];
                if is_diskann {
                    stats.diskann_range_gets.fetch_add(1, Ordering::Relaxed);
                    stats
                        .diskann_range_bytes
                        .fetch_add(body.len() as u64, Ordering::Relaxed);
                }
                let content_range = format!("bytes {start}-{end}/{}", bytes.len());
                write_http_response(
                    &mut stream,
                    "206 Partial Content",
                    &[
                        ("Accept-Ranges", "bytes"),
                        ("Content-Range", &content_range),
                    ],
                    body,
                );
            }
            ("GET", None) => {
                if is_diskann {
                    stats.diskann_full_gets.fetch_add(1, Ordering::Relaxed);
                }
                write_http_response(&mut stream, "200 OK", &[("Accept-Ranges", "bytes")], &bytes);
            }
            _ => write_http_response(&mut stream, "416 Range Not Satisfiable", &[], &[]),
        }
    }

    fn write_http_response(
        stream: &mut TcpStream,
        status: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) {
        let mut response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for (name, value) in headers {
            response.push_str(name);
            response.push_str(": ");
            response.push_str(value);
            response.push_str("\r\n");
        }
        response.push_str("\r\n");
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
    }

    fn ls_vec_config(name: &str) -> CollectionConfig {
        CollectionConfig {
            name: name.to_string(),
            vector_dim: 2,
            metric: DistanceMetric::L2,
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
        }
    }

    #[test]
    fn graph_manifest_db_recovery_and_wal_tail_plaintext_and_encrypted() {
        use crate::{
            encryption,
            graph::{EdgeId, EdgePropertyMode, GraphEpoch, Nid, UpdateEdgeRequest},
            graph_generation::GraphGeneration,
            mutable_graph::recovery::tests::{candidate_at, legacy_candidate_at},
        };
        use base64::{Engine, engine::general_purpose::STANDARD};
        use std::{env, process::Command};
        const MODE: &str = "CHIRONDB_GRAPH_DB_RECOVERY_MODE";
        const ROOT: &str = "CHIRONDB_GRAPH_DB_RECOVERY_ROOT";
        const LEGACY: &str = "CHIRONDB_GRAPH_DB_RECOVERY_LEGACY";
        const TEST: &str =
            "db::tests::graph_manifest_db_recovery_and_wal_tail_plaintext_and_encrypted";
        let Some(mode) = env::var_os(MODE) else {
            for mode in ["plaintext", "encrypted"] {
                for legacy in ["0", "1"] {
                    let temp = TempDir::new().unwrap();
                    assert!(
                        Command::new(env::current_exe().unwrap())
                            .args(["--exact", TEST, "--nocapture"])
                            .env(MODE, mode)
                            .env(ROOT, temp.path())
                            .env(LEGACY, legacy)
                            .status()
                            .unwrap()
                            .success()
                    );
                }
            }
            return;
        };
        let root = PathBuf::from(env::var_os(ROOT).unwrap());
        let legacy = env::var(LEGACY).unwrap() == "1";
        let base_id = if legacy { "legacy-1" } else { "sg-1" };
        if mode == "encrypted" {
            let keyring = root.join("keyring.json");
            fs::write(&keyring,json!({"version":1,"active_key_id":"graph-db-test","keys":[{"id":"graph-db-test","key_base64":STANDARD.encode([91;32])}]}).to_string()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
            }
            encryption::install_process_keyring(encryption::Keyring::load(&keyring).unwrap(), true)
                .unwrap();
        }
        let data = root.join("db");
        let db = Db::open(&data).unwrap();
        let mut config = ls_vec_config("docs");
        config.vector_dim = 4;
        db.create_collection(config.clone()).unwrap();
        let cut = db
            .get_coll("docs")
            .unwrap()
            .write()
            .wal
            .append(&WalEntry::GraphEpochAdvance {
                epoch: GraphEpoch::INITIAL,
                enabled: true,
            })
            .unwrap();
        drop(db);
        let dir = super::collection_dir(&data, "docs");
        let manifest = if legacy {
            legacy_candidate_at(&dir, cut)
        } else {
            candidate_at(&dir, cut)
        };
        let published = GraphGeneration::publish(&dir, None, manifest.clone()).unwrap();
        // Model a crash after the sole manifest switch but before checkpoint
        // metadata catches up. The covered prefix is physically unavailable.
        Wal::open(&dir.join("wal"))
            .unwrap()
            .drop_prefix(cut)
            .unwrap();
        assert_eq!(
            checkpoint::read_checkpoint(&dir)
                .unwrap()
                .unwrap()
                .wal_watermark,
            0
        );
        let edge2 = EdgeId::from_parts(1, 2).unwrap();
        let mut ahead =
            crate::overlay::OverlayStore::from_graph_manifest(&dir, Arc::clone(&published.overlay))
                .unwrap();
        ahead.tombstone_point(base_id, 1).unwrap();
        let mut edges = published.overlay.edge_tombstones().clone();
        edges.insert(edge2.raw());
        ahead.replace_edges(&edges).unwrap();
        ahead.publish_pending().unwrap();
        let base_dir = dir.join("searchers").join(base_id);
        let vectors = if legacy {
            crate::seal::V4Store::open(&base_dir).unwrap()
        } else {
            crate::seal::V4Store::open_graph_base(&base_dir).unwrap()
        };
        crate::seal::write_tombstones(&base_dir, &vectors, &HashSet::from(["p1".into()])).unwrap();
        drop(published);
        let db = Db::open(&data).unwrap();
        let scope = crate::tenant::TenantScope::tenant("recovery-writer", "acme");
        if legacy {
            wait_for_graph_backfill(&db, "docs");
            assert!(
                db.get_coll("docs")
                    .unwrap()
                    .read()
                    .graph_resolver
                    .as_ref()
                    .unwrap()
                    .live_nid("untouched")
                    .is_some()
            );
            assert!(
                !base_dir.join(crate::graph_nid::NID_FILE).exists(),
                "legacy recovery must not rewrite immutable vector segments"
            );
        }
        assert_eq!(
            db.get_points("docs", &["p0".into(), "p1".into()])
                .unwrap()
                .len(),
            2
        );
        let search = db
            .search(
                "docs",
                serde_json::from_value(json!({"vector":[1,1,2,3],"k":2})).unwrap(),
            )
            .unwrap();
        assert_eq!(search.hits.len(), 2);
        assert_eq!(search.hits[0].id, "p1");
        let coll = db.get_coll("docs").unwrap();
        let pinned = Arc::clone(coll.read().graph_generation.as_ref().unwrap());
        assert_eq!(coll.read().wal_watermark, cut);
        assert!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .edge(edge2)
                .is_some()
        );
        let token = crate::edge_token::encode(db.graph_database_id(), edge2).unwrap();
        db.update_edge_scoped(
            "docs",
            &token,
            UpdateEdgeRequest {
                mode: EdgePropertyMode::Merge,
                properties: json!({"tail":true}),
            },
            true,
            &scope,
        )
        .unwrap();
        let mut replacement = db.get_points("docs", &["p0".into()]).unwrap().remove(0);
        replacement.vector[0] = 4.0;
        db.upsert("docs", vec![replacement]).unwrap();
        drop(coll);
        drop(db);
        // A malformed CURRENT must not prevent graph-manifest recovery.
        encryption::atomic_write_persistent(
            &dir.join("overlays/CURRENT"),
            encryption::FileType::Metadata,
            b"invalid-current\n",
        )
        .unwrap();
        let db = Db::open(&data).unwrap();
        assert_eq!(
            db.get_points("docs", &["p0".into()]).unwrap()[0].vector[0],
            4.0
        );
        let coll = db.get_coll("docs").unwrap();
        assert_eq!(
            coll.read().graph_resolver.as_ref().unwrap().live_nid("p0"),
            Some(Nid::from_parts(1, 1).unwrap())
        );
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .edge(edge2)
                .unwrap()
                .properties["tail"],
            true
        );
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .pending_edge_count(),
            2
        );
        assert!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .idempotency("retry")
                .is_some()
        );
        db.unrelate_scoped("docs", &token, true, &scope).unwrap();
        db.delete("docs", &["p1".into()]).unwrap();
        assert!(!pinned.overlay.edge_tombstones().contains(edge2.raw()));
        drop(coll);
        drop(db);
        let db = Db::open(&data).unwrap();
        assert!(db.get_points("docs", &["p1".into()]).unwrap().is_empty());
        let coll = db.get_coll("docs").unwrap();
        assert!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .edge(edge2)
                .is_none()
        );
        assert!(
            coll.read()
                .graph_resolver
                .as_ref()
                .unwrap()
                .is_retired(Nid::from_parts(1, 2).unwrap())
        );
        assert_eq!(coll.read().wal_watermark, cut);
        // An unprepared vector-only reset still refuses graph authority. The
        // whole-state PITR coordinator must select a complete baseline first.
        assert!(
            super::load_collection_state(
                &dir,
                config,
                1,
                cut,
                None,
                crate::overlay::OverlayOpenMode::ResetToSegmentBase
            )
            .is_err()
        );
        drop(coll);
        drop(db);
        let orphan = dir.join("searchers/unlisted/sentinel");
        fs::create_dir_all(orphan.parent().unwrap()).unwrap();
        fs::write(&orphan, b"preserve-on-rejected-admission").unwrap();
        let catalog = dir.join("graph/recovery/control-1/catalog.gdx");
        let mut bytes = fs::read(&catalog).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&catalog, bytes).unwrap();
        assert!(Db::open(&data).is_err());
        assert!(
            orphan.exists(),
            "invalid authority must fail before segment cleanup"
        );
        assert_eq!(
            checkpoint::read_segments_manifest(&dir).unwrap(),
            Some(manifest)
        );
    }

    fn ls_vec_point(id: &str, x: f32, version: &str) -> Point {
        Point {
            id: id.to_string(),
            vector: vec![x, 0.0],
            vectors: HashMap::new(),
            sparse_vector: None,
            payload: json!({"version": version}),
        }
    }

    fn graph_point(id: &str, x: f32, tenant: &str) -> Point {
        let mut point = ls_vec_point(id, x, "graph");
        point.payload = json!({"tenant_id": tenant, "private": format!("{id}-payload")});
        point
    }

    fn wait_for_graph_backfill(db: &super::Db, collection_name: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let coll = db.get_coll(collection_name).unwrap();
            let collection = coll.read();
            if !collection.graph_backfill_in_flight && !collection.graph_backfill_pending() {
                return;
            }
            let assigned = collection
                .graph_resolver
                .as_ref()
                .map_or(0, crate::graph_resolver::PointIncarnationResolver::live_len);
            let total = collection.id_index.len();
            drop(collection);
            assert!(
                Instant::now() < deadline,
                "graph backfill timed out at {assigned}/{total} assigned points"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn prepare_forced_graph_vector_seal(
        db: &Db,
        root: &Path,
        collection_name: &str,
    ) -> PendingSeal {
        let coll = db.get_coll(collection_name).unwrap();
        let wal_archive_policy = {
            let inner = db.inner.read();
            super::seal_wal_archive_policy(&inner, collection_name)
        };
        let (frozen, end_lsn, config, graph, wal_archive_cut) = {
            let mut collection = coll.write();
            collection.wal.sync().unwrap();
            collection.overlays.publish_pending().unwrap();
            let end_lsn = collection.wal.len().unwrap();
            let graph = super::capture_graph_seal(
                &mut collection,
                &super::collection_dir(root, collection_name),
                end_lsn,
            )
            .unwrap();
            let wal_archive_cut = if graph.is_some() {
                collection.wal.freeze_archive_cut(end_lsn).unwrap()
            } else {
                None
            };
            let frozen = freeze_streamer_for_seal(&mut collection, end_lsn);
            (
                frozen,
                end_lsn,
                collection.config.clone(),
                graph,
                wal_archive_cut,
            )
        };
        PendingSeal {
            coll,
            data_dir_lock: Arc::clone(&db._data_dir_lock),
            lifecycle: Arc::clone(&db.build_lifecycle),
            collection_dir: super::collection_dir(root, collection_name),
            frozen,
            end_lsn,
            graph,
            wal_archive_cut,
            wal_archive_policy,
            vector_dim: config.vector_dim,
            metric: config.metric,
            hnsw_m: config.hnsw_m,
            hnsw_ef_construction: config.hnsw_ef_construction,
            index_kind: crate::seal::SealIndexKind::Algorithm2,
            cascade: Arc::clone(&db.cascade),
            intra_query_parallel: Arc::clone(&db.intra_query_parallel),
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct C1EdgeOracle {
        source: crate::graph::Nid,
        target: crate::graph::Nid,
        revision: u64,
        live: bool,
    }

    fn c1_next_random(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = *state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn assert_c1_mutation_oracle(
        collection: &Collection,
        point_ids: &[String],
        live_nids: &[Option<crate::graph::Nid>],
        retired_nids: &HashSet<crate::graph::Nid>,
        edges: &HashMap<crate::graph::EdgeId, C1EdgeOracle>,
    ) {
        let resolver = collection.graph_resolver.as_ref().unwrap();
        let graph = collection.graph_mutable.as_ref().unwrap();
        assert_eq!(resolver.live_len(), live_nids.iter().flatten().count());
        assert_eq!(resolver.retired_len(), retired_nids.len());
        for (point_id, expected_nid) in point_ids.iter().zip(live_nids) {
            assert_eq!(resolver.live_nid(point_id), *expected_nid, "{point_id}");
            assert_eq!(
                collection.id_index.contains_key(point_id),
                expected_nid.is_some()
            );
        }
        for nid in retired_nids {
            assert!(
                resolver.is_retired(*nid),
                "retired Nid {} was lost",
                nid.raw()
            );
            assert!(resolver.live_point_id(*nid).is_none());
        }

        assert_eq!(graph.stored_edge_count(), edges.len() as u64);
        assert_eq!(
            graph.live_edge_count(),
            edges.values().filter(|edge| edge.live).count() as u64
        );
        assert_eq!(
            graph.tombstone_count(),
            edges.values().filter(|edge| !edge.live).count() as u64
        );
        // Snapshot the test-only full oracle once. Calling graph.edge() for
        // every sealed edge would rebuild and hydrate this entire map each time.
        let actual_edges = graph
            .stored_edges()
            .map(|edge| (edge.edge_id, edge))
            .collect::<HashMap<_, _>>();
        let actual_ids = actual_edges.keys().copied().collect::<HashSet<_>>();
        assert_eq!(actual_ids, edges.keys().copied().collect::<HashSet<_>>());
        let tenant = crate::graph::GraphNamespace::Tenant("acme".to_string());
        for edge in actual_edges.values() {
            let expected = edges[&edge.edge_id];
            assert_eq!(edge.source, expected.source);
            assert_eq!(edge.target, expected.target);
            assert_eq!(edge.type_id, crate::graph::TypeId::from_raw(1));
            assert_eq!(edge.namespace, tenant);
            assert_eq!(
                edge.properties["revision"].as_u64(),
                Some(expected.revision)
            );
            assert_eq!(graph.edge_visible(edge.edge_id), expected.live);
        }

        let live_nid_set = live_nids.iter().flatten().copied().collect::<HashSet<_>>();
        let expected_visible = edges
            .iter()
            .filter_map(|(edge_id, edge)| {
                (edge.live
                    && live_nid_set.contains(&edge.source)
                    && live_nid_set.contains(&edge.target))
                .then_some(*edge_id)
            })
            .collect::<HashSet<_>>();
        let actual_visible = live_nid_set
            .iter()
            .flat_map(|nid| {
                graph
                    .live_incident_edge_ids(*nid, "acme", resolver)
                    .unwrap()
            })
            .collect::<HashSet<_>>();
        assert_eq!(actual_visible, expected_visible);
        for edge_id in actual_visible {
            let edge = &actual_edges[&edge_id];
            assert!(graph.edge_visible(edge_id));
            assert!(resolver.live_point_id(edge.source).is_some());
            assert!(resolver.live_point_id(edge.target).is_some());
            assert!(!retired_nids.contains(&edge.source));
            assert!(!retired_nids.contains(&edge.target));
        }
    }

    #[test]
    fn exclusive_lifecycle_gate_blocks_hybrid_recommend_and_rerank() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        seed_recommendation_docs(&db);
        seed_rerank_collection(&db);

        let exclusive = db.lifecycle_gate.write();
        let start = Arc::new(Barrier::new(4));
        let completed = Arc::new(AtomicUsize::new(0));
        let workers = [
            {
                let db = db.clone();
                let start = Arc::clone(&start);
                let completed = Arc::clone(&completed);
                thread::spawn(move || {
                    start.wait();
                    let result = db.hybrid_search(
                        "docs",
                        HybridSearchRequest {
                            graph: None,
                            vector: Some(vec![1.0, 0.0]),
                            vector_name: None,
                            sparse_vector: None,
                            k: 1,
                            filter: None,
                            budget_ms: None,
                            fusion: crate::HybridFusion::Rrf,
                            dense_weight: 1.0,
                            sparse_weight: 1.0,
                        },
                    );
                    completed.fetch_add(1, Ordering::Release);
                    result.map(|_| ())
                })
            },
            {
                let db = db.clone();
                let start = Arc::clone(&start);
                let completed = Arc::clone(&completed);
                thread::spawn(move || {
                    start.wait();
                    let result = db.recommend(
                        "docs",
                        RecommendRequest {
                            positive: vec!["anchor".to_string()],
                            negative: vec!["negative".to_string()],
                            vector_name: None,
                            k: 1,
                            filter: None,
                            budget_ms: None,
                        },
                    );
                    completed.fetch_add(1, Ordering::Release);
                    result.map(|_| ())
                })
            },
            {
                let db = db.clone();
                let start = Arc::clone(&start);
                let completed = Arc::clone(&completed);
                thread::spawn(move || {
                    start.wait();
                    let result = db.rerank(
                        "items",
                        RerankRequest {
                            vector: vec![1.0, 0.0],
                            vector_name: None,
                            k: 1,
                            prefetch_k: None,
                            filter: None,
                            score_boosts: Vec::new(),
                            budget_ms: None,
                        },
                    );
                    completed.fetch_add(1, Ordering::Release);
                    result.map(|_| ())
                })
            },
        ];

        start.wait();
        thread::sleep(Duration::from_millis(50));
        assert_eq!(completed.load(Ordering::Acquire), 0);
        drop(exclusive);
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
        assert_eq!(completed.load(Ordering::Acquire), 3);
    }

    #[test]
    fn sealed_updates_publish_overlay_without_rewriting_segment_tombstones() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert("docs", vec![ls_vec_point("point-1", 1.0, "sealed")])
            .unwrap();
        let compact = db.compact_collection("docs").unwrap();
        let collection_dir = temp.path().join("collections/docs");
        let tombstone_path = collection_dir
            .join("searchers")
            .join(&compact.segment_id)
            .join(crate::seal::TOMBSTONE_FILE);
        let tombstone_before = fs::read(&tombstone_path).unwrap();
        let current_path = collection_dir.join("overlays/CURRENT");
        let current_before = fs::read(&current_path).unwrap();

        db.upsert("docs", vec![ls_vec_point("point-1", 2.0, "streamer")])
            .unwrap();

        assert_eq!(fs::read(&tombstone_path).unwrap(), tombstone_before);
        assert_ne!(fs::read(&current_path).unwrap(), current_before);
        assert_eq!(
            db.get_points("docs", &["point-1".to_string()]).unwrap()[0].payload,
            json!({"version": "streamer"})
        );

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        let points = reopened
            .get_points("docs", &["point-1".to_string()])
            .unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].vector, vec![2.0, 0.0]);
        assert_eq!(points[0].payload, json!({"version": "streamer"}));
    }

    #[test]
    fn empty_overlay_preserves_sealed_search_results_across_restart() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert(
            "docs",
            vec![
                ls_vec_point("nearest", 0.0, "v1"),
                ls_vec_point("middle", 1.0, "v1"),
                ls_vec_point("far", 2.0, "v1"),
            ],
        )
        .unwrap();
        db.compact_collection("docs").unwrap();
        let request = SearchRequest {
            graph: None,
            vector: vec![0.0, 0.0],
            vector_name: None,
            k: 3,
            filter: None,
            budget_ms: None,
            consistency: None,
            ef_search: None,
            recall_target: None,
            with_payload: None,
        };
        let before = db
            .search("docs", request.clone())
            .unwrap()
            .hits
            .into_iter()
            .map(|hit| hit.id)
            .collect::<Vec<_>>();

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        let after = reopened
            .search("docs", request)
            .unwrap()
            .hits
            .into_iter()
            .map(|hit| hit.id)
            .collect::<Vec<_>>();
        assert_eq!(after, before);
    }

    #[test]
    fn pitr_before_sealed_delete_resets_later_overlay_visibility() {
        let temp = TempDir::new().unwrap();
        let snapshot = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert("docs", vec![ls_vec_point("restore-me", 1.0, "v1")])
            .unwrap();
        db.compact_collection("docs").unwrap();
        let pre_delete_lsn =
            Wal::retained_base_lsn(&temp.path().join("collections/docs/wal")).unwrap();
        db.delete("docs", &["restore-me".to_string()]).unwrap();
        assert!(
            db.get_points("docs", &["restore-me".to_string()])
                .unwrap()
                .is_empty()
        );
        db.snapshot(snapshot.path()).unwrap();

        db.restore_to_wal_lsns(
            snapshot.path(),
            &HashMap::from([("docs".to_string(), pre_delete_lsn)]),
        )
        .unwrap();
        assert_eq!(
            db.get_points("docs", &["restore-me".to_string()])
                .unwrap()
                .len(),
            1
        );

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(
            reopened
                .get_points("docs", &["restore-me".to_string()])
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn db_holds_data_directory_lock_until_the_last_clone_drops() {
        let sandbox = TempDir::new().unwrap();
        let root = sandbox.path().join("db");
        let db = Db::open(&root).unwrap();
        let clone = db.clone();
        assert!(matches!(
            Db::open(&root),
            Err(GaussError::DataDirLocked { .. })
        ));
        drop(db);
        assert!(matches!(
            Db::open(&root),
            Err(GaussError::DataDirLocked { .. })
        ));
        drop(clone);
        Db::open(&root).unwrap();
    }

    #[test]
    fn recovery_removes_unreferenced_segments_but_rejects_missing_installed_segments() {
        let sandbox = TempDir::new().unwrap();
        let root = sandbox.path().join("db");
        let db = Db::open(&root).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert("docs", vec![ls_vec_point("stable", 1.0, "before")])
            .unwrap();
        db.compact_collection("docs").unwrap();
        drop(db);

        let collection_dir = root.join("collections/docs");
        let orphan = collection_dir.join("searchers/sg-unreferenced");
        fs::create_dir(&orphan).unwrap();
        let reopened = Db::open(&root).unwrap();
        assert!(!orphan.exists());
        drop(reopened);

        let manifest = checkpoint::read_segments_manifest(&collection_dir)
            .unwrap()
            .unwrap();
        let installed = collection_dir.join("searchers").join(&manifest.segments[0]);
        fs::remove_dir_all(installed).unwrap();
        assert!(matches!(
            Db::open(&root),
            Err(GaussError::SegmentCorruption { .. })
        ));
    }

    #[test]
    fn snapshot_destination_lock_excludes_concurrent_publish_and_cleans_orphan_staging() {
        let sandbox = TempDir::new().unwrap();
        let root = sandbox.path().join("db");
        let destination = sandbox.path().join("snapshot");
        let db = Db::open(&root).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();

        let destination_lock = super::DataDirLock::acquire(&destination).unwrap();
        assert!(matches!(
            db.snapshot(&destination),
            Err(GaussError::DataDirLocked { .. })
        ));
        drop(destination_lock);

        let orphan = super::snapshot_staging_path(&destination, uuid::Uuid::new_v4()).unwrap();
        fs::create_dir(&orphan).unwrap();
        fs::write(orphan.join("partial"), b"not a snapshot").unwrap();
        db.snapshot(&destination).unwrap();
        assert!(!orphan.exists());
        drop(db);
        Db::open(&destination).unwrap();
    }

    #[test]
    fn snapshot_fork_gets_new_graph_identity_and_restore_retains_installation() {
        let sandbox = TempDir::new().unwrap();
        let root = sandbox.path().join("db");
        let snapshot = sandbox.path().join("snapshot");
        let db = Db::open(&root).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let database_id = db.graph_database_id();
        let open_epoch = db.graph_allocator_epoch();

        db.snapshot(&snapshot).unwrap();
        assert!(!snapshot.join(GRAPH_IDENTITY_FILE).exists());

        let fork = Db::open(&snapshot).unwrap();
        assert_ne!(fork.graph_database_id(), database_id);
        assert_eq!(fork.graph_allocator_epoch(), 1);
        drop(fork);

        db.restore(&snapshot).unwrap();
        assert_eq!(db.graph_database_id(), database_id);
        assert_eq!(db.graph_allocator_epoch(), open_epoch + 1);
        assert!(root.join(GRAPH_IDENTITY_FILE).is_file());

        drop(db);
        let reopened = Db::open(&root).unwrap();
        assert_eq!(reopened.graph_database_id(), database_id);
        assert_eq!(reopened.graph_allocator_epoch(), open_epoch + 2);
    }

    #[test]
    fn g0_c2_pitr_burns_allocator_ranges_and_fork_rejects_foreign_edge_tokens() {
        use crate::graph::{
            ConfigureEdgeTypeRequest, EdgePropertyMode, GraphRelationScope, RelateRequest,
            UpdateEdgeRequest,
        };

        let sandbox = TempDir::new().unwrap();
        let root = sandbox.path().join("db");
        let snapshot = sandbox.path().join("snapshot");
        let db = Db::open(&root).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let scope = crate::tenant::TenantScope::tenant("c2-writer", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        db.upsert(
            "docs",
            vec![
                graph_point("source", 1.0, "acme"),
                graph_point("target", 2.0, "acme"),
            ],
        )
        .unwrap();
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: "cites".to_string(),
                weight_property: None,
            },
            true,
            &scope,
        )
        .unwrap();
        let request = |key: &str| RelateRequest {
            source_point_id: "source".to_string(),
            target_point_id: "target".to_string(),
            edge_type: "cites".to_string(),
            properties: json!({"key": key}),
            scope: GraphRelationScope::Local,
            idempotency_key: Some(key.to_string()),
        };
        let snapshotted = db
            .relate_scoped("docs", request("snapshotted"), true, &scope)
            .unwrap();
        let database_id = db.graph_database_id();
        let pre_restore_epoch = db.graph_allocator_epoch();
        db.snapshot(&snapshot).unwrap();

        let fork = Db::open(&snapshot).unwrap();
        assert_ne!(fork.graph_database_id(), database_id);
        let foreign_error = fork
            .unrelate_scoped("docs", &snapshotted.edge_id, true, &scope)
            .unwrap_err();
        assert!(
            foreign_error
                .to_string()
                .contains("another database incarnation"),
            "{foreign_error}"
        );
        drop(fork);

        db.upsert("docs", vec![graph_point("post-snapshot", 3.0, "acme")])
            .unwrap();
        let post_snapshot_nid = db
            .get_coll("docs")
            .unwrap()
            .read()
            .graph_resolver
            .as_ref()
            .unwrap()
            .live_nid("post-snapshot")
            .unwrap();
        let post_snapshot_edge = db
            .relate_scoped("docs", request("post-snapshot"), true, &scope)
            .unwrap();
        let post_snapshot_edge_id =
            crate::edge_token::decode(database_id, &post_snapshot_edge.edge_id).unwrap();

        db.restore(&snapshot).unwrap();
        assert_eq!(db.graph_database_id(), database_id);
        assert!(db.graph_allocator_epoch() > pre_restore_epoch);
        db.update_edge_scoped(
            "docs",
            &snapshotted.edge_id,
            UpdateEdgeRequest {
                mode: EdgePropertyMode::Merge,
                properties: json!({"restored": true}),
            },
            true,
            &scope,
        )
        .unwrap();
        assert!(
            db.unrelate_scoped("docs", &post_snapshot_edge.edge_id, true, &scope)
                .is_err(),
            "post-snapshot topology must not survive PITR"
        );

        db.upsert("docs", vec![graph_point("after-restore", 4.0, "acme")])
            .unwrap();
        let after_restore_nid = db
            .get_coll("docs")
            .unwrap()
            .read()
            .graph_resolver
            .as_ref()
            .unwrap()
            .live_nid("after-restore")
            .unwrap();
        let after_restore_edge = db
            .relate_scoped("docs", request("after-restore"), true, &scope)
            .unwrap();
        let after_restore_edge_id =
            crate::edge_token::decode(database_id, &after_restore_edge.edge_id).unwrap();
        assert!(after_restore_nid.raw() > post_snapshot_nid.raw());
        assert!(after_restore_edge_id.raw() > post_snapshot_edge_id.raw());
    }

    #[test]
    fn maintenance_guard_can_latch_a_fatal_restore_state() {
        let maintenance = Arc::new(AtomicBool::new(false));
        {
            let mut guard = super::MaintenanceGuard::enter(Arc::clone(&maintenance)).unwrap();
            guard.latch();
        }
        assert!(maintenance.load(Ordering::Acquire));
        assert!(super::MaintenanceGuard::enter(maintenance).is_err());
    }

    #[test]
    fn startup_recovers_each_durable_restore_journal_phase_to_one_generation() {
        use crate::restore_journal::{self, RestoreJournal, RestorePhase};

        for phase in [
            RestorePhase::Prepared,
            RestorePhase::OldMoved,
            RestorePhase::NewInstalled,
        ] {
            let sandbox = TempDir::new().unwrap();
            let root = sandbox.path().join("live");
            let source = sandbox.path().join("source");
            let old = super::Db::open(&root).unwrap();
            old.create_collection(ls_vec_config("old")).unwrap();
            drop(old);
            let new = super::Db::open(&source).unwrap();
            new.create_collection(ls_vec_config("new")).unwrap();
            drop(new);

            let control = super::restore_control_dir(&root).unwrap();
            fs::create_dir(&control).unwrap();
            let operation_id = uuid::Uuid::new_v4();
            let (staging, backup) =
                super::operation_siblings(&control.join("generation"), "restore", operation_id)
                    .unwrap();
            fs::create_dir(&staging).unwrap();
            super::copy_dir_contents(&source, &staging).unwrap();

            match phase {
                RestorePhase::Prepared => {}
                RestorePhase::OldMoved => {
                    super::durable_rename(&root, &backup).unwrap();
                }
                RestorePhase::NewInstalled => {
                    super::durable_rename(&root, &backup).unwrap();
                    super::durable_rename(&staging, &root).unwrap();
                }
            }
            let journal = RestoreJournal::new(
                operation_id,
                phase,
                super::sibling_file_name(&staging).unwrap(),
                super::sibling_file_name(&backup).unwrap(),
            )
            .unwrap();
            restore_journal::write(&control, &journal).unwrap();

            let recovered = super::Db::open(&root).unwrap();
            let names = recovered
                .list_collections()
                .into_iter()
                .map(|config| config.name)
                .collect::<Vec<_>>();
            let expected = if phase == RestorePhase::Prepared {
                vec!["old".to_string()]
            } else {
                vec!["new".to_string()]
            };
            assert_eq!(names, expected, "unexpected generation for {phase:?}");
            assert!(!control.exists());
        }
    }

    #[test]
    fn generation_restore_switches_current_and_reopens_new_generation() {
        let sandbox = TempDir::new().unwrap();
        let data_dir = sandbox.path().join("generation-data");
        crate::storage_layout::initialize_empty(&data_dir).unwrap();
        let db = super::Db::open(&data_dir).unwrap();
        db.create_collection(ls_vec_config("old")).unwrap();
        let database_id = db.graph_database_id();
        let open_epoch = db.graph_allocator_epoch();

        let source_db_dir = sandbox.path().join("source-db");
        let source_db = super::Db::open(&source_db_dir).unwrap();
        source_db.create_collection(ls_vec_config("new")).unwrap();
        let snapshot = sandbox.path().join("source-snapshot");
        source_db.snapshot(&snapshot).unwrap();
        drop(source_db);

        let previous = db.active_generation().unwrap();
        db.restore(&snapshot).unwrap();
        let installed = db.active_generation().unwrap();
        assert_ne!(installed, previous);
        assert_eq!(db.graph_database_id(), database_id);
        assert_eq!(db.graph_allocator_epoch(), open_epoch + 1);
        assert!(
            !data_dir
                .join(crate::storage_layout::GENERATIONS_DIR)
                .join(&installed)
                .join(GRAPH_IDENTITY_FILE)
                .exists()
        );
        assert_eq!(
            db.list_collections()
                .into_iter()
                .map(|config| config.name)
                .collect::<Vec<_>>(),
            vec!["new".to_string()]
        );
        drop(db);

        let reopened = super::Db::open(&data_dir).unwrap();
        assert_eq!(
            reopened.active_generation().as_deref(),
            Some(installed.as_str())
        );
        assert_eq!(reopened.list_collections()[0].name, "new");
        assert_eq!(reopened.graph_database_id(), database_id);
        assert_eq!(reopened.graph_allocator_epoch(), open_epoch + 2);
    }

    #[test]
    fn startup_cleans_restore_staging_without_a_published_journal_under_data_lock() {
        let sandbox = TempDir::new().unwrap();
        let root = sandbox.path().join("live");
        let db = super::Db::open(&root).unwrap();
        drop(db);
        let control = super::restore_control_dir(&root).unwrap();
        fs::create_dir(&control).unwrap();
        fs::write(control.join("preparing"), b"still active").unwrap();

        let reopened = super::Db::open(&root).unwrap();
        assert!(reopened.list_collections().is_empty());
        assert!(!control.exists());
    }

    #[test]
    fn fatal_restore_maintenance_is_read_only() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert("docs", vec![ls_vec_point("stable", 1.0, "before")])
            .unwrap();

        db.maintenance.store(true, Ordering::Release);
        assert!(!db.durability_ready());
        assert_eq!(db.count("docs", None).unwrap().count, 1);
        assert!(matches!(
            db.upsert("docs", vec![ls_vec_point("rejected", 2.0, "after")]),
            Err(GaussError::WalUnavailable(_))
        ));
        assert!(matches!(
            db.delete("docs", &["stable".to_string()]),
            Err(GaussError::WalUnavailable(_))
        ));
        assert_eq!(db.count("docs", None).unwrap().count, 1);
    }

    #[test]
    fn wait_true_wal_failures_do_not_publish_batch_state_and_poison_collection() {
        for failure in ["write", "sync"] {
            let temp = TempDir::new().unwrap();
            let db = Db::open(temp.path()).unwrap();
            db.create_collection(ls_vec_config("docs")).unwrap();
            let coll = db.get_coll("docs").unwrap();
            if failure == "write" {
                coll.read().wal.inject_write_failure();
            } else {
                coll.read().wal.inject_sync_failure();
            }

            let error = db
                .upsert_wait(
                    "docs",
                    vec![
                        ls_vec_point("a", 1.0, "failed"),
                        ls_vec_point("b", 2.0, "failed"),
                    ],
                    true,
                )
                .unwrap_err();
            assert!(matches!(error, GaussError::WalUnavailable(_)));
            assert_eq!(db.count("docs", None).unwrap().count, 0);
            assert!(matches!(
                db.upsert("docs", vec![ls_vec_point("later", 3.0, "failed")]),
                Err(GaussError::WalUnavailable(_))
            ));
        }
    }

    #[test]
    fn request_batch_replays_as_an_atomic_record() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert(
            "docs",
            vec![
                ls_vec_point("a", 1.0, "batch"),
                ls_vec_point("b", 2.0, "batch"),
            ],
        )
        .unwrap();
        let records = Wal::load(&temp.path().join("collections/docs/wal")).unwrap();
        assert_eq!(records.len(), 1);
        assert!(matches!(
            &records[0].entry,
            WalEntry::UpsertBatch { points } if points.len() == 2
        ));
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("docs", None).unwrap().count, 2);
    }

    #[test]
    fn graph_batch_replay_preserves_upsert_and_retires_reinserted_incarnations() {
        use crate::{
            graph::Nid,
            wal::{GraphBatch, GraphHandleAssignment, GraphPointMutation},
        };

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let nids = db
            .graph_identity
            .allocate_nids(std::num::NonZeroU64::new(2).unwrap())
            .unwrap()
            .nids()
            .collect::<Vec<_>>();
        let old_nid = nids[0];
        let new_nid = nids[1];

        let coll = db.get_coll("docs").unwrap();
        let mut collection = coll.write();
        collection
            .wal
            .append(&WalEntry::GraphEpochAdvance {
                epoch: crate::graph::GraphEpoch::INITIAL,
                enabled: true,
            })
            .unwrap();
        let batches = [
            GraphBatch {
                point_mutations: vec![GraphPointMutation::Upsert {
                    point: ls_vec_point("node", 1.0, "first"),
                }],
                handle_assignments: vec![GraphHandleAssignment {
                    point_id: "node".to_string(),
                    nid: old_nid,
                }],
                ..GraphBatch::default()
            },
            GraphBatch {
                point_mutations: vec![GraphPointMutation::Upsert {
                    point: ls_vec_point("node", 2.0, "updated"),
                }],
                ..GraphBatch::default()
            },
            GraphBatch {
                point_mutations: vec![GraphPointMutation::Delete {
                    point_id: "node".to_string(),
                    nid: old_nid,
                }],
                ..GraphBatch::default()
            },
            GraphBatch {
                point_mutations: vec![GraphPointMutation::Upsert {
                    point: ls_vec_point("node", 3.0, "reinserted"),
                }],
                handle_assignments: vec![GraphHandleAssignment {
                    point_id: "node".to_string(),
                    nid: new_nid,
                }],
                ..GraphBatch::default()
            },
        ];
        for batch in batches {
            collection
                .wal
                .append(&WalEntry::GraphBatch { batch })
                .unwrap();
        }
        drop(collection);
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let points = reopened.get_points("docs", &["node".to_string()]).unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].payload["version"], "reinserted");
        let coll = reopened.get_coll("docs").unwrap();
        let collection = coll.read();
        let resolver = collection.graph_resolver.as_ref().unwrap();
        assert_eq!(resolver.live_nid("node"), Some(new_nid));
        assert_eq!(resolver.live_point_id(new_nid), Some("node"));
        assert!(resolver.is_retired(old_nid));
        assert_ne!(old_nid, new_nid);
        assert!(Nid::from_parts(old_nid.epoch(), old_nid.counter()).is_some());
    }

    #[test]
    fn graph_batch_replays_types_edges_properties_and_stable_unrelate() {
        use crate::{
            graph::{
                EdgeMutation, EdgePropertyMode, EdgePropertyMutation, GraphNamespace,
                RelateMutation, TypeId, UnrelateMutation,
            },
            wal::{GraphHandleAssignment, GraphIdempotencyState, GraphTypeConfiguration},
        };

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let nids = db
            .graph_identity
            .allocate_nids(std::num::NonZeroU64::new(2).unwrap())
            .unwrap()
            .nids()
            .collect::<Vec<_>>();
        let edge_ids = db
            .graph_identity
            .allocate_edge_ids(std::num::NonZeroU64::new(2).unwrap())
            .unwrap()
            .edge_ids()
            .collect::<Vec<_>>();
        let edge_id = edge_ids[0];
        let conflicting_edge_id = edge_ids[1];
        let type_id = TypeId::from_raw(7);
        let tenant = GraphNamespace::Tenant("acme".to_string());
        let mut source = ls_vec_point("source", 1.0, "first");
        source.payload[crate::tenant::TENANT_FIELD] = json!("acme");
        let mut target = ls_vec_point("target", 2.0, "first");
        target.payload[crate::tenant::TENANT_FIELD] = json!("acme");

        let coll = db.get_coll("docs").unwrap();
        let mut collection = coll.write();
        collection
            .wal
            .append(&WalEntry::GraphEpochAdvance {
                epoch: crate::graph::GraphEpoch::INITIAL,
                enabled: true,
            })
            .unwrap();
        collection
            .wal
            .append(&WalEntry::GraphBatch {
                batch: GraphBatch {
                    type_configurations: vec![GraphTypeConfiguration {
                        type_id,
                        name: "cites".to_string(),
                        weight_property: Some("weight".to_string()),
                    }],
                    point_mutations: vec![
                        GraphPointMutation::Upsert { point: source },
                        GraphPointMutation::Upsert { point: target },
                    ],
                    handle_assignments: vec![
                        GraphHandleAssignment {
                            point_id: "source".to_string(),
                            nid: nids[0],
                        },
                        GraphHandleAssignment {
                            point_id: "target".to_string(),
                            nid: nids[1],
                        },
                    ],
                    edge_mutations: vec![EdgeMutation::Relate(RelateMutation {
                        edge_id,
                        source: nids[0],
                        target: nids[1],
                        type_id,
                        namespace: tenant.clone(),
                        properties: json!({"since": 2026}),
                    })],
                    idempotency: Some(GraphIdempotencyState {
                        key: "relate-request".to_string(),
                        request_sha256: [7; 32],
                        // Deliberately expired in wall-clock terms. G0 cannot
                        // evict it before checkpoint/compaction proves the
                        // corresponding WAL is no longer replayable.
                        created_at_unix_ms: 1,
                        expires_at_unix_ms: 2,
                        edge_ids: vec![edge_id],
                    }),
                    ..GraphBatch::default()
                },
            })
            .unwrap();
        collection
            .wal
            .append(&WalEntry::GraphBatch {
                batch: GraphBatch {
                    edge_mutations: vec![EdgeMutation::Properties(EdgePropertyMutation {
                        edge_id,
                        mode: EdgePropertyMode::Merge,
                        properties: json!({"weight": 2}),
                    })],
                    ..GraphBatch::default()
                },
            })
            .unwrap();
        drop(collection);
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("docs").unwrap();
        {
            let mut collection = coll.write();
            {
                let graph = collection.graph_mutable.as_ref().unwrap();
                assert_eq!(graph.types().resolve_name("cites"), Some(type_id));
                assert_eq!(graph.live_edge_count(), 1);
                assert_eq!(graph.outgoing(&tenant, nids[0]), &[edge_id]);
                assert_eq!(graph.incoming(&tenant, nids[1]), &[edge_id]);
                let edge = graph.edge(edge_id).unwrap();
                assert_eq!(edge.properties, json!({"since": 2026, "weight": 2}));
                assert_eq!(graph.idempotency_len(), 1);
                let retry = graph.idempotency("relate-request").unwrap();
                assert_eq!(retry.request_sha256, [7; 32]);
                assert_eq!(retry.edge_ids, vec![edge_id]);
            }
            let Collection {
                config,
                streamer,
                searchers,
                id_index,
                graph_lifecycle,
                graph_resolver,
                graph_mutable,
                payload_index,
                ..
            } = &mut *collection;
            let mut moved_source = ls_vec_point("source", 3.0, "must-not-move");
            moved_source.payload[crate::tenant::TENANT_FIELD] = json!("globex");
            let tenant_error = super::apply_wal_graph_batch(
                config,
                streamer,
                searchers,
                id_index,
                super::GraphReplayState {
                    record_lsn: 0,
                    lifecycle: *graph_lifecycle,
                    resolver: graph_resolver,
                    mutable: graph_mutable,
                },
                payload_index,
                GraphBatch {
                    point_mutations: vec![GraphPointMutation::Upsert {
                        point: moved_source,
                    }],
                    ..GraphBatch::default()
                },
            )
            .unwrap_err();
            assert!(tenant_error.to_string().contains("incident edge"));
            assert_eq!(
                graph_resolver.as_ref().unwrap().live_nid("source"),
                Some(nids[0])
            );
            assert_eq!(graph_mutable.as_ref().unwrap().live_edge_count(), 1);
            assert_eq!(
                streamer.points["source"].payload[crate::tenant::TENANT_FIELD],
                json!("acme")
            );
            let idempotency_error = super::apply_wal_graph_batch(
                config,
                streamer,
                searchers,
                id_index,
                super::GraphReplayState {
                    record_lsn: 0,
                    lifecycle: *graph_lifecycle,
                    resolver: graph_resolver,
                    mutable: graph_mutable,
                },
                payload_index,
                GraphBatch {
                    edge_mutations: vec![EdgeMutation::Relate(RelateMutation {
                        edge_id: conflicting_edge_id,
                        source: nids[0],
                        target: nids[1],
                        type_id,
                        namespace: tenant.clone(),
                        properties: json!({}),
                    })],
                    idempotency: Some(GraphIdempotencyState {
                        key: "relate-request".to_string(),
                        request_sha256: [8; 32],
                        created_at_unix_ms: 3,
                        expires_at_unix_ms: 4,
                        edge_ids: vec![conflicting_edge_id],
                    }),
                    ..GraphBatch::default()
                },
            )
            .unwrap_err();
            assert!(idempotency_error.to_string().contains("already bound"));
            assert!(
                graph_mutable
                    .as_ref()
                    .unwrap()
                    .edge(conflicting_edge_id)
                    .is_none()
            );
            collection
                .wal
                .append(&WalEntry::GraphBatch {
                    batch: GraphBatch {
                        point_mutations: vec![GraphPointMutation::Delete {
                            point_id: "source".to_string(),
                            nid: nids[0],
                        }],
                        ..GraphBatch::default()
                    },
                })
                .unwrap();
        }
        drop(coll);
        drop(reopened);

        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("docs").unwrap();
        let mut collection = coll.write();
        {
            let graph = collection.graph_mutable.as_ref().unwrap();
            assert_eq!(graph.live_edge_count(), 1);
            assert_eq!(graph.stored_edge_count(), 1);
            assert_eq!(graph.tombstone_count(), 0);
            assert!(graph.edge(edge_id).is_some());
            assert_eq!(graph.outgoing(&tenant, nids[0]), &[edge_id]);
        }
        assert!(
            collection
                .overlays
                .current_ref()
                .edge_tombstones()
                .is_empty()
        );
        assert!(
            collection
                .graph_resolver
                .as_ref()
                .unwrap()
                .is_retired(nids[0])
        );
        assert!(!collection.id_index.contains_key("source"));
        collection
            .wal
            .append(&WalEntry::GraphBatch {
                batch: GraphBatch {
                    edge_mutations: vec![EdgeMutation::Unrelate(UnrelateMutation { edge_id })],
                    ..GraphBatch::default()
                },
            })
            .unwrap();
        drop(collection);
        drop(coll);
        drop(reopened);

        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("docs").unwrap();
        let mut collection = coll.write();
        let graph = collection.graph_mutable.as_ref().unwrap();
        assert_eq!(graph.live_edge_count(), 0);
        assert_eq!(graph.stored_edge_count(), 1);
        assert_eq!(graph.tombstone_count(), 1);
        assert!(graph.edge(edge_id).is_none());
        assert!(
            collection
                .overlays
                .current_ref()
                .edge_tombstones()
                .contains(edge_id.raw())
        );
        for (raw_epoch, enabled) in [(2, false), (3, true)] {
            collection
                .wal
                .append(&WalEntry::GraphEpochAdvance {
                    epoch: crate::graph::GraphEpoch::from_raw(raw_epoch).unwrap(),
                    enabled,
                })
                .unwrap();
        }
        drop(collection);
        drop(coll);
        drop(reopened);

        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("docs").unwrap();
        let collection = coll.read();
        assert_eq!(
            collection.graph_mutable.as_ref().unwrap().live_edge_count(),
            0
        );
        assert_eq!(
            collection.graph_mutable.as_ref().unwrap().idempotency_len(),
            0
        );
        assert!(
            collection
                .overlays
                .current_ref()
                .edge_tombstones()
                .is_empty()
        );
        assert_eq!(
            collection
                .graph_resolver
                .as_ref()
                .unwrap()
                .live_nid("target"),
            Some(nids[1])
        );
    }

    #[test]
    fn graph_deferred_sessions_bind_exact_incarnations_and_abort_pending_edges() {
        use crate::{
            graph::{GraphNamespace, TypeId},
            wal::{
                GraphBatch, GraphDeferredBind, GraphDeferredEndpoint, GraphDeferredSessionMutation,
                GraphEdgeBind, GraphHandleAssignment, GraphPointMutation, GraphTypeConfiguration,
            },
        };

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let nids = db
            .graph_identity
            .allocate_nids(std::num::NonZeroU64::new(2).unwrap())
            .unwrap()
            .nids()
            .collect::<Vec<_>>();
        let edge_ids = db
            .graph_identity
            .allocate_edge_ids(std::num::NonZeroU64::new(3).unwrap())
            .unwrap()
            .edge_ids()
            .collect::<Vec<_>>();
        let type_id = TypeId::from_raw(9);
        let tenant = GraphNamespace::Tenant("acme".to_string());
        let mut source = ls_vec_point("source", 1.0, "source");
        source.payload[crate::tenant::TENANT_FIELD] = json!("acme");

        let coll = db.get_coll("docs").unwrap();
        let mut collection = coll.write();
        collection
            .wal
            .append(&WalEntry::GraphEpochAdvance {
                epoch: crate::graph::GraphEpoch::INITIAL,
                enabled: true,
            })
            .unwrap();
        collection
            .wal
            .append(&WalEntry::GraphBatch {
                batch: GraphBatch {
                    type_configurations: vec![GraphTypeConfiguration {
                        type_id,
                        name: "links".to_string(),
                        weight_property: None,
                    }],
                    point_mutations: vec![GraphPointMutation::Upsert { point: source }],
                    handle_assignments: vec![GraphHandleAssignment {
                        point_id: "source".to_string(),
                        nid: nids[0],
                    }],
                    ..GraphBatch::default()
                },
            })
            .unwrap();
        let opening_lsn = collection.wal.len().unwrap();
        collection
            .wal
            .append(&WalEntry::GraphBatch {
                batch: GraphBatch {
                    deferred_sessions: vec![GraphDeferredSessionMutation::Open {
                        session_id: "load-1".to_string(),
                    }],
                    ..GraphBatch::default()
                },
            })
            .unwrap();
        collection
            .wal
            .append(&WalEntry::GraphBatch {
                batch: GraphBatch {
                    deferred_binds: vec![GraphDeferredBind {
                        session_id: "load-1".to_string(),
                        edge_id: edge_ids[0],
                        source_point_id: "source".to_string(),
                        target_point_id: "target".to_string(),
                        source_nid: Some(nids[0]),
                        target_nid: None,
                        type_id,
                        namespace: tenant.clone(),
                        properties: json!({"pending": true}),
                    }],
                    ..GraphBatch::default()
                },
            })
            .unwrap();
        drop(collection);
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("docs").unwrap();
        let mut collection = coll.write();
        let graph = collection.graph_mutable.as_ref().unwrap();
        assert_eq!(graph.deferred_opening_lsn("load-1"), Some(opening_lsn));
        assert_eq!(graph.pending_edge_count(), 1);
        assert_eq!(
            graph.pending_binding_count("target", "load-1", opening_lsn),
            1
        );
        assert_eq!(
            graph.pending_binding_count("source", "load-1", opening_lsn),
            0
        );
        assert_eq!(graph.live_edge_count(), 0);
        assert_eq!(graph.stored_edge_count(), 1);

        let steal_lsn = collection.wal.len().unwrap();
        {
            let Collection {
                config,
                streamer,
                searchers,
                id_index,
                graph_lifecycle,
                graph_resolver,
                graph_mutable,
                payload_index,
                ..
            } = &mut *collection;
            let steal_error = super::apply_wal_graph_batch(
                config,
                streamer,
                searchers,
                id_index,
                super::GraphReplayState {
                    record_lsn: steal_lsn,
                    lifecycle: *graph_lifecycle,
                    resolver: graph_resolver,
                    mutable: graph_mutable,
                },
                payload_index,
                GraphBatch {
                    edge_mutations: vec![crate::graph::EdgeMutation::Relate(
                        crate::graph::RelateMutation {
                            edge_id: edge_ids[0],
                            source: nids[0],
                            target: nids[1],
                            type_id,
                            namespace: tenant.clone(),
                            properties: json!({}),
                        },
                    )],
                    ..GraphBatch::default()
                },
            )
            .unwrap_err();
            assert!(steal_error.to_string().contains("already exists"));
            assert_eq!(graph_mutable.as_ref().unwrap().pending_edge_count(), 1);
            assert_eq!(graph_mutable.as_ref().unwrap().live_edge_count(), 0);
        }

        let mut target = ls_vec_point("target", 2.0, "target");
        target.payload[crate::tenant::TENANT_FIELD] = json!("acme");
        collection
            .wal
            .append(&WalEntry::GraphBatch {
                batch: GraphBatch {
                    point_mutations: vec![GraphPointMutation::Upsert { point: target }],
                    handle_assignments: vec![GraphHandleAssignment {
                        point_id: "target".to_string(),
                        nid: nids[1],
                    }],
                    edge_binds: vec![GraphEdgeBind {
                        session_id: "load-1".to_string(),
                        edge_id: edge_ids[0],
                        endpoint: GraphDeferredEndpoint::Target,
                        point_id: "target".to_string(),
                        nid: nids[1],
                    }],
                    ..GraphBatch::default()
                },
            })
            .unwrap();
        drop(collection);
        drop(coll);
        drop(reopened);

        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("docs").unwrap();
        let mut collection = coll.write();
        let graph = collection.graph_mutable.as_ref().unwrap();
        assert_eq!(graph.pending_edge_count(), 0);
        assert_eq!(
            graph.pending_binding_count("target", "load-1", opening_lsn),
            0
        );
        assert_eq!(graph.live_edge_count(), 1);
        let edge = graph.edge(edge_ids[0]).unwrap();
        assert_eq!(edge.source, nids[0]);
        assert_eq!(edge.target, nids[1]);
        collection
            .wal
            .append(&WalEntry::GraphBatch {
                batch: GraphBatch {
                    deferred_sessions: vec![GraphDeferredSessionMutation::Commit {
                        session_id: "load-1".to_string(),
                    }],
                    ..GraphBatch::default()
                },
            })
            .unwrap();
        let immediate_opening_lsn = collection.wal.len().unwrap();
        collection
            .wal
            .append(&WalEntry::GraphBatch {
                batch: GraphBatch {
                    deferred_sessions: vec![GraphDeferredSessionMutation::Open {
                        session_id: "load-3".to_string(),
                    }],
                    deferred_binds: vec![GraphDeferredBind {
                        session_id: "load-3".to_string(),
                        edge_id: edge_ids[2],
                        source_point_id: "source".to_string(),
                        target_point_id: "target".to_string(),
                        source_nid: Some(nids[0]),
                        target_nid: Some(nids[1]),
                        type_id,
                        namespace: GraphNamespace::Tenant("acme".to_string()),
                        properties: json!({"immediate": true}),
                    }],
                    ..GraphBatch::default()
                },
            })
            .unwrap();
        collection
            .wal
            .append(&WalEntry::GraphBatch {
                batch: GraphBatch {
                    deferred_sessions: vec![GraphDeferredSessionMutation::Open {
                        session_id: "load-2".to_string(),
                    }],
                    ..GraphBatch::default()
                },
            })
            .unwrap();
        collection
            .wal
            .append(&WalEntry::GraphBatch {
                batch: GraphBatch {
                    deferred_binds: vec![GraphDeferredBind {
                        session_id: "load-2".to_string(),
                        edge_id: edge_ids[1],
                        source_point_id: "source".to_string(),
                        target_point_id: "never-created".to_string(),
                        source_nid: Some(nids[0]),
                        target_nid: None,
                        type_id,
                        namespace: tenant,
                        properties: json!({}),
                    }],
                    ..GraphBatch::default()
                },
            })
            .unwrap();
        drop(collection);
        drop(coll);
        drop(reopened);

        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("docs").unwrap();
        let mut collection = coll.write();
        assert!(
            collection
                .graph_mutable
                .as_ref()
                .unwrap()
                .deferred_session_is_committed("load-1")
        );
        assert_eq!(
            collection
                .graph_mutable
                .as_ref()
                .unwrap()
                .deferred_opening_lsn("load-3"),
            Some(immediate_opening_lsn)
        );
        assert!(
            collection
                .graph_mutable
                .as_ref()
                .unwrap()
                .edge(edge_ids[2])
                .is_some()
        );
        assert_eq!(
            collection.graph_mutable.as_ref().unwrap().live_edge_count(),
            2
        );
        assert_eq!(
            collection
                .graph_mutable
                .as_ref()
                .unwrap()
                .pending_edge_count(),
            1
        );
        let close_lsn = collection.wal.len().unwrap();
        {
            let Collection {
                config,
                streamer,
                searchers,
                id_index,
                graph_lifecycle,
                graph_resolver,
                graph_mutable,
                payload_index,
                ..
            } = &mut *collection;
            let close_error = super::apply_wal_graph_batch(
                config,
                streamer,
                searchers,
                id_index,
                super::GraphReplayState {
                    record_lsn: close_lsn,
                    lifecycle: *graph_lifecycle,
                    resolver: graph_resolver,
                    mutable: graph_mutable,
                },
                payload_index,
                GraphBatch {
                    deferred_sessions: vec![GraphDeferredSessionMutation::Commit {
                        session_id: "load-2".to_string(),
                    }],
                    ..GraphBatch::default()
                },
            )
            .unwrap_err();
            assert!(
                close_error
                    .to_string()
                    .contains("graph.deferred_endpoints_remain")
            );
            assert_eq!(graph_mutable.as_ref().unwrap().pending_edge_count(), 1);
            assert!(
                graph_mutable
                    .as_ref()
                    .unwrap()
                    .deferred_session_is_open("load-2")
            );
        }
        collection
            .wal
            .append(&WalEntry::GraphBatch {
                batch: GraphBatch {
                    deferred_sessions: vec![GraphDeferredSessionMutation::Commit {
                        session_id: "load-3".to_string(),
                    }],
                    ..GraphBatch::default()
                },
            })
            .unwrap();
        collection
            .wal
            .append(&WalEntry::GraphBatch {
                batch: GraphBatch {
                    deferred_sessions: vec![GraphDeferredSessionMutation::Abort {
                        session_id: "load-2".to_string(),
                    }],
                    ..GraphBatch::default()
                },
            })
            .unwrap();
        drop(collection);
        drop(coll);
        drop(reopened);

        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("docs").unwrap();
        let collection = coll.read();
        let graph = collection.graph_mutable.as_ref().unwrap();
        assert!(graph.deferred_session_is_aborted("load-2"));
        assert!(graph.deferred_session_is_committed("load-3"));
        assert_eq!(graph.pending_edge_count(), 0);
        assert_eq!(graph.live_edge_count(), 2);
        assert_eq!(graph.stored_edge_count(), 3);
        assert_eq!(graph.tombstone_count(), 1);
        assert!(graph.edge(edge_ids[1]).is_none());
        assert!(
            collection
                .overlays
                .current_ref()
                .edge_tombstones()
                .contains(edge_ids[1].raw())
        );
    }

    #[test]
    fn graph_batch_semantic_rejection_publishes_no_point_or_assignment_prefix() {
        use crate::wal::{GraphBatch, GraphHandleAssignment, GraphPointMutation};

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let nid = db
            .graph_identity
            .allocate_nids(std::num::NonZeroU64::new(1).unwrap())
            .unwrap()
            .nids()
            .next()
            .unwrap();
        let coll = db.get_coll("docs").unwrap();
        let mut collection = coll.write();
        let Collection {
            config,
            streamer,
            searchers,
            id_index,
            graph_lifecycle,
            graph_resolver,
            graph_mutable,
            payload_index,
            ..
        } = &mut *collection;
        graph_lifecycle
            .apply_advance(crate::graph::GraphEpoch::INITIAL, true)
            .unwrap();
        *graph_mutable = Some(crate::mutable_graph::MutableGraphState::new(
            crate::graph::GraphEpoch::INITIAL,
        ));
        let error = super::apply_wal_graph_batch(
            config,
            streamer,
            searchers,
            id_index,
            super::GraphReplayState {
                record_lsn: 0,
                lifecycle: *graph_lifecycle,
                resolver: graph_resolver,
                mutable: graph_mutable,
            },
            payload_index,
            GraphBatch {
                point_mutations: vec![
                    GraphPointMutation::Upsert {
                        point: ls_vec_point("assigned", 1.0, "would-publish-first"),
                    },
                    GraphPointMutation::Upsert {
                        point: ls_vec_point("missing", 2.0, "must-reject-all"),
                    },
                ],
                handle_assignments: vec![GraphHandleAssignment {
                    point_id: "assigned".to_string(),
                    nid,
                }],
                ..GraphBatch::default()
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("has no live Nid assignment"));
        assert!(streamer.points.is_empty());
        assert!(id_index.is_empty());
        assert!(graph_resolver.is_none());
        assert_eq!(
            graph_mutable.as_ref().unwrap().epoch(),
            crate::graph::GraphEpoch::INITIAL
        );
        assert_eq!(graph_mutable.as_ref().unwrap().live_edge_count(), 0);
        assert!(payload_index.equality.is_empty());
        assert!(payload_index.numeric.is_empty());
        assert!(payload_index.text.is_empty());
    }

    #[test]
    fn graph_batch_edge_rejection_publishes_no_point_type_or_edge_prefix() {
        use crate::{
            graph::{EdgeMutation, GraphNamespace, RelateMutation, TypeId},
            wal::{GraphHandleAssignment, GraphTypeConfiguration},
        };

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let nids = db
            .graph_identity
            .allocate_nids(std::num::NonZeroU64::new(2).unwrap())
            .unwrap()
            .nids()
            .collect::<Vec<_>>();
        let edge_id = db
            .graph_identity
            .allocate_edge_ids(std::num::NonZeroU64::new(1).unwrap())
            .unwrap()
            .edge_ids()
            .next()
            .unwrap();
        let type_id = TypeId::from_raw(1);
        let mut source = ls_vec_point("source", 1.0, "must-not-publish");
        source.payload[crate::tenant::TENANT_FIELD] = json!("acme");

        let coll = db.get_coll("docs").unwrap();
        let mut collection = coll.write();
        let Collection {
            config,
            streamer,
            searchers,
            id_index,
            graph_lifecycle,
            graph_resolver,
            graph_mutable,
            payload_index,
            ..
        } = &mut *collection;
        graph_lifecycle
            .apply_advance(crate::graph::GraphEpoch::INITIAL, true)
            .unwrap();
        *graph_mutable = Some(crate::mutable_graph::MutableGraphState::new(
            crate::graph::GraphEpoch::INITIAL,
        ));

        let error = super::apply_wal_graph_batch(
            config,
            streamer,
            searchers,
            id_index,
            super::GraphReplayState {
                record_lsn: 0,
                lifecycle: *graph_lifecycle,
                resolver: graph_resolver,
                mutable: graph_mutable,
            },
            payload_index,
            GraphBatch {
                type_configurations: vec![GraphTypeConfiguration {
                    type_id,
                    name: "cites".to_string(),
                    weight_property: None,
                }],
                point_mutations: vec![GraphPointMutation::Upsert { point: source }],
                handle_assignments: vec![GraphHandleAssignment {
                    point_id: "source".to_string(),
                    nid: nids[0],
                }],
                edge_mutations: vec![EdgeMutation::Relate(RelateMutation {
                    edge_id,
                    source: nids[0],
                    target: nids[1],
                    type_id,
                    namespace: GraphNamespace::Tenant("acme".to_string()),
                    properties: json!({}),
                })],
                ..GraphBatch::default()
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("endpoint Nid"));
        assert!(streamer.points.is_empty());
        assert!(id_index.is_empty());
        assert!(graph_resolver.is_none());
        let graph = graph_mutable.as_ref().unwrap();
        assert_eq!(graph.types().len(), 0);
        assert_eq!(graph.live_edge_count(), 0);
        assert!(payload_index.equality.is_empty());
    }

    #[test]
    fn graph_epoch_lifecycle_replays_enable_drop_and_reenable() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let nid = db
            .graph_identity
            .allocate_nids(std::num::NonZeroU64::new(1).unwrap())
            .unwrap()
            .nids()
            .next()
            .unwrap();
        let coll = db.get_coll("docs").unwrap();
        let mut collection = coll.write();
        collection
            .wal
            .append(&WalEntry::GraphEpochAdvance {
                epoch: crate::graph::GraphEpoch::INITIAL,
                enabled: true,
            })
            .unwrap();
        collection
            .wal
            .append(&WalEntry::GraphBatch {
                batch: GraphBatch {
                    point_mutations: vec![GraphPointMutation::Upsert {
                        point: ls_vec_point("node", 1.0, "retained"),
                    }],
                    handle_assignments: vec![crate::wal::GraphHandleAssignment {
                        point_id: "node".to_string(),
                        nid,
                    }],
                    ..GraphBatch::default()
                },
            })
            .unwrap();
        for (raw_epoch, enabled) in [(2, false), (3, true)] {
            collection
                .wal
                .append(&WalEntry::GraphEpochAdvance {
                    epoch: crate::graph::GraphEpoch::from_raw(raw_epoch).unwrap(),
                    enabled,
                })
                .unwrap();
        }
        drop(collection);
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("docs").unwrap();
        let collection = coll.read();
        assert!(collection.graph_lifecycle.is_enabled());
        assert_eq!(
            collection.graph_lifecycle.epoch(),
            crate::graph::GraphEpoch::from_raw(3)
        );
        assert!(collection.graph_resolver.is_some());
        assert_eq!(
            collection.graph_resolver.as_ref().unwrap().live_nid("node"),
            Some(nid)
        );
        let mutable = collection.graph_mutable.as_ref().unwrap();
        assert_eq!(
            mutable.epoch(),
            crate::graph::GraphEpoch::from_raw(3).unwrap()
        );
        assert_eq!(mutable.types().len(), 0);
        assert_eq!(mutable.live_edge_count(), 0);
    }

    #[test]
    fn scoped_graph_lifecycle_is_idempotent_and_backfills_in_bounded_batches() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let backfill_batch = super::graph_runtime::GRAPH_HANDLE_BACKFILL_BATCH;
        let points = (0..(backfill_batch + 1))
            .map(|index| ls_vec_point(&format!("legacy-{index:04}"), index as f32, "legacy"))
            .collect();
        db.upsert("docs", points).unwrap();
        let scope = crate::tenant::TenantScope::tenant("graph-admin", "acme");

        let enabled = db
            .set_graph_lifecycle_scoped("docs", true, false, &scope)
            .unwrap();
        assert!(enabled.transitioned);
        assert_eq!(enabled.graph_epoch, Some(crate::graph::GraphEpoch::INITIAL));
        assert!(enabled.operation_lsn.is_some());
        assert!(!enabled.durable);
        assert!(enabled.backfill_in_progress);
        wait_for_graph_backfill(&db, "docs");

        let coll = db.get_coll("docs").unwrap();
        let collection = coll.read();
        let wal_after_backfill = collection.wal.len().unwrap();
        assert_eq!(
            collection.graph_resolver.as_ref().unwrap().live_len(),
            backfill_batch + 1
        );
        assert_eq!(
            db.graph_identity.snapshot().node_high_water,
            (backfill_batch + 1) as u64
        );
        drop(collection);

        let repeated_enable = db
            .set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        assert!(!repeated_enable.transitioned);
        assert_eq!(repeated_enable.operation_lsn, None);
        assert!(repeated_enable.durable);
        assert!(!repeated_enable.backfill_in_progress);
        assert_eq!(coll.read().wal.len().unwrap(), wal_after_backfill);

        let dropped = db
            .set_graph_lifecycle_scoped("docs", false, true, &scope)
            .unwrap();
        assert!(dropped.transitioned);
        assert_eq!(dropped.graph_epoch.unwrap().raw(), 2);
        let collection = coll.read();
        assert!(collection.graph_mutable.is_none());
        assert_eq!(
            collection.graph_resolver.as_ref().unwrap().live_len(),
            backfill_batch + 1
        );
        let wal_after_drop = collection.wal.len().unwrap();
        drop(collection);

        let repeated_drop = db
            .set_graph_lifecycle_scoped("docs", false, false, &scope)
            .unwrap();
        assert!(!repeated_drop.transitioned);
        assert_eq!(repeated_drop.operation_lsn, None);
        assert_eq!(coll.read().wal.len().unwrap(), wal_after_drop);

        let high_water_before_reenable = db.graph_identity.snapshot().node_high_water;
        let reenabled = db
            .set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        assert!(reenabled.transitioned);
        assert_eq!(reenabled.graph_epoch.unwrap().raw(), 3);
        assert!(!reenabled.backfill_in_progress);
        assert_eq!(
            db.graph_identity.snapshot().node_high_water,
            high_water_before_reenable
        );

        let root = db.inner.read().root.clone();
        let wal_dir = super::collection_dir(&root, "docs").join("wal");
        let mut assignment_batches = Vec::new();
        Wal::scan_from(&wal_dir, 0, |record| {
            if let WalEntry::GraphBatch { batch } = record.entry
                && !batch.handle_assignments.is_empty()
            {
                assignment_batches.push(batch.handle_assignments.len());
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(assignment_batches, vec![backfill_batch, 1]);
        drop(coll);
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        wait_for_graph_backfill(&reopened, "docs");
        let coll = reopened.get_coll("docs").unwrap();
        let collection = coll.read();
        assert_eq!(collection.graph_lifecycle.epoch().unwrap().raw(), 3);
        assert!(collection.graph_lifecycle.is_enabled());
        assert_eq!(
            collection.graph_resolver.as_ref().unwrap().live_len(),
            backfill_batch + 1
        );
        assert_eq!(
            collection.graph_mutable.as_ref().unwrap().live_edge_count(),
            0
        );

        let audit_log = fs::read_to_string(audit::audit_log_path(temp.path())).unwrap();
        assert!(audit_log.contains("graph_enable"));
        assert!(audit_log.contains("graph_drop"));
        assert!(audit_log.contains("graph_handle_backfill"));
        assert!(!audit_log.contains("legacy-0000"));
        audit::verify_hash_chain(temp.path()).unwrap();
    }

    #[test]
    fn recovered_graph_lifecycle_resumes_only_missing_handle_assignments() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert(
            "docs",
            (0..5)
                .map(|index| ls_vec_point(&format!("node-{index}"), index as f32, "legacy"))
                .collect(),
        )
        .unwrap();
        let retained = db
            .graph_identity
            .allocate_nids(std::num::NonZeroU64::new(2).unwrap())
            .unwrap()
            .nids()
            .collect::<Vec<_>>();
        let coll = db.get_coll("docs").unwrap();
        let mut collection = coll.write();
        collection
            .wal
            .append(&WalEntry::GraphEpochAdvance {
                epoch: crate::graph::GraphEpoch::INITIAL,
                enabled: true,
            })
            .unwrap();
        collection
            .wal
            .append(&WalEntry::GraphBatch {
                batch: GraphBatch {
                    handle_assignments: retained
                        .iter()
                        .enumerate()
                        .map(|(index, nid)| crate::wal::GraphHandleAssignment {
                            point_id: format!("node-{index}"),
                            nid: *nid,
                        })
                        .collect(),
                    ..GraphBatch::default()
                },
            })
            .unwrap();
        drop(collection);
        drop(coll);
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        wait_for_graph_backfill(&reopened, "docs");
        let coll = reopened.get_coll("docs").unwrap();
        let collection = coll.read();
        let resolver = collection.graph_resolver.as_ref().unwrap();
        assert_eq!(resolver.live_len(), 5);
        assert_eq!(resolver.live_nid("node-0"), Some(retained[0]));
        assert_eq!(resolver.live_nid("node-1"), Some(retained[1]));
        let unique = (0..5)
            .map(|index| resolver.live_nid(&format!("node-{index}")).unwrap())
            .collect::<HashSet<_>>();
        assert_eq!(unique.len(), 5);
        assert_eq!(
            unique
                .iter()
                .filter(|nid| nid.epoch() == retained[0].epoch())
                .count(),
            2
        );
    }

    #[test]
    fn graph_enabled_point_mutations_use_graph_batches_and_preserve_incarnations() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let scope = crate::tenant::TenantScope::tenant("graph-admin", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();

        assert_eq!(
            db.upsert(
                "docs",
                vec![
                    ls_vec_point("node", 1.0, "superseded"),
                    ls_vec_point("node", 2.0, "initial"),
                ],
            )
            .unwrap(),
            1
        );
        let coll = db.get_coll("docs").unwrap();
        let first_nid = coll
            .read()
            .graph_resolver
            .as_ref()
            .unwrap()
            .live_nid("node")
            .unwrap();
        assert_eq!(
            db.get_points("docs", &["node".to_string()]).unwrap()[0].payload["version"],
            "initial"
        );

        db.upsert("docs", vec![ls_vec_point("node", 3.0, "updated")])
            .unwrap();
        db.set_payload("docs", "node", json!({"remove": true}), true)
            .unwrap();
        assert_eq!(
            coll.read()
                .graph_resolver
                .as_ref()
                .unwrap()
                .live_nid("node"),
            Some(first_nid)
        );

        let wal_before_missing_delete = coll.read().wal.len().unwrap();
        assert_eq!(
            db.delete("docs", &["missing".to_string(), "missing".to_string()])
                .unwrap(),
            0
        );
        assert_eq!(coll.read().wal.len().unwrap(), wal_before_missing_delete);
        assert_eq!(
            db.delete("docs", &["node".to_string(), "node".to_string()])
                .unwrap(),
            1
        );
        {
            let collection = coll.read();
            let resolver = collection.graph_resolver.as_ref().unwrap();
            assert_eq!(resolver.live_nid("node"), None);
            assert!(resolver.is_retired(first_nid));
        }

        db.upsert("docs", vec![ls_vec_point("node", 4.0, "filter-delete")])
            .unwrap();
        let second_nid = coll
            .read()
            .graph_resolver
            .as_ref()
            .unwrap()
            .live_nid("node")
            .unwrap();
        assert_ne!(second_nid, first_nid);
        assert_eq!(
            db.delete_by_filter("docs", &Filter(json!({"version": "filter-delete"})))
                .unwrap(),
            1
        );

        let root = db.inner.read().root.clone();
        let wal_dir = super::collection_dir(&root, "docs").join("wal");
        let mut graph_batches = 0_usize;
        let mut assignments = 0_usize;
        let mut legacy_point_mutations = 0_usize;
        Wal::scan_from(&wal_dir, 0, |record| {
            match record.entry {
                WalEntry::GraphBatch { batch } => {
                    graph_batches += 1;
                    assignments += batch.handle_assignments.len();
                    let unique = batch
                        .point_mutations
                        .iter()
                        .map(|mutation| match mutation {
                            GraphPointMutation::Upsert { point } => point.id.as_str(),
                            GraphPointMutation::Delete { point_id, .. } => point_id.as_str(),
                        })
                        .collect::<HashSet<_>>();
                    assert_eq!(unique.len(), batch.point_mutations.len());
                }
                WalEntry::Upsert { .. }
                | WalEntry::UpsertBatch { .. }
                | WalEntry::Delete { .. }
                | WalEntry::DeleteBatch { .. }
                | WalEntry::SetPayload { .. } => legacy_point_mutations += 1,
                _ => {}
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(graph_batches, 6);
        assert_eq!(assignments, 2);
        assert_eq!(legacy_point_mutations, 0);
        drop(coll);
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("docs").unwrap();
        let collection = coll.read();
        let resolver = collection.graph_resolver.as_ref().unwrap();
        assert_eq!(resolver.live_nid("node"), None);
        assert!(resolver.is_retired(first_nid));
        assert!(resolver.is_retired(second_nid));
        assert_eq!(resolver.retired_len(), 2);
        assert!(!collection.id_index.contains_key("node"));
    }

    #[test]
    fn graph_batch_point_delete_publishes_sealed_tombstone_and_replays_it() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert(
            "docs",
            vec![
                ls_vec_point("sealed-delete", 1.0, "remove"),
                ls_vec_point("sealed-keep", 2.0, "keep"),
            ],
        )
        .unwrap();
        db.compact_collection("docs").unwrap();
        let coll = db.get_coll("docs").unwrap();
        let (segment_id, ordinal) = {
            let collection = coll.read();
            assert!(collection.streamer.points.is_empty());
            assert_eq!(collection.searchers.len(), 1);
            let searcher = &collection.searchers[0];
            (
                searcher.id.clone(),
                searcher.ordinal("sealed-delete").unwrap(),
            )
        };
        let scope = crate::tenant::TenantScope::tenant("graph-admin", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        wait_for_graph_backfill(&db, "docs");

        assert_eq!(
            db.delete("docs", &["sealed-delete".to_string()]).unwrap(),
            1
        );
        {
            let collection = coll.read();
            assert!(
                collection
                    .overlays
                    .current_ref()
                    .point_tombstones()
                    .contains(&segment_id, ordinal)
            );
            assert!(!collection.id_index.contains_key("sealed-delete"));
        }
        assert!(
            db.get_points("docs", &["sealed-delete".to_string()])
                .unwrap()
                .is_empty()
        );
        assert!(
            db.search("docs", ls_vec_search(1.0, 2))
                .unwrap()
                .hits
                .iter()
                .all(|hit| hit.id != "sealed-delete")
        );
        drop(coll);
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("docs").unwrap();
        let collection = coll.read();
        assert!(
            collection
                .overlays
                .current_ref()
                .point_tombstones()
                .contains(&segment_id, ordinal)
        );
        assert!(!collection.id_index.contains_key("sealed-delete"));
        assert!(collection.id_index.contains_key("sealed-keep"));
    }

    #[test]
    fn ordinary_point_upsert_rejects_tenant_change_with_incident_edge_before_wal() {
        use crate::{
            graph::{EdgeMutation, GraphNamespace, RelateMutation, TypeId},
            wal::GraphTypeConfiguration,
        };

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let scope = crate::tenant::TenantScope::tenant("graph-admin", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        let mut source = ls_vec_point("source", 1.0, "live");
        source.payload[crate::tenant::TENANT_FIELD] = json!("acme");
        let mut target = ls_vec_point("target", 2.0, "live");
        target.payload[crate::tenant::TENANT_FIELD] = json!("acme");
        db.upsert("docs", vec![source, target]).unwrap();
        let coll = db.get_coll("docs").unwrap();
        let nids = {
            let collection = coll.read();
            let resolver = collection.graph_resolver.as_ref().unwrap();
            [
                resolver.live_nid("source").unwrap(),
                resolver.live_nid("target").unwrap(),
            ]
        };
        let edge_id = db
            .graph_identity
            .allocate_edge_ids(std::num::NonZeroU64::new(1).unwrap())
            .unwrap()
            .edge_ids()
            .next()
            .unwrap();
        db.commit_graph_batch_scoped(
            "docs",
            GraphBatch {
                type_configurations: vec![GraphTypeConfiguration {
                    type_id: TypeId::from_raw(1),
                    name: "cites".to_string(),
                    weight_property: None,
                }],
                edge_mutations: vec![EdgeMutation::Relate(RelateMutation {
                    edge_id,
                    source: nids[0],
                    target: nids[1],
                    type_id: TypeId::from_raw(1),
                    namespace: GraphNamespace::Tenant("acme".to_string()),
                    properties: json!({}),
                })],
                ..GraphBatch::default()
            },
            true,
            &scope,
        )
        .unwrap();
        let wal_before = coll.read().wal.len().unwrap();

        let mut changed = ls_vec_point("source", 9.0, "must-reject");
        changed.payload[crate::tenant::TENANT_FIELD] = json!("globex");
        let error = db.upsert("docs", vec![changed]).unwrap_err();
        assert!(error.to_string().contains("tenant change"), "{error}");
        assert_eq!(coll.read().wal.len().unwrap(), wal_before);
        let retained = db.get_points("docs", &["source".to_string()]).unwrap();
        assert_eq!(retained[0].payload[crate::tenant::TENANT_FIELD], "acme");
        assert_eq!(retained[0].payload["version"], "live");

        let error = db
            .set_payload("docs", "source", json!({"tenant_id": "globex"}), false)
            .unwrap_err();
        assert!(error.to_string().contains("tenant change"), "{error}");
        assert_eq!(coll.read().wal.len().unwrap(), wal_before);
    }

    #[test]
    fn legacy_point_replication_fails_closed_after_graph_history() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let scope = crate::tenant::TenantScope::tenant("graph-admin", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        db.set_graph_lifecycle_scoped("docs", false, true, &scope)
            .unwrap();

        let error = db
            .upsert_replicated("docs", ls_vec_point("node", 1.0, "blocked"))
            .unwrap_err();
        assert!(error.to_string().contains("point-only replication"));
        let error = db.delete_replicated("docs", "node").unwrap_err();
        assert!(error.to_string().contains("point-only replication"));
        assert!(
            db.get_points("docs", &["node".to_string()])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn graph_production_seal_cut_tail_and_publication_plaintext_and_encrypted() {
        use crate::{
            checkpoint::FragmentDirectoryManifest,
            encryption,
            graph::{
                ConfigureEdgeTypeRequest, EdgePropertyMode, GraphRelationScope, RelateRequest,
                UpdateEdgeRequest,
            },
            graph_generation::GraphGeneration,
        };
        use base64::{Engine, engine::general_purpose::STANDARD};
        use std::{env, process::Command};
        const MODE: &str = "CHIRONDB_GRAPH_SEAL_TEST_MODE";
        const ROOT: &str = "CHIRONDB_GRAPH_SEAL_TEST_ROOT";
        const TEST: &str =
            "db::tests::graph_production_seal_cut_tail_and_publication_plaintext_and_encrypted";
        let Some(mode) = env::var_os(MODE) else {
            let cases = if cfg!(feature = "fault-injection") {
                vec!["normal", "before_manifest", "after_install"]
            } else {
                vec!["normal"]
            };
            for mode in ["plaintext", "encrypted"] {
                for case in &cases {
                    let temp = TempDir::new().unwrap();
                    let mut command = Command::new(env::current_exe().unwrap());
                    command
                        .args(["--exact", TEST, "--nocapture"])
                        .env(MODE, mode)
                        .env(ROOT, temp.path());
                    if *case != "normal" {
                        command.env(
                            "CHIRONDB_FAILPOINT",
                            format!("error:graph_generation.{case}"),
                        );
                    } else {
                        command.env_remove("CHIRONDB_FAILPOINT");
                    }
                    assert!(command.status().unwrap().success(), "{mode}/{case}");
                }
            }
            return;
        };
        let root = PathBuf::from(env::var_os(ROOT).unwrap());
        if mode == "encrypted" {
            let keyring = root.join("keyring.json");
            fs::write(&keyring, json!({"version":1,"active_key_id":"seal","keys":[{"id":"seal","key_base64":STANDARD.encode([93;32])}]}).to_string()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
            }
            encryption::install_process_keyring(encryption::Keyring::load(&keyring).unwrap(), true)
                .unwrap();
        }
        let data = root.join("db");
        let dir = super::collection_dir(&data, "docs");
        let scope = crate::tenant::TenantScope::tenant("seal-writer", "acme");
        let db = Db::open(&data).unwrap();
        let mut config = ls_vec_config("docs");
        config.streamer_max_bytes = usize::MAX;
        db.create_collection(config).unwrap();
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        db.upsert(
            "docs",
            vec![graph_point("a", 1.0, "acme"), graph_point("b", 2.0, "acme")],
        )
        .unwrap();
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: "links".into(),
                weight_property: None,
            },
            true,
            &scope,
        )
        .unwrap();
        let request = |target: &str| RelateRequest {
            source_point_id: "a".into(),
            target_point_id: target.into(),
            edge_type: "links".into(),
            properties: json!({"revision":1}),
            scope: GraphRelationScope::Local,
            idempotency_key: Some(format!("edge-{target}")),
        };
        let related = db
            .relate_scoped("docs", request("b"), true, &scope)
            .unwrap();
        let edge = crate::edge_token::decode(db.graph_database_id(), &related.edge_id).unwrap();
        let session = db
            .open_deferred_graph_session_scoped("docs", true, &scope)
            .unwrap();
        let pending = db
            .relate_deferred_scoped("docs", &session.session_id, request("future"), true, &scope)
            .unwrap();
        let pending_id =
            crate::edge_token::decode(db.graph_database_id(), &pending.edge_id).unwrap();
        let seal = prepare_forced_graph_vector_seal(&db, &data, "docs");
        let first_cut = seal.end_lsn;
        db.upsert("docs", vec![graph_point("b", 2.5, "acme")])
            .unwrap();
        db.update_edge_scoped(
            "docs",
            &related.edge_id,
            UpdateEdgeRequest {
                mode: EdgePropertyMode::Merge,
                properties: json!({"revision":2}),
            },
            true,
            &scope,
        )
        .unwrap();
        let result = run_segment_seal(&seal);
        if let Ok(failpoint) = env::var("CHIRONDB_FAILPOINT") {
            let coll = Arc::clone(&seal.coll);
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("injected failpoint")
            );
            if failpoint.ends_with("before_manifest") {
                assert!(!super::seal_generation_is_published(&seal));
                super::cleanup_unpublished_seal(&seal);
                let reader_pin = Arc::clone(&seal.frozen);
                super::restore_failed_seal(seal.coll, seal.frozen);
                drop(seal.data_dir_lock);
                assert_eq!(reader_pin.points["b"].vector, vec![2.0, 0.0]);
                assert_eq!(coll.read().wal_watermark, 0);
                assert!(coll.read().graph_generation.is_none());
            } else {
                assert!(super::seal_generation_is_published(&seal));
                assert_eq!(seal.coll.read().wal_watermark, first_cut);
                assert!(seal.coll.read().graph_generation.is_some());
                drop(seal);
            }
            assert!(coll.read().sealing.is_none());
            drop(coll);
            drop(db);
            let reopened = Db::open(&data).unwrap();
            assert_eq!(
                reopened.get_points("docs", &["b".into()]).unwrap()[0].vector,
                vec![2.5, 0.0]
            );
            let coll = reopened.get_coll("docs").unwrap();
            let state = coll.read();
            assert_eq!(
                state
                    .graph_mutable
                    .as_ref()
                    .unwrap()
                    .edge(edge)
                    .unwrap()
                    .properties["revision"],
                2
            );
            assert_eq!(
                state.graph_mutable.as_ref().unwrap().pending_edge_count(),
                1
            );
            assert_eq!(state.live_points(), 2);
            return;
        }
        result.unwrap();
        assert_eq!(seal.coll.read().wal_watermark, first_cut);
        let cut = GraphGeneration::open(&dir).unwrap().unwrap();
        assert_eq!(cut.bases.len(), 1);
        assert_eq!(cut.bases[0].adjacency.edge_count(), 1);
        let first_graph = cut.manifest.graph.as_ref().unwrap();
        let first_catalog = first_graph.fragment_catalog.as_ref().unwrap().clone();
        let FragmentDirectoryManifest::Present {
            base: first_directory,
            overlays,
        } = &first_graph.fragment_directory
        else {
            panic!("first seal must publish a directory");
        };
        assert!(overlays.is_empty());
        let first_directory = first_directory.clone();
        let first_directory_bytes = fs::read(&cut.fragments[0].path).unwrap();
        assert_eq!(
            cut.recovered
                .as_ref()
                .unwrap()
                .mutable
                .edge_properties(edge)
                .unwrap()
                .unwrap()["revision"],
            1
        );
        assert_eq!(
            cut.recovered
                .as_ref()
                .unwrap()
                .mutable
                .unsealed_topology_rows(),
            0
        );
        assert_eq!(
            cut.recovered
                .as_ref()
                .unwrap()
                .mutable
                .stored_topology_count(),
            1
        );
        assert_eq!(
            cut.recovered.as_ref().unwrap().mutable.pending_edge_count(),
            1
        );
        let first_pin = cut;
        drop(seal);
        drop(db);

        let db = Db::open(&data).unwrap();
        assert!(
            db.relate_scoped("docs", request("b"), true, &scope)
                .unwrap()
                .receipt
                .replayed
        );
        db.upsert_deferred_scoped(
            "docs",
            &session.session_id,
            vec![graph_point("future", 3.0, "acme")],
            true,
            &scope,
        )
        .unwrap();
        db.commit_deferred_graph_session_scoped("docs", &session.session_id, true, &scope)
            .unwrap();
        let second = prepare_forced_graph_vector_seal(&db, &data, "docs");
        db.update_edge_scoped(
            "docs",
            &related.edge_id,
            UpdateEdgeRequest {
                mode: EdgePropertyMode::Replace,
                properties: json!({"revision":3}),
            },
            true,
            &scope,
        )
        .unwrap();
        run_segment_seal(&second).unwrap();
        let cut = GraphGeneration::open(&dir).unwrap().unwrap();
        let graph = cut.manifest.graph.as_ref().unwrap();
        let FragmentDirectoryManifest::Present { base, overlays } = &graph.fragment_directory
        else {
            panic!("second seal must retain the directory");
        };
        assert_eq!(base, &first_directory);
        assert_eq!(
            fs::read(&cut.fragments[0].path).unwrap(),
            first_directory_bytes
        );
        assert_eq!(overlays.len(), 1);
        assert_eq!(overlays[0].first_lsn, first_cut);
        let catalog = graph.fragment_catalog.as_ref().unwrap();
        for binding in &first_catalog.bindings {
            assert!(catalog.bindings.contains(binding));
        }
        for group in 0..cut.fragments[1].reader.group_count() {
            let group = cut.fragments[1]
                .reader
                .read_group(&cut.fragments[1].path, group)
                .unwrap();
            assert!(
                group
                    .rows
                    .iter()
                    .flat_map(|row| &row.fragments)
                    .all(|reference| reference.fragment_id > first_catalog.high_watermark)
            );
        }
        let namespace = crate::graph::GraphNamespace::Tenant("acme".into());
        let source_nid = first_pin
            .recovered
            .as_ref()
            .unwrap()
            .resolver
            .live_nid("a")
            .unwrap();
        assert_eq!(
            first_pin
                .fragment_rows(&namespace, source_nid)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(cut.fragment_rows(&namespace, source_nid).unwrap().len(), 2);
        let second_directory = graph.fragment_directory.clone();
        assert_eq!(
            graph.edge_ledger.runs.len(),
            0,
            "promotion must not duplicate a reserved key"
        );
        assert_eq!(graph.edge_properties.runs.len(), 1);
        assert_eq!(graph.edge_properties.runs[0].first_lsn, first_cut);
        assert_eq!(graph.edge_properties.base.last_lsn, first_cut - 1);
        assert_eq!(cut.deltas.len(), 1);
        let recovered = &cut.recovered.as_ref().unwrap().mutable;
        assert_eq!(
            recovered.edge_properties(edge).unwrap().unwrap()["revision"],
            2
        );
        assert!(recovered.edge_properties(pending_id).unwrap().is_some());
        assert_eq!(recovered.unsealed_topology_rows(), 0);
        assert_eq!(recovered.stored_topology_count(), 2);
        assert_eq!(recovered.pending_edge_count(), 0);
        drop(cut);
        drop(second);
        drop(db);

        // WAL replay dirties the property row again after restart. A third seal
        // must include it. The lifecycle API waits for an in-flight seal, so
        // request DROP on another thread and let it follow manifest publication.
        let db = Arc::new(Db::open(&data).unwrap());
        db.upsert("docs", vec![graph_point("new", 4.0, "acme")])
            .unwrap();
        let third = prepare_forced_graph_vector_seal(&db, &data, "docs");
        let dropping = Arc::clone(&db);
        let drop_task = thread::spawn(move || {
            let scope = crate::tenant::TenantScope::tenant("seal-writer", "acme");
            dropping
                .set_graph_lifecycle_scoped("docs", false, true, &scope)
                .unwrap();
        });
        run_segment_seal(&third).unwrap();
        drop_task.join().unwrap();
        let cut = GraphGeneration::open(&dir).unwrap().unwrap();
        assert_eq!(
            cut.manifest.graph.as_ref().unwrap().fragment_directory,
            second_directory,
            "property-only/new isolated point seal must not rewrite the directory"
        );
        assert_eq!(
            cut.recovered
                .as_ref()
                .unwrap()
                .mutable
                .edge_properties(edge)
                .unwrap()
                .unwrap()["revision"],
            3
        );
        let manifest = cut.manifest.as_ref().clone();
        drop(cut);
        drop(third);
        drop(db);
        let db = Db::open(&data).unwrap();
        let coll = db.get_coll("docs").unwrap();
        assert!(!coll.read().graph_lifecycle.is_enabled());
        coll.write().config.streamer_max_bytes = 1;
        db.upsert("docs", vec![graph_point("disabled-tail", 5.0, "acme")])
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let state = coll.read();
            if state.sealing.is_none()
                && state.graph_generation.as_ref().unwrap().manifest.generation
                    > manifest.generation
            {
                assert!(state.graph_mutable.is_none());
                assert_eq!(state.wal_watermark, state.wal.len().unwrap());
                break;
            }
            drop(state);
            assert!(
                Instant::now() < deadline,
                "disabled automatic seal did not complete"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let disabled = GraphGeneration::open(&dir).unwrap().unwrap();
        assert!(!disabled.recovered.as_ref().unwrap().lifecycle.is_enabled());
        assert!(disabled.bases.is_empty());
        assert!(disabled.fragments.is_empty());
        let disabled_catalog = disabled
            .manifest
            .graph
            .as_ref()
            .unwrap()
            .fragment_catalog
            .as_ref()
            .unwrap();
        assert!(disabled_catalog.bindings.is_empty());
        assert_eq!(
            disabled_catalog.high_watermark,
            manifest
                .graph
                .as_ref()
                .unwrap()
                .fragment_catalog
                .as_ref()
                .unwrap()
                .high_watermark
        );
        drop(disabled);
        drop(coll);
        drop(db);
        let reopened = Db::open(&data).unwrap();
        assert_eq!(
            reopened
                .get_points("docs", &["disabled-tail".into()])
                .unwrap()
                .len(),
            1
        );
        assert!(
            !reopened
                .get_coll("docs")
                .unwrap()
                .read()
                .graph_lifecycle
                .is_enabled()
        );
        assert_pinned_graph_adjacency(&root.join("pinned-cursors"));
    }

    fn assert_pinned_graph_adjacency(data: &Path) {
        use crate::graph::{
            ConfigureEdgeTypeRequest, EdgePropertyMode, GraphDirection, GraphRelationScope,
            GraphTraverseRequest, RelateRequest, TraversalBudget, TraversalTruncationReason,
            UpdateEdgeRequest,
        };
        let scope = crate::tenant::TenantScope::tenant("cursor-test", "acme");
        let db = Db::open(data).unwrap();
        let mut config = ls_vec_config("docs");
        config.streamer_max_bytes = usize::MAX;
        db.create_collection(config).unwrap();
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        db.upsert(
            "docs",
            vec![
                graph_point("a", 1.0, "acme"),
                graph_point("b", 2.0, "acme"),
                graph_point("c", 3.0, "acme"),
            ],
        )
        .unwrap();
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: "links".into(),
                weight_property: None,
            },
            true,
            &scope,
        )
        .unwrap();
        let relate = |target: &str| RelateRequest {
            source_point_id: "a".into(),
            target_point_id: target.into(),
            edge_type: "links".into(),
            properties: json!({"revision":1}),
            scope: GraphRelationScope::Local,
            idempotency_key: None,
        };
        let first_edge = db.relate_scoped("docs", relate("b"), true, &scope).unwrap();
        let seal = prepare_forced_graph_vector_seal(&db, data, "docs");
        let second_edge = db.relate_scoped("docs", relate("c"), true, &scope).unwrap();
        run_segment_seal(&seal).unwrap();
        assert_eq!(
            seal.coll
                .read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .unsealed_adjacency_entries(),
            2,
            "only the post-cut edge remains in mutable adjacency"
        );
        assert_eq!(
            seal.coll
                .read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .unsealed_topology_rows(),
            1
        );
        assert_eq!(
            seal.coll
                .read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .unsealed_ledger_keys(),
            1
        );
        assert_eq!(
            seal.coll
                .read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .stored_edge_count(),
            2
        );
        assert_eq!(
            seal.coll
                .read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .unsealed_property_documents(),
            1
        );
        drop(seal);
        let request = |anchor: &str, direction| GraphTraverseRequest {
            anchors: vec![anchor.into()],
            edge_types: vec![],
            direction,
            node_filter: None,
            edge_filter: None,
            budget: TraversalBudget {
                max_depth: 1,
                ..TraversalBudget::default()
            },
        };
        let targets = |db: &Db, anchor: &str, direction| {
            let result = db
                .traverse_scoped("docs", request(anchor, direction), &scope)
                .unwrap();
            assert!(result.truncation.is_none());
            result
                .nodes
                .into_iter()
                .map(|node| node.point_id)
                .collect::<Vec<_>>()
        };
        assert_eq!(targets(&db, "a", GraphDirection::Outgoing), vec!["b", "c"]);
        assert_eq!(targets(&db, "b", GraphDirection::Incoming), vec!["a"]);
        assert_eq!(targets(&db, "c", GraphDirection::Incoming), vec!["a"]);
        drop(db);
        let db = Db::open(data).unwrap();
        let coll = db.get_coll("docs").unwrap();
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .unsealed_adjacency_entries(),
            2,
            "recovery attaches the base before replaying tail"
        );
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .unsealed_property_documents(),
            1
        );
        let first_id =
            crate::edge_token::decode(db.graph_database_id(), &first_edge.edge_id).unwrap();
        let second_id =
            crate::edge_token::decode(db.graph_database_id(), &second_edge.edge_id).unwrap();
        let old_graph = coll.read().graph_mutable.as_ref().unwrap().clone();
        assert_eq!(old_graph.unsealed_topology_rows(), 1);
        assert_eq!(old_graph.stored_topology_count(), 2);
        db.set_tenant_enforcement(crate::tenant::TenantEnforcement::Enforced);
        let other = crate::tenant::TenantScope::tenant("hidden-cursor-test", "other");
        let before_hidden = coll.read().wal.len().unwrap();
        for error in [
            db.update_edge_scoped(
                "docs",
                &first_edge.edge_id,
                UpdateEdgeRequest {
                    mode: EdgePropertyMode::Merge,
                    properties: json!({"unauthorized":true}),
                },
                true,
                &other,
            )
            .unwrap_err(),
            db.unrelate_scoped("docs", &first_edge.edge_id, true, &other)
                .unwrap_err(),
        ] {
            assert!(
                error.to_string().contains("graph.edge_not_found"),
                "{error}"
            );
        }
        assert_eq!(coll.read().wal.len().unwrap(), before_hidden);
        assert_eq!(
            old_graph.edge_namespace(first_id).unwrap(),
            Some(&crate::graph::GraphNamespace::Tenant("acme".into()))
        );
        assert_eq!(old_graph.unsealed_ledger_keys(), 1);
        assert_eq!(old_graph.stored_edge_count(), 2);
        assert!(old_graph.contains_edge_id(first_id).unwrap());
        assert!(old_graph.contains_edge_id(second_id).unwrap());
        let existing = old_graph.edge(first_id).unwrap();
        let before_duplicate = coll.read().wal.len().unwrap();
        let duplicate = db
            .commit_graph_batch_locked(
                &mut coll.write(),
                crate::wal::GraphBatch {
                    graph_epoch: old_graph.epoch(),
                    edge_mutations: vec![crate::graph::EdgeMutation::Relate(
                        crate::graph::RelateMutation {
                            edge_id: first_id,
                            source: existing.source,
                            target: existing.target,
                            type_id: existing.type_id,
                            namespace: existing.namespace,
                            properties: existing.properties,
                        },
                    )],
                    ..crate::wal::GraphBatch::default()
                },
                true,
            )
            .unwrap_err();
        assert!(
            duplicate.to_string().contains("stable ledger"),
            "{duplicate}"
        );
        assert_eq!(coll.read().wal.len().unwrap(), before_duplicate);
        assert_eq!(
            old_graph.edge_properties(first_id).unwrap().unwrap()["revision"],
            1
        );
        // A successful lookup must not install the sealed document in the tail.
        assert_eq!(old_graph.unsealed_property_documents(), 1);
        db.update_edge_scoped(
            "docs",
            &first_edge.edge_id,
            UpdateEdgeRequest {
                mode: EdgePropertyMode::Merge,
                properties: json!({"revision":2,"merged":true}),
            },
            true,
            &scope,
        )
        .unwrap();
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .unsealed_property_documents(),
            2
        );
        assert_eq!(
            old_graph.edge_properties(first_id).unwrap().unwrap()["revision"],
            1
        );
        // Validate the complete merged document, not only the small patch.
        db.update_edge_scoped(
            "docs",
            &first_edge.edge_id,
            UpdateEdgeRequest {
                mode: EdgePropertyMode::Replace,
                properties: json!({"large":"x".repeat(crate::graph::MAX_EDGE_PROPERTY_BYTES - 20)}),
            },
            true,
            &scope,
        )
        .unwrap();
        let before_merge = coll.read().wal.len().unwrap();
        let error = db
            .update_edge_scoped(
                "docs",
                &first_edge.edge_id,
                UpdateEdgeRequest {
                    mode: EdgePropertyMode::Merge,
                    properties: json!({"extra":"y".repeat(32)}),
                },
                true,
                &scope,
            )
            .unwrap_err();
        assert!(error.to_string().contains("maximum"), "{error}");
        assert_eq!(coll.read().wal.len().unwrap(), before_merge);
        db.update_edge_scoped(
            "docs",
            &first_edge.edge_id,
            UpdateEdgeRequest {
                mode: EdgePropertyMode::Replace,
                properties: json!({"revision":2}),
            },
            true,
            &scope,
        )
        .unwrap();
        let mut filtered = request("a", GraphDirection::Outgoing);
        filtered.edge_filter = Some(Filter(json!({"revision":2})));
        assert_eq!(
            db.traverse_scoped("docs", filtered, &scope).unwrap().nodes[0].point_id,
            "b"
        );
        let before = coll.read().wal.len().unwrap();
        assert!(
            db.upsert("docs", vec![graph_point("a", 4.0, "globex")])
                .is_err()
        );
        assert_eq!(
            coll.read().wal.len().unwrap(),
            before,
            "disk incident-edge check precedes WAL"
        );
        db.upsert("docs", vec![graph_point("a", 4.0, "acme")])
            .unwrap();
        let second = prepare_forced_graph_vector_seal(&db, data, "docs");
        db.update_edge_scoped(
            "docs",
            &second_edge.edge_id,
            UpdateEdgeRequest {
                mode: EdgePropertyMode::Merge,
                properties: json!({"revision":3,"tail":true}),
            },
            true,
            &scope,
        )
        .unwrap();
        db.unrelate_scoped("docs", &first_edge.edge_id, true, &scope)
            .unwrap();
        run_segment_seal(&second).unwrap();
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .unsealed_topology_rows(),
            0
        );
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .stored_topology_count(),
            2
        );
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .unsealed_adjacency_entries(),
            0
        );
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .unsealed_property_documents(),
            1,
            "post-cut property update survives prefix acknowledgement"
        );
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .unsealed_ledger_keys(),
            0
        );
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .stored_edge_count(),
            2
        );
        assert!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .contains_edge_id(first_id)
                .unwrap(),
            "UNRELATE does not erase the stable sealed identity"
        );
        assert_eq!(old_graph.unsealed_ledger_keys(), 1);
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .edge_properties(second_id)
                .unwrap()
                .unwrap()["revision"],
            3
        );
        assert_eq!(
            old_graph.edge_properties(second_id).unwrap().unwrap()["revision"],
            1
        );
        let source = coll
            .read()
            .graph_resolver
            .as_ref()
            .unwrap()
            .live_nid("a")
            .unwrap();
        assert_eq!(
            old_graph
                .outgoing(&crate::graph::GraphNamespace::Tenant("acme".into()), source)
                .len(),
            2,
            "an old snapshot keeps its base and tail"
        );
        assert_eq!(targets(&db, "a", GraphDirection::Outgoing), vec!["c"]);
        let mut bounded = request("a", GraphDirection::Outgoing);
        bounded.budget.max_edges = 1;
        assert_eq!(
            db.traverse_scoped("docs", bounded, &scope)
                .unwrap()
                .truncation,
            Some(TraversalTruncationReason::Edges)
        );
        let mut bounded = request("a", GraphDirection::Outgoing);
        bounded.budget.max_memory_bytes = 64 * 1024;
        assert_eq!(
            db.traverse_scoped("docs", bounded, &scope)
                .unwrap()
                .truncation,
            Some(TraversalTruncationReason::Memory)
        );
        drop(second);
        drop(coll);
        drop(db);
        let db = Db::open(data).unwrap();
        assert_eq!(targets(&db, "a", GraphDirection::Outgoing), vec!["c"]);
        let state = db.get_coll("docs").unwrap();
        assert_eq!(
            state
                .read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .unsealed_topology_rows(),
            0
        );
        assert_eq!(
            state
                .read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .unsealed_property_documents(),
            1
        );
        assert_eq!(
            state
                .read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .edge_properties(second_id)
                .unwrap()
                .unwrap(),
            std::borrow::Cow::Owned::<serde_json::Value>(json!({"revision":3,"tail":true}))
        );
        db.upsert("docs", vec![graph_point("a", 6.0, "acme")])
            .unwrap();
        let third = prepare_forced_graph_vector_seal(&db, data, "docs");
        run_segment_seal(&third).unwrap();
        assert_eq!(
            state
                .read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .unsealed_ledger_keys(),
            0
        );
        assert_eq!(
            state
                .read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .stored_edge_count(),
            2
        );
        assert_eq!(
            state
                .read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .unsealed_property_documents(),
            0
        );
        assert_eq!(
            state
                .read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .edge_properties(second_id)
                .unwrap()
                .unwrap()["revision"],
            3
        );
        drop(third);
        drop(state);
        assert!(db.delete("docs", &["c".into()]).is_err());
        db.delete_with_edges_scoped("docs", &["c".into()], &scope)
            .unwrap();
        db.upsert("docs", vec![graph_point("c", 5.0, "acme")])
            .unwrap();
        assert!(
            targets(&db, "a", GraphDirection::Outgoing).is_empty(),
            "retired endpoint cannot be revived by point ID reuse"
        );
    }

    #[test]
    fn graph_disabled_seals_retire_incarnations_and_reenable_plaintext_and_encrypted() {
        use crate::{
            encryption,
            graph::{ConfigureEdgeTypeRequest, GraphRelationScope, RelateRequest},
            graph_generation::GraphGeneration,
        };
        use base64::{Engine, engine::general_purpose::STANDARD};
        use std::{env, process::Command};
        const MODE: &str = "CHIRONDB_DISABLED_SEAL_TEST_MODE";
        const ROOT: &str = "CHIRONDB_DISABLED_SEAL_TEST_ROOT";
        const TEST: &str = "db::tests::graph_disabled_seals_retire_incarnations_and_reenable_plaintext_and_encrypted";
        let Some(mode) = env::var_os(MODE) else {
            for mode in ["plaintext", "encrypted"] {
                let temp = TempDir::new().unwrap();
                assert!(
                    Command::new(env::current_exe().unwrap())
                        .args(["--exact", TEST, "--nocapture"])
                        .env(MODE, mode)
                        .env(ROOT, temp.path())
                        .status()
                        .unwrap()
                        .success()
                );
            }
            return;
        };
        let root = PathBuf::from(env::var_os(ROOT).unwrap());
        if mode == "encrypted" {
            let keyring = root.join("keyring.json");
            fs::write(&keyring, json!({"version":1,"active_key_id":"disabled-seal","keys":[{"id":"disabled-seal","key_base64":STANDARD.encode([95;32])}]}).to_string()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
            }
            encryption::install_process_keyring(encryption::Keyring::load(&keyring).unwrap(), true)
                .unwrap();
        }
        let data = root.join("db");
        let dir = super::collection_dir(&data, "docs");
        let scope = crate::tenant::TenantScope::tenant("lifecycle-writer", "acme");
        let db = Db::open(&data).unwrap();
        let mut config = ls_vec_config("docs");
        config.streamer_max_bytes = usize::MAX;
        db.create_collection(config).unwrap();
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        let ids = [
            "stable",
            "by-id",
            "by-filter",
            "single",
            "sealing",
            "old-tail",
        ];
        db.upsert(
            "docs",
            ids.iter()
                .enumerate()
                .map(|(i, id)| graph_point(id, i as f32 + 1.0, "acme"))
                .collect(),
        )
        .unwrap();
        let nids = {
            let coll = db.get_coll("docs").unwrap();
            let state = coll.read();
            ids.iter()
                .map(|id| {
                    (
                        *id,
                        state.graph_resolver.as_ref().unwrap().live_nid(id).unwrap(),
                    )
                })
                .collect::<HashMap<_, _>>()
        };
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: "old-type".into(),
                weight_property: None,
            },
            true,
            &scope,
        )
        .unwrap();
        let old_edge = db
            .relate_scoped(
                "docs",
                RelateRequest {
                    source_point_id: "stable".into(),
                    target_point_id: "by-id".into(),
                    edge_type: "old-type".into(),
                    properties: json!({}),
                    scope: GraphRelationScope::Local,
                    idempotency_key: Some("old-retry".into()),
                },
                true,
                &scope,
            )
            .unwrap();
        let session = db
            .open_deferred_graph_session_scoped("docs", true, &scope)
            .unwrap();
        let enabled = prepare_forced_graph_vector_seal(&db, &data, "docs");
        run_segment_seal(&enabled).unwrap();
        let enabled_base = enabled.coll.read().searchers[0].id.clone();
        let enabled_fragment_high = enabled
            .coll
            .read()
            .graph_generation
            .as_ref()
            .unwrap()
            .manifest
            .graph
            .as_ref()
            .unwrap()
            .fragment_catalog
            .as_ref()
            .unwrap()
            .high_watermark;
        drop(enabled);

        db.set_graph_lifecycle_scoped("docs", false, true, &scope)
            .unwrap();
        assert_eq!(db.delete("docs", &["by-id".into()]).unwrap(), 1);
        assert_eq!(
            db.delete_by_filter_scoped(
                "docs",
                &Filter(json!({"private":"by-filter-payload"})),
                &scope
            )
            .unwrap(),
            1
        );
        db.upsert(
            "docs",
            vec![
                graph_point("by-id", 10.0, "acme"),
                graph_point("by-filter", 11.0, "acme"),
                graph_point("sealing", 12.0, "acme"),
                graph_point("new-disabled", 13.0, "acme"),
            ],
        )
        .unwrap();
        let first = prepare_forced_graph_vector_seal(&db, &data, "docs");
        // Exercise disabled deletion from the frozen and old sealed locations.
        assert_eq!(
            db.delete("docs", &["sealing".into(), "old-tail".into()])
                .unwrap(),
            2
        );
        {
            let state = first.coll.read();
            let resolver = state.graph_resolver.as_ref().unwrap();
            for id in ["by-id", "by-filter", "sealing", "old-tail"] {
                assert!(resolver.is_retired(nids[id]), "runtime retirement: {id}");
                assert!(resolver.live_nid(id).is_none());
            }
            assert_eq!(resolver.live_nid("stable"), Some(nids["stable"]));
        }
        run_segment_seal(&first).unwrap();
        let first_cut = first.end_lsn;
        let selected = GraphGeneration::open(&dir).unwrap().unwrap();
        let recovered = selected.recovered.as_ref().unwrap();
        assert!(!recovered.lifecycle.is_enabled());
        assert_eq!(recovered.lifecycle.epoch().unwrap().raw(), 2);
        assert_eq!(
            recovered.resolver.live_nid("sealing"),
            Some(nids["sealing"]),
            "tail must not leak into frozen cut"
        );
        assert!(recovered.resolver.is_retired(nids["by-id"]));
        assert!(selected.bases.is_empty() && selected.deltas.is_empty());
        let fragment_catalog = selected
            .manifest
            .graph
            .as_ref()
            .unwrap()
            .fragment_catalog
            .as_ref()
            .unwrap();
        assert!(fragment_catalog.bindings.is_empty());
        assert_eq!(fragment_catalog.high_watermark, enabled_fragment_high);
        assert_eq!(recovered.mutable.live_edge_count(), 0);
        assert_eq!(recovered.mutable.types().len(), 0);
        assert!(recovered.mutable.idempotency("old-retry").is_none());
        let mut invalid = selected.manifest.as_ref().clone();
        invalid
            .graph
            .as_mut()
            .unwrap()
            .base_segments
            .push(enabled_base);
        assert!(
            GraphGeneration::load_candidate(&dir, invalid).is_err(),
            "disabled state must not admit old active topology"
        );
        drop(selected);
        // A durable legacy single-delete, modeled immediately before process
        // loss, exercises the other replay spelling after a disabled checkpoint.
        first
            .coll
            .write()
            .wal
            .append(&WalEntry::Delete {
                id: "single".into(),
            })
            .unwrap();
        drop(first);
        drop(db);

        let db = Db::open(&data).unwrap();
        let coll = db.get_coll("docs").unwrap();
        {
            let state = coll.read();
            assert_eq!(state.wal_watermark, first_cut);
            assert!(!state.graph_lifecycle.is_enabled());
            assert!(state.graph_mutable.is_none());
            assert_eq!(state.live_points(), 4);
            let resolver = state.graph_resolver.as_ref().unwrap();
            assert_eq!(resolver.retired_len(), 5);
            for id in ["by-id", "by-filter", "single", "sealing", "old-tail"] {
                assert!(resolver.is_retired(nids[id]));
            }
            for id in ["by-id", "by-filter", "new-disabled"] {
                assert!(resolver.live_nid(id).is_none());
            }
        }
        db.set_payload("docs", "stable", json!({"changed":true}), true)
            .unwrap();
        let second = prepare_forced_graph_vector_seal(&db, &data, "docs");
        // Deleting an unassigned disabled point must not resurrect its old Nid.
        db.delete_by_filter("docs", &Filter(json!({"private":"by-filter-payload"})))
            .unwrap();
        db.upsert("docs", vec![graph_point("by-filter", 14.0, "acme")])
            .unwrap();
        run_segment_seal(&second).unwrap();
        assert!(second.coll.read().graph_mutable.is_none());
        assert_eq!(
            second
                .coll
                .read()
                .graph_generation
                .as_ref()
                .unwrap()
                .manifest
                .graph
                .as_ref()
                .unwrap()
                .edge_ledger
                .runs
                .len(),
            0
        );
        drop(second);
        drop(coll);
        drop(db);

        let db = Db::open(&data).unwrap();
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        wait_for_graph_backfill(&db, "docs");
        {
            let coll = db.get_coll("docs").unwrap();
            let state = coll.read();
            assert_eq!(state.graph_lifecycle.epoch().unwrap().raw(), 3);
            let resolver = state.graph_resolver.as_ref().unwrap();
            assert_eq!(resolver.live_nid("stable"), Some(nids["stable"]));
            for id in ["by-id", "by-filter"] {
                assert_ne!(resolver.live_nid(id), Some(nids[id]));
            }
            assert_eq!(resolver.live_len(), 4);
            assert_eq!(resolver.retired_len(), 5);
            let graph = state.graph_mutable.as_ref().unwrap();
            assert_eq!(graph.live_edge_count(), 0);
            assert_eq!(graph.types().len(), 0);
            assert!(graph.idempotency("old-retry").is_none());
            assert!(!graph.deferred_session_is_open(session.session_id.as_str()));
        }
        assert!(
            db.unrelate_scoped("docs", &old_edge.edge_id, true, &scope)
                .is_err()
        );
        db.upsert("docs", vec![graph_point("stable", 20.0, "acme")])
            .unwrap();
        let final_seal = prepare_forced_graph_vector_seal(&db, &data, "docs");
        run_segment_seal(&final_seal).unwrap();
        let selected = GraphGeneration::open(&dir).unwrap().unwrap();
        let catalog = selected
            .manifest
            .graph
            .as_ref()
            .unwrap()
            .fragment_catalog
            .as_ref()
            .unwrap();
        assert!(!catalog.bindings.is_empty());
        assert!(
            catalog
                .bindings
                .iter()
                .all(|binding| binding.fragment_id > enabled_fragment_high)
        );
        drop(selected);
        drop(final_seal);
        drop(db);
        let db = Db::open(&data).unwrap();
        let coll = db.get_coll("docs").unwrap();
        let state = coll.read();
        assert!(state.graph_lifecycle.is_enabled());
        assert_eq!(state.live_points(), 4);
        assert_eq!(
            state.graph_resolver.as_ref().unwrap().live_nid("stable"),
            Some(nids["stable"])
        );
        assert_eq!(state.graph_resolver.as_ref().unwrap().retired_len(), 5);
        assert_eq!(state.graph_mutable.as_ref().unwrap().live_edge_count(), 0);
    }

    #[test]
    fn graph_production_seal_preserves_legacy_vectors_and_reenabled_epoch() {
        use crate::graph::{ConfigureEdgeTypeRequest, GraphRelationScope, RelateRequest};
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("docs");
        config.streamer_max_bytes = usize::MAX;
        db.create_collection(config).unwrap();
        db.upsert("docs", vec![graph_point("legacy", 1.0, "acme")])
            .unwrap();
        db.compact_collection("docs").unwrap();
        let legacy_dir = db.get_coll("docs").unwrap().read().searchers[0].dir.clone();
        let scope = crate::tenant::TenantScope::tenant("seal-writer", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        wait_for_graph_backfill(&db, "docs");
        db.upsert("docs", vec![graph_point("new", 2.0, "acme")])
            .unwrap();
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: "links".into(),
                weight_property: None,
            },
            true,
            &scope,
        )
        .unwrap();
        db.relate_scoped(
            "docs",
            RelateRequest {
                source_point_id: "legacy".into(),
                target_point_id: "new".into(),
                edge_type: "links".into(),
                properties: json!({}),
                scope: GraphRelationScope::Local,
                idempotency_key: None,
            },
            true,
            &scope,
        )
        .unwrap();
        let seal = prepare_forced_graph_vector_seal(&db, temp.path(), "docs");
        run_segment_seal(&seal).unwrap();
        assert!(!legacy_dir.join(crate::graph_nid::NID_FILE).exists());
        assert_eq!(
            seal.coll
                .read()
                .graph_generation
                .as_ref()
                .unwrap()
                .deltas
                .len(),
            1
        );
        drop(seal);
        drop(db);
        let db = Db::open(temp.path()).unwrap();
        assert_eq!(
            db.get_coll("docs")
                .unwrap()
                .read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .live_edge_count(),
            1
        );
        db.set_graph_lifecycle_scoped("docs", false, true, &scope)
            .unwrap();
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        db.upsert("docs", vec![graph_point("epoch-three", 3.0, "acme")])
            .unwrap();
        let seal = prepare_forced_graph_vector_seal(&db, temp.path(), "docs");
        run_segment_seal(&seal).unwrap();
        assert_eq!(
            seal.coll
                .read()
                .graph_generation
                .as_ref()
                .unwrap()
                .bases
                .len(),
            1
        );
        drop(seal);
        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("docs").unwrap();
        let state = coll.read();
        assert_eq!(state.live_points(), 3);
        assert_eq!(state.graph_lifecycle.epoch().unwrap().raw(), 3);
        assert_eq!(state.graph_mutable.as_ref().unwrap().live_edge_count(), 0);
        assert_eq!(
            reopened
                .get_points("docs", &["legacy".into()])
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn graph_automatic_seal_checkpoints_complete_authority_and_retains_disabled_history() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        for name in ["enabled", "dropped"] {
            let mut config = ls_vec_config(name);
            config.streamer_max_bytes = 1;
            db.create_collection(config).unwrap();
            let coll = db.get_coll(name).unwrap();
            let mut collection = coll.write();
            collection
                .wal
                .append(&WalEntry::GraphEpochAdvance {
                    epoch: crate::graph::GraphEpoch::INITIAL,
                    enabled: true,
                })
                .unwrap();
            if name == "dropped" {
                collection
                    .wal
                    .append(&WalEntry::GraphEpochAdvance {
                        epoch: crate::graph::GraphEpoch::from_raw(2).unwrap(),
                        enabled: false,
                    })
                    .unwrap();
            }
        }
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let enabled = reopened.get_coll("enabled").unwrap();
        let wal_before = enabled.read().wal.len().unwrap();

        // Crossing the cap publishes complete graph/vector authority, so the
        // installed prefix can be retired while lifecycle remains recoverable.
        reopened
            .upsert("enabled", vec![ls_vec_point("node", 1.0, "live")])
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let collection = enabled.read();
            if collection.sealing.is_none() && !collection.searchers.is_empty() {
                break;
            }
            drop(collection);
            assert!(
                std::time::Instant::now() < deadline,
                "graph-aware production seal did not complete"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let collection = enabled.read();
        assert!(collection.graph_lifecycle.is_enabled());
        assert!(collection.sealing.is_none());
        assert_eq!(collection.searchers.len(), 1);
        assert!(collection.wal_watermark > wal_before);
        assert!(collection.wal.len().unwrap() > wal_before);
        let retained_wal_len = collection.wal.len().unwrap();
        let watermark = collection.wal_watermark;
        assert_eq!(watermark, retained_wal_len);
        assert!(collection.graph_generation.is_some());
        drop(collection);

        let wal_dir = super::collection_dir(temp.path(), "enabled").join("wal");
        assert_eq!(Wal::retained_base_lsn(&wal_dir).unwrap(), watermark);
        let archives = fs::read_dir(wal_dir.join("archive"))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().is_dir())
            .collect::<Vec<_>>();
        assert_eq!(archives.len(), 1);
        let archived_records = Wal::load(&archives[0].path()).unwrap();
        assert!(!archived_records.is_empty());
        assert!(archived_records.last().unwrap().lsn < watermark);

        let checkpoint =
            crate::checkpoint::read_checkpoint(&super::collection_dir(temp.path(), "enabled"))
                .unwrap()
                .unwrap();
        assert_eq!(checkpoint.wal_watermark, watermark);

        // D3 compaction now replaces vector and graph artifacts through one
        // manifest for both an active graph and retained disabled history.
        assert_eq!(reopened.compact_collection("enabled").unwrap().points, 1);
        assert_eq!(reopened.compact_collection("dropped").unwrap().points, 0);
        let enabled_after_compaction = enabled.read();
        let wal_after_compaction = enabled_after_compaction.wal.len().unwrap();
        let watermark_after_compaction = enabled_after_compaction.wal_watermark;
        assert!(wal_after_compaction > watermark_after_compaction);
        assert_eq!(
            Wal::retained_base_lsn(&wal_dir).unwrap(),
            watermark_after_compaction
        );
        assert_eq!(enabled_after_compaction.searchers.len(), 1);
        assert_eq!(
            enabled_after_compaction
                .graph_generation
                .as_ref()
                .unwrap()
                .manifest
                .segments
                .len(),
            1
        );
        drop(enabled_after_compaction);
        drop(enabled);
        drop(reopened);

        let recovered = Db::open(temp.path()).unwrap();
        let enabled = recovered.get_coll("enabled").unwrap();
        let enabled = enabled.read();
        assert!(enabled.graph_lifecycle.is_enabled());
        assert_eq!(enabled.wal.len().unwrap(), wal_after_compaction);
        assert_eq!(enabled.wal_watermark, watermark_after_compaction);
        assert_eq!(enabled.searchers.len(), 1);
        assert!(enabled.id_index.contains_key("node"));
        drop(enabled);
        let dropped = recovered.get_coll("dropped").unwrap();
        let dropped = dropped.read();
        assert!(!dropped.graph_lifecycle.is_enabled());
        assert_eq!(dropped.graph_lifecycle.epoch().unwrap().raw(), 2);
    }

    #[test]
    fn graph_point_mutations_route_from_frozen_seal_to_live_state() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("docs");
        config.streamer_max_bytes = usize::MAX;
        db.create_collection(config).unwrap();
        let scope = crate::tenant::TenantScope::tenant("graph-writer", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();

        let mut source = graph_point("source", 1.0, "acme");
        source.sparse_vector = Some(SparseVector {
            indices: vec![7],
            values: vec![1.0],
        });
        db.upsert("docs", vec![source]).unwrap();
        let nid_before = db
            .get_coll("docs")
            .unwrap()
            .read()
            .graph_resolver
            .as_ref()
            .unwrap()
            .live_nid("source")
            .unwrap();

        let seal = prepare_forced_graph_vector_seal(&db, temp.path(), "docs");
        assert_eq!(
            seal.coll.read().id_index.get("source"),
            Some(&crate::searcher::SegLoc::Sealing)
        );

        let mut replacement = graph_point("source", 2.0, "acme");
        replacement.payload["version"] = json!("superseded-during-seal");
        replacement.sparse_vector = Some(SparseVector {
            indices: vec![9],
            values: vec![2.0],
        });
        db.upsert("docs", vec![replacement]).unwrap();
        run_segment_seal(&seal).unwrap();

        {
            let collection = seal.coll.read();
            assert_eq!(
                collection
                    .graph_resolver
                    .as_ref()
                    .unwrap()
                    .live_nid("source"),
                Some(nid_before)
            );
            assert_eq!(
                collection.id_index.get("source"),
                Some(&crate::searcher::SegLoc::Streamer)
            );
            assert!(collection.searchers[0].tombstones.contains("source"));
            assert!(
                collection
                    .sparse_index
                    .dimensions
                    .get(&7)
                    .is_none_or(|posting| posting.postings.iter().all(|row| row.id != "source"))
            );
            assert!(
                collection.sparse_index.dimensions[&9]
                    .postings
                    .iter()
                    .any(|row| row.id == "source" && row.value == 2.0)
            );
            assert_eq!(collection.wal_watermark, seal.end_lsn);
        }
        drop(seal);

        let mut doomed = graph_point("delete-me", 3.0, "acme");
        doomed.sparse_vector = Some(SparseVector {
            indices: vec![11],
            values: vec![3.0],
        });
        db.upsert("docs", vec![doomed]).unwrap();
        let doomed_nid = db
            .get_coll("docs")
            .unwrap()
            .read()
            .graph_resolver
            .as_ref()
            .unwrap()
            .live_nid("delete-me")
            .unwrap();
        let delete_seal = prepare_forced_graph_vector_seal(&db, temp.path(), "docs");
        assert_eq!(
            db.delete_with_edges_scoped("docs", &["delete-me".to_string()], &scope)
                .unwrap(),
            1
        );
        run_segment_seal(&delete_seal).unwrap();
        {
            let collection = delete_seal.coll.read();
            let resolver = collection.graph_resolver.as_ref().unwrap();
            assert!(resolver.is_retired(doomed_nid));
            assert!(resolver.live_nid("delete-me").is_none());
            assert!(!collection.id_index.contains_key("delete-me"));
            assert!(collection.searchers[1].tombstones.contains("delete-me"));
            assert!(
                collection
                    .sparse_index
                    .dimensions
                    .get(&11)
                    .is_none_or(|posting| posting.postings.iter().all(|row| row.id != "delete-me"))
            );
        }
        drop(delete_seal);
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let collection = reopened.get_coll("docs").unwrap();
        let collection = collection.read();
        assert_eq!(
            collection
                .graph_resolver
                .as_ref()
                .unwrap()
                .live_nid("source"),
            Some(nid_before)
        );
        assert_eq!(
            collection.id_index.get("source"),
            Some(&crate::searcher::SegLoc::Searcher(1))
        );
        assert_eq!(
            collection.searchers[1].store.get("source").unwrap().vector,
            vec![2.0, 0.0]
        );
        assert!(
            collection.sparse_index.dimensions[&9]
                .postings
                .iter()
                .any(|row| row.id == "source" && row.value == 2.0)
        );
        assert!(
            collection
                .graph_resolver
                .as_ref()
                .unwrap()
                .is_retired(doomed_nid)
        );
        assert!(!collection.id_index.contains_key("delete-me"));
    }

    #[test]
    fn c1_million_randomized_mutations_interleaved_with_forced_seals_match_oracle() {
        use crate::{
            graph::{
                ConfigureEdgeTypeRequest, EdgeMutation, EdgePropertyMode, EdgePropertyMutation,
                GraphNamespace, RelateMutation, TypeId, UnrelateMutation,
            },
            wal::GraphBatch,
        };

        const POINT_COUNT: usize = 64;
        const EDGE_BATCH_SIZE: usize = 4_096;
        const EDGE_BATCHES: usize = 245;
        const EDGE_MUTATION_COUNT: usize = EDGE_BATCH_SIZE * EDGE_BATCHES;
        const SEAL_EVERY_BATCHES: usize = 32;

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("docs");
        config.streamer_max_bytes = usize::MAX;
        db.create_collection(config).unwrap();
        let scope = crate::tenant::TenantScope::tenant("c1-writer", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: "CITES".to_string(),
                weight_property: None,
            },
            true,
            &scope,
        )
        .unwrap();

        let point_ids = (0..POINT_COUNT)
            .map(|index| format!("node-{index:03}"))
            .collect::<Vec<_>>();
        db.upsert(
            "docs",
            point_ids
                .iter()
                .enumerate()
                .map(|(index, point_id)| graph_point(point_id, index as f32, "acme"))
                .collect(),
        )
        .unwrap();
        let mut live_nids = {
            let collection = db.get_coll("docs").unwrap();
            let collection = collection.read();
            let resolver = collection.graph_resolver.as_ref().unwrap();
            point_ids
                .iter()
                .map(|point_id| resolver.live_nid(point_id))
                .collect::<Vec<_>>()
        };
        let mut retired_nids = HashSet::new();
        let mut edges = HashMap::new();
        let mut slots = vec![None; EDGE_BATCH_SIZE];
        let mut edge_ids = db
            .graph_identity
            .allocate_edge_ids(std::num::NonZeroU64::new((EDGE_MUTATION_COUNT + 1) as u64).unwrap())
            .unwrap()
            .edge_ids();

        let initial_seal = prepare_forced_graph_vector_seal(&db, temp.path(), "docs");
        run_segment_seal(&initial_seal).unwrap();
        assert_c1_mutation_oracle(
            &initial_seal.coll.read(),
            &point_ids,
            &live_nids,
            &retired_nids,
            &edges,
        );
        drop(initial_seal);
        let mut forced_seals = 1_usize;

        // Named opposite outcomes required by C1: UPSERT supersession keeps
        // the Nid and relation, while delete-then-recreate changes the Nid and
        // must never reconnect the old relation.
        let named_edge_id = edge_ids.next().unwrap();
        let named_source = live_nids[0].unwrap();
        let retired_target = live_nids[1].unwrap();
        {
            let coll = db.get_coll("docs").unwrap();
            db.commit_graph_batch_locked(
                &mut coll.write(),
                GraphBatch {
                    graph_epoch: crate::graph::GraphEpoch::INITIAL,
                    edge_mutations: vec![EdgeMutation::Relate(RelateMutation {
                        edge_id: named_edge_id,
                        source: named_source,
                        target: retired_target,
                        type_id: TypeId::from_raw(1),
                        namespace: GraphNamespace::Tenant("acme".to_string()),
                        properties: json!({"revision": 0}),
                    })],
                    ..GraphBatch::default()
                },
                false,
            )
            .unwrap();
        }
        edges.insert(
            named_edge_id,
            C1EdgeOracle {
                source: named_source,
                target: retired_target,
                revision: 0,
                live: true,
            },
        );

        let mut superseded = graph_point(&point_ids[0], 10_000.0, "acme");
        superseded.payload["revision"] = json!("superseded");
        db.upsert("docs", vec![superseded]).unwrap();
        assert_eq!(
            db.get_coll("docs")
                .unwrap()
                .read()
                .graph_resolver
                .as_ref()
                .unwrap()
                .live_nid(&point_ids[0]),
            Some(named_source)
        );
        let named_seal = prepare_forced_graph_vector_seal(&db, temp.path(), "docs");
        run_segment_seal(&named_seal).unwrap();
        assert_c1_mutation_oracle(
            &named_seal.coll.read(),
            &point_ids,
            &live_nids,
            &retired_nids,
            &edges,
        );
        drop(named_seal);
        forced_seals += 1;

        assert_eq!(
            db.delete_with_edges_scoped("docs", &[point_ids[1].clone()], &scope)
                .unwrap(),
            1
        );
        live_nids[1] = None;
        retired_nids.insert(retired_target);
        assert_c1_mutation_oracle(
            &db.get_coll("docs").unwrap().read(),
            &point_ids,
            &live_nids,
            &retired_nids,
            &edges,
        );
        db.upsert("docs", vec![graph_point(&point_ids[1], 20_000.0, "acme")])
            .unwrap();
        let replacement_target = db
            .get_coll("docs")
            .unwrap()
            .read()
            .graph_resolver
            .as_ref()
            .unwrap()
            .live_nid(&point_ids[1])
            .unwrap();
        assert_ne!(replacement_target, retired_target);
        assert!(retired_nids.contains(&retired_target));
        live_nids[1] = Some(replacement_target);
        assert_c1_mutation_oracle(
            &db.get_coll("docs").unwrap().read(),
            &point_ids,
            &live_nids,
            &retired_nids,
            &edges,
        );

        let mut random_state = 0xc1c1_5ea1_5eed_2026_u64;
        let mut relates = 0_usize;
        let mut unrelates = 0_usize;
        let mut property_updates = 0_usize;
        let mut point_supersessions = 1_usize;
        let mut point_deletes = 1_usize;
        let mut point_recreates = 1_usize;

        for batch_index in 0..EDGE_BATCHES {
            let seal_boundary = (batch_index + 1).is_multiple_of(SEAL_EVERY_BATCHES);
            let point_index = (c1_next_random(&mut random_state) as usize) % point_ids.len();
            let point_random = c1_next_random(&mut random_state);
            match live_nids[point_index] {
                Some(current_nid) if !seal_boundary && point_random.is_multiple_of(8) => {
                    assert_eq!(
                        db.delete_with_edges_scoped(
                            "docs",
                            &[point_ids[point_index].clone()],
                            &scope,
                        )
                        .unwrap(),
                        1
                    );
                    live_nids[point_index] = None;
                    assert!(retired_nids.insert(current_nid));
                    point_deletes += 1;
                }
                Some(current_nid) => {
                    let mut point =
                        graph_point(&point_ids[point_index], batch_index as f32, "acme");
                    point.payload["revision"] = json!(batch_index);
                    db.upsert("docs", vec![point]).unwrap();
                    assert_eq!(
                        db.get_coll("docs")
                            .unwrap()
                            .read()
                            .graph_resolver
                            .as_ref()
                            .unwrap()
                            .live_nid(&point_ids[point_index]),
                        Some(current_nid)
                    );
                    point_supersessions += 1;
                }
                None => {
                    let mut point =
                        graph_point(&point_ids[point_index], batch_index as f32, "acme");
                    point.payload["revision"] = json!(batch_index);
                    db.upsert("docs", vec![point]).unwrap();
                    let replacement = db
                        .get_coll("docs")
                        .unwrap()
                        .read()
                        .graph_resolver
                        .as_ref()
                        .unwrap()
                        .live_nid(&point_ids[point_index])
                        .unwrap();
                    assert!(!retired_nids.contains(&replacement));
                    live_nids[point_index] = Some(replacement);
                    point_recreates += 1;
                }
            }

            let current_nids = live_nids.iter().flatten().copied().collect::<Vec<_>>();
            assert!(!current_nids.is_empty());
            let mut mutations = Vec::with_capacity(EDGE_BATCH_SIZE);
            for slot in &mut slots {
                let choice = c1_next_random(&mut random_state);
                match *slot {
                    Some(edge_id) if !choice.is_multiple_of(8) => {
                        let revision = (batch_index * EDGE_BATCH_SIZE + mutations.len() + 1) as u64;
                        mutations.push(EdgeMutation::Properties(EdgePropertyMutation {
                            edge_id,
                            mode: EdgePropertyMode::Replace,
                            properties: json!({"revision": revision}),
                        }));
                        edges.get_mut(&edge_id).unwrap().revision = revision;
                        property_updates += 1;
                    }
                    Some(edge_id) => {
                        mutations.push(EdgeMutation::Unrelate(UnrelateMutation { edge_id }));
                        edges.get_mut(&edge_id).unwrap().live = false;
                        *slot = None;
                        unrelates += 1;
                    }
                    None => {
                        let edge_id = edge_ids.next().unwrap();
                        let source = current_nids[(choice as usize) % current_nids.len()];
                        let target_random = c1_next_random(&mut random_state);
                        let target = current_nids[(target_random as usize) % current_nids.len()];
                        let revision = (batch_index * EDGE_BATCH_SIZE + mutations.len() + 1) as u64;
                        mutations.push(EdgeMutation::Relate(RelateMutation {
                            edge_id,
                            source,
                            target,
                            type_id: TypeId::from_raw(1),
                            namespace: GraphNamespace::Tenant("acme".to_string()),
                            properties: json!({"revision": revision}),
                        }));
                        edges.insert(
                            edge_id,
                            C1EdgeOracle {
                                source,
                                target,
                                revision,
                                live: true,
                            },
                        );
                        *slot = Some(edge_id);
                        relates += 1;
                    }
                }
            }
            assert_eq!(mutations.len(), EDGE_BATCH_SIZE);
            let coll = db.get_coll("docs").unwrap();
            db.commit_graph_batch_locked(
                &mut coll.write(),
                GraphBatch {
                    graph_epoch: crate::graph::GraphEpoch::INITIAL,
                    edge_mutations: mutations,
                    ..GraphBatch::default()
                },
                false,
            )
            .unwrap();

            if seal_boundary {
                let seal = prepare_forced_graph_vector_seal(&db, temp.path(), "docs");
                run_segment_seal(&seal).unwrap();
                assert_c1_mutation_oracle(
                    &seal.coll.read(),
                    &point_ids,
                    &live_nids,
                    &retired_nids,
                    &edges,
                );
                drop(seal);
                forced_seals += 1;
            }
        }

        let final_seal = prepare_forced_graph_vector_seal(&db, temp.path(), "docs");
        run_segment_seal(&final_seal).unwrap();
        assert_c1_mutation_oracle(
            &final_seal.coll.read(),
            &point_ids,
            &live_nids,
            &retired_nids,
            &edges,
        );
        // Prefix retirement preserves absolute LSNs, including after restart.
        let final_cut = final_seal.end_lsn;
        assert!(final_cut > 0);
        assert_eq!(final_seal.coll.read().wal_watermark, final_cut);
        assert_eq!(
            Wal::retained_base_lsn(&temp.path().join("collections/docs/wal")).unwrap(),
            final_cut
        );
        drop(final_seal);
        forced_seals += 1;

        assert_eq!(EDGE_MUTATION_COUNT, 1_003_520);
        assert_eq!(relates + unrelates + property_updates, EDGE_MUTATION_COUNT);
        assert_eq!(point_supersessions + point_deletes + point_recreates, 248);
        assert_eq!(edges.len(), relates + 1);
        assert!(relates > 0);
        assert!(unrelates > 0);
        assert!(property_updates > 0);
        assert!(point_supersessions > 1);
        assert!(point_deletes > 1);
        assert!(point_recreates > 1);
        assert_eq!(forced_seals, 10);
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let collection = reopened.get_coll("docs").unwrap();
        let collection = collection.read();
        assert_c1_mutation_oracle(&collection, &point_ids, &live_nids, &retired_nids, &edges);
        assert_eq!(collection.wal_watermark, final_cut);
    }

    #[test]
    fn graph_batch_scoped_prevalidates_wal_and_publishes_wait_receipts() {
        use crate::{
            graph::{EdgeMutation, GraphNamespace, RelateMutation, TypeId, UnrelateMutation},
            wal::{GraphHandleAssignment, GraphTypeConfiguration},
        };

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let coll = db.get_coll("docs").unwrap();
        coll.write()
            .wal
            .append(&WalEntry::GraphEpochAdvance {
                epoch: crate::graph::GraphEpoch::INITIAL,
                enabled: true,
            })
            .unwrap();
        drop(coll);
        drop(db);

        let db = Db::open(temp.path()).unwrap();
        let nids = db
            .graph_identity
            .allocate_nids(std::num::NonZeroU64::new(2).unwrap())
            .unwrap()
            .nids()
            .collect::<Vec<_>>();
        let edge_id = db
            .graph_identity
            .allocate_edge_ids(std::num::NonZeroU64::new(1).unwrap())
            .unwrap()
            .edge_ids()
            .next()
            .unwrap();
        let mut source = ls_vec_point("source-secret", 1.0, "source");
        source.payload = json!({"tenant_id": "acme"});
        let mut target = ls_vec_point("target-secret", 2.0, "target");
        target.payload = json!({"tenant_id": "acme"});
        let type_id = TypeId::from_raw(1);
        let scope = crate::tenant::TenantScope::tenant("graph-key", "acme");
        let receipt = db
            .commit_graph_batch_scoped(
                "docs",
                GraphBatch {
                    type_configurations: vec![GraphTypeConfiguration {
                        type_id,
                        name: "cites".to_string(),
                        weight_property: None,
                    }],
                    point_mutations: vec![
                        GraphPointMutation::Upsert { point: source },
                        GraphPointMutation::Upsert { point: target },
                    ],
                    handle_assignments: vec![
                        GraphHandleAssignment {
                            point_id: "source-secret".to_string(),
                            nid: nids[0],
                        },
                        GraphHandleAssignment {
                            point_id: "target-secret".to_string(),
                            nid: nids[1],
                        },
                    ],
                    edge_mutations: vec![EdgeMutation::Relate(RelateMutation {
                        edge_id,
                        source: nids[0],
                        target: nids[1],
                        type_id,
                        namespace: GraphNamespace::Tenant("acme".to_string()),
                        properties: json!({"secret": "edge-secret"}),
                    })],
                    ..GraphBatch::default()
                },
                false,
                &scope,
            )
            .unwrap();
        assert_eq!(receipt.graph_epoch, crate::graph::GraphEpoch::INITIAL);
        assert!(!receipt.durable);
        let coll = db.get_coll("docs").unwrap();
        let collection = coll.read();
        assert!(collection.wal.is_dirty());
        assert_eq!(
            collection.graph_mutable.as_ref().unwrap().live_edge_count(),
            1
        );
        let wal_before_rejection = collection.wal.len().unwrap();
        drop(collection);

        let error = db
            .commit_graph_batch_scoped(
                "docs",
                GraphBatch {
                    edge_mutations: vec![EdgeMutation::Relate(RelateMutation {
                        edge_id,
                        source: nids[0],
                        target: nids[1],
                        type_id,
                        namespace: GraphNamespace::Tenant("acme".to_string()),
                        properties: json!({}),
                    })],
                    ..GraphBatch::default()
                },
                true,
                &scope,
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("EdgeId already exists"),
            "{error}"
        );
        let collection = coll.read();
        assert_eq!(collection.wal.len().unwrap(), wal_before_rejection);
        assert_eq!(
            collection.graph_mutable.as_ref().unwrap().live_edge_count(),
            1
        );
        drop(collection);

        let removed = db
            .commit_graph_batch_scoped(
                "docs",
                GraphBatch {
                    edge_mutations: vec![EdgeMutation::Unrelate(UnrelateMutation { edge_id })],
                    ..GraphBatch::default()
                },
                true,
                &scope,
            )
            .unwrap();
        assert!(removed.durable);
        assert!(removed.operation_lsn > receipt.operation_lsn);
        let collection = coll.read();
        assert_eq!(
            collection.graph_mutable.as_ref().unwrap().live_edge_count(),
            0
        );
        assert!(
            collection
                .overlays
                .current_ref()
                .edge_tombstones()
                .contains(edge_id.raw())
        );
        drop(collection);
        drop(coll);
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("docs").unwrap();
        let collection = coll.read();
        let graph = collection.graph_mutable.as_ref().unwrap();
        assert_eq!(graph.stored_edge_count(), 1);
        assert_eq!(graph.live_edge_count(), 0);
        assert!(
            collection
                .overlays
                .current_ref()
                .edge_tombstones()
                .contains(edge_id.raw())
        );
        drop(collection);

        let audit_log = std::fs::read_to_string(audit::audit_log_path(temp.path())).unwrap();
        assert!(audit_log.contains("graph_batch"));
        assert!(!audit_log.contains("source-secret"));
        assert!(!audit_log.contains("target-secret"));
        assert!(!audit_log.contains("edge-secret"));
        audit::verify_hash_chain(temp.path()).unwrap();
    }

    #[test]
    fn typed_graph_operations_are_idempotent_opaque_and_recoverable() {
        use crate::graph::{
            ConfigureEdgeTypeRequest, EdgePropertyMode, GraphRelationScope, RelateRequest,
            UpdateEdgeRequest,
        };

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let scope = crate::tenant::TenantScope::tenant("graph-writer", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        db.upsert(
            "docs",
            vec![
                graph_point("source-private", 1.0, "acme"),
                graph_point("target-private", 2.0, "acme"),
            ],
        )
        .unwrap();

        let configured = db
            .configure_edge_type_scoped(
                "docs",
                ConfigureEdgeTypeRequest {
                    name: "cites".to_string(),
                    weight_property: Some("confidence".to_string()),
                },
                true,
                &scope,
            )
            .unwrap();
        assert!(configured.changed);
        assert!(configured.receipt.durable);
        assert!(configured.receipt.operation_lsn.is_some());
        assert_eq!(
            db.list_edge_types_scoped("docs", &scope).unwrap(),
            vec![configured.edge_type.clone()]
        );
        let public_catalog =
            serde_json::to_string(&db.list_edge_types_scoped("docs", &scope).unwrap()).unwrap();
        assert!(!public_catalog.contains("type_id"));

        let unchanged = db
            .configure_edge_type_scoped(
                "docs",
                ConfigureEdgeTypeRequest {
                    name: "cites".to_string(),
                    weight_property: Some("confidence".to_string()),
                },
                true,
                &scope,
            )
            .unwrap();
        assert!(!unchanged.changed);
        assert!(unchanged.receipt.replayed);
        assert_eq!(unchanged.receipt.operation_lsn, None);

        let request = RelateRequest {
            source_point_id: "source-private".to_string(),
            target_point_id: "target-private".to_string(),
            edge_type: "cites".to_string(),
            properties: json!({"secret": "edge-private", "confidence": 0.7}),
            scope: GraphRelationScope::Local,
            idempotency_key: Some("relate-once-private".to_string()),
        };
        let related = db
            .relate_scoped("docs", request.clone(), false, &scope)
            .unwrap();
        assert_eq!(related.edge_id.as_str().len(), 39);
        assert!(!related.edge_id.as_str().contains('='));
        assert!(!related.receipt.durable);
        assert!(!related.receipt.replayed);
        let relate_lsn = related.receipt.operation_lsn.unwrap();
        let public_result = serde_json::to_value(&related).unwrap();
        assert!(public_result["edge_id"].is_string());
        assert!(public_result.get("source").is_none());
        assert!(public_result.get("target").is_none());
        assert!(public_result.get("type_id").is_none());

        let coll = db.get_coll("docs").unwrap();
        let wal_after_relate = coll.read().wal.len().unwrap();
        let replayed = db
            .relate_scoped("docs", request.clone(), true, &scope)
            .unwrap();
        assert_eq!(replayed.edge_id, related.edge_id);
        assert!(replayed.receipt.durable);
        assert!(replayed.receipt.replayed);
        assert_eq!(replayed.receipt.operation_lsn, None);
        assert_eq!(coll.read().wal.len().unwrap(), wal_after_relate);

        let mut conflicting = request.clone();
        conflicting.properties = json!({"secret": "different-request"});
        let error = db
            .relate_scoped("docs", conflicting, true, &scope)
            .unwrap_err();
        assert!(error.to_string().contains("already bound"), "{error}");
        assert_eq!(coll.read().wal.len().unwrap(), wal_after_relate);

        let merged = db
            .update_edge_scoped(
                "docs",
                &related.edge_id,
                UpdateEdgeRequest {
                    mode: EdgePropertyMode::Merge,
                    properties: json!({"confidence": 0.9, "reviewed": true}),
                },
                false,
                &scope,
            )
            .unwrap();
        let merged_lsn = merged.operation_lsn.unwrap();
        assert!(merged_lsn > relate_lsn);
        let edge_id = crate::edge_token::decode(db.graph_database_id(), &related.edge_id).unwrap();
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .edge(edge_id)
                .unwrap()
                .properties,
            json!({"secret": "edge-private", "confidence": 0.9, "reviewed": true})
        );

        let replaced = db
            .update_edge_scoped(
                "docs",
                &related.edge_id,
                UpdateEdgeRequest {
                    mode: EdgePropertyMode::Replace,
                    properties: json!({"state": "final-private"}),
                },
                true,
                &scope,
            )
            .unwrap();
        assert!(replaced.operation_lsn.unwrap() > merged_lsn);
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .edge(edge_id)
                .unwrap()
                .properties,
            json!({"state": "final-private"})
        );

        let removed = db
            .unrelate_scoped("docs", &related.edge_id, true, &scope)
            .unwrap();
        assert!(removed.operation_lsn.unwrap() > replaced.operation_lsn.unwrap());
        assert!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .edge(edge_id)
                .is_none()
        );
        let error = db
            .unrelate_scoped("docs", &related.edge_id, true, &scope)
            .unwrap_err();
        assert!(
            error.to_string().contains("graph.edge_not_found"),
            "{error}"
        );
        drop(coll);
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let wal_before_replay = reopened.get_coll("docs").unwrap().read().wal.len().unwrap();
        let recovered = reopened
            .relate_scoped("docs", request, true, &scope)
            .unwrap();
        assert_eq!(recovered.edge_id, related.edge_id);
        assert!(recovered.receipt.replayed);
        assert_eq!(recovered.receipt.operation_lsn, None);
        assert_eq!(
            reopened.get_coll("docs").unwrap().read().wal.len().unwrap(),
            wal_before_replay
        );

        let audit_log = fs::read_to_string(audit::audit_log_path(temp.path())).unwrap();
        for secret in [
            "source-private",
            "target-private",
            "edge-private",
            "final-private",
        ] {
            assert!(!audit_log.contains(secret), "audit leaked {secret}");
        }
        for operation in [
            "graph_type_configure",
            "graph_relate",
            "graph_edge_update",
            "graph_unrelate",
        ] {
            assert!(audit_log.contains(operation), "missing audit {operation}");
        }
        audit::verify_hash_chain(temp.path()).unwrap();
    }

    #[test]
    fn exact_graph_traversal_is_scoped_filtered_budgeted_and_recoverable() {
        use std::sync::atomic::AtomicBool;

        use crate::{
            graph::{
                ConfigureEdgeTypeRequest, GraphDirection, GraphRelationScope, GraphTraverseRequest,
                GraphWarning, RelateRequest, TraversalBudget, TraversalTruncationReason,
            },
            tenant::{TenantCapability, TenantEnforcement, TenantScope},
        };

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let acme = TenantScope::tenant("acme-reader", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &acme)
            .unwrap();
        db.upsert(
            "docs",
            vec![
                graph_point("a-private", 1.0, "acme"),
                graph_point("b-private", 2.0, "acme"),
                graph_point("c-private", 3.0, "acme"),
                graph_point("x-private", 4.0, "globex"),
            ],
        )
        .unwrap();
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: "links".to_string(),
                weight_property: None,
            },
            true,
            &acme,
        )
        .unwrap();
        let local = |source: &str, target: &str, enabled: bool| RelateRequest {
            source_point_id: source.to_string(),
            target_point_id: target.to_string(),
            edge_type: "links".to_string(),
            properties: json!({"enabled": enabled}),
            scope: GraphRelationScope::Local,
            idempotency_key: None,
        };
        db.relate_scoped("docs", local("a-private", "b-private", true), true, &acme)
            .unwrap();
        db.relate_scoped("docs", local("a-private", "b-private", false), true, &acme)
            .unwrap();
        db.relate_scoped("docs", local("b-private", "c-private", true), true, &acme)
            .unwrap();
        db.relate_scoped("docs", local("b-private", "b-private", true), true, &acme)
            .unwrap();

        db.set_tenant_enforcement(TenantEnforcement::Enforced);
        let cross_writer = TenantScope::tenant("cross-writer", "acme")
            .with_capabilities([TenantCapability::CrossRead, TenantCapability::CrossWrite]);
        db.relate_scoped(
            "docs",
            RelateRequest {
                source_point_id: "b-private".to_string(),
                target_point_id: "x-private".to_string(),
                edge_type: "links".to_string(),
                properties: json!({"enabled": true}),
                scope: GraphRelationScope::AdminCrossTenant,
                idempotency_key: None,
            },
            true,
            &cross_writer,
        )
        .unwrap();

        let request = GraphTraverseRequest {
            anchors: vec!["a-private".to_string()],
            edge_types: vec!["links".to_string()],
            direction: GraphDirection::Outgoing,
            node_filter: None,
            edge_filter: None,
            budget: TraversalBudget {
                max_depth: 2,
                ..TraversalBudget::default()
            },
        };
        let scoped = db.traverse_scoped("docs", request.clone(), &acme).unwrap();
        assert_eq!(
            scoped
                .nodes
                .iter()
                .map(|node| (node.point_id.as_str(), node.depth))
                .collect::<Vec<_>>(),
            vec![("b-private", 1), ("c-private", 2)]
        );
        assert_eq!(scoped.truncation, None);
        assert!(!serde_json::to_string(&scoped).unwrap().contains("nid"));

        let cross_reader = TenantScope::tenant("cross-reader", "acme")
            .with_capability(TenantCapability::CrossRead);
        let cross = db
            .traverse_scoped("docs", request.clone(), &cross_reader)
            .unwrap();
        assert_eq!(
            cross
                .nodes
                .iter()
                .map(|node| (node.point_id.as_str(), node.depth))
                .collect::<Vec<_>>(),
            vec![("b-private", 1), ("c-private", 2), ("x-private", 2)]
        );

        let mut edge_filtered = request.clone();
        edge_filtered.edge_filter = Some(Filter(json!({"enabled": true})));
        assert_eq!(
            db.traverse_scoped("docs", edge_filtered, &acme)
                .unwrap()
                .nodes
                .len(),
            2
        );

        let mut bounded = request.clone();
        bounded.budget.max_edges = 1;
        let bounded = db.traverse_scoped("docs", bounded, &acme).unwrap();
        assert_eq!(bounded.truncation, Some(TraversalTruncationReason::Edges));
        assert!(bounded.warnings.contains(&GraphWarning::ResultTruncated));

        let cancelled = AtomicBool::new(true);
        let error = db
            .traverse_cancellable_scoped("docs", request.clone(), &acme, &cancelled)
            .unwrap_err();
        assert!(error.to_string().contains("graph.cancelled"));
        let hidden = db
            .traverse_scoped(
                "docs",
                GraphTraverseRequest {
                    anchors: vec!["x-private".to_string()],
                    ..request.clone()
                },
                &acme,
            )
            .unwrap_err();
        assert!(hidden.to_string().contains("graph.endpoint_not_found"));
        assert!(!hidden.to_string().contains("x-private"));

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        reopened.set_tenant_enforcement(TenantEnforcement::Enforced);
        let recovered = reopened
            .traverse_scoped("docs", request, &cross_reader)
            .unwrap();
        assert_eq!(recovered.nodes, cross.nodes);
        assert_eq!(recovered.graph_epoch, cross.graph_epoch);
    }

    #[test]
    fn typed_relate_strict_failures_do_not_consume_identity_or_wal() {
        use crate::graph::{ConfigureEdgeTypeRequest, GraphRelationScope, RelateRequest};

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let scope = crate::tenant::TenantScope::tenant("graph-writer", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        db.upsert("docs", vec![graph_point("source", 1.0, "acme")])
            .unwrap();
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: "cites".to_string(),
                weight_property: None,
            },
            true,
            &scope,
        )
        .unwrap();
        let coll = db.get_coll("docs").unwrap();

        for request in [
            RelateRequest {
                source_point_id: "source".to_string(),
                target_point_id: "missing-private".to_string(),
                edge_type: "cites".to_string(),
                properties: json!({}),
                scope: GraphRelationScope::Local,
                idempotency_key: None,
            },
            RelateRequest {
                source_point_id: "source".to_string(),
                target_point_id: "source".to_string(),
                edge_type: "unknown-type".to_string(),
                properties: json!({}),
                scope: GraphRelationScope::Local,
                idempotency_key: None,
            },
            RelateRequest {
                source_point_id: "source".to_string(),
                target_point_id: "source".to_string(),
                edge_type: "cites".to_string(),
                properties: json!(["not", "an", "object"]),
                scope: GraphRelationScope::Local,
                idempotency_key: None,
            },
        ] {
            let identity_before = db.graph_identity.snapshot();
            let wal_before = coll.read().wal.len().unwrap();
            assert!(db.relate_scoped("docs", request, true, &scope).is_err());
            assert_eq!(db.graph_identity.snapshot(), identity_before);
            assert_eq!(coll.read().wal.len().unwrap(), wal_before);
            assert_eq!(
                coll.read()
                    .graph_mutable
                    .as_ref()
                    .unwrap()
                    .live_edge_count(),
                0
            );
        }
    }

    #[test]
    fn typed_graph_operations_separate_admin_cross_tenant_namespace() {
        use crate::{
            graph::{
                ConfigureEdgeTypeRequest, EdgePropertyMode, GraphNamespace, GraphRelationScope,
                RelateRequest, UpdateEdgeRequest,
            },
            tenant::{TenantCapability, TenantEnforcement, TenantScope},
        };

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let acme = TenantScope::tenant("acme-writer", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &acme)
            .unwrap();
        db.upsert(
            "docs",
            vec![
                graph_point("acme-private", 1.0, "acme"),
                graph_point("globex-private", 2.0, "globex"),
            ],
        )
        .unwrap();
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: "shares".to_string(),
                weight_property: None,
            },
            true,
            &acme,
        )
        .unwrap();
        let cross = TenantScope::tenant("migration-admin", "acme")
            .with_capability(TenantCapability::CrossWrite);
        let base = RelateRequest {
            source_point_id: "acme-private".to_string(),
            target_point_id: "globex-private".to_string(),
            edge_type: "shares".to_string(),
            properties: json!({"private": "cross-edge-private"}),
            scope: GraphRelationScope::Local,
            idempotency_key: None,
        };

        let error = db
            .relate_scoped("docs", base.clone(), true, &cross)
            .unwrap_err();
        assert!(error.to_string().contains("explicit admin_cross_tenant"));
        let mut explicit = base.clone();
        explicit.scope = GraphRelationScope::AdminCrossTenant;
        let error = db
            .relate_scoped("docs", explicit.clone(), true, &acme)
            .unwrap_err();
        assert!(error.to_string().contains("tenant:cross_write"));

        db.set_tenant_enforcement(TenantEnforcement::Enforced);
        let related = db.relate_scoped("docs", explicit, true, &cross).unwrap();
        let edge_id = crate::edge_token::decode(db.graph_database_id(), &related.edge_id).unwrap();
        let coll = db.get_coll("docs").unwrap();
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .edge(edge_id)
                .unwrap()
                .namespace,
            GraphNamespace::AdminCrossTenant
        );

        let seal = prepare_forced_graph_vector_seal(&db, temp.path(), "docs");
        run_segment_seal(&seal).unwrap();
        drop(seal);
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .unsealed_topology_rows(),
            0
        );
        let before_hidden = coll.read().wal.len().unwrap();

        let hidden = db
            .update_edge_scoped(
                "docs",
                &related.edge_id,
                UpdateEdgeRequest {
                    mode: EdgePropertyMode::Merge,
                    properties: json!({"blocked": true}),
                },
                true,
                &acme,
            )
            .unwrap_err();
        assert!(
            hidden.to_string().contains("graph.edge_not_found"),
            "{hidden}"
        );
        let hidden_delete = db
            .unrelate_scoped("docs", &related.edge_id, true, &acme)
            .unwrap_err();
        assert!(hidden_delete.to_string().contains("graph.edge_not_found"));
        assert_eq!(coll.read().wal.len().unwrap(), before_hidden);
        db.update_edge_scoped(
            "docs",
            &related.edge_id,
            UpdateEdgeRequest {
                mode: EdgePropertyMode::Merge,
                properties: json!({"approved": true}),
            },
            true,
            &cross,
        )
        .unwrap();
        db.unrelate_scoped("docs", &related.edge_id, true, &cross)
            .unwrap();
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .live_edge_count(),
            0
        );
    }

    #[test]
    fn typed_deferred_session_binds_only_a_fresh_session_incarnation() {
        use crate::graph::{
            ConfigureEdgeTypeRequest, GraphDeferredSessionState, GraphRelationScope, RelateRequest,
        };

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let scope = crate::tenant::TenantScope::tenant("bulk-writer", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        db.upsert("docs", vec![graph_point("source-private", 1.0, "acme")])
            .unwrap();
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: "imports".to_string(),
                weight_property: None,
            },
            true,
            &scope,
        )
        .unwrap();

        let opened = db
            .open_deferred_graph_session_scoped("docs", true, &scope)
            .unwrap();
        assert_eq!(opened.state, GraphDeferredSessionState::Open);
        assert_eq!(opened.session_id.as_str().len(), 32);
        let request = RelateRequest {
            source_point_id: "source-private".to_string(),
            target_point_id: "target-private".to_string(),
            edge_type: "imports".to_string(),
            properties: json!({"secret": "deferred-edge-private"}),
            scope: GraphRelationScope::Local,
            idempotency_key: Some("deferred-once-private".to_string()),
        };
        let related = db
            .relate_deferred_scoped("docs", &opened.session_id, request.clone(), false, &scope)
            .unwrap();
        let edge_id = crate::edge_token::decode(db.graph_database_id(), &related.edge_id).unwrap();
        let coll = db.get_coll("docs").unwrap();
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .pending_edge_count(),
            1
        );
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .live_edge_count(),
            0
        );
        let wal_after_relate = coll.read().wal.len().unwrap();
        let replayed = db
            .relate_deferred_scoped("docs", &opened.session_id, request.clone(), true, &scope)
            .unwrap();
        assert_eq!(replayed.edge_id, related.edge_id);
        assert!(replayed.receipt.replayed);
        assert_eq!(replayed.receipt.operation_lsn, None);
        assert_eq!(coll.read().wal.len().unwrap(), wal_after_relate);

        // An ordinary UPSERT creates an incarnation outside the session and
        // must not capture the pending edge.
        db.upsert("docs", vec![graph_point("target-private", 2.0, "acme")])
            .unwrap();
        let outside_nid = coll
            .read()
            .graph_resolver
            .as_ref()
            .unwrap()
            .live_nid("target-private")
            .unwrap();
        let no_bind = db
            .upsert_deferred_scoped(
                "docs",
                &opened.session_id,
                vec![graph_point("target-private", 3.0, "acme")],
                true,
                &scope,
            )
            .unwrap();
        assert_eq!(no_bind.bound_endpoints, 0);
        let wal_before_failed_close = coll.read().wal.len().unwrap();
        let error = db
            .commit_deferred_graph_session_scoped("docs", &opened.session_id, true, &scope)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("graph.deferred_endpoints_remain"),
            "{error}"
        );
        assert_eq!(coll.read().wal.len().unwrap(), wal_before_failed_close);
        assert!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .deferred_session_is_open(opened.session_id.as_str())
        );

        db.delete("docs", &["target-private".to_string()]).unwrap();
        let bound = db
            .upsert_deferred_scoped(
                "docs",
                &opened.session_id,
                vec![graph_point("target-private", 4.0, "acme")],
                false,
                &scope,
            )
            .unwrap();
        assert_eq!(bound.bound_endpoints, 1);
        let session_nid = coll
            .read()
            .graph_resolver
            .as_ref()
            .unwrap()
            .live_nid("target-private")
            .unwrap();
        assert_ne!(session_nid, outside_nid);
        {
            let collection = coll.read();
            let graph = collection.graph_mutable.as_ref().unwrap();
            assert_eq!(graph.pending_edge_count(), 0);
            assert_eq!(graph.live_edge_count(), 1);
            assert_eq!(graph.edge(edge_id).unwrap().target, session_nid);
        }

        let committed = db
            .commit_deferred_graph_session_scoped("docs", &opened.session_id, true, &scope)
            .unwrap();
        assert_eq!(committed.state, GraphDeferredSessionState::Committed);
        let wal_after_commit = coll.read().wal.len().unwrap();
        let repeated = db
            .commit_deferred_graph_session_scoped("docs", &opened.session_id, true, &scope)
            .unwrap();
        assert!(repeated.receipt.replayed);
        assert_eq!(repeated.receipt.operation_lsn, None);
        assert_eq!(coll.read().wal.len().unwrap(), wal_after_commit);
        drop(coll);
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("docs").unwrap();
        let collection = coll.read();
        let graph = collection.graph_mutable.as_ref().unwrap();
        assert!(graph.deferred_session_is_committed(opened.session_id.as_str()));
        assert_eq!(graph.pending_edge_count(), 0);
        assert_eq!(graph.live_edge_count(), 1);
        assert_eq!(graph.edge(edge_id).unwrap().target, session_nid);
        drop(collection);

        let audit_log = fs::read_to_string(audit::audit_log_path(temp.path())).unwrap();
        for secret in [
            "source-private",
            "target-private",
            "deferred-edge-private",
            opened.session_id.as_str(),
        ] {
            assert!(!audit_log.contains(secret), "audit leaked {secret}");
        }
        for operation in [
            "graph_deferred_open",
            "graph_deferred_relate",
            "graph_deferred_commit",
        ] {
            assert!(audit_log.contains(operation), "missing audit {operation}");
        }
        audit::verify_hash_chain(temp.path()).unwrap();
    }

    #[test]
    fn typed_deferred_close_is_atomic_and_abort_tombstones_pending_edges() {
        use crate::graph::{
            ConfigureEdgeTypeRequest, GraphDeferredSessionId, GraphDeferredSessionState,
            GraphRelationScope, RelateRequest,
        };

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let scope = crate::tenant::TenantScope::tenant("bulk-writer", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: "imports".to_string(),
                weight_property: None,
            },
            true,
            &scope,
        )
        .unwrap();
        let opened = db
            .open_deferred_graph_session_scoped("docs", false, &scope)
            .unwrap();
        let request = RelateRequest {
            source_point_id: "missing-source-private".to_string(),
            target_point_id: "missing-target-private".to_string(),
            edge_type: "imports".to_string(),
            properties: json!({"secret": "abort-edge-private"}),
            scope: GraphRelationScope::Local,
            idempotency_key: Some("abort-once-private".to_string()),
        };
        let related = db
            .relate_deferred_scoped("docs", &opened.session_id, request.clone(), true, &scope)
            .unwrap();
        let edge_id = crate::edge_token::decode(db.graph_database_id(), &related.edge_id).unwrap();
        let coll = db.get_coll("docs").unwrap();
        let wal_before_close = coll.read().wal.len().unwrap();
        let error = db
            .commit_deferred_graph_session_scoped("docs", &opened.session_id, true, &scope)
            .unwrap_err();
        assert!(error.to_string().contains("missing-source-private"));
        assert!(error.to_string().contains("missing-target-private"));
        assert_eq!(coll.read().wal.len().unwrap(), wal_before_close);

        let aborted = db
            .abort_deferred_graph_session_scoped("docs", &opened.session_id, true, &scope)
            .unwrap();
        assert_eq!(aborted.state, GraphDeferredSessionState::Aborted);
        let collection = coll.read();
        let graph = collection.graph_mutable.as_ref().unwrap();
        assert!(graph.deferred_session_is_aborted(opened.session_id.as_str()));
        assert_eq!(graph.pending_edge_count(), 0);
        assert_eq!(graph.live_edge_count(), 0);
        assert_eq!(graph.stored_edge_count(), 1);
        assert!(graph.edge(edge_id).is_none());
        assert!(
            collection
                .overlays
                .current_ref()
                .edge_tombstones()
                .contains(edge_id.raw())
        );
        let wal_after_abort = collection.wal.len().unwrap();
        drop(collection);

        let repeated = db
            .abort_deferred_graph_session_scoped("docs", &opened.session_id, true, &scope)
            .unwrap();
        assert!(repeated.receipt.replayed);
        assert_eq!(repeated.receipt.operation_lsn, None);
        assert_eq!(coll.read().wal.len().unwrap(), wal_after_abort);
        let error = db
            .commit_deferred_graph_session_scoped("docs", &opened.session_id, true, &scope)
            .unwrap_err();
        assert!(error.to_string().contains("another terminal state"));
        assert_eq!(coll.read().wal.len().unwrap(), wal_after_abort);

        let replayed_relate = db
            .relate_deferred_scoped("docs", &opened.session_id, request, true, &scope)
            .unwrap();
        assert_eq!(replayed_relate.edge_id, related.edge_id);
        assert!(replayed_relate.receipt.replayed);
        assert_eq!(coll.read().wal.len().unwrap(), wal_after_abort);

        let invalid = GraphDeferredSessionId::from_encoded("not-a-session");
        let error = db
            .abort_deferred_graph_session_scoped("docs", &invalid, true, &scope)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("graph.deferred_session_not_found"),
            "{error}"
        );
        assert_eq!(coll.read().wal.len().unwrap(), wal_after_abort);
        drop(coll);
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("docs").unwrap();
        let collection = coll.read();
        let graph = collection.graph_mutable.as_ref().unwrap();
        assert!(graph.deferred_session_is_aborted(opened.session_id.as_str()));
        assert_eq!(graph.pending_edge_count(), 0);
        assert!(graph.edge(edge_id).is_none());
        assert!(
            collection
                .overlays
                .current_ref()
                .edge_tombstones()
                .contains(edge_id.raw())
        );
    }

    #[test]
    fn typed_deferred_cross_tenant_edge_promotes_only_after_both_tenants_exist() {
        use crate::{
            graph::{ConfigureEdgeTypeRequest, GraphNamespace, GraphRelationScope, RelateRequest},
            tenant::{TenantCapability, TenantEnforcement, TenantScope},
        };

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let acme = TenantScope::tenant("bulk-admin", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &acme)
            .unwrap();
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: "shares".to_string(),
                weight_property: None,
            },
            true,
            &acme,
        )
        .unwrap();
        let cross = acme.clone().with_capability(TenantCapability::CrossWrite);
        db.set_tenant_enforcement(TenantEnforcement::Enforced);
        let opened = db
            .open_deferred_graph_session_scoped("docs", true, &cross)
            .unwrap();
        let related = db
            .relate_deferred_scoped(
                "docs",
                &opened.session_id,
                RelateRequest {
                    source_point_id: "acme-private".to_string(),
                    target_point_id: "globex-private".to_string(),
                    edge_type: "shares".to_string(),
                    properties: json!({}),
                    scope: GraphRelationScope::AdminCrossTenant,
                    idempotency_key: None,
                },
                true,
                &cross,
            )
            .unwrap();
        let edge_id = crate::edge_token::decode(db.graph_database_id(), &related.edge_id).unwrap();
        let first = db
            .upsert_deferred_scoped(
                "docs",
                &opened.session_id,
                vec![graph_point("acme-private", 1.0, "acme")],
                true,
                &cross,
            )
            .unwrap();
        assert_eq!(first.bound_endpoints, 1);
        let coll = db.get_coll("docs").unwrap();
        assert_eq!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .live_edge_count(),
            0
        );

        let second = db
            .upsert_deferred_scoped(
                "docs",
                &opened.session_id,
                vec![graph_point("globex-private", 2.0, "globex")],
                true,
                &cross,
            )
            .unwrap();
        assert_eq!(second.bound_endpoints, 1);
        let collection = coll.read();
        let graph = collection.graph_mutable.as_ref().unwrap();
        assert_eq!(graph.pending_edge_count(), 0);
        assert_eq!(graph.live_edge_count(), 1);
        assert_eq!(
            graph.edge(edge_id).unwrap().namespace,
            GraphNamespace::AdminCrossTenant
        );
        drop(collection);
        db.commit_deferred_graph_session_scoped("docs", &opened.session_id, true, &cross)
            .unwrap();

        let rejected = db
            .open_deferred_graph_session_scoped("docs", true, &cross)
            .unwrap();
        db.relate_deferred_scoped(
            "docs",
            &rejected.session_id,
            RelateRequest {
                source_point_id: "same-a-private".to_string(),
                target_point_id: "same-b-private".to_string(),
                edge_type: "shares".to_string(),
                properties: json!({}),
                scope: GraphRelationScope::AdminCrossTenant,
                idempotency_key: None,
            },
            true,
            &cross,
        )
        .unwrap();
        db.upsert_deferred_scoped(
            "docs",
            &rejected.session_id,
            vec![graph_point("same-a-private", 3.0, "acme")],
            true,
            &cross,
        )
        .unwrap();
        let wal_before_rejection = coll.read().wal.len().unwrap();
        let error = db
            .upsert_deferred_scoped(
                "docs",
                &rejected.session_id,
                vec![graph_point("same-b-private", 4.0, "acme")],
                true,
                &cross,
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("different named tenants"),
            "{error}"
        );
        assert_eq!(coll.read().wal.len().unwrap(), wal_before_rejection);
        assert!(
            db.get_points_scoped("docs", &["same-b-private".to_string()], &cross)
                .unwrap()
                .is_empty()
        );
        db.abort_deferred_graph_session_scoped("docs", &rejected.session_id, true, &cross)
            .unwrap();
    }

    #[test]
    fn typed_delete_with_edges_is_atomic_opaque_and_restart_safe() {
        use crate::graph::{
            ConfigureEdgeTypeRequest, GraphErrorCode, GraphRelationScope, RelateRequest,
        };

        let metrics = crate::observability::init_metrics();
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let scope = crate::tenant::TenantScope::tenant("graph-writer", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        db.upsert(
            "docs",
            vec![
                graph_point("source-private", 1.0, "acme"),
                graph_point("target-private", 2.0, "acme"),
            ],
        )
        .unwrap();
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: "cites".to_string(),
                weight_property: None,
            },
            true,
            &scope,
        )
        .unwrap();
        let mut edge_ids = Vec::new();
        for (source, target) in [
            ("source-private", "target-private"),
            ("source-private", "source-private"),
            ("target-private", "source-private"),
        ] {
            let related = db
                .relate_scoped(
                    "docs",
                    RelateRequest {
                        source_point_id: source.to_string(),
                        target_point_id: target.to_string(),
                        edge_type: "cites".to_string(),
                        properties: json!({"private": "must-not-enter-audit"}),
                        scope: GraphRelationScope::Local,
                        idempotency_key: None,
                    },
                    true,
                    &scope,
                )
                .unwrap();
            edge_ids
                .push(crate::edge_token::decode(db.graph_database_id(), &related.edge_id).unwrap());
        }

        let coll = db.get_coll("docs").unwrap();
        let (source_nid, wal_before) = {
            let collection = coll.read();
            (
                collection
                    .graph_resolver
                    .as_ref()
                    .unwrap()
                    .live_nid("source-private")
                    .unwrap(),
                collection.wal.len().unwrap(),
            )
        };
        let error = db
            .delete("docs", &["source-private".to_string()])
            .unwrap_err();
        match error {
            GaussError::Graph(error) => {
                assert_eq!(error.code, GraphErrorCode::EdgesExist);
                assert_eq!(
                    error.message,
                    "point deletion requires the WITH EDGES acknowledgement"
                );
                assert!(!error.message.contains("source-private"));
            }
            other => panic!("expected graph guard, got {other}"),
        }
        assert_eq!(coll.read().wal.len().unwrap(), wal_before);
        assert_eq!(db.count("docs", None).unwrap().count, 2);

        assert_eq!(
            db.delete_with_edges("docs", &["source-private".to_string()])
                .unwrap(),
            1
        );
        {
            let collection = coll.read();
            let resolver = collection.graph_resolver.as_ref().unwrap();
            let graph = collection.graph_mutable.as_ref().unwrap();
            assert!(resolver.is_retired(source_nid));
            assert!(
                graph
                    .live_incident_edge_ids(source_nid, "acme", resolver)
                    .unwrap()
                    .is_empty()
            );
            assert!(
                edge_ids
                    .iter()
                    .all(|edge_id| graph.edge(*edge_id).is_some())
            );
            assert_eq!(graph.live_edge_count(), 3);
        }
        assert!(
            metrics
                .render()
                .contains("graph_edges_orphaned_by_delete_total")
        );

        db.upsert("docs", vec![graph_point("source-private", 3.0, "acme")])
            .unwrap();
        let replacement_nid = coll
            .read()
            .graph_resolver
            .as_ref()
            .unwrap()
            .live_nid("source-private")
            .unwrap();
        assert_ne!(replacement_nid, source_nid);
        assert!(
            coll.read()
                .graph_mutable
                .as_ref()
                .unwrap()
                .live_incident_edge_ids(
                    replacement_nid,
                    "acme",
                    coll.read().graph_resolver.as_ref().unwrap()
                )
                .unwrap()
                .is_empty()
        );
        drop(coll);
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("docs").unwrap();
        let collection = coll.read();
        let resolver = collection.graph_resolver.as_ref().unwrap();
        let graph = collection.graph_mutable.as_ref().unwrap();
        assert!(resolver.is_retired(source_nid));
        assert_eq!(resolver.live_nid("source-private"), Some(replacement_nid));
        assert!(
            graph
                .live_incident_edge_ids(replacement_nid, "acme", resolver)
                .unwrap()
                .is_empty()
        );
        assert!(
            edge_ids
                .iter()
                .all(|edge_id| graph.edge(*edge_id).is_some())
        );
        drop(collection);

        let audit_log = fs::read_to_string(audit::audit_log_path(temp.path())).unwrap();
        assert!(audit_log.contains("\"with_edges_acknowledged\":true"));
        for secret in [
            "source-private",
            "target-private",
            "must-not-enter-audit",
            "orphaned_edges",
            "incident_edge_count",
        ] {
            assert!(!audit_log.contains(secret), "audit leaked {secret}");
        }
        audit::verify_hash_chain(temp.path()).unwrap();
    }

    #[test]
    fn typed_delete_by_filter_with_edges_guards_the_whole_batch() {
        use crate::graph::{ConfigureEdgeTypeRequest, GraphRelationScope, RelateRequest};

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let scope = crate::tenant::TenantScope::tenant("graph-writer", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        let mut selected_a = graph_point("selected-a", 1.0, "acme");
        selected_a.payload["delete_group"] = json!(true);
        let mut selected_b = graph_point("selected-b", 2.0, "acme");
        selected_b.payload["delete_group"] = json!(true);
        let mut keep = graph_point("keep", 3.0, "acme");
        keep.payload["delete_group"] = json!(false);
        let mut foreign = graph_point("foreign", 4.0, "globex");
        foreign.payload["delete_group"] = json!(true);
        db.upsert("docs", vec![selected_a, selected_b, keep, foreign])
            .unwrap();
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: "cites".to_string(),
                weight_property: None,
            },
            true,
            &scope,
        )
        .unwrap();
        for source in ["selected-a", "selected-b"] {
            db.relate_scoped(
                "docs",
                RelateRequest {
                    source_point_id: source.to_string(),
                    target_point_id: "keep".to_string(),
                    edge_type: "cites".to_string(),
                    properties: json!({}),
                    scope: GraphRelationScope::Local,
                    idempotency_key: None,
                },
                true,
                &scope,
            )
            .unwrap();
        }

        let filter = Filter(json!({"delete_group": true}));
        let coll = db.get_coll("docs").unwrap();
        db.set_tenant_enforcement(crate::tenant::TenantEnforcement::Enforced);
        let wal_before = coll.read().wal.len().unwrap();
        let error = db
            .delete_by_filter_scoped("docs", &filter, &scope)
            .unwrap_err();
        assert!(error.to_string().contains("graph.edges_exist"), "{error}");
        assert_eq!(coll.read().wal.len().unwrap(), wal_before);
        assert_eq!(db.count_scoped("docs", None, &scope).unwrap().count, 3);

        assert_eq!(
            db.delete_by_filter_with_edges_scoped("docs", &filter, &scope)
                .unwrap(),
            2
        );
        assert_eq!(db.count_scoped("docs", None, &scope).unwrap().count, 1);
        let foreign_scope = crate::tenant::TenantScope::tenant("foreign-writer", "globex");
        assert_eq!(
            db.count_scoped("docs", None, &foreign_scope).unwrap().count,
            1
        );
        let collection = coll.read();
        let resolver = collection.graph_resolver.as_ref().unwrap();
        let keep_nid = resolver.live_nid("keep").unwrap();
        assert!(
            collection
                .graph_mutable
                .as_ref()
                .unwrap()
                .live_incident_edge_ids(keep_nid, "acme", resolver)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn graph_batch_from_retired_epoch_fails_closed_after_reenable() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let coll = db.get_coll("docs").unwrap();
        let mut collection = coll.write();
        for (raw_epoch, enabled) in [(1, true), (2, false), (3, true)] {
            collection
                .wal
                .append(&WalEntry::GraphEpochAdvance {
                    epoch: crate::graph::GraphEpoch::from_raw(raw_epoch).unwrap(),
                    enabled,
                })
                .unwrap();
        }
        collection
            .wal
            .append(&WalEntry::GraphBatch {
                batch: GraphBatch {
                    point_mutations: vec![GraphPointMutation::Upsert {
                        point: ls_vec_point("stale", 1.0, "must-not-publish"),
                    }],
                    graph_epoch: crate::graph::GraphEpoch::INITIAL,
                    ..GraphBatch::default()
                },
            })
            .unwrap();
        drop(collection);
        drop(db);

        let error = Db::open(temp.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("GraphBatch epoch 1 does not match active graph epoch 3")
        );
    }

    #[cfg(all(unix, feature = "fault-injection"))]
    #[test]
    fn g0_c2_sigkill_graph_batch_boundaries_recover_all_old_or_all_new() {
        use crate::{
            graph::{EdgeMutation, GraphNamespace, RelateMutation},
            wal::{GraphHandleAssignment, GraphIdempotencyState},
        };

        const TEST_NAME: &str =
            "db::tests::g0_c2_sigkill_graph_batch_boundaries_recover_all_old_or_all_new";
        const CHILD_MODE_ENV: &str = "CHIRONDB_G0_C2_GRAPH_BATCH_CHILD";
        const DATA_DIR_ENV: &str = "CHIRONDB_G0_C2_GRAPH_BATCH_DATA_DIR";
        const ATTEMPT_ENV: &str = "CHIRONDB_G0_C2_GRAPH_BATCH_ATTEMPT";
        const IDEMPOTENCY_KEY: &str = "c2-mixed-request";

        if std::env::var_os(CHILD_MODE_ENV).is_some() {
            let data_dir = PathBuf::from(std::env::var_os(DATA_DIR_ENV).unwrap());
            let attempt_path = PathBuf::from(std::env::var_os(ATTEMPT_ENV).unwrap());
            let db = Db::open(&data_dir).unwrap();
            let coll = db.get_coll("docs").unwrap();
            let mut collection = coll.write();
            let graph_epoch = collection.graph_mutable.as_ref().unwrap().epoch();
            let source_nid = collection
                .graph_resolver
                .as_ref()
                .unwrap()
                .live_nid("source")
                .unwrap();
            let type_id = collection
                .graph_mutable
                .as_ref()
                .unwrap()
                .types()
                .resolve_name("cites")
                .unwrap();
            let target_nid = db
                .graph_identity
                .allocate_nids(std::num::NonZeroU64::new(1).unwrap())
                .unwrap()
                .nids()
                .next()
                .unwrap();
            let edge_id = db
                .graph_identity
                .allocate_edge_ids(std::num::NonZeroU64::new(1).unwrap())
                .unwrap()
                .edge_ids()
                .next()
                .unwrap();
            let mut evidence = fs::File::create(&attempt_path).unwrap();
            writeln!(evidence, "{} {}", target_nid.raw(), edge_id.raw()).unwrap();
            evidence.sync_all().unwrap();

            db.commit_graph_batch_locked(
                &mut collection,
                GraphBatch {
                    graph_epoch,
                    point_mutations: vec![GraphPointMutation::Upsert {
                        point: graph_point("batch-target", 2.0, "acme"),
                    }],
                    handle_assignments: vec![GraphHandleAssignment {
                        point_id: "batch-target".to_string(),
                        nid: target_nid,
                    }],
                    edge_mutations: vec![EdgeMutation::Relate(RelateMutation {
                        edge_id,
                        source: source_nid,
                        target: target_nid,
                        type_id,
                        namespace: GraphNamespace::Tenant("acme".to_string()),
                        properties: json!({"revision": 7, "contract": "G0-C2"}),
                    })],
                    idempotency: Some(GraphIdempotencyState {
                        key: IDEMPOTENCY_KEY.to_string(),
                        request_sha256: [7; 32],
                        created_at_unix_ms: 1,
                        expires_at_unix_ms: 2,
                        edge_ids: vec![edge_id],
                    }),
                    ..GraphBatch::default()
                },
                true,
            )
            .unwrap();
            panic!("C2 GraphBatch failpoint returned instead of blocking");
        }

        for (boundary, expected_new) in [
            ("graph_batch.after_prepare", Some(false)),
            ("graph_batch.after_wal_append", None),
            ("graph_batch.after_wal_sync", Some(true)),
            ("graph_batch.after_apply", Some(true)),
            ("graph_batch.after_overlay_publish", Some(true)),
        ] {
            let temp = TempDir::new().unwrap();
            let db = Db::open(temp.path()).unwrap();
            db.create_collection(ls_vec_config("docs")).unwrap();
            let scope = crate::tenant::TenantScope::tenant("c2-writer", "acme");
            db.set_graph_lifecycle_scoped("docs", true, true, &scope)
                .unwrap();
            db.upsert("docs", vec![graph_point("source", 1.0, "acme")])
                .unwrap();
            db.configure_edge_type_scoped(
                "docs",
                crate::graph::ConfigureEdgeTypeRequest {
                    name: "cites".to_string(),
                    weight_property: None,
                },
                true,
                &scope,
            )
            .unwrap();
            drop(db);

            let marker = temp
                .path()
                .join(format!("{}.marker", boundary.replace('.', "-")));
            let attempt = temp
                .path()
                .join(format!("{}.attempt", boundary.replace('.', "-")));
            let mut child = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(TEST_NAME)
                .arg("--nocapture")
                .env(CHILD_MODE_ENV, "1")
                .env(DATA_DIR_ENV, temp.path())
                .env(ATTEMPT_ENV, &attempt)
                .env("CHIRONDB_FAILPOINT", format!("pause:{boundary}"))
                .env("CHIRONDB_FAILPOINT_MARKER", &marker)
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            while !marker.exists() && Instant::now() < deadline {
                if let Some(status) = child.try_wait().unwrap() {
                    panic!("GraphBatch child exited before {boundary}: {status}");
                }
                thread::sleep(Duration::from_millis(10));
            }
            assert!(marker.exists(), "GraphBatch child missed {boundary}");
            child.kill().unwrap();
            let status = child.wait().unwrap();
            assert_eq!(
                status.signal(),
                Some(9),
                "GraphBatch child was not SIGKILLed"
            );

            let attempted = fs::read_to_string(&attempt).unwrap();
            let mut attempted = attempted.split_whitespace();
            let attempted_nid =
                crate::graph::Nid::from_raw(attempted.next().unwrap().parse().unwrap());
            let attempted_edge =
                crate::graph::EdgeId::from_raw(attempted.next().unwrap().parse().unwrap());
            assert!(attempted.next().is_none());

            let recovered = Db::open(temp.path()).unwrap();
            let coll = recovered.get_coll("docs").unwrap();
            let collection = coll.read();
            let resolver = collection.graph_resolver.as_ref().unwrap();
            let graph = collection.graph_mutable.as_ref().unwrap();
            let point_present = collection.id_index.contains_key("batch-target");
            let nid_present = resolver.live_nid("batch-target").is_some();
            let edge_present = graph.edge(attempted_edge).is_some();
            let ledger_present = graph.stored_edge_count() == 1 && graph.live_edge_count() == 1;
            let idempotency_present = graph.idempotency(IDEMPOTENCY_KEY).is_some();
            assert!(
                [
                    nid_present,
                    edge_present,
                    ledger_present,
                    idempotency_present
                ]
                .into_iter()
                .all(|present| present == point_present),
                "partial GraphBatch recovered at {boundary}"
            );
            if let Some(expected_new) = expected_new {
                assert_eq!(
                    point_present, expected_new,
                    "unexpected GraphBatch state at {boundary}"
                );
            }
            if point_present {
                assert_eq!(resolver.live_nid("batch-target"), Some(attempted_nid));
                let edge = graph.edge(attempted_edge).unwrap();
                assert_eq!(edge.target, attempted_nid);
                assert_eq!(edge.properties, json!({"revision": 7, "contract": "G0-C2"}));
                assert_eq!(
                    graph.idempotency(IDEMPOTENCY_KEY).unwrap().edge_ids,
                    vec![attempted_edge]
                );
            } else {
                assert_eq!(graph.stored_edge_count(), 0);
                assert_eq!(graph.idempotency_len(), 0);
            }
            drop(collection);
            drop(coll);

            let next_nid = recovered
                .graph_identity
                .allocate_nids(std::num::NonZeroU64::new(1).unwrap())
                .unwrap()
                .nids()
                .next()
                .unwrap();
            let next_edge = recovered
                .graph_identity
                .allocate_edge_ids(std::num::NonZeroU64::new(1).unwrap())
                .unwrap()
                .edge_ids()
                .next()
                .unwrap();
            assert_ne!(next_nid, attempted_nid, "Nid reused at {boundary}");
            assert_ne!(next_edge, attempted_edge, "EdgeId reused at {boundary}");
        }
    }

    #[test]
    fn catalog_replay_finishes_staged_create_and_committed_drop_idempotently() {
        let create_temp = TempDir::new().unwrap();
        drop(Db::open(create_temp.path()).unwrap());
        let config = ls_vec_config("staged").normalize();
        let staging = super::collection_create_staging_dir(create_temp.path(), &config.name);
        fs::create_dir_all(staging.join("wal")).unwrap();
        fs::create_dir_all(staging.join("searchers")).unwrap();
        drop(Wal::open(&staging.join("wal")).unwrap());
        let checkpoint = checkpoint::CollectionCheckpoint::new(&config, 1, 0, 0, None).unwrap();
        checkpoint::write_checkpoint(&staging, &checkpoint).unwrap();
        crate::fs_util::sync_tree(&staging).unwrap();
        let mut catalog_wal = Wal::open(&create_temp.path().join(super::CATALOG_WAL_DIR)).unwrap();
        catalog_wal
            .append(&WalEntry::CreateCollection {
                config: config.clone(),
            })
            .unwrap();
        drop(catalog_wal);

        let created = Db::open(create_temp.path()).unwrap();
        let collections = created.list_collections();
        assert_eq!(collections.len(), 1);
        assert_eq!(collections[0].name, config.name);
        assert_eq!(collections[0].vector_dim, config.vector_dim);
        assert!(create_temp.path().join("collections/staged").exists());
        drop(created);
        assert_eq!(
            Db::open(create_temp.path())
                .unwrap()
                .list_collections()
                .len(),
            1
        );

        let drop_temp = TempDir::new().unwrap();
        let db = Db::open(drop_temp.path()).unwrap();
        db.create_collection(ls_vec_config("dropped")).unwrap();
        db.inner
            .write()
            .catalog_wal
            .append(&WalEntry::DropCollection {
                name: "dropped".to_string(),
            })
            .unwrap();
        drop(db);

        let dropped = Db::open(drop_temp.path()).unwrap();
        assert!(dropped.list_collections().is_empty());
        assert!(!drop_temp.path().join("collections/dropped").exists());
        drop(dropped);
        assert!(
            Db::open(drop_temp.path())
                .unwrap()
                .list_collections()
                .is_empty()
        );
    }

    fn ls_vec_search(x: f32, k: usize) -> SearchRequest {
        SearchRequest {
            graph: None,
            vector: vec![x, 0.0],
            vector_name: None,
            k,
            filter: None,
            budget_ms: None,
            consistency: None,
            ef_search: None,
            recall_target: None,
            with_payload: None,
        }
    }

    #[test]
    fn frozen_streamer_stays_query_visible_and_rolls_back_without_cloning() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert(
            "docs",
            vec![ls_vec_point("a", 1.0, "old"), ls_vec_point("b", 2.0, "old")],
        )
        .unwrap();
        let coll = db.get_coll("docs").unwrap();
        let frozen = {
            let mut collection = coll.write();
            let end_lsn = collection.wal.len().unwrap();
            freeze_streamer_for_seal(&mut collection, end_lsn)
        };

        assert_eq!(db.get_points("docs", &["b".to_string()]).unwrap().len(), 1);
        db.upsert("docs", vec![ls_vec_point("a", 0.0, "new")])
            .unwrap();
        let hit = db
            .search("docs", ls_vec_search(0.0, 1))
            .unwrap()
            .hits
            .remove(0);
        assert_eq!(hit.id, "a");
        assert_eq!(hit.payload, json!({"version": "new"}));

        restore_failed_seal(Arc::clone(&coll), frozen);
        let collection = coll.read();
        assert!(collection.sealing.is_none());
        assert_eq!(collection.id_index["a"], crate::searcher::SegLoc::Streamer);
        assert_eq!(collection.id_index["b"], crate::searcher::SegLoc::Streamer);
    }

    #[test]
    fn cap_triggered_v4_seal_installs_and_replays_only_wal_suffix() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("docs");
        config.streamer_max_bytes = 1;
        db.create_collection(config).unwrap();
        db.upsert(
            "docs",
            (0..100)
                .map(|i| ls_vec_point(&format!("p{i:03}"), i as f32, "sealed"))
                .collect(),
        )
        .unwrap();

        db.set_payload("docs", "p000", json!({"version": "suffix"}), false)
            .unwrap();
        db.delete("docs", &["p001".to_string()]).unwrap();
        db.upsert("docs", vec![ls_vec_point("p002", -1.0, "suffix")])
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let coll = db.get_coll("docs").unwrap();
            let collection = coll.read();
            if collection.sealing.is_none() {
                assert!(collection.searchers.iter().any(|searcher| matches!(
                    searcher.store,
                    crate::searcher::SegmentStore::V4(_)
                )));
                assert!(collection.wal_watermark > 0);
                break;
            }
            assert!(Instant::now() < deadline, "background seal timed out");
            drop(collection);
            std::thread::sleep(Duration::from_millis(10));
        }

        let checkpoint = checkpoint::read_checkpoint(&temp.path().join("collections/docs"))
            .unwrap()
            .unwrap();
        assert!(checkpoint.wal_watermark > 0);
        assert!(
            checkpoint
                .segments
                .as_ref()
                .is_some_and(|segments| segments.iter().any(|id| id.starts_with("sg-v6-")))
        );
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("docs", None).unwrap().count, 99);
        let points = reopened
            .get_points(
                "docs",
                &["p000".to_string(), "p001".to_string(), "p002".to_string()],
            )
            .unwrap();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].payload, json!({"version": "suffix"}));
        assert_eq!(points[1].payload, json!({"version": "suffix"}));
    }

    #[test]
    fn lsvec_algorithm2_seal_serves_and_reopens() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("docs");
        config.streamer_max_bytes = 1;
        config.named_vector_dims = HashMap::from([("image".to_string(), 2)]);
        let created = db.create_collection(config).unwrap();
        assert_eq!(created.index_kind.as_deref(), Some("lsvec"));
        db.upsert(
            "docs",
            (0..256)
                .map(|i| {
                    let mut point = ls_vec_point(&format!("p{i:03}"), i as f32, "sealed");
                    point
                        .vectors
                        .insert("image".to_string(), vec![(255 - i) as f32, 0.0]);
                    point
                })
                .collect(),
        )
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let coll = db.get_coll("docs").unwrap();
            let collection = coll.read();
            if collection.sealing.is_none() {
                assert!(matches!(
                    collection.searchers[0].index,
                    crate::searcher::SegmentIndex::Ivf(_)
                ));
                assert!(
                    collection.searchers[0]
                        .dir
                        .join(crate::index::ivf::IVF_FILE)
                        .exists()
                );
                assert!(matches!(
                    collection.searchers[0].named_index.get("image"),
                    Some(crate::searcher::SegmentIndex::Ivf(_))
                ));
                break;
            }
            assert!(Instant::now() < deadline, "Algorithm 2 seal timed out");
            drop(collection);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            db.search("docs", ls_vec_search(17.0, 1)).unwrap().hits[0].id,
            "p017"
        );
        let mut named_search = ls_vec_search(17.0, 1);
        named_search.vector_name = Some("image".to_string());
        assert_eq!(
            db.search("docs", named_search.clone()).unwrap().hits[0].id,
            "p238"
        );
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("docs", None).unwrap().count, 256);
        assert_eq!(
            reopened
                .search("docs", ls_vec_search(233.0, 1))
                .unwrap()
                .hits[0]
                .id,
            "p233"
        );
        assert_eq!(
            reopened.search("docs", named_search).unwrap().hits[0].id,
            "p238"
        );
        let coll = reopened.get_coll("docs").unwrap();
        assert!(matches!(
            coll.read().searchers[0].index,
            crate::searcher::SegmentIndex::Ivf(_)
        ));
    }

    #[test]
    fn lsvec_v9_named_cold_segment_restarts_and_compacts_without_duplicate_primary_files() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("docs");
        config.index_kind = Some("lsvec".to_string());
        config.streamer_max_bytes = 1;
        config.named_vector_dims = HashMap::from([("image".to_string(), 2)]);
        db.create_collection(config).unwrap();
        db.upsert(
            "docs",
            (0..128)
                .map(|i| {
                    let mut point = ls_vec_point(&format!("p{i:03}"), i as f32, "sealed");
                    point
                        .vectors
                        .insert("image".to_string(), vec![(127 - i) as f32, 0.0]);
                    point
                })
                .collect(),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let coll = db.get_coll("docs").unwrap();
            if coll.read().sealing.is_none() {
                break;
            }
            assert!(Instant::now() < deadline, "Algorithm 2 seal timed out");
            std::thread::sleep(Duration::from_millis(10));
        }

        let tiered = db.tier_collection_to_cold("docs").unwrap();
        assert_eq!(tiered.segments, 1);
        let cold_segment = std::fs::read_dir(temp.path().join("collections/docs/cold"))
            .unwrap()
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .find(|path| path.is_dir())
            .unwrap();
        assert_eq!(
            crate::seal::read_marker(&cold_segment.join(crate::seal::SEAL_FILE))
                .unwrap()
                .version,
            9
        );
        assert!(!cold_segment.join(crate::seal::VECTOR_FILE).exists());
        assert!(
            !cold_segment
                .join(crate::index::vamana::VAMANA_SEGMENT_FILE)
                .exists()
        );
        assert!(cold_segment.join("named-image.vec.gdx").exists());
        assert!(cold_segment.join("named-image.vamana.gdx").exists());
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("docs", None).unwrap().count, 128);
        let fetched = reopened.get_points("docs", &["p017".to_string()]).unwrap();
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].vector, vec![17.0, 0.0]);
        assert_eq!(fetched[0].vectors["image"], vec![110.0, 0.0]);
        assert_eq!(fetched[0].payload, json!({"version": "sealed"}));
        let scrolled = reopened.scroll("docs", None, 200, None).unwrap();
        assert_eq!(scrolled.points.len(), 128);
        reopened.reset_diskann_io_stats("docs").unwrap();
        assert_eq!(
            reopened
                .search("docs", ls_vec_search(91.0, 1))
                .unwrap()
                .hits[0]
                .id,
            "p091"
        );
        let io = reopened.diskann_io_stats("docs").unwrap();
        assert_eq!(io.active_segments, 1);
        assert!(io.physical_page_reads > 0);
        assert_eq!(io.page_read_errors, 0);
        assert_eq!(io.cache_capacity_bytes, 64 * 1024 * 1024);
        let mut named_search = ls_vec_search(85.0, 1);
        named_search.vector_name = Some("image".to_string());
        assert_eq!(
            reopened.search("docs", named_search).unwrap().hits[0].id,
            "p042"
        );
        let coll = reopened.get_coll("docs").unwrap();
        let collection = coll.read();
        assert!(
            collection.searchers[0]
                .dir
                .starts_with(temp.path().join("collections/docs/cold"))
        );
        assert!(matches!(
            collection.searchers[0].index,
            crate::searcher::SegmentIndex::Ivf(_)
        ));
        drop(collection);
        drop(coll);

        let mut appended = ls_vec_point("p128", 128.0, "merged");
        appended
            .vectors
            .insert("image".to_string(), vec![-1.0, 0.0]);
        reopened.upsert("docs", vec![appended]).unwrap();
        let compacted = reopened.compact_collection("docs").unwrap();
        assert_eq!(compacted.points, 129);
        assert_eq!(reopened.count("docs", None).unwrap().count, 129);
        assert_eq!(
            reopened
                .search("docs", ls_vec_search(128.0, 1))
                .unwrap()
                .hits[0]
                .id,
            "p128"
        );
        let hot_segment = temp
            .path()
            .join("collections/docs/searchers")
            .join(compacted.segment_id);
        assert_eq!(
            crate::seal::read_marker(&hot_segment.join(crate::seal::SEAL_FILE))
                .unwrap()
                .version,
            8
        );
        assert!(hot_segment.join(crate::seal::VECTOR_FILE).exists());
        assert!(
            hot_segment
                .join(crate::index::vamana::VAMANA_SEGMENT_FILE)
                .exists()
        );
    }

    #[test]
    fn recall_sla_calibration_uses_multi_segment_lsvec_view() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("docs");
        config.index_kind = Some("lsvec".to_string());
        config.streamer_max_bytes = 1;
        config.recall_sla = Some(0.5);
        db.create_collection(config).unwrap();

        for range in [0..64, 64..128] {
            db.upsert(
                "docs",
                range
                    .map(|i| ls_vec_point(&format!("p{i:03}"), i as f32, "sealed"))
                    .collect(),
            )
            .unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                let coll = db.get_coll("docs").unwrap();
                if coll.read().sealing.is_none() {
                    break;
                }
                assert!(Instant::now() < deadline, "Algorithm 2 seal timed out");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        assert_eq!(db.get_coll("docs").unwrap().read().searchers.len(), 2);

        let curve = db.calibrate_collection("docs", 10, 8).unwrap();
        assert!(!curve.is_empty());
        assert!(db.check_recall_drift("docs").unwrap().is_none());
    }

    /// Implementation test for the full LS-VEC cascade: ingest clustered
    /// multi-dim vectors through the `index_kind="lsvec"` path (IVF → RaBitQ
    /// → Vamana → exact f32 rescore), force a seal into one Algorithm 2
    /// segment, then verify recall@10 against a brute-force oracle. Proves the
    /// IVF + RaBitQ + Vamana stack composes without a recall bug in LS-VEC.
    #[test]
    fn lsvec_cascade_recall_at_10_vs_brute_force() {
        let dim = 16usize;
        let n_clusters = 40usize;
        let per_cluster = 20usize; // 800 points
        let mut state = 0xA5A5_1234_u64;
        let rng = |s: &mut u64| -> f32 {
            *s = crate::h2qg::splitmix64(*s);
            (*s >> 11) as f32 / (1_u64 << 53) as f32 // [0, 1)
        };
        let sq_l2 =
            |a: &[f32], b: &[f32]| -> f32 { a.iter().zip(b).map(|(x, y)| (x - y) * (x - y)).sum() };

        let centers: Vec<Vec<f32>> = (0..n_clusters)
            .map(|_| (0..dim).map(|_| rng(&mut state) * 10.0).collect())
            .collect();
        let mut vectors: Vec<(String, Vec<f32>)> = Vec::new();
        for (c, center) in centers.iter().enumerate() {
            for j in 0..per_cluster {
                let v: Vec<f32> = center
                    .iter()
                    .map(|&x| x + (rng(&mut state) - 0.5) * 0.5)
                    .collect();
                vectors.push((format!("c{c:02}p{j:02}"), v));
            }
        }

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("vecs");
        config.vector_dim = dim;
        config.index_kind = Some("lsvec".to_string());
        config.streamer_max_bytes = 1; // seal the batch into one Algorithm 2 segment
        db.create_collection(config).unwrap();

        db.upsert(
            "vecs",
            vectors
                .iter()
                .map(|(id, v)| Point {
                    id: id.clone(),
                    vector: v.clone(),
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({}),
                })
                .collect(),
        )
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let coll = db.get_coll("vecs").unwrap();
            let collection = coll.read();
            if collection.sealing.is_none() && !collection.searchers.is_empty() {
                assert!(matches!(
                    collection.searchers[0].index,
                    crate::searcher::SegmentIndex::Ivf(_)
                ));
                break;
            }
            assert!(Instant::now() < deadline, "lsvec seal timed out");
            drop(collection);
            std::thread::sleep(Duration::from_millis(10));
        }

        let k = 10usize;
        let queries = 30usize;
        let mut hit = 0usize;
        for qi in 0..queries {
            let center = &centers[qi % n_clusters];
            let q: Vec<f32> = center
                .iter()
                .map(|&x| x + (rng(&mut state) - 0.5) * 0.5)
                .collect();
            let mut exact: Vec<(f32, &str)> = vectors
                .iter()
                .map(|(id, v)| (sq_l2(&q, v), id.as_str()))
                .collect();
            exact.sort_by(|a, b| a.0.total_cmp(&b.0));
            let truth: std::collections::HashSet<&str> =
                exact.iter().take(k).map(|&(_, id)| id).collect();

            let req = SearchRequest {
                graph: None,
                vector: q,
                vector_name: None,
                k,
                filter: None,
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: None,
            };
            let got = db.search("vecs", req).unwrap();
            for id in got.hits.iter().map(|h| h.id.as_str()) {
                if truth.contains(id) {
                    hit += 1;
                }
            }
        }
        let recall = hit as f32 / (k * queries) as f32;
        assert!(
            recall >= 0.85,
            "lsvec cascade recall@10 = {recall:.3} (< 0.85) — IVF/RaBitQ/Vamana bug"
        );
    }

    #[test]
    fn sealed_lsvec_filters_keep_exact_k_at_50_10_and_1_percent() {
        fn assert_filtered_exact_k(db: &Db, filter: Filter, allowed: &HashSet<String>) {
            let response = db
                .search(
                    "filtered",
                    SearchRequest {
                        graph: None,
                        vector: vec![3_000.0, 0.0],
                        vector_name: None,
                        k: 10,
                        filter: Some(filter),
                        budget_ms: None,
                        consistency: None,
                        ef_search: None,
                        recall_target: Some(0.95),
                        with_payload: Some(false),
                    },
                )
                .unwrap();
            assert_eq!(
                response.hits.len(),
                10,
                "filtered LS-VEC search underfilled"
            );
            assert!(!response.degraded, "filtered LS-VEC search degraded");
            assert!(
                response.hits.iter().all(|hit| allowed.contains(&hit.id)),
                "filtered LS-VEC search admitted a payload-rejected point"
            );
        }

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("filtered");
        config.index_kind = Some("lsvec".to_string());
        config.streamer_max_bytes = usize::MAX;
        db.create_collection(config).unwrap();

        let mut half = HashSet::new();
        let mut tenth = HashSet::new();
        let mut hundredth = HashSet::new();
        let mut correlated = HashSet::new();
        let points = (0..12_000)
            .map(|index| {
                let id = format!("p{index:05}");
                if index % 2 == 0 {
                    half.insert(id.clone());
                }
                if index % 10 == 0 {
                    tenth.insert(id.clone());
                }
                let is_hundredth = index % 100 == 0;
                if is_hundredth {
                    hundredth.insert(id.clone());
                    correlated.insert(id.clone());
                }
                let events = if is_hundredth {
                    json!([
                        {"kind": "target", "active": true},
                        {"kind": "other", "active": false}
                    ])
                } else if index % 100 == 1 {
                    // Both scalar conditions exist, but in different array
                    // elements. A flattened filter may accept this; the
                    // nested correlated filter below must not.
                    json!([
                        {"kind": "target", "active": false},
                        {"kind": "other", "active": true}
                    ])
                } else {
                    json!([{"kind": "other", "active": false}])
                };
                Point {
                    id,
                    vector: vec![index as f32, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({
                        "bucket_2": index % 2,
                        "bucket_10": index % 10,
                        "bucket_100": index % 100,
                        "events": events,
                    }),
                }
            })
            .collect::<Vec<_>>();
        for chunk in points.chunks(1_000) {
            db.upsert("filtered", chunk.to_vec()).unwrap();
        }
        wait_for_h2qg(
            &db.get_coll("filtered").unwrap(),
            BACKGROUND_INDEX_TEST_TIMEOUT,
        );
        db.compact_collection("filtered").unwrap();

        {
            let filters = [
                (Filter(json!({"bucket_2": 0})), &half),
                (Filter(json!({"bucket_10": 0})), &tenth),
                (Filter(json!({"bucket_100": 0})), &hundredth),
                (
                    Filter(json!({
                        "events": {"nested": {"kind": "target", "active": true}}
                    })),
                    &correlated,
                ),
            ];
            for (filter, allowed) in filters {
                assert_filtered_exact_k(&db, filter, allowed);
            }
        }

        let deleted = (0..500)
            .step_by(100)
            .map(|index| format!("p{index:05}"))
            .collect::<Vec<_>>();
        db.delete("filtered", &deleted).unwrap();
        for id in &deleted {
            half.remove(id);
            tenth.remove(id);
            hundredth.remove(id);
            correlated.remove(id);
        }
        assert_filtered_exact_k(&db, Filter(json!({"bucket_100": 0})), &hundredth);
        assert_filtered_exact_k(
            &db,
            Filter(json!({
                "events": {"nested": {"kind": "target", "active": true}}
            })),
            &correlated,
        );

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        let reopened_filters = [
            (Filter(json!({"bucket_2": 0})), &half),
            (Filter(json!({"bucket_10": 0})), &tenth),
            (Filter(json!({"bucket_100": 0})), &hundredth),
            (
                Filter(json!({
                    "events": {"nested": {"kind": "target", "active": true}}
                })),
                &correlated,
            ),
        ];
        for (filter, allowed) in reopened_filters {
            assert_filtered_exact_k(&reopened, filter, allowed);
        }
    }

    #[test]
    fn lsvec_compaction_flushes_mutable_prefix_without_rewriting_immutable_segments() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("docs");
        config.index_kind = Some("lsvec".to_string());
        config.streamer_max_bytes = 1;
        config.named_vector_dims = HashMap::from([("image".to_string(), 2)]);
        db.create_collection(config).unwrap();

        for range in [0..64, 64..128] {
            db.upsert(
                "docs",
                range
                    .map(|i| {
                        let mut point = ls_vec_point(&format!("p{i:03}"), i as f32, "sealed");
                        point
                            .vectors
                            .insert("image".to_string(), vec![(127 - i) as f32, 0.0]);
                        point
                    })
                    .collect(),
            )
            .unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                let coll = db.get_coll("docs").unwrap();
                if coll.read().sealing.is_none() {
                    break;
                }
                assert!(Instant::now() < deadline, "Algorithm 2 seal timed out");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        db.get_coll("docs")
            .unwrap()
            .write()
            .config
            .streamer_max_bytes = usize::MAX;
        db.upsert("docs", vec![ls_vec_point("p000", -1.0, "new")])
            .unwrap();
        db.delete("docs", &["p001".to_string()]).unwrap();

        let before = {
            let coll = db.get_coll("docs").unwrap();
            let collection = coll.read();
            assert_eq!(collection.searchers.len(), 2);
            collection
                .searchers
                .iter()
                .map(|searcher| searcher.id.clone())
                .collect::<HashSet<_>>()
        };
        let compact = db.compact_collection("docs").unwrap();
        assert_eq!(compact.points, 127);

        let collection_dir = temp.path().join("collections/docs");
        let manifest = checkpoint::read_segments_manifest(&collection_dir)
            .unwrap()
            .unwrap();
        assert_eq!(manifest.segments.len(), 3);
        assert!(manifest.segments.contains(&compact.segment_id));
        assert!(before.iter().all(|id| manifest.segments.contains(id)));
        assert!(
            before
                .iter()
                .all(|id| collection_dir.join("searchers").join(id).exists())
        );
        {
            let coll = db.get_coll("docs").unwrap();
            let collection = coll.read();
            assert_eq!(collection.searchers.len(), 3);
            assert!(matches!(
                collection.searchers[2].store,
                crate::searcher::SegmentStore::V4(_)
            ));
            assert!(matches!(
                collection.searchers[2].index,
                crate::searcher::SegmentIndex::Ivf(_)
            ));
            assert!(matches!(
                collection.searchers[0].named_index.get("image"),
                Some(crate::searcher::SegmentIndex::Ivf(_))
            ));
            assert!(collection.streamer.points.is_empty());
        }
        assert_eq!(
            db.search("docs", ls_vec_search(-1.0, 1)).unwrap().hits[0].id,
            "p000"
        );
        let mut named_search = ls_vec_search(85.0, 1);
        named_search.vector_name = Some("image".to_string());
        assert_eq!(
            db.search("docs", named_search.clone()).unwrap().hits[0].id,
            "p042"
        );
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("docs", None).unwrap().count, 127);
        assert_eq!(
            reopened
                .search("docs", ls_vec_search(-1.0, 1))
                .unwrap()
                .hits[0]
                .id,
            "p000"
        );
        assert_eq!(
            reopened.search("docs", named_search).unwrap().hits[0].id,
            "p042"
        );
    }

    #[cfg(feature = "benchmark-internals")]
    #[test]
    fn benchmark_major_compaction_rewrites_one_sealed_generation() {
        fn stable_adjacency(
            searcher: &crate::searcher::SegmentSearcher,
        ) -> HashMap<String, HashSet<String>> {
            let crate::searcher::SegmentStore::V4(store) = &searcher.store else {
                panic!("major-compaction topology test requires a v4 store");
            };
            let ivf = crate::index::ivf::IvfArtifact::open(
                &searcher.dir.join(crate::index::ivf::IVF_FILE),
            )
            .unwrap();
            let vamana = crate::index::vamana::VamanaArtifact::open(
                &searcher.dir.join(crate::index::vamana::VAMANA_SEGMENT_FILE),
                &ivf,
            )
            .unwrap();
            vamana
                .ordinal_adjacency(&ivf)
                .unwrap()
                .into_iter()
                .enumerate()
                .map(|(ordinal, neighbors)| {
                    (
                        store.id(ordinal).unwrap().to_string(),
                        neighbors
                            .into_iter()
                            .map(|neighbor| store.id(neighbor as usize).unwrap().to_string())
                            .collect(),
                    )
                })
                .collect()
        }

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("major");
        config.streamer_max_bytes = 1;
        db.create_collection(config).unwrap();
        db.upsert(
            "major",
            (0..80)
                .map(|index| ls_vec_point(&format!("p{index:04}"), index as f32, "sealed"))
                .collect(),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let coll = db.get_coll("major").unwrap();
            if coll.read().sealing.is_none() {
                break;
            }
            assert!(Instant::now() < deadline, "initial seal timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
        let prior_adjacency = {
            let coll = db.get_coll("major").unwrap();
            let collection = coll.read();
            assert_eq!(collection.searchers.len(), 1);
            stable_adjacency(&collection.searchers[0])
        };
        db.get_coll("major")
            .unwrap()
            .write()
            .config
            .streamer_max_bytes = usize::MAX;
        db.upsert(
            "major",
            (80..84)
                .map(|index| ls_vec_point(&format!("p{index:04}"), index as f32, "tail"))
                .collect(),
        )
        .unwrap();

        db.compact_collection_full_for_benchmark("major").unwrap();
        {
            let coll = db.get_coll("major").unwrap();
            let collection = coll.read();
            assert_eq!(collection.searchers.len(), 1);
            assert_eq!(collection.searchers[0].store.len(), 84);
            assert!(collection.streamer.points.is_empty());
            let merged_adjacency = stable_adjacency(&collection.searchers[0]);
            for (id, prior_neighbors) in &prior_adjacency {
                let retained = merged_adjacency[id].intersection(prior_neighbors).count();
                let loss = 1.0 - retained as f64 / prior_neighbors.len() as f64;
                assert!(loss <= 0.055, "{id} prior-neighbor loss {loss:.6}");
            }
        }
        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("major", None).unwrap().count, 84);
    }

    #[test]
    fn lsvec_size_tier_merges_only_similar_segments_and_reopens() {
        fn stable_adjacency(
            searchers: &[crate::searcher::SegmentSearcher],
        ) -> HashMap<String, HashSet<String>> {
            let mut rows = HashMap::new();
            for searcher in searchers {
                let crate::searcher::SegmentStore::V4(store) = &searcher.store else {
                    panic!("topology test requires a v4 segment store");
                };
                let ivf = crate::index::ivf::IvfArtifact::open(
                    &searcher.dir.join(crate::index::ivf::IVF_FILE),
                )
                .unwrap();
                let vamana = crate::index::vamana::VamanaArtifact::open(
                    &searcher.dir.join(crate::index::vamana::VAMANA_SEGMENT_FILE),
                    &ivf,
                )
                .unwrap();
                for (ordinal, neighbors) in vamana
                    .ordinal_adjacency(&ivf)
                    .unwrap()
                    .into_iter()
                    .enumerate()
                {
                    rows.insert(
                        store.id(ordinal).unwrap().to_string(),
                        neighbors
                            .into_iter()
                            .map(|neighbor| store.id(neighbor as usize).unwrap().to_string())
                            .collect(),
                    );
                }
            }
            rows
        }

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("tiered");
        config.streamer_max_bytes = 1;
        db.create_collection(config).unwrap();

        let mut next = 0usize;
        for count in [16usize, 16, 16, 16, 256] {
            db.upsert(
                "tiered",
                (next..next + count)
                    .map(|index| ls_vec_point(&format!("p{index:04}"), index as f32, "tiered"))
                    .collect(),
            )
            .unwrap();
            next += count;
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                let coll = db.get_coll("tiered").unwrap();
                if coll.read().sealing.is_none() {
                    break;
                }
                assert!(Instant::now() < deadline, "tier input seal timed out");
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        let (small_ids, large_id, prior_adjacency) = {
            let coll = db.get_coll("tiered").unwrap();
            let collection = coll.read();
            assert_eq!(collection.searchers.len(), 5);
            (
                collection.searchers[..4]
                    .iter()
                    .map(|searcher| searcher.id.clone())
                    .collect::<Vec<_>>(),
                collection.searchers[4].id.clone(),
                stable_adjacency(&collection.searchers[..4]),
            )
        };

        let compact = db.compact_collection("tiered").unwrap();
        assert_eq!(compact.points, 320);
        let collection_dir = temp.path().join("collections/tiered");
        let manifest = checkpoint::read_segments_manifest(&collection_dir)
            .unwrap()
            .unwrap();
        assert_eq!(
            manifest.segments,
            [compact.segment_id.clone(), large_id.clone()]
        );
        assert!(collection_dir.join("searchers").join(&large_id).is_dir());
        assert!(
            small_ids
                .iter()
                .all(|id| !collection_dir.join("searchers").join(id).exists())
        );
        {
            let coll = db.get_coll("tiered").unwrap();
            let collection = coll.read();
            assert_eq!(collection.searchers.len(), 2);
            assert_eq!(collection.searchers[0].store.len(), 64);
            assert_eq!(collection.searchers[1].store.len(), 256);
            assert!(!collection.generation_build_in_flight);
            let merged_adjacency = stable_adjacency(&collection.searchers[..1]);
            for (id, prior_neighbors) in &prior_adjacency {
                let retained = merged_adjacency[id].intersection(prior_neighbors).count();
                let loss = 1.0 - retained as f64 / prior_neighbors.len() as f64;
                assert!(loss <= 0.055, "{id} prior-neighbor loss {loss:.6}");
            }
        }

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("tiered", None).unwrap().count, 320);
        assert_eq!(
            checkpoint::read_segments_manifest(&collection_dir)
                .unwrap()
                .unwrap()
                .segments,
            [compact.segment_id, large_id]
        );
    }

    #[test]
    fn lsvec_size_tier_discards_corrupt_prior_graph_seed() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("corrupt-prior");
        config.streamer_max_bytes = usize::MAX;
        db.create_collection(config).unwrap();

        for segment in 0..4usize {
            db.upsert(
                "corrupt-prior",
                (0..16)
                    .map(|offset| {
                        let index = segment * 16 + offset;
                        ls_vec_point(&format!("p{index:04}"), index as f32, "prior")
                    })
                    .collect(),
            )
            .unwrap();
            let seal = prepare_forced_graph_vector_seal(&db, temp.path(), "corrupt-prior");
            run_segment_seal(&seal).unwrap();
        }

        let vamana_path = {
            let coll = db.get_coll("corrupt-prior").unwrap();
            let collection = coll.read();
            collection.searchers[0]
                .dir
                .join(crate::index::vamana::VAMANA_SEGMENT_FILE)
        };
        let mut bytes = fs::read(&vamana_path).unwrap();
        *bytes.last_mut().unwrap() ^= 0xff;
        fs::write(&vamana_path, bytes).unwrap();

        let compact = db.compact_collection("corrupt-prior").unwrap();
        assert_eq!(compact.points, 64);
        {
            let coll = db.get_coll("corrupt-prior").unwrap();
            assert_eq!(coll.read().searchers.len(), 1);
        }
        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("corrupt-prior", None).unwrap().count, 64);
    }

    #[test]
    fn lsvec_partial_compaction_preserves_selective_filters_tombstones_and_exact_k() {
        fn assert_selective_search(db: &Db, modulo: usize, deleted: &HashSet<String>) {
            let filter = match modulo {
                2 => Filter(json!({"bucket_2": 0})),
                10 => Filter(json!({"bucket_10": 0})),
                100 => Filter(json!({"bucket_100": 0})),
                _ => unreachable!("test only exercises declared selectivity tiers"),
            };
            let response = db
                .search(
                    "selective-tier",
                    SearchRequest {
                        graph: None,
                        vector: vec![6_000.0, 0.0],
                        vector_name: None,
                        k: 10,
                        filter: Some(filter),
                        budget_ms: None,
                        consistency: None,
                        ef_search: None,
                        recall_target: Some(0.95),
                        with_payload: Some(false),
                    },
                )
                .unwrap();
            assert_eq!(
                response.hits.len(),
                10,
                "1/{modulo} tier search underfilled"
            );
            assert!(!response.degraded, "1/{modulo} tier search degraded");
            for hit in response.hits {
                assert!(!deleted.contains(&hit.id), "deleted point was returned");
                let index = hit.id.trim_start_matches('p').parse::<usize>().unwrap();
                assert_eq!(index % modulo, 0, "payload-rejected point was returned");
            }
        }

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("selective-tier");
        config.index_kind = Some("lsvec".to_string());
        config.streamer_max_bytes = 1;
        db.create_collection(config).unwrap();

        let mut next = 0usize;
        for count in [1_024usize, 1_024, 1_024, 1_024, 4_096] {
            db.upsert(
                "selective-tier",
                (next..next + count)
                    .map(|index| Point {
                        id: format!("p{index:05}"),
                        vector: vec![index as f32, 0.0],
                        vectors: HashMap::new(),
                        sparse_vector: None,
                        payload: json!({
                            "bucket_2": index % 2,
                            "bucket_10": index % 10,
                            "bucket_100": index % 100,
                        }),
                    })
                    .collect(),
            )
            .unwrap();
            next += count;
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                let coll = db.get_coll("selective-tier").unwrap();
                if coll.read().sealing.is_none() {
                    break;
                }
                assert!(Instant::now() < deadline, "tier input seal timed out");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let deleted = ["p02900", "p03000", "p03100", "p06000"]
            .into_iter()
            .map(str::to_string)
            .collect::<HashSet<_>>();
        db.delete(
            "selective-tier",
            &deleted.iter().cloned().collect::<Vec<_>>(),
        )
        .unwrap();

        let retained_id = {
            let coll = db.get_coll("selective-tier").unwrap();
            let collection = coll.read();
            assert_eq!(collection.searchers.len(), 5);
            collection.searchers[4].id.clone()
        };
        let compact = db.compact_collection("selective-tier").unwrap();
        assert_eq!(compact.points, 8_188);

        let collection_dir = temp.path().join("collections/selective-tier");
        assert_eq!(
            checkpoint::read_segments_manifest(&collection_dir)
                .unwrap()
                .unwrap()
                .segments,
            [compact.segment_id.clone(), retained_id]
        );
        for modulo in [2, 10, 100] {
            assert_selective_search(&db, modulo, &deleted);
        }

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("selective-tier", None).unwrap().count, 8_188);
        for modulo in [2, 10, 100] {
            assert_selective_search(&reopened, modulo, &deleted);
        }
    }

    #[test]
    fn lsvec_size_tier_reclaims_a_fully_dead_segment_and_reopens() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("dead-tier");
        config.streamer_max_bytes = 1;
        db.create_collection(config).unwrap();

        for range in [0..16, 16..32] {
            db.upsert(
                "dead-tier",
                range
                    .map(|index| ls_vec_point(&format!("p{index:04}"), index as f32, "tiered"))
                    .collect(),
            )
            .unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                let coll = db.get_coll("dead-tier").unwrap();
                if coll.read().sealing.is_none() {
                    break;
                }
                assert!(Instant::now() < deadline, "tier input seal timed out");
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        let old_ids = {
            let coll = db.get_coll("dead-tier").unwrap();
            let collection = coll.read();
            assert_eq!(collection.searchers.len(), 2);
            collection
                .searchers
                .iter()
                .map(|searcher| searcher.id.clone())
                .collect::<Vec<_>>()
        };
        db.delete(
            "dead-tier",
            &(0..16)
                .map(|index| format!("p{index:04}"))
                .collect::<Vec<_>>(),
        )
        .unwrap();

        let compact = db.compact_collection("dead-tier").unwrap();
        assert_eq!(compact.points, 16);
        let collection_dir = temp.path().join("collections/dead-tier");
        let manifest = checkpoint::read_segments_manifest(&collection_dir)
            .unwrap()
            .unwrap();
        assert_eq!(
            manifest.segments.as_slice(),
            std::slice::from_ref(&compact.segment_id)
        );
        assert!(
            old_ids
                .iter()
                .all(|id| !collection_dir.join("searchers").join(id).exists())
        );

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("dead-tier", None).unwrap().count, 16);
        assert!(
            reopened
                .get_points("dead-tier", &["p0000".to_string()])
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            reopened
                .search("dead-tier", ls_vec_search(31.0, 1))
                .unwrap()
                .hits[0]
                .id,
            "p0031"
        );
    }

    #[test]
    fn lsvec_delete_only_wal_is_not_mistaken_for_a_noop_compaction() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("delete-only");
        config.streamer_max_bytes = usize::MAX;
        db.create_collection(config).unwrap();
        db.upsert(
            "delete-only",
            vec![ls_vec_point("p0000", 0.0, "delete-only")],
        )
        .unwrap();
        db.compact_collection("delete-only").unwrap();
        db.delete("delete-only", &["p0000".to_string()]).unwrap();
        db.compact_collection("delete-only").unwrap();

        let collection_dir = temp.path().join("collections/delete-only");
        assert!(
            checkpoint::read_segments_manifest(&collection_dir)
                .unwrap()
                .unwrap()
                .segments
                .is_empty()
        );
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("delete-only", None).unwrap().count, 0);
        assert!(
            reopened
                .get_points("delete-only", &["p0000".to_string()])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn lsvec_offlock_compaction_preserves_concurrent_wal_tail_across_restart() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("docs");
        config.index_kind = Some("lsvec".to_string());
        config.vector_dim = 8;
        config.streamer_max_bytes = 1;
        db.create_collection(config).unwrap();
        db.upsert(
            "docs",
            (0..12_000)
                .map(|i| Point {
                    id: format!("p{i:05}"),
                    vector: vec![i as f32; 8],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"version": "snapshot"}),
                })
                .collect(),
        )
        .unwrap();
        // A full workspace test can run several graph builders concurrently.
        // Keep this as a liveness bound, but do not turn host contention into
        // a correctness failure for the off-lock lifecycle assertion below.
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let coll = db.get_coll("docs").unwrap();
            if coll.read().sealing.is_none() {
                break;
            }
            assert!(Instant::now() < deadline, "initial LS-VEC seal timed out");
            thread::sleep(Duration::from_millis(5));
        }
        db.get_coll("docs")
            .unwrap()
            .write()
            .config
            .streamer_max_bytes = usize::MAX;
        db.upsert(
            "docs",
            (0..12_000)
                .map(|i| Point {
                    id: format!("p{i:05}"),
                    vector: vec![i as f32; 8],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"version": "precompact"}),
                })
                .collect(),
        )
        .unwrap();

        let compact_db = db.clone();
        let compact = thread::spawn(move || compact_db.compact_collection("docs"));
        // Match the initial-seal liveness allowance above: under the full
        // workspace suite, build admission can queue this compaction behind
        // several other graph builders before it freezes the streamer.
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let coll = db.get_coll("docs").unwrap();
            if coll.read().sealing.is_some() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "off-lock compaction snapshot was not observed"
            );
            thread::sleep(Duration::from_millis(1));
        }

        // The frozen snapshot remains a serveable generation while the new
        // global graph is built off-lock. Queries must neither wait for the
        // build nor fall back to degraded/underfilled output.
        for query_index in 0..16 {
            let response = db
                .search(
                    "docs",
                    SearchRequest {
                        graph: None,
                        vector: vec![(6_000 + query_index) as f32; 8],
                        vector_name: None,
                        k: 10,
                        filter: None,
                        budget_ms: None,
                        consistency: None,
                        ef_search: None,
                        recall_target: Some(0.95),
                        with_payload: Some(false),
                    },
                )
                .unwrap();
            assert_eq!(response.hits.len(), 10);
            assert!(!response.degraded);
        }

        db.upsert(
            "docs",
            vec![
                Point {
                    id: "p00000".to_string(),
                    vector: vec![-1.0; 8],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"version": "tail"}),
                },
                Point {
                    id: "tail-new".to_string(),
                    vector: vec![-2.0; 8],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"version": "tail"}),
                },
            ],
        )
        .unwrap();
        db.delete("docs", &["p00001".to_string()]).unwrap();
        compact.join().unwrap().unwrap();

        assert_eq!(db.count("docs", None).unwrap().count, 12_000);
        let points = db
            .get_points(
                "docs",
                &[
                    "p00000".to_string(),
                    "p00001".to_string(),
                    "tail-new".to_string(),
                ],
            )
            .unwrap();
        assert_eq!(points.len(), 2);
        assert!(
            points
                .iter()
                .any(|point| { point.id == "p00000" && point.payload["version"] == json!("tail") })
        );
        assert!(points.iter().any(|point| point.id == "tail-new"));
        {
            let coll = db.get_coll("docs").unwrap();
            let collection = coll.read();
            assert!(collection.wal_watermark > 0);
            assert!(!collection.streamer.points.is_empty());
        }
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("docs", None).unwrap().count, 12_000);
        let points = reopened
            .get_points(
                "docs",
                &[
                    "p00000".to_string(),
                    "p00001".to_string(),
                    "tail-new".to_string(),
                ],
            )
            .unwrap();
        assert_eq!(points.len(), 2);
        assert!(
            points
                .iter()
                .any(|point| { point.id == "p00000" && point.payload["version"] == json!("tail") })
        );
        assert!(points.iter().any(|point| point.id == "tail-new"));
    }

    #[test]
    fn lsvec_compaction_rebuilds_unlisted_partial_generation() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("docs");
        config.index_kind = Some("lsvec".to_string());
        config.streamer_max_bytes = 1;
        db.create_collection(config).unwrap();
        db.upsert(
            "docs",
            (0..128)
                .map(|i| ls_vec_point(&format!("p{i:03}"), i as f32, "base"))
                .collect(),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let coll = db.get_coll("docs").unwrap();
            if coll.read().sealing.is_none() {
                break;
            }
            assert!(Instant::now() < deadline, "initial LS-VEC seal timed out");
            thread::sleep(Duration::from_millis(5));
        }
        db.get_coll("docs")
            .unwrap()
            .write()
            .config
            .streamer_max_bytes = usize::MAX;
        db.upsert("docs", vec![ls_vec_point("p000", -1.0, "updated")])
            .unwrap();

        let collection_dir = temp.path().join("collections/docs");
        let (end_lsn, generation) = {
            let coll = db.get_coll("docs").unwrap();
            let collection = coll.read();
            (
                collection.wal.len().unwrap(),
                checkpoint::read_segments_manifest(&collection_dir)
                    .unwrap()
                    .unwrap()
                    .generation
                    + 1,
            )
        };
        let segment_id = format!("sg-v6-merge-{end_lsn:020}-{generation:020}");
        let orphan = collection_dir.join("searchers").join(&segment_id);
        fs::create_dir_all(&orphan).unwrap();
        fs::write(orphan.join("partial"), b"crash-before-manifest").unwrap();

        let compact = db.compact_collection("docs").unwrap();
        assert_eq!(compact.segment_id, segment_id);
        assert!(!orphan.join("partial").exists());
        assert!(orphan.join(crate::seal::SEAL_FILE).exists());
        assert_eq!(
            db.get_points("docs", &["p000".to_string()]).unwrap()[0].payload["version"],
            json!("updated")
        );
    }

    #[test]
    fn failed_lsvec_generation_write_restores_old_serveable_state() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("docs");
        config.index_kind = Some("lsvec".to_string());
        config.streamer_max_bytes = 1;
        db.create_collection(config).unwrap();
        db.upsert(
            "docs",
            (0..128)
                .map(|i| ls_vec_point(&format!("p{i:03}"), i as f32, "base"))
                .collect(),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let coll = db.get_coll("docs").unwrap();
            if coll.read().sealing.is_none() {
                break;
            }
            assert!(Instant::now() < deadline, "initial LS-VEC seal timed out");
            thread::sleep(Duration::from_millis(5));
        }
        db.get_coll("docs")
            .unwrap()
            .write()
            .config
            .streamer_max_bytes = usize::MAX;
        db.upsert("docs", vec![ls_vec_point("p000", -1.0, "updated")])
            .unwrap();

        let collection_dir = temp.path().join("collections/docs");
        let (end_lsn, generation, old_manifest) = {
            let coll = db.get_coll("docs").unwrap();
            let collection = coll.read();
            let manifest = checkpoint::read_segments_manifest(&collection_dir)
                .unwrap()
                .unwrap();
            (
                collection.wal.len().unwrap(),
                manifest.generation + 1,
                manifest,
            )
        };
        let segment_id = format!("sg-v6-merge-{end_lsn:020}-{generation:020}");
        let build_workspace =
            crate::build_progress::workspace(&collection_dir.join("searchers"), &segment_id);
        fs::create_dir_all(&build_workspace).unwrap();
        let blocked_candidate =
            crate::build_progress::BuildProgress::candidate_dir(&build_workspace);
        // A non-directory at the stable candidate path deterministically
        // simulates a generation write failure after the streamer is frozen.
        fs::write(&blocked_candidate, b"injected-write-failure").unwrap();

        assert!(db.compact_collection("docs").is_err());
        {
            let coll = db.get_coll("docs").unwrap();
            let collection = coll.read();
            assert!(collection.sealing.is_none());
            assert!(collection.streamer.points.contains_key("p000"));
        }
        assert_eq!(
            checkpoint::read_segments_manifest(&collection_dir)
                .unwrap()
                .unwrap(),
            old_manifest
        );
        assert_eq!(
            db.get_points("docs", &["p000".to_string()]).unwrap()[0].payload["version"],
            json!("updated")
        );

        fs::remove_file(blocked_candidate).unwrap();
        db.compact_collection("docs").unwrap();
        assert_eq!(
            db.get_points("docs", &["p000".to_string()]).unwrap()[0].payload["version"],
            json!("updated")
        );
    }

    #[test]
    fn persists_points_through_wal_reopen() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
            name: "docs".to_string(),
            vector_dim: 3,
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "a".to_string(),
                vector: vec![1.0, 0.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let hits = reopened
            .search(
                "docs",
                SearchRequest {
                    graph: None,
                    vector: vec![1.0, 0.0, 0.0],
                    vector_name: None,
                    k: 2,
                    filter: None,
                    budget_ms: None,
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .unwrap();
        assert!(!hits.degraded);
        assert_eq!(hits.hits[0].id, "a");
    }

    #[test]
    fn delete_is_replayed_after_reopen() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
            name: "docs".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::L2,
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "gone".to_string(),
                vector: vec![0.0, 1.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            }],
        )
        .unwrap();
        db.delete("docs", &["gone".to_string()]).unwrap();
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("docs", None).unwrap().count, 0);
    }

    #[test]
    fn get_points_returns_found_and_skips_missing() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
            name: "col".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::L2,
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
        })
        .unwrap();
        db.upsert(
            "col",
            vec![
                Point {
                    id: "a".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"x": 1}),
                },
                Point {
                    id: "b".to_string(),
                    vector: vec![0.0, 1.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"x": 2}),
                },
            ],
        )
        .unwrap();
        let points = db
            .get_points("col", &["a".to_string(), "missing".to_string()])
            .unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].id, "a");
    }

    #[test]
    fn set_payload_merge_adds_fields() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
            name: "col".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::L2,
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
        })
        .unwrap();
        db.upsert(
            "col",
            vec![Point {
                id: "p".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"a": 1, "b": 2}),
            }],
        )
        .unwrap();
        let updated = db
            .set_payload("col", "p", json!({"b": 99, "c": 3}), true)
            .unwrap();
        assert_eq!(updated.payload["a"], 1);
        assert_eq!(updated.payload["b"], 99);
        assert_eq!(updated.payload["c"], 3);
    }

    #[test]
    fn set_payload_replace_overwrites() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
            name: "col".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::L2,
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
        })
        .unwrap();
        db.upsert(
            "col",
            vec![Point {
                id: "p".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"a": 1, "b": 2}),
            }],
        )
        .unwrap();
        let updated = db.set_payload("col", "p", json!({"c": 3}), false).unwrap();
        assert!(updated.payload["a"].is_null());
        assert!(updated.payload["b"].is_null());
        assert_eq!(updated.payload["c"], 3);
    }

    #[test]
    fn set_payload_replayed_after_reopen() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
            name: "col".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::L2,
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
        })
        .unwrap();
        db.upsert(
            "col",
            vec![Point {
                id: "p".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"a": 1}),
            }],
        )
        .unwrap();
        db.set_payload("col", "p", json!({"b": 2}), true).unwrap();
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let points = reopened.get_points("col", &["p".to_string()]).unwrap();
        assert_eq!(points[0].payload["a"], 1);
        assert_eq!(points[0].payload["b"], 2);
    }

    #[test]
    fn delete_by_filter_removes_matching() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
            name: "col".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::L2,
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
        })
        .unwrap();
        db.upsert(
            "col",
            vec![
                Point {
                    id: "a".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"keep": true}),
                },
                Point {
                    id: "b".to_string(),
                    vector: vec![0.0, 1.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"keep": false}),
                },
                Point {
                    id: "c".to_string(),
                    vector: vec![0.5, 0.5],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"keep": false}),
                },
            ],
        )
        .unwrap();
        let filter: crate::Filter = serde_json::from_value(json!({"keep": false})).unwrap();
        let deleted = db.delete_by_filter("col", &filter).unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(db.count("col", None).unwrap().count, 1);
    }

    #[test]
    fn scroll_id_cursor_paginates_stably() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
            name: "col".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::L2,
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
        })
        .unwrap();
        db.upsert(
            "col",
            (0..5_usize)
                .map(|i| Point {
                    id: format!("p{i:02}"),
                    vector: vec![i as f32, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({}),
                })
                .collect(),
        )
        .unwrap();

        // First page
        let page1 = db.scroll("col", None, 2, None).unwrap();
        assert_eq!(page1.points.len(), 2);
        assert_eq!(page1.points[0].id, "p00");
        assert_eq!(page1.points[1].id, "p01");
        assert_eq!(page1.next_offset.as_deref(), Some("p01"));

        // Second page using cursor
        let page2 = db
            .scroll("col", page1.next_offset.as_deref(), 2, None)
            .unwrap();
        assert_eq!(page2.points[0].id, "p02");
        assert_eq!(page2.points[1].id, "p03");
        assert_eq!(page2.next_offset.as_deref(), Some("p03"));

        // Last page
        let page3 = db
            .scroll("col", page2.next_offset.as_deref(), 2, None)
            .unwrap();
        assert_eq!(page3.points.len(), 1);
        assert_eq!(page3.points[0].id, "p04");
        assert!(page3.next_offset.is_none());
    }

    #[test]
    fn hot_cold_fuse_dedups_tombstones_and_exactly_reranks() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert(
            "docs",
            vec![
                ls_vec_point("sealed-near", 1.0, "sealed"),
                ls_vec_point("deleted-near", 0.1, "sealed"),
                ls_vec_point("superseded", 0.2, "old"),
                ls_vec_point("sealed-far", 10.0, "sealed"),
            ],
        )
        .unwrap();
        db.compact_collection("docs").unwrap();
        db.delete("docs", &["deleted-near".to_string()]).unwrap();
        db.upsert(
            "docs",
            vec![
                ls_vec_point("streamer-nearest", 0.0, "streamer"),
                ls_vec_point("streamer-second", 2.0, "streamer"),
                ls_vec_point("superseded", 50.0, "new"),
                ls_vec_point("streamer-far", 20.0, "streamer"),
            ],
        )
        .unwrap();

        let response = db.search("docs", ls_vec_search(0.0, 3)).unwrap();
        let ids: Vec<_> = response.hits.iter().map(|hit| hit.id.as_str()).collect();
        assert_eq!(ids, ["streamer-nearest", "sealed-near", "streamer-second"]);
        assert_eq!(
            response
                .hits
                .iter()
                .map(|hit| hit.score)
                .collect::<Vec<_>>(),
            [0.0, -1.0, -2.0]
        );
        assert!(!ids.contains(&"deleted-near"));
        assert!(!ids.contains(&"superseded"));
        let collection = db.get_coll("docs").unwrap();
        let collection = collection.read();
        assert_eq!(collection.searchers.len(), 1);
        assert_eq!(collection.streamer.points.len(), 4);
        assert!(collection.searchers[0].tombstones.contains("deleted-near"));
        assert!(collection.searchers[0].tombstones.contains("superseded"));
    }

    #[test]
    fn query_time_tombstones_exclude_deleted() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert(
            "docs",
            vec![
                ls_vec_point("deleted", 0.0, "sealed"),
                ls_vec_point("live", 1.0, "sealed"),
            ],
        )
        .unwrap();
        db.compact_collection("docs").unwrap();
        assert_eq!(db.delete("docs", &["deleted".to_string()]).unwrap(), 1);

        let response = db.search("docs", ls_vec_search(0.0, 2)).unwrap();
        assert_eq!(response.hits.len(), 1);
        assert_eq!(response.hits[0].id, "live");
        let collection = db.get_coll("docs").unwrap();
        assert!(
            collection.read().searchers[0]
                .tombstones
                .contains("deleted")
        );
    }

    #[test]
    fn newest_wins_upsert_across_segments() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert("docs", vec![ls_vec_point("same", 50.0, "old")])
            .unwrap();
        db.compact_collection("docs").unwrap();
        db.upsert("docs", vec![ls_vec_point("same", 0.0, "new")])
            .unwrap();

        let response = db.search("docs", ls_vec_search(0.0, 1)).unwrap();
        assert_eq!(response.hits.len(), 1);
        assert_eq!(response.hits[0].id, "same");
        assert_eq!(response.hits[0].score, 0.0);
        assert_eq!(response.hits[0].payload["version"], "new");
        let collection = db.get_coll("docs").unwrap();
        let collection = collection.read();
        assert_eq!(
            collection.id_index["same"],
            crate::searcher::SegLoc::Streamer
        );
        assert!(collection.searchers[0].tombstones.contains("same"));
    }

    #[test]
    fn scroll_cursor_stable_across_segments() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert(
            "docs",
            vec![
                ls_vec_point("b", 2.0, "sealed"),
                ls_vec_point("d", 4.0, "sealed"),
            ],
        )
        .unwrap();
        db.compact_collection("docs").unwrap();
        db.upsert(
            "docs",
            vec![
                ls_vec_point("a", 1.0, "streamer"),
                ls_vec_point("c", 3.0, "streamer"),
                ls_vec_point("e", 5.0, "streamer"),
            ],
        )
        .unwrap();

        let first = db.scroll("docs", None, 2, None).unwrap();
        assert_eq!(
            first
                .points
                .iter()
                .map(|point| point.id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        let second = db
            .scroll("docs", first.next_offset.as_deref(), 2, None)
            .unwrap();
        assert_eq!(
            second
                .points
                .iter()
                .map(|point| point.id.as_str())
                .collect::<Vec<_>>(),
            ["c", "d"]
        );
        let third = db
            .scroll("docs", second.next_offset.as_deref(), 2, None)
            .unwrap();
        assert_eq!(
            third
                .points
                .iter()
                .map(|point| point.id.as_str())
                .collect::<Vec<_>>(),
            ["e"]
        );
        assert!(third.next_offset.is_none());
    }

    #[test]
    fn legacy_single_segment_loads_as_searcher() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert(
            "docs",
            vec![
                ls_vec_point("near", 0.0, "sealed"),
                ls_vec_point("far", 9.0, "sealed"),
            ],
        )
        .unwrap();
        db.compact_collection("docs").unwrap();
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let response = reopened.search("docs", ls_vec_search(0.0, 2)).unwrap();
        assert_eq!(
            response
                .hits
                .iter()
                .map(|hit| hit.id.as_str())
                .collect::<Vec<_>>(),
            ["near", "far"]
        );
        let collection = reopened.get_coll("docs").unwrap();
        let collection = collection.read();
        assert_eq!(collection.searchers.len(), 1);
        assert!(collection.streamer.points.is_empty());
        assert_eq!(collection.id_index.len(), 2);
        assert_eq!(
            collection.id_index["near"],
            crate::searcher::SegLoc::Searcher(0)
        );
    }

    #[test]
    fn recovery_replays_only_past_checkpoint_watermark() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        let covered = ls_vec_point("covered", 1.0, "sealed");
        db.upsert("docs", vec![covered.clone()]).unwrap();
        db.compact_collection("docs").unwrap();

        let collection = db.get_coll("docs").unwrap();
        let mut collection = collection.write();
        let wal_watermark = collection
            .wal
            .append(&WalEntry::Upsert { point: covered })
            .unwrap();
        let last_applied_lsn = collection
            .wal
            .append(&WalEntry::Upsert {
                point: ls_vec_point("tail", 2.0, "wal-tail"),
            })
            .unwrap();
        let mut checkpoint = checkpoint::CollectionCheckpoint::new(
            &collection.config,
            collection.schema_epoch,
            last_applied_lsn,
            2,
            collection.last_segment_id.clone(),
        )
        .unwrap();
        checkpoint.segments = Some(
            collection
                .searchers
                .iter()
                .map(|searcher| searcher.id.clone())
                .collect(),
        );
        checkpoint.wal_watermark = wal_watermark;
        checkpoint::write_checkpoint(&temp.path().join("collections/docs"), &checkpoint).unwrap();
        drop(collection);
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("docs", None).unwrap().count, 2);
        let collection = reopened.get_coll("docs").unwrap();
        let collection = collection.read();
        assert_eq!(collection.wal_watermark, wal_watermark);
        assert_eq!(collection.streamer.points.len(), 1);
        assert!(collection.streamer.points.contains_key("tail"));
        assert_eq!(
            collection.id_index["covered"],
            crate::searcher::SegLoc::Searcher(0)
        );
        drop(collection);

        reopened
            .update_payload_schema("docs", Default::default())
            .unwrap();
        let checkpoint = checkpoint::read_checkpoint(&temp.path().join("collections/docs"))
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.wal_watermark, wal_watermark);
        assert_eq!(
            checkpoint.segments,
            Some(vec![checkpoint.segment_id.unwrap()])
        );
    }

    #[test]
    fn streamer_accounting_tracks_db_mutation_paths() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("docs");
        config.streamer_max_bytes = 32;
        db.create_collection(config).unwrap();
        db.upsert("docs", vec![ls_vec_point("a", 1.0, "first")])
            .unwrap();
        db.upsert("docs", vec![ls_vec_point("a", 2.0, "replacement")])
            .unwrap();
        db.set_payload("docs", "a", json!({"version": "expanded-payload"}), false)
            .unwrap();

        let collection = db.get_coll("docs").unwrap();
        let collection = collection.read();
        let expected: usize = collection
            .streamer
            .points
            .values()
            .map(crate::streamer::point_bytes)
            .sum();
        assert_eq!(collection.streamer.estimated_bytes(), expected);
        assert!(
            collection
                .streamer
                .should_seal(collection.config.streamer_max_bytes)
        );
        drop(collection);

        db.delete("docs", &["a".to_string()]).unwrap();
        assert_eq!(
            db.get_coll("docs")
                .unwrap()
                .read()
                .streamer
                .estimated_bytes(),
            0
        );
    }

    #[test]
    fn count_and_get_resolve_from_store() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert(
            "docs",
            vec![
                ls_vec_point("a", 1.0, "sealed"),
                ls_vec_point("b", 2.0, "sealed"),
                ls_vec_point("c", 3.0, "sealed"),
            ],
        )
        .unwrap();
        db.compact_collection("docs").unwrap();
        db.delete("docs", &["b".to_string()]).unwrap();
        db.upsert("docs", vec![ls_vec_point("d", 4.0, "streamer")])
            .unwrap();

        assert_eq!(db.count("docs", None).unwrap().count, 3);
        let points = db
            .get_points(
                "docs",
                &[
                    "d".to_string(),
                    "b".to_string(),
                    "a".to_string(),
                    "c".to_string(),
                ],
            )
            .unwrap();
        assert_eq!(
            points
                .iter()
                .map(|point| point.id.as_str())
                .collect::<Vec<_>>(),
            ["d", "a", "c"]
        );
    }

    #[test]
    fn compact_writes_mmap_lsvec_artifacts() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
            name: "paged".to_string(),
            vector_dim: 8,
            metric: DistanceMetric::L2,
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
        })
        .unwrap();
        let bulk: Vec<Point> = (0..crate::h2qg::HNSW_THRESHOLD + 10)
            .map(|i| Point {
                id: format!("p{i}"),
                vector: vec![i as f32; 8],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            })
            .collect();
        db.upsert("paged", bulk).unwrap();

        let compact = db.compact_collection("paged").unwrap();
        let segment_dir = temp
            .path()
            .join("collections/paged/searchers")
            .join(&compact.segment_id);
        assert!(segment_dir.join(crate::index::ivf::IVF_FILE).exists());
        assert!(segment_dir.join(crate::index::rabitq::RABITQ_FILE).exists());
        assert!(
            segment_dir
                .join(crate::index::vamana::VAMANA_SEGMENT_FILE)
                .exists()
        );
        assert!(!segment_dir.join(crate::h2qg::HNSW_VECS_FILE).exists());

        let search = |db: &Db, query: Vec<f32>| {
            db.search(
                "paged",
                SearchRequest {
                    graph: None,
                    vector: query,
                    vector_name: None,
                    k: 1,
                    filter: None,
                    budget_ms: None,
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .unwrap()
            .hits
        };
        // Search through the mmap-paged graph must find the exact point.
        assert_eq!(search(&db, vec![42.0; 8])[0].id, "p42");

        // Live insert after the paged index landed: even a subthreshold
        // replacement tail gets a real mutable HNSW because the collection as
        // a whole is ANN-sized. Later inserts are backfilled beside the
        // immutable generation.
        // In-distribution vector (between p500 and p501) — an extreme
        // outlier here would test HNSW reverse-edge pruning reachability,
        // a pre-existing property unrelated to paging.
        db.upsert(
            "paged",
            vec![Point {
                id: "tail".to_string(),
                vector: vec![500.5; 8],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            }],
        )
        .unwrap();
        let coll = db.get_coll("paged").unwrap();
        wait_for_h2qg(&coll, BACKGROUND_INDEX_TEST_TIMEOUT);
        {
            let guard = coll.read();
            let h2qg = guard.streamer.hnsw.as_ref().unwrap();
            assert!(h2qg.is_hnsw());
            assert_eq!(crate::index::IndexBackend::indexed_points(h2qg), 1);
            assert!(h2qg.contains("tail"));
            assert!(
                guard.streamer.points.contains_key("tail"),
                "live insert must remain query-visible in the replacement tail"
            );
            assert!(
                guard
                    .searchers
                    .iter()
                    .all(|searcher| searcher.get_live("tail").is_none()),
                "immutable generation must not claim the replacement-tail row"
            );
        }
        assert_eq!(search(&db, vec![500.5; 8])[0].id, "tail");
        assert_eq!(search(&db, vec![42.0; 8])[0].id, "p42");

        // Restart: reload must re-attach the mmap sidecar and stay correct.
        drop(db);
        let db = Db::open(temp.path()).unwrap();
        assert_eq!(search(&db, vec![42.0; 8])[0].id, "p42");
    }

    #[test]
    fn compaction_seals_points_and_truncates_wal() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "kept".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();

        let compact = db.compact_collection("docs").unwrap();
        assert_eq!(compact.points, 1);
        assert_eq!(compact.sparse_dimensions, 0);
        assert_eq!(compact.sparse_postings, 0);
        assert_eq!(compact.payload_fields, 1);
        assert_eq!(compact.payload_values, 1);
        assert_eq!(compact.payload_postings, 1);
        assert_eq!(
            db.count("docs", Some(Filter(json!({"tenant": "acme"}))))
                .unwrap()
                .count,
            1,
            "sealed payload ordinals and the mutable fallback must not return the same id twice"
        );
        assert_eq!(compact.wal_archived_segments, 1);
        assert!(compact.wal_archived_bytes > 0);
        assert!(
            temp.path()
                .join("collections/docs/searchers")
                .join(&compact.segment_id)
                .join("vec.gdx")
                .exists()
        );
        assert!(
            temp.path()
                .join("collections/docs/searchers")
                .join(&compact.segment_id)
                .join(crate::index::ivf::IVF_FILE)
                .exists()
        );
        assert!(
            temp.path()
                .join("collections/docs/searchers")
                .join(&compact.segment_id)
                .join("payload.gdx")
                .exists()
        );
        let checkpoint_path = temp.path().join("collections/docs/checkpoint.gdx");
        assert!(checkpoint_path.exists());
        let checkpoint = checkpoint::read_checkpoint(&temp.path().join("collections/docs"))
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.collection, "docs");
        assert_eq!(checkpoint.schema_epoch, 1);
        assert_eq!(checkpoint.points, 1);
        assert_eq!(checkpoint.segment_id, Some(compact.segment_id.clone()));
        assert!(checkpoint.last_applied_lsn > 0);
        assert!(
            Wal::load(&temp.path().join("collections/docs/wal"))
                .unwrap()
                .is_empty()
        );
        let archive_root = temp.path().join("collections/docs/wal/archive");
        let archives = std::fs::read_dir(&archive_root)
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(archives.len(), 1);
        assert_eq!(Wal::load(&archives[0].path()).unwrap().len(), 2);
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let hits = reopened
            .search(
                "docs",
                SearchRequest {
                    graph: None,
                    vector: vec![1.0, 0.0],
                    vector_name: None,
                    k: 1,
                    filter: None,
                    budget_ms: None,
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .unwrap();
        assert!(!hits.degraded);
        assert_eq!(hits.hits[0].id, "kept");
    }

    #[test]
    fn auto_compaction_compacts_collections_over_wal_threshold() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "kept".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();

        let compacted = db.compact_collections_over_wal_bytes(1).unwrap();
        assert_eq!(compacted.len(), 1);
        assert_eq!(compacted[0].collection, "docs");
        assert_eq!(compacted[0].points, 1);
        assert_eq!(compacted[0].sparse_dimensions, 1);
        assert_eq!(compacted[0].payload_fields, 1);
        assert_eq!(compacted[0].wal_archived_segments, 1);
        assert!(compacted[0].wal_archived_bytes > 0);
        assert!(
            temp.path()
                .join("collections/docs/searchers")
                .join(&compacted[0].segment_id)
                .join(crate::seal::SEAL_FILE)
                .exists()
        );
        assert!(
            Wal::load(&temp.path().join("collections/docs/wal"))
                .unwrap()
                .is_empty()
        );
        assert!(db.compact_collections_over_wal_bytes(1).unwrap().is_empty());

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        let response = reopened
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: None,
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                    k: 2,
                    filter: Some(Filter(json!({"tenant": "acme"}))),
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();
        assert_eq!(response.hits[0].id, "kept");
        assert_eq!(response.searched, 1);
    }

    #[test]
    fn scored_compaction_uses_logical_wal_delete_density() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("scored");
        config.streamer_max_bytes = usize::MAX;
        db.create_collection(config).unwrap();
        db.upsert(
            "scored",
            (0..10)
                .map(|index| Point {
                    id: format!("p{index}"),
                    vector: vec![index as f32, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: serde_json::Value::Null,
                })
                .collect(),
        )
        .unwrap();
        db.delete(
            "scored",
            &(0..8).map(|index| format!("p{index}")).collect::<Vec<_>>(),
        )
        .unwrap();

        let compacted = db
            .compact_collections_by_score(
                0.4,
                Some(crate::compaction::CompactionWeights {
                    wal_ratio_weight: 0.0,
                    deletion_density_weight: 1.0,
                    min_wal_bytes: 0,
                }),
            )
            .unwrap();
        assert_eq!(compacted.len(), 1);
        assert_eq!(compacted[0].collection, "scored");
        assert_eq!(compacted[0].points, 2);
    }

    #[test]
    fn prune_wal_archive_retains_newest_archives() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        for id in ["first", "second", "third"] {
            db.upsert(
                "docs",
                vec![Point {
                    id: id.to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                    payload: json!({"tenant": "acme"}),
                }],
            )
            .unwrap();
            db.compact_collection("docs").unwrap();
        }

        let archive_root = temp.path().join("collections/docs/wal/archive");
        assert_eq!(std::fs::read_dir(&archive_root).unwrap().count(), 3);
        let pruned = db.prune_wal_archive("docs", 1).unwrap();
        assert_eq!(pruned.collection, "docs");
        assert_eq!(pruned.retained_archives, 1);
        assert_eq!(pruned.pruned_archives, 2);
        assert!(pruned.pruned_bytes > 0);
        let archives = std::fs::read_dir(&archive_root)
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(archives.len(), 1);
        assert_eq!(Wal::load(&archives[0].path()).unwrap().len(), 2);

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        let response = reopened
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: None,
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                    k: 3,
                    filter: Some(Filter(json!({"tenant": "acme"}))),
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();
        assert_eq!(response.hits.len(), 3);
        assert_eq!(response.searched, 3);
    }

    #[test]
    fn compact_applies_wal_archive_retention_policy() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.set_wal_archive_retain_last(Some(1));
        assert_eq!(db.wal_archive_retain_last(), Some(1));
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();

        for id in ["first", "second", "third"] {
            db.upsert(
                "docs",
                vec![Point {
                    id: id.to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                    payload: json!({"tenant": "acme"}),
                }],
            )
            .unwrap();
        }

        let first = db.compact_collection("docs").unwrap();
        assert_eq!(first.wal_auto_retained_archives, 1);
        assert_eq!(first.wal_auto_pruned_archives, 0);

        db.upsert(
            "docs",
            vec![Point {
                id: "fourth".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();
        let second = db.compact_collection("docs").unwrap();
        assert_eq!(second.wal_auto_retained_archives, 1);
        assert_eq!(second.wal_auto_pruned_archives, 1);
        assert!(second.wal_auto_pruned_bytes > 0);

        let archive_root = temp.path().join("collections/docs/wal/archive");
        let archives = std::fs::read_dir(&archive_root)
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(archives.len(), 1);
        assert_eq!(Wal::load(&archives[0].path()).unwrap().len(), 2);

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        let response = reopened
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: None,
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                    k: 4,
                    filter: Some(Filter(json!({"tenant": "acme"}))),
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();
        assert_eq!(response.hits.len(), 4);
        assert_eq!(response.searched, 4);
    }

    fn selected_graph_authority_bytes(collection: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        fn collect(collection: &Path, path: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
            if path.is_dir() {
                let mut entries = fs::read_dir(path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .collect::<Vec<_>>();
                entries.sort();
                for entry in entries {
                    collect(collection, &entry, out);
                }
            } else if path.is_file() {
                out.push((
                    path.strip_prefix(collection).unwrap().to_path_buf(),
                    fs::read(path).unwrap(),
                ));
            }
        }

        let mut files = Vec::new();
        for relative in [
            crate::checkpoint::SEGMENTS_MANIFEST_FILE,
            crate::checkpoint::CHECKPOINT_FILE,
            "graph",
            "overlays",
        ] {
            collect(collection, &collection.join(relative), &mut files);
        }
        files.sort_by(|left, right| left.0.cmp(&right.0));
        files
    }

    #[test]
    fn graph_cold_tier_preserves_generation_local_and_remote_plaintext_and_encrypted() {
        use crate::{
            encryption,
            graph::{ConfigureEdgeTypeRequest, GraphRelationScope, RelateRequest},
        };
        use base64::{Engine, engine::general_purpose::STANDARD};
        use std::{env, process::Command};

        const MODE: &str = "CHIRONDB_GRAPH_COLD_TEST_MODE";
        const ROOT: &str = "CHIRONDB_GRAPH_COLD_TEST_ROOT";
        const TEST: &str = "db::tests::graph_cold_tier_preserves_generation_local_and_remote_plaintext_and_encrypted";
        const GRAPH_PEERS: [&str; 3] = [
            crate::graph_nid::NID_FILE,
            crate::graph_edge::EDGE_FILE,
            crate::graph_edgeprop::EDGE_PROPERTY_FILE,
        ];

        let Some(mode) = env::var_os(MODE) else {
            for mode in [
                "plaintext-local",
                "plaintext-remote",
                "encrypted-local",
                "encrypted-remote",
            ] {
                let temp = TempDir::new().unwrap();
                assert!(
                    Command::new(env::current_exe().unwrap())
                        .args(["--exact", TEST, "--nocapture"])
                        .env(MODE, mode)
                        .env(ROOT, temp.path())
                        .status()
                        .unwrap()
                        .success(),
                    "{mode}"
                );
            }
            return;
        };
        let mode = mode.to_string_lossy();
        let encrypted = mode.starts_with("encrypted");
        let remote = mode.ends_with("remote");
        let root = PathBuf::from(env::var_os(ROOT).unwrap());
        if encrypted {
            let keyring = root.join("keyring.json");
            fs::write(
                &keyring,
                json!({"version":1,"active_key_id":"graph-cold","keys":[{"id":"graph-cold","key_base64":STANDARD.encode([83;32])}]}).to_string(),
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

        let data = root.join("db");
        let object_store = root.join("object-store");
        let db = Db::open(&data).unwrap();
        if remote {
            db.set_cold_object_store_dir(Some(object_store.clone()));
        }
        let mut config = ls_vec_config("docs");
        config.streamer_max_bytes = usize::MAX;
        db.create_collection(config).unwrap();
        let scope = crate::tenant::TenantScope::tenant("graph-cold", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        db.upsert(
            "docs",
            vec![graph_point("a", 1.0, "acme"), graph_point("b", 2.0, "acme")],
        )
        .unwrap();
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: "links".into(),
                weight_property: None,
            },
            true,
            &scope,
        )
        .unwrap();
        db.relate_scoped(
            "docs",
            RelateRequest {
                source_point_id: "a".into(),
                target_point_id: "b".into(),
                edge_type: "links".into(),
                properties: json!({"weight":1}),
                scope: GraphRelationScope::Local,
                idempotency_key: Some("a-b".into()),
            },
            true,
            &scope,
        )
        .unwrap();
        let seal = prepare_forced_graph_vector_seal(&db, &data, "docs");
        run_segment_seal(&seal).unwrap();
        drop(seal);

        let collection = super::collection_dir(&data, "docs");
        let manifest = checkpoint::read_segments_manifest(&collection)
            .unwrap()
            .unwrap();
        let segment_id = manifest.segments[0].clone();
        let hot = collection.join("searchers").join(&segment_id);
        let cold = collection.join("cold").join(&segment_id);
        let hot_marker = crate::seal::read_marker(&hot.join(crate::seal::SEAL_FILE)).unwrap();
        assert!(matches!(hot_marker.version, 12 | 14));
        let authority = selected_graph_authority_bytes(&collection);
        let lifecycle = db.get_coll("docs").unwrap().read().graph_lifecycle;

        let response = db.tier_collection_to_cold("docs").unwrap();
        assert_eq!(response.points, 2);
        assert!(!hot.exists());
        assert!(cold.exists());
        let cold_marker = crate::seal::read_marker(&cold.join(crate::seal::SEAL_FILE)).unwrap();
        assert_eq!(cold_marker.version, hot_marker.version + 1);
        for peer in GRAPH_PEERS {
            assert!(cold.join(peer).is_file(), "missing cold graph peer {peer}");
        }
        assert_eq!(selected_graph_authority_bytes(&collection), authority);
        {
            let coll = db.get_coll("docs").unwrap();
            let state = coll.read();
            assert_eq!(state.graph_lifecycle, lifecycle);
            assert_eq!(
                state.graph_generation.as_ref().unwrap().bases[0]
                    .adjacency
                    .edge_count(),
                1
            );
        }
        drop(db);

        if remote {
            let mirrored = object_store
                .join("collections/docs/segments")
                .join(&segment_id);
            for peer in GRAPH_PEERS {
                assert!(
                    mirrored.join(peer).is_file(),
                    "missing mirrored graph peer {peer}"
                );
            }
            assert!(mirrored.join(crate::index::diskann::DISKANN_FILE).is_file());
            fs::remove_dir_all(&cold).unwrap();
        }

        let reopened = if remote {
            Db::open_with_cold_object_store(&data, Some(object_store)).unwrap()
        } else {
            Db::open(&data).unwrap()
        };
        assert!(cold.exists());
        for peer in GRAPH_PEERS {
            assert!(
                cold.join(peer).is_file(),
                "missing materialized graph peer {peer}"
            );
        }
        if remote {
            assert!(!cold.join(crate::index::diskann::DISKANN_FILE).exists());
        }
        assert_eq!(selected_graph_authority_bytes(&collection), authority);
        let coll = reopened.get_coll("docs").unwrap();
        let state = coll.read();
        assert_eq!(state.graph_lifecycle, lifecycle);
        assert!(state.graph_lifecycle.is_enabled());
        let generation = state.graph_generation.as_ref().unwrap();
        assert_eq!(generation.manifest.as_ref(), &manifest);
        assert_eq!(generation.bases[0].dir, cold);
        assert_eq!(generation.bases[0].adjacency.edge_count(), 1);
        assert!(generation.bases[0].vectors.diskann().is_some());
        drop(state);
        drop(coll);
        let search = reopened.search("docs", ls_vec_search(1.0, 2)).unwrap();
        assert_eq!(search.hits.len(), 2);
        assert_eq!(search.hits[0].id, "a");
        assert_eq!(
            reopened
                .get_points("docs", &["a".into(), "b".into()])
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn graph_cold_tier_rejects_corrupt_selected_authority_before_publication() {
        use crate::{
            graph_generation::{ArtifactFamily, artifact_path},
            tenant::TenantScope,
        };

        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("docs");
        config.streamer_max_bytes = usize::MAX;
        db.create_collection(config).unwrap();
        let scope = TenantScope::tenant("graph-cold", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        db.upsert("docs", vec![graph_point("a", 1.0, "acme")])
            .unwrap();
        let seal = prepare_forced_graph_vector_seal(&db, temp.path(), "docs");
        run_segment_seal(&seal).unwrap();
        drop(seal);

        let collection = super::collection_dir(temp.path(), "docs");
        let manifest = checkpoint::read_segments_manifest(&collection)
            .unwrap()
            .unwrap();
        let recovery = manifest.graph.as_ref().unwrap().recovery.as_ref().unwrap();
        let recovery_path =
            artifact_path(&collection, ArtifactFamily::Recovery, &recovery.id).unwrap();
        let mut bytes = fs::read(&recovery_path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&recovery_path, bytes).unwrap();

        let segment_id = &manifest.segments[0];
        let error = db.tier_collection_to_cold("docs").unwrap_err();
        assert!(error.to_string().contains("recovery"), "{error}");
        assert!(collection.join("searchers").join(segment_id).exists());
        assert!(!collection.join("cold").join(segment_id).exists());
        assert!(!collection.join("cold/cold_index.gdx").exists());
    }

    #[test]
    fn graph_cold_tier_rejects_wal_only_graph_history() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert("docs", vec![graph_point("legacy", 1.0, "acme")])
            .unwrap();
        let compact = db.compact_collection("docs").unwrap();
        let scope = crate::tenant::TenantScope::tenant("graph-cold", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        wait_for_graph_backfill(&db, "docs");
        assert!(
            db.get_coll("docs")
                .unwrap()
                .read()
                .graph_generation
                .is_none()
        );

        let error = db.tier_collection_to_cold("docs").unwrap_err();
        assert!(error.to_string().contains("WAL-only G0 graph state"));
        let collection = super::collection_dir(temp.path(), "docs");
        assert!(
            collection
                .join("searchers")
                .join(compact.segment_id)
                .exists()
        );
        assert!(!collection.join("cold/cold_index.gdx").exists());
    }

    #[test]
    fn tier_cold_moves_searcher_and_reopens_from_cold_dir() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "cold".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();
        db.compact_collection("docs").unwrap();

        let response = db.tier_collection_to_cold("docs").unwrap();

        assert_eq!(response.collection, "docs");
        assert_eq!(response.segments, 1);
        assert!(response.files >= 5);
        assert!(response.bytes > 0);
        assert_eq!(response.points, 1);
        assert_eq!(
            std::fs::read_dir(temp.path().join("collections/docs/searchers"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            std::fs::read_dir(temp.path().join("collections/docs/cold"))
                .unwrap()
                .filter(|entry| entry.as_ref().unwrap().path().is_dir())
                .count(),
            1
        );
        assert!(
            temp.path()
                .join("collections/docs/cold/cold_index.gdx")
                .exists()
        );
        let search = db
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: None,
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                    k: 1,
                    filter: Some(Filter(json!({"tenant": "acme"}))),
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();
        assert_eq!(search.hits.len(), 1);
        assert_eq!(search.hits[0].id, "cold");

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        let search = reopened
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: None,
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                    k: 1,
                    filter: Some(Filter(json!({"tenant": "acme"}))),
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();
        assert_eq!(search.hits.len(), 1);
        assert_eq!(search.hits[0].id, "cold");
    }

    #[test]
    fn open_rejects_corrupt_cold_index() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "cold".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            }],
        )
        .unwrap();
        db.compact_collection("docs").unwrap();
        db.tier_collection_to_cold("docs").unwrap();
        drop(db);

        let cold_index = temp.path().join("collections/docs/cold/cold_index.gdx");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(cold_index)
            .unwrap();
        use std::io::{Seek, Write};
        file.seek(std::io::SeekFrom::Start(20)).unwrap();
        file.write_all(b"x").unwrap();

        let error = Db::open(temp.path()).unwrap_err();
        assert!(error.to_string().contains("cold index crc mismatch"));
    }

    #[test]
    fn cold_tier_mirrors_segments_to_configured_object_store() {
        let temp = TempDir::new().unwrap();
        let object_store = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.set_cold_object_store_dir(Some(object_store.path().to_path_buf()));
        assert_eq!(
            db.cold_object_store_dir(),
            Some(object_store.path().to_path_buf())
        );
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "remote-cold".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();
        let compact = db.compact_collection("docs").unwrap();
        db.tier_collection_to_cold("docs").unwrap();
        drop(db);

        let object_segment = object_store
            .path()
            .join("collections/docs/segments")
            .join(&compact.segment_id);
        assert!(object_segment.join(crate::seal::SEAL_FILE).exists());
        assert!(!object_segment.join(crate::seal::VECTOR_FILE).exists());
        assert!(
            !object_segment
                .join(crate::index::vamana::VAMANA_SEGMENT_FILE)
                .exists()
        );
        assert!(
            object_segment
                .join(crate::index::diskann::DISKANN_FILE)
                .exists()
        );
        let cold_index = temp.path().join("collections/docs/cold/cold_index.gdx");
        let cold_index_payload = std::fs::read(&cold_index).unwrap();
        let cold_index_json = std::str::from_utf8(&cold_index_payload[20..]).unwrap();
        assert!(cold_index_json.contains(&format!(
            "collections/docs/segments/{}/{}",
            compact.segment_id,
            crate::seal::SEAL_FILE
        )));

        std::fs::remove_dir_all(
            temp.path()
                .join("collections/docs/cold")
                .join(&compact.segment_id),
        )
        .unwrap();
        let reopened =
            Db::open_with_cold_object_store(temp.path(), Some(object_store.path().to_path_buf()))
                .unwrap();
        let local_cold_segment = temp
            .path()
            .join("collections/docs/cold")
            .join(&compact.segment_id);
        assert!(!local_cold_segment.exists());
        reopened
            .ensure_collection_cold_materialized("docs")
            .unwrap();
        assert!(local_cold_segment.exists());
        assert!(
            !local_cold_segment
                .join(crate::index::diskann::DISKANN_FILE)
                .exists(),
            "remote DiskANN must not be materialized locally"
        );
        let startup_io = reopened.diskann_io_stats("docs").unwrap();
        assert_eq!(startup_io.remote_segments, 1);
        assert_eq!(startup_io.physical_page_reads, 0);
        assert_eq!(startup_io.remote_range_requests, 0);
        let search = reopened
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: None,
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                    k: 1,
                    filter: Some(Filter(json!({"tenant": "acme"}))),
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();
        assert_eq!(search.hits.len(), 1);
        assert_eq!(search.hits[0].id, "remote-cold");
        reopened.reset_diskann_io_stats("docs").unwrap();
        let dense = reopened.search("docs", ls_vec_search(1.0, 1)).unwrap();
        assert_eq!(dense.hits[0].id, "remote-cold");
        let io = reopened.diskann_io_stats("docs").unwrap();
        assert_eq!(io.remote_segments, 1);
        assert!(io.remote_range_requests > 0);
        assert!(io.remote_range_pages > 0);
        assert_eq!(io.page_read_errors, 0);
    }

    #[test]
    fn cold_object_store_url_uses_object_store_backend() {
        let temp = TempDir::new().unwrap();
        let object_store = TempDir::new().unwrap();
        let object_store_url = url::Url::from_directory_path(object_store.path())
            .unwrap()
            .to_string();
        let db = Db::open(temp.path()).unwrap();
        db.set_cold_object_store_url(Some(object_store_url.clone()));
        assert_eq!(db.cold_object_store_url(), Some(object_store_url.clone()));
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "url-cold".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();
        let compact = db.compact_collection("docs").unwrap();
        db.tier_collection_to_cold("docs").unwrap();
        drop(db);

        let object_segment = object_store
            .path()
            .join("collections/docs/segments")
            .join(&compact.segment_id);
        assert!(object_segment.join(crate::seal::SEAL_FILE).exists());
        assert!(!object_segment.join(crate::seal::VECTOR_FILE).exists());
        assert!(
            !object_segment
                .join(crate::index::vamana::VAMANA_SEGMENT_FILE)
                .exists()
        );
        assert!(
            object_segment
                .join(crate::index::diskann::DISKANN_FILE)
                .exists()
        );
        std::fs::remove_dir_all(
            temp.path()
                .join("collections/docs/cold")
                .join(&compact.segment_id),
        )
        .unwrap();
        let reopened = Db::open_with_cold_object_store_config(
            temp.path(),
            Some(ColdObjectStoreConfig::Url(object_store_url)),
        )
        .unwrap();
        let local_cold_segment = temp
            .path()
            .join("collections/docs/cold")
            .join(&compact.segment_id);
        assert!(!local_cold_segment.exists());
        let search = reopened
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: None,
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                    k: 1,
                    filter: Some(Filter(json!({"tenant": "acme"}))),
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();
        assert!(local_cold_segment.exists());
        assert_eq!(search.hits.len(), 1);
        assert_eq!(search.hits[0].id, "url-cold");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cold_http_object_store_serves_diskann_only_with_ranges() {
        let temp = TempDir::new().unwrap();
        let object_store = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.set_cold_object_store_dir(Some(object_store.path().to_path_buf()));
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert(
            "docs",
            (0..128)
                .map(|ordinal| Point {
                    id: format!("p{ordinal:03}"),
                    vector: vec![ordinal as f32, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![ordinal as f32 + 1.0],
                    }),
                    payload: json!({"tenant": "acme", "ordinal": ordinal}),
                })
                .collect(),
        )
        .unwrap();
        let compact = db.compact_collection("docs").unwrap();
        db.tier_collection_to_cold("docs").unwrap();
        drop(db);

        let remote_diskann = object_store
            .path()
            .join("collections/docs/segments")
            .join(&compact.segment_id)
            .join(crate::index::diskann::DISKANN_FILE);
        let remote_diskann_bytes = remote_diskann.metadata().unwrap().len();
        assert!(remote_diskann_bytes > crate::index::diskann::PAGE_SIZE as u64);
        let local_cold_segment = temp
            .path()
            .join("collections/docs/cold")
            .join(&compact.segment_id);
        fs::remove_dir_all(&local_cold_segment).unwrap();

        let fixture = RangeHttpFixture::start(object_store.path().to_path_buf());
        let reopened = Db::open_with_cold_object_store_config(
            temp.path(),
            Some(ColdObjectStoreConfig::Url(fixture.url.clone())),
        )
        .unwrap();
        assert!(!local_cold_segment.exists());
        reopened
            .ensure_collection_cold_materialized("docs")
            .unwrap();
        assert!(local_cold_segment.exists());
        assert!(
            !local_cold_segment
                .join(crate::index::diskann::DISKANN_FILE)
                .exists()
        );
        let startup_io = reopened.diskann_io_stats("docs").unwrap();
        assert_eq!(startup_io.remote_segments, 1);
        assert_eq!(startup_io.physical_page_reads, 0);
        assert_eq!(startup_io.remote_range_requests, 0);
        assert_eq!(fixture.stats.diskann_full_gets.load(Ordering::Relaxed), 0);
        assert_eq!(
            fixture.stats.diskann_range_gets.load(Ordering::Relaxed),
            1,
            "startup must fetch only the DiskANN header range"
        );
        assert_eq!(
            fixture.stats.diskann_range_bytes.load(Ordering::Relaxed),
            crate::index::diskann::PAGE_SIZE as u64
        );
        let requests_after_materialization = fixture.stats.total_requests.load(Ordering::Relaxed);
        reopened
            .ensure_collection_cold_materialized("docs")
            .unwrap();
        assert_eq!(
            fixture.stats.total_requests.load(Ordering::Relaxed),
            requests_after_materialization,
            "an already materialized segment must not revalidate its remote sidecars"
        );

        reopened.reset_diskann_io_stats("docs").unwrap();
        let dense = reopened.search("docs", ls_vec_search(91.0, 1)).unwrap();
        assert_eq!(dense.hits[0].id, "p091");
        let fetched = reopened.get_points("docs", &["p017".to_string()]).unwrap();
        assert_eq!(fetched[0].id, "p017");
        assert_eq!(fetched[0].payload["tenant"], "acme");
        let io = reopened.diskann_io_stats("docs").unwrap();
        assert_eq!(io.remote_segments, 1);
        assert!(io.remote_range_requests > 0);
        assert!(io.remote_range_pages > 0);
        assert_eq!(io.page_read_errors, 0);
        assert_eq!(
            fixture.stats.diskann_full_gets.load(Ordering::Relaxed),
            0,
            "DiskANN must never be fetched with an unbounded HTTP GET"
        );
        assert!(
            fixture.stats.diskann_range_gets.load(Ordering::Relaxed) > 1,
            "dense search must fetch remote DiskANN data-page ranges"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires GAUSSDB_TEST_S3_COLD_URL and an S3-compatible service"]
    async fn cold_s3_object_store_serves_diskann_without_materializing_it() {
        let object_store_url =
            std::env::var("GAUSSDB_TEST_S3_COLD_URL").expect("S3 cold URL is required");
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.set_cold_object_store_url(Some(object_store_url.clone()));
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert(
            "docs",
            (0..128)
                .map(|ordinal| Point {
                    id: format!("p{ordinal:03}"),
                    vector: vec![ordinal as f32, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"ordinal": ordinal}),
                })
                .collect(),
        )
        .unwrap();
        let compact = db.compact_collection("docs").unwrap();
        db.tier_collection_to_cold("docs").unwrap();
        drop(db);

        let local_cold_segment = temp
            .path()
            .join("collections/docs/cold")
            .join(&compact.segment_id);
        fs::remove_dir_all(&local_cold_segment).unwrap();
        let reopened = Db::open_with_cold_object_store_config(
            temp.path(),
            Some(ColdObjectStoreConfig::Url(object_store_url)),
        )
        .unwrap();
        assert!(!local_cold_segment.exists());
        reopened
            .ensure_collection_cold_materialized("docs")
            .unwrap();
        assert!(local_cold_segment.exists());
        assert!(
            !local_cold_segment
                .join(crate::index::diskann::DISKANN_FILE)
                .exists()
        );
        let startup_io = reopened.diskann_io_stats("docs").unwrap();
        assert_eq!(startup_io.remote_segments, 1);
        assert_eq!(startup_io.physical_page_reads, 0);
        assert_eq!(startup_io.remote_range_requests, 0);

        reopened.reset_diskann_io_stats("docs").unwrap();
        let dense = reopened.search("docs", ls_vec_search(91.0, 1)).unwrap();
        assert_eq!(dense.hits[0].id, "p091");
        let io = reopened.diskann_io_stats("docs").unwrap();
        assert_eq!(io.remote_segments, 1);
        assert!(io.remote_range_requests > 0);
        assert!(io.remote_range_pages > 0);
        assert_eq!(io.page_read_errors, 0);
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "s3_url": "s3://gaussdb-cold/range-proof",
                "segment_id": compact.segment_id,
                "local_diskann_materialized": false,
                "startup_io": startup_io,
                "query_io": io,
                "top_hit": dense.hits[0].id,
            }))
            .unwrap()
        );
    }

    #[test]
    fn compact_mirrors_wal_archive_before_local_retention_prunes() {
        let temp = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.set_wal_external_archive_dir(Some(external.path().to_path_buf()));
        db.set_wal_archive_retain_last(Some(0));
        assert_eq!(
            db.wal_external_archive_dir(),
            Some(external.path().to_path_buf())
        );
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();

        db.upsert(
            "docs",
            vec![Point {
                id: "mirrored".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();

        let compact = db.compact_collection("docs").unwrap();
        assert_eq!(compact.wal_archived_segments, 1);
        assert!(compact.wal_archived_bytes > 0);
        assert_eq!(compact.wal_external_archived_segments, 1);
        assert_eq!(
            compact.wal_external_archived_bytes,
            compact.wal_archived_bytes
        );
        assert_eq!(compact.wal_auto_retained_archives, 0);
        assert_eq!(compact.wal_auto_pruned_archives, 1);
        assert!(compact.wal_auto_pruned_bytes > 0);

        let archive_root = temp.path().join("collections/docs/wal/archive");
        assert_eq!(std::fs::read_dir(&archive_root).unwrap().count(), 0);
        let external_archive_root = external.path().join("collections/docs");
        let archives = std::fs::read_dir(&external_archive_root)
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(archives.len(), 1);
        assert_eq!(Wal::load(&archives[0].path()).unwrap().len(), 2);

        db.upsert(
            "docs",
            vec![Point {
                id: "mirrore2".to_string(),
                vector: vec![0.0, 1.0],
                vectors: HashMap::new(),
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();
        let second_compact = db.compact_collection("docs").unwrap();
        assert_eq!(second_compact.wal_external_archived_segments, 1);
        assert_eq!(std::fs::read_dir(&archive_root).unwrap().count(), 0);
        let archives = std::fs::read_dir(&external_archive_root)
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(archives.len(), 2);
        for archive in archives {
            assert_eq!(Wal::load(&archive.path()).unwrap().len(), 2);
        }

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        let response = reopened
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: None,
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                    k: 2,
                    filter: Some(Filter(json!({"tenant": "acme"}))),
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();
        assert_eq!(response.hits.len(), 2);
        assert_eq!(response.searched, 2);
    }

    #[test]
    fn compact_mirrors_wal_archive_to_object_store_before_local_retention_prunes() {
        let temp = TempDir::new().unwrap();
        let object_store = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.set_wal_object_store_dir(Some(object_store.path().to_path_buf()));
        db.set_wal_archive_retain_last(Some(0));
        assert_eq!(
            db.wal_object_store_dir(),
            Some(object_store.path().to_path_buf())
        );
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "object-wal".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();

        let compact = db.compact_collection("docs").unwrap();
        assert_eq!(compact.wal_archived_segments, 1);
        assert!(compact.wal_archived_bytes > 0);
        assert_eq!(compact.wal_object_archived_segments, 1);
        assert_eq!(
            compact.wal_object_archived_bytes,
            compact.wal_archived_bytes
        );
        assert_eq!(compact.wal_auto_pruned_archives, 1);

        let archive_root = temp.path().join("collections/docs/wal/archive");
        assert_eq!(std::fs::read_dir(&archive_root).unwrap().count(), 0);
        let object_wal_root = object_store.path().join("collections/docs/wal");
        let archives = std::fs::read_dir(&object_wal_root)
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(archives.len(), 1);
        let wal_segments = std::fs::read_dir(archives[0].path())
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(wal_segments.len(), 2);
        let names = wal_segments
            .iter()
            .map(|entry| entry.file_name())
            .collect::<HashSet<_>>();
        assert!(names.contains(std::ffi::OsStr::new("000000.gdwal")));
        assert!(names.contains(std::ffi::OsStr::new("wal.manifest.json")));
        assert_eq!(
            wal_segments
                .iter()
                .map(|entry| std::fs::metadata(entry.path()).unwrap().len())
                .sum::<u64>(),
            compact.wal_archived_bytes
        );
    }

    #[test]
    fn restore_imports_external_wal_archives() {
        let temp = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();
        let snapshot = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.set_wal_external_archive_dir(Some(external.path().to_path_buf()));
        db.set_wal_archive_retain_last(Some(0));
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "archived".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            }],
        )
        .unwrap();
        let compact = db.compact_collection("docs").unwrap();
        assert_eq!(compact.wal_archived_segments, 1);
        assert_eq!(compact.wal_external_archived_segments, 1);
        assert_eq!(compact.wal_auto_pruned_archives, 1);
        assert_eq!(
            std::fs::read_dir(temp.path().join("collections/docs/wal/archive"))
                .unwrap()
                .count(),
            0
        );
        db.snapshot(snapshot.path()).unwrap();

        db.restore_to_wal_targets_with_archive_dir(
            snapshot.path(),
            &HashMap::new(),
            &HashMap::new(),
            Some(external.path()),
        )
        .unwrap();

        let archive_root = temp.path().join("collections/docs/wal/archive");
        let archives = std::fs::read_dir(&archive_root)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(archives.len(), 1);
        let records = Wal::load(&archives[0].path()).unwrap();
        assert_eq!(records.len(), 2);
        assert!(matches!(
            &records[0].entry,
            WalEntry::UpsertBatch { points }
                if points.len() == 1 && points[0].id == "archived"
        ));
        assert!(matches!(records[1].entry, WalEntry::Compact { .. }));
    }

    #[test]
    fn restore_replays_imported_external_wal_archives() {
        let temp = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();
        let snapshot = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.set_wal_external_archive_dir(Some(external.path().to_path_buf()));
        db.set_wal_archive_retain_last(Some(0));
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.snapshot(snapshot.path()).unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "replayed".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();
        let compact = db.compact_collection("docs").unwrap();
        assert_eq!(compact.wal_external_archived_segments, 1);
        assert_eq!(compact.wal_auto_pruned_archives, 1);

        db.restore_to_wal_targets_with_archive_dir(
            snapshot.path(),
            &HashMap::new(),
            &HashMap::new(),
            Some(external.path()),
        )
        .unwrap();

        let response = db
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: None,
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                    k: 1,
                    filter: Some(Filter(json!({"tenant": "acme"}))),
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();
        assert_eq!(response.hits.len(), 1);
        assert_eq!(response.hits[0].id, "replayed");

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("docs", None).unwrap().count, 1);
        assert_eq!(
            crate::snapshot::read_snapshot_marker(temp.path())
                .unwrap()
                .unwrap()
                .collections[0]
                .points,
            1
        );
    }

    #[test]
    fn restore_replays_imported_external_schema_wal_archives() {
        let temp = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();
        let snapshot = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.set_wal_external_archive_dir(Some(external.path().to_path_buf()));
        db.set_wal_archive_retain_last(Some(0));
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.snapshot(snapshot.path()).unwrap();
        db.update_payload_schema("docs", [("tenant".to_string(), PayloadType::String)].into())
            .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "schema-replayed".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();
        let compact = db.compact_collection("docs").unwrap();
        assert_eq!(compact.wal_external_archived_segments, 1);
        assert_eq!(compact.wal_auto_pruned_archives, 1);

        db.restore_to_wal_targets_with_archive_dir(
            snapshot.path(),
            &HashMap::new(),
            &HashMap::new(),
            Some(external.path()),
        )
        .unwrap();

        let config = db.list_collections().remove(0);
        assert_eq!(config.payload_schema["tenant"], PayloadType::String);
        assert_eq!(db.count("docs", None).unwrap().count, 1);
        assert!(
            db.upsert(
                "docs",
                vec![Point {
                    id: "missing-schema-field".to_string(),
                    vector: vec![0.0, 1.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({}),
                }],
            )
            .unwrap_err()
            .to_string()
            .contains("payload field 'tenant' is required by schema")
        );

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        let config = reopened.list_collections().remove(0);
        assert_eq!(config.payload_schema["tenant"], PayloadType::String);
        assert_eq!(reopened.count("docs", None).unwrap().count, 1);
        assert_eq!(
            crate::snapshot::read_snapshot_marker(temp.path())
                .unwrap()
                .unwrap()
                .collections[0]
                .schema_epoch,
            2
        );
    }

    #[test]
    fn restore_imports_object_store_wal_archives() {
        let temp = TempDir::new().unwrap();
        let object_store = TempDir::new().unwrap();
        let snapshot = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.set_wal_object_store_dir(Some(object_store.path().to_path_buf()));
        db.set_wal_archive_retain_last(Some(0));
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "object-archived".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            }],
        )
        .unwrap();
        let compact = db.compact_collection("docs").unwrap();
        assert_eq!(compact.wal_archived_segments, 1);
        assert_eq!(compact.wal_object_archived_segments, 1);
        assert_eq!(compact.wal_auto_pruned_archives, 1);
        assert_eq!(
            std::fs::read_dir(temp.path().join("collections/docs/wal/archive"))
                .unwrap()
                .count(),
            0
        );
        db.snapshot(snapshot.path()).unwrap();

        db.restore_to_wal_targets_with_archive_sources(
            snapshot.path(),
            &HashMap::new(),
            &HashMap::new(),
            None,
            Some(&ColdObjectStoreConfig::LocalDir(
                object_store.path().to_path_buf(),
            )),
        )
        .unwrap();

        let archive_root = temp.path().join("collections/docs/wal/archive");
        let archives = std::fs::read_dir(&archive_root)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(archives.len(), 1);
        let records = Wal::load(&archives[0].path()).unwrap();
        assert_eq!(records.len(), 2);
        assert!(matches!(
            &records[0].entry,
            WalEntry::UpsertBatch { points }
                if points.len() == 1 && points[0].id == "object-archived"
        ));
        assert!(matches!(records[1].entry, WalEntry::Compact { .. }));
    }

    #[test]
    fn restore_replays_imported_object_store_wal_archives() {
        let temp = TempDir::new().unwrap();
        let object_store = TempDir::new().unwrap();
        let snapshot = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.set_wal_object_store_dir(Some(object_store.path().to_path_buf()));
        db.set_wal_archive_retain_last(Some(0));
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.snapshot(snapshot.path()).unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "object-replayed".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            }],
        )
        .unwrap();
        let compact = db.compact_collection("docs").unwrap();
        assert_eq!(compact.wal_object_archived_segments, 1);
        assert_eq!(compact.wal_auto_pruned_archives, 1);

        db.restore_to_wal_targets_with_archive_sources(
            snapshot.path(),
            &HashMap::new(),
            &HashMap::new(),
            None,
            Some(&ColdObjectStoreConfig::LocalDir(
                object_store.path().to_path_buf(),
            )),
        )
        .unwrap();

        let response = db
            .search(
                "docs",
                SearchRequest {
                    graph: None,
                    vector: vec![1.0, 0.0],
                    vector_name: None,
                    k: 1,
                    filter: None,
                    budget_ms: None,
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .unwrap();
        assert_eq!(response.hits.len(), 1);
        assert_eq!(response.hits[0].id, "object-replayed");

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("docs", None).unwrap().count, 1);
    }

    #[test]
    fn restore_replays_imported_object_store_schema_wal_archives() {
        let temp = TempDir::new().unwrap();
        let object_store = TempDir::new().unwrap();
        let snapshot = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.set_wal_object_store_dir(Some(object_store.path().to_path_buf()));
        db.set_wal_archive_retain_last(Some(0));
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.snapshot(snapshot.path()).unwrap();
        db.update_payload_schema("docs", [("tenant".to_string(), PayloadType::String)].into())
            .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "object-schema-replayed".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();
        let compact = db.compact_collection("docs").unwrap();
        assert_eq!(compact.wal_object_archived_segments, 1);
        assert_eq!(compact.wal_auto_pruned_archives, 1);

        db.restore_to_wal_targets_with_archive_sources(
            snapshot.path(),
            &HashMap::new(),
            &HashMap::new(),
            None,
            Some(&ColdObjectStoreConfig::LocalDir(
                object_store.path().to_path_buf(),
            )),
        )
        .unwrap();

        let config = db.list_collections().remove(0);
        assert_eq!(config.payload_schema["tenant"], PayloadType::String);
        assert_eq!(db.count("docs", None).unwrap().count, 1);

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        let config = reopened.list_collections().remove(0);
        assert_eq!(config.payload_schema["tenant"], PayloadType::String);
        assert_eq!(reopened.count("docs", None).unwrap().count, 1);
    }

    #[test]
    fn compact_runs_wal_archive_command_before_local_retention_prunes() {
        let temp = TempDir::new().unwrap();
        let command_dest = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.set_wal_archive_retain_last(Some(0));
        db.set_wal_archive_command(Some(format!(
            "mkdir -p {0} && cp -R \"$GAUSSDB_WAL_ARCHIVE_PATH\" \"{0}/$GAUSSDB_WAL_ARCHIVE_NAME\" && printf '%s %s' \"$GAUSSDB_WAL_ARCHIVE_COLLECTION\" \"$GAUSSDB_WAL_ARCHIVE_BYTES\" > \"{0}/marker\"",
            command_dest.path().display()
        )));
        assert!(db.wal_archive_command().is_some());
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();

        db.upsert(
            "docs",
            vec![Point {
                id: "archived".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();

        let compact = db.compact_collection("docs").unwrap();
        assert!(compact.wal_archive_command_executed);
        assert_eq!(compact.wal_auto_pruned_archives, 1);
        let archive_root = temp.path().join("collections/docs/wal/archive");
        assert_eq!(std::fs::read_dir(&archive_root).unwrap().count(), 0);
        let archives = std::fs::read_dir(command_dest.path())
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.unwrap();
                entry.file_type().unwrap().is_dir().then_some(entry)
            })
            .collect::<Vec<_>>();
        assert_eq!(archives.len(), 1);
        assert_eq!(Wal::load(&archives[0].path()).unwrap().len(), 2);
        let marker = std::fs::read_to_string(command_dest.path().join("marker")).unwrap();
        assert!(marker.starts_with("docs "));
    }

    #[test]
    fn failing_wal_archive_command_keeps_local_archive_generation() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.set_wal_archive_retain_last(Some(0));
        db.set_wal_archive_command(Some("echo archive failed >&2; exit 7".to_string()));
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();

        db.upsert(
            "docs",
            vec![Point {
                id: "not_pruned".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();

        let error = db.compact_collection("docs").unwrap_err();
        assert!(error.to_string().contains("status 7"));
        let archive_root = temp.path().join("collections/docs/wal/archive");
        assert_eq!(std::fs::read_dir(&archive_root).unwrap().count(), 1);
    }

    #[test]
    fn compact_prunes_wal_archives_over_max_bytes() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.set_wal_archive_max_bytes(Some(1));
        assert_eq!(db.wal_archive_max_bytes(), Some(1));
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();

        db.upsert(
            "docs",
            vec![Point {
                id: "kept".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();

        let compact = db.compact_collection("docs").unwrap();
        assert_eq!(compact.wal_auto_retained_archives, 0);
        assert_eq!(compact.wal_auto_pruned_archives, 1);
        assert!(compact.wal_auto_pruned_bytes > 1);
        let archive_root = temp.path().join("collections/docs/wal/archive");
        assert_eq!(std::fs::read_dir(&archive_root).unwrap().count(), 0);

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        let response = reopened
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: None,
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                    k: 1,
                    filter: Some(Filter(json!({"tenant": "acme"}))),
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();
        assert_eq!(response.hits[0].id, "kept");
        assert_eq!(response.searched, 1);
    }

    #[test]
    fn compact_prunes_wal_archives_over_max_age() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.set_wal_archive_max_age(Some(Duration::ZERO));
        assert_eq!(db.wal_archive_max_age(), Some(Duration::ZERO));
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();

        db.upsert(
            "docs",
            vec![Point {
                id: "kept".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();

        let compact = db.compact_collection("docs").unwrap();
        assert_eq!(compact.wal_auto_retained_archives, 0);
        assert_eq!(compact.wal_auto_pruned_archives, 1);
        assert!(compact.wal_auto_pruned_bytes > 0);
        let archive_root = temp.path().join("collections/docs/wal/archive");
        assert_eq!(std::fs::read_dir(&archive_root).unwrap().count(), 0);

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        let response = reopened
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: None,
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                    k: 1,
                    filter: Some(Filter(json!({"tenant": "acme"}))),
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();
        assert_eq!(response.hits[0].id, "kept");
        assert_eq!(response.searched, 1);
    }

    #[test]
    fn corrupt_checkpoint_rejects_open() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        drop(db);

        std::fs::write(temp.path().join("collections/docs/checkpoint.gdx"), b"bad").unwrap();
        let error = Db::open(temp.path()).unwrap_err();
        assert!(error.to_string().contains("checkpoint shorter than header"));
    }

    #[test]
    fn restore_replaces_contents_without_recreating_root() {
        let temp = TempDir::new().unwrap();
        let snapshot = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![
                Point {
                    id: "keep".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({}),
                },
                Point {
                    id: "restore-me".to_string(),
                    vector: vec![0.0, 1.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({}),
                },
            ],
        )
        .unwrap();
        db.snapshot(snapshot.path()).unwrap();
        let marker = snapshot::read_snapshot_marker(snapshot.path())
            .unwrap()
            .unwrap();
        assert_eq!(marker.collections.len(), 1);
        assert_eq!(marker.collections[0].collection, "docs");
        assert!(marker.collections[0].wal_lsn > 0);

        db.delete("docs", &["restore-me".to_string()]).unwrap();
        assert_eq!(db.count("docs", None).unwrap().count, 1);

        db.restore(snapshot.path()).unwrap();
        assert_eq!(db.count("docs", None).unwrap().count, 2);
        assert!(temp.path().exists());
    }

    #[test]
    fn restore_can_target_collection_wal_lsn() {
        let temp = TempDir::new().unwrap();
        let snapshot = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();

        db.upsert(
            "docs",
            vec![Point {
                id: "kept".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();
        let first_lsn = std::fs::metadata(temp.path().join("collections/docs/wal/000000.gdwal"))
            .unwrap()
            .len();
        db.upsert(
            "docs",
            vec![Point {
                id: "excluded".to_string(),
                vector: vec![0.0, 1.0],
                vectors: HashMap::new(),
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();
        db.snapshot(snapshot.path()).unwrap();

        let mut targets = HashMap::new();
        targets.insert("docs".to_string(), first_lsn);
        db.restore_to_wal_lsns(snapshot.path(), &targets).unwrap();

        let marker = snapshot::read_snapshot_marker(temp.path())
            .unwrap()
            .unwrap();
        assert_eq!(marker.collections[0].wal_lsn, first_lsn);
        assert_eq!(marker.collections[0].points, 1);
        let response = db
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: None,
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                    k: 10,
                    filter: Some(Filter(json!({"tenant": "acme"}))),
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();
        assert_eq!(response.hits.len(), 1);
        assert_eq!(response.hits[0].id, "kept");

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        let response = reopened
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: None,
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                    k: 10,
                    filter: Some(Filter(json!({"tenant": "acme"}))),
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();
        assert_eq!(response.hits.len(), 1);
        assert_eq!(response.hits[0].id, "kept");
    }

    #[test]
    fn restore_can_target_lsn_before_schema_change() {
        let temp = TempDir::new().unwrap();
        let snapshot = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "kept".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();
        let pre_schema_lsn =
            std::fs::metadata(temp.path().join("collections/docs/wal/000000.gdwal"))
                .unwrap()
                .len();
        db.update_payload_schema("docs", [("tenant".to_string(), PayloadType::String)].into())
            .unwrap();
        db.snapshot(snapshot.path()).unwrap();

        let mut targets = HashMap::new();
        targets.insert("docs".to_string(), pre_schema_lsn);
        db.restore_to_wal_lsns(snapshot.path(), &targets).unwrap();

        let config = db.list_collections().remove(0);
        assert!(config.payload_schema.is_empty());
        let marker = snapshot::read_snapshot_marker(temp.path())
            .unwrap()
            .unwrap();
        assert_eq!(marker.collections[0].schema_epoch, 1);
        assert_eq!(marker.collections[0].wal_lsn, pre_schema_lsn);
        assert_eq!(marker.collections[0].points, 1);
        let checkpoint = checkpoint::read_checkpoint(&temp.path().join("collections/docs"))
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.schema_epoch, 1);
        assert_eq!(checkpoint.last_applied_lsn, pre_schema_lsn);
        db.upsert(
            "docs",
            vec![Point {
                id: "missing-schema-field".to_string(),
                vector: vec![0.0, 1.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            }],
        )
        .unwrap();

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        let config = reopened.list_collections().remove(0);
        assert!(config.payload_schema.is_empty());
        assert_eq!(reopened.count("docs", None).unwrap().count, 2);
    }

    #[test]
    fn restore_can_target_collection_wal_unix_ms() {
        let temp = TempDir::new().unwrap();
        let snapshot = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();

        db.upsert(
            "docs",
            vec![Point {
                id: "kept".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();
        let first_lsn = std::fs::metadata(temp.path().join("collections/docs/wal/000000.gdwal"))
            .unwrap()
            .len();
        let first_unix_ms = Wal::load(&temp.path().join("collections/docs/wal"))
            .unwrap()
            .first()
            .unwrap()
            .unix_ms;
        std::thread::sleep(Duration::from_millis(3));
        db.upsert(
            "docs",
            vec![Point {
                id: "excluded".to_string(),
                vector: vec![0.0, 1.0],
                vectors: HashMap::new(),
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();
        db.snapshot(snapshot.path()).unwrap();

        let mut target_wal_unix_ms = HashMap::new();
        target_wal_unix_ms.insert("docs".to_string(), first_unix_ms);
        db.restore_to_wal_targets(snapshot.path(), &HashMap::new(), &target_wal_unix_ms)
            .unwrap();

        let marker = snapshot::read_snapshot_marker(temp.path())
            .unwrap()
            .unwrap();
        assert_eq!(marker.collections[0].wal_lsn, first_lsn);
        assert_eq!(marker.collections[0].points, 1);
        let response = db
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: None,
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                    k: 10,
                    filter: Some(Filter(json!({"tenant": "acme"}))),
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();
        assert_eq!(response.hits.len(), 1);
        assert_eq!(response.hits[0].id, "kept");
    }

    #[test]
    fn restore_can_target_unix_ms_before_schema_change() {
        let temp = TempDir::new().unwrap();
        let snapshot = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "kept".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();
        let pre_schema_lsn =
            std::fs::metadata(temp.path().join("collections/docs/wal/000000.gdwal"))
                .unwrap()
                .len();
        let pre_schema_unix_ms = Wal::load(&temp.path().join("collections/docs/wal"))
            .unwrap()
            .first()
            .unwrap()
            .unix_ms;
        std::thread::sleep(Duration::from_millis(3));
        db.update_payload_schema("docs", [("tenant".to_string(), PayloadType::String)].into())
            .unwrap();
        db.snapshot(snapshot.path()).unwrap();

        let mut target_wal_unix_ms = HashMap::new();
        target_wal_unix_ms.insert("docs".to_string(), pre_schema_unix_ms);
        db.restore_to_wal_targets(snapshot.path(), &HashMap::new(), &target_wal_unix_ms)
            .unwrap();

        let config = db.list_collections().remove(0);
        assert!(config.payload_schema.is_empty());
        let marker = snapshot::read_snapshot_marker(temp.path())
            .unwrap()
            .unwrap();
        assert_eq!(marker.collections[0].schema_epoch, 1);
        assert_eq!(marker.collections[0].wal_lsn, pre_schema_lsn);

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        let config = reopened.list_collections().remove(0);
        assert!(config.payload_schema.is_empty());
        assert_eq!(reopened.count("docs", None).unwrap().count, 1);
    }

    #[test]
    fn restore_rejects_corrupt_snapshot_marker() {
        let temp = TempDir::new().unwrap();
        let snapshot = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.snapshot(snapshot.path()).unwrap();
        std::fs::write(snapshot::snapshot_marker_path(snapshot.path()), b"bad").unwrap();

        let error = db.restore(snapshot.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("snapshot marker shorter than header")
        );
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_hard_links_immutable_searcher_files_and_copies_active_wal() {
        let temp = TempDir::new().unwrap();
        let snapshot = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "sealed".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            }],
        )
        .unwrap();
        let compact = db.compact_collection("docs").unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "wal-suffix".to_string(),
                vector: vec![0.0, 1.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            }],
        )
        .unwrap();

        db.snapshot(snapshot.path()).unwrap();
        let live_vec = temp
            .path()
            .join("collections/docs/searchers")
            .join(&compact.segment_id)
            .join("vec.gdx");
        let snapshot_vec = snapshot
            .path()
            .join("collections/docs/searchers")
            .join(&compact.segment_id)
            .join("vec.gdx");
        assert!(
            live_vec.exists(),
            "live vec missing at {}",
            live_vec.display()
        );
        assert!(
            snapshot_vec.exists(),
            "snapshot vec missing at {}",
            snapshot_vec.display()
        );
        assert_eq!(
            std::fs::metadata(live_vec).unwrap().ino(),
            std::fs::metadata(snapshot_vec).unwrap().ino()
        );

        let find_active_wal = |root: &Path| {
            std::fs::read_dir(root.join("collections/docs/wal"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "gdwal")
                })
                .unwrap()
        };
        let live_wal = find_active_wal(temp.path());
        let snapshot_wal = find_active_wal(snapshot.path());
        let snapshot_wal_metadata = std::fs::metadata(&snapshot_wal).unwrap();
        assert_ne!(
            std::fs::metadata(&live_wal).unwrap().ino(),
            snapshot_wal_metadata.ino()
        );
        let snapshot_wal_len = snapshot_wal_metadata.len();
        db.upsert(
            "docs",
            vec![Point {
                id: "after-snapshot".to_string(),
                vector: vec![0.5, 0.5],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            }],
        )
        .unwrap();
        assert!(std::fs::metadata(live_wal).unwrap().len() > snapshot_wal_len);
        assert_eq!(
            std::fs::metadata(snapshot_wal).unwrap().len(),
            snapshot_wal_len
        );
    }

    #[test]
    fn audit_log_records_mutating_operations_without_payloads() {
        let temp = TempDir::new().unwrap();
        let snapshot = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "secret-id".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"token": "super-secret"}),
            }],
        )
        .unwrap();
        db.delete("docs", &["secret-id".to_string()]).unwrap();
        db.compact_collection("docs").unwrap();
        db.snapshot(snapshot.path()).unwrap();
        db.audit_admin_event(
            "shard_move",
            json!({"mode": "single_node_noop", "transport": "embedded"}),
        )
        .unwrap();
        db.restore(snapshot.path()).unwrap();

        let audit_log = std::fs::read_to_string(audit::audit_log_path(temp.path())).unwrap();
        let records = audit_log
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        let operations = records
            .iter()
            .map(|record| record["operation"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(operations.contains(&"create_collection"));
        assert!(operations.contains(&"upsert"));
        assert!(operations.contains(&"delete"));
        assert!(operations.contains(&"compact"));
        assert!(operations.contains(&"snapshot"));
        assert!(operations.contains(&"shard_move"));
        assert!(operations.contains(&"restore"));
        assert!(
            records
                .iter()
                .all(|record| matches!(record["outcome"].as_str(), Some("intent" | "success")))
        );
        assert!(
            records
                .iter()
                .all(|record| record["principal_id"].as_str() == Some("embedded-system"))
        );
        assert!(
            records
                .iter()
                .all(|record| record["timestamp_unix_ms"].as_u64().is_some())
        );
        assert!(
            records
                .iter()
                .all(|record| record["prev_record_hash"].as_str().is_some())
        );
        assert!(
            records
                .iter()
                .all(|record| record["record_hash"].as_str().is_some())
        );
        audit::verify_hash_chain(temp.path()).unwrap();
        assert!(!audit_log.contains("super-secret"));
        assert!(!audit_log.contains("secret-id"));
    }

    #[test]
    fn audit_hash_chain_rejects_tampered_records() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        audit::verify_hash_chain(temp.path()).unwrap();

        let path = audit::audit_log_path(temp.path());
        let mut audit_log = std::fs::read_to_string(&path).unwrap();
        audit_log = audit_log.replace(
            "\"operation\":\"create_collection\"",
            "\"operation\":\"delete\"",
        );
        std::fs::write(path, audit_log).unwrap();
        assert!(audit::verify_hash_chain(temp.path()).is_err());
    }

    #[test]
    fn snapshot_and_restore_reject_paths_inside_live_data_dir() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        assert!(db.snapshot(temp.path().join("snapshot")).is_err());
        assert!(db.restore(temp.path().join("snapshot")).is_err());
    }

    #[test]
    fn search_budget_can_return_degraded_partial_result() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            (0..100)
                .map(|index| Point {
                    id: format!("doc-{index:03}"),
                    vector: vec![index as f32, 1.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({}),
                })
                .collect(),
        )
        .unwrap();

        let response = db
            .search(
                "docs",
                SearchRequest {
                    graph: None,
                    vector: vec![1.0, 0.0],
                    vector_name: None,
                    k: 10,
                    filter: None,
                    budget_ms: Some(0),
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .unwrap();

        assert!(response.degraded);
        assert!(response.searched < 100);
    }

    #[test]
    fn cancelled_search_returns_degraded_without_starting_work() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert(
            "docs",
            (0..100)
                .map(|index| ls_vec_point(&format!("doc-{index:03}"), index as f32, "current"))
                .collect(),
        )
        .unwrap();
        let cancelled = AtomicBool::new(true);
        crate::index::search_metrics::reset();

        let response = db
            .search_with_cancellation("docs", ls_vec_search(1.0, 10), &cancelled)
            .unwrap();

        assert!(cancelled.load(Ordering::Acquire));
        assert!(response.degraded);
        assert!(response.hits.is_empty());
        assert_eq!(response.searched, 0);
        if cfg!(feature = "search-metrics") {
            let metrics = crate::index::search_metrics::snapshot();
            assert_eq!(metrics.cancelled_count, 1);
            assert_eq!(metrics.degraded_count, 1);
            assert_eq!(metrics.underfilled_count, 1);
        }
    }

    #[test]
    fn multi_search_returns_one_response_per_query() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        seed_recommendation_docs(&db);

        let response = db
            .multi_search(
                "docs",
                MultiSearchRequest {
                    searches: vec![
                        SearchRequest {
                            graph: None,
                            vector: vec![1.0, 0.0],
                            vector_name: None,
                            k: 1,
                            filter: None,
                            budget_ms: None,
                            consistency: None,
                            ef_search: None,
                            recall_target: None,
                            with_payload: None,
                        },
                        SearchRequest {
                            graph: None,
                            vector: vec![0.0, 1.0],
                            vector_name: None,
                            k: 1,
                            filter: None,
                            budget_ms: None,
                            consistency: None,
                            ef_search: None,
                            recall_target: None,
                            with_payload: None,
                        },
                    ],
                    fusion: None,
                    fused_k: None,
                    weights: Vec::new(),
                },
            )
            .unwrap();

        assert_eq!(response.results.len(), 2);
        assert_eq!(response.results[0].hits[0].id, "anchor");
        assert_eq!(response.results[1].hits[0].id, "negative");
        assert!(response.fused.is_none());
    }

    #[test]
    fn multi_search_can_fuse_query_results() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        seed_recommendation_docs(&db);

        let response = db
            .multi_search(
                "docs",
                MultiSearchRequest {
                    searches: vec![
                        SearchRequest {
                            graph: None,
                            vector: vec![1.0, 0.0],
                            vector_name: None,
                            k: 2,
                            filter: None,
                            budget_ms: None,
                            consistency: None,
                            ef_search: None,
                            recall_target: None,
                            with_payload: None,
                        },
                        SearchRequest {
                            graph: None,
                            vector: vec![0.8, 0.2],
                            vector_name: None,
                            k: 2,
                            filter: None,
                            budget_ms: None,
                            consistency: None,
                            ef_search: None,
                            recall_target: None,
                            with_payload: None,
                        },
                    ],
                    fusion: Some(crate::HybridFusion::Rrf),
                    fused_k: Some(2),
                    weights: Vec::new(),
                },
            )
            .unwrap();

        let fused = response.fused.unwrap();
        assert_eq!(fused.hits.len(), 2);
        assert_eq!(fused.hits[0].id, "anchor");
        assert_eq!(fused.hits[1].id, "similar");
        assert!(!fused.degraded);
    }

    #[test]
    fn hybrid_search_fuses_dense_and_sparse_rankings() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![
                Point {
                    id: "dense".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: Some(SparseVector {
                        indices: vec![1],
                        values: vec![1.0],
                    }),
                    payload: json!({"kind": "semantic"}),
                },
                Point {
                    id: "hybrid".to_string(),
                    vector: vec![0.9, 0.1],
                    vectors: HashMap::new(),
                    sparse_vector: Some(SparseVector {
                        indices: vec![9],
                        values: vec![1.0],
                    }),
                    payload: json!({"kind": "keyword"}),
                },
                Point {
                    id: "other".to_string(),
                    vector: vec![0.0, 1.0],
                    vectors: HashMap::new(),
                    sparse_vector: Some(SparseVector {
                        indices: vec![2],
                        values: vec![1.0],
                    }),
                    payload: json!({"kind": "other"}),
                },
            ],
        )
        .unwrap();

        let response = db
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: Some(vec![1.0, 0.0]),
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![9],
                        values: vec![1.0],
                    }),
                    k: 1,
                    filter: None,
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();

        assert_eq!(response.hits[0].id, "hybrid");
        assert!(!response.degraded);
    }

    #[test]
    fn sparse_index_limits_candidates_and_tracks_mutations() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![
                Point {
                    id: "needle".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: Some(SparseVector {
                        indices: vec![42],
                        values: vec![2.0],
                    }),
                    payload: json!({}),
                },
                Point {
                    id: "hay".to_string(),
                    vector: vec![0.0, 1.0],
                    vectors: HashMap::new(),
                    sparse_vector: Some(SparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                    payload: json!({}),
                },
            ],
        )
        .unwrap();

        let response = db
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: None,
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![42],
                        values: vec![1.0],
                    }),
                    k: 10,
                    filter: None,
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();
        assert_eq!(response.hits[0].id, "needle");
        assert_eq!(response.searched, 1);

        db.upsert(
            "docs",
            vec![Point {
                id: "needle".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: Some(SparseVector {
                    indices: vec![9],
                    values: vec![1.0],
                }),
                payload: json!({}),
            }],
        )
        .unwrap();
        let old_dimension = db
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: None,
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![42],
                        values: vec![1.0],
                    }),
                    k: 10,
                    filter: None,
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();
        assert!(old_dimension.hits.is_empty());

        db.delete("docs", &["needle".to_string()]).unwrap();
        let deleted = db
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: None,
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![9],
                        values: vec![1.0],
                    }),
                    k: 10,
                    filter: None,
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();
        assert!(deleted.hits.is_empty());
    }

    #[test]
    fn sparse_block_max_prunes_low_impact_blocks_without_changing_top_hit() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();

        let mut points = vec![Point {
            id: "needle".to_string(),
            vector: vec![1.0, 0.0],
            vectors: HashMap::new(),
            sparse_vector: Some(SparseVector {
                indices: vec![42],
                values: vec![10.0],
            }),
            payload: json!({}),
        }];
        points.extend((0..15).map(|index| Point {
            id: format!("medium-{index:02}"),
            vector: vec![0.0, 1.0],
            vectors: HashMap::new(),
            sparse_vector: Some(SparseVector {
                indices: vec![42],
                values: vec![0.2],
            }),
            payload: json!({}),
        }));
        points.extend((0..64).map(|index| Point {
            id: format!("low-{index:02}"),
            vector: vec![0.0, 1.0],
            vectors: HashMap::new(),
            sparse_vector: Some(SparseVector {
                indices: vec![42],
                values: vec![0.05],
            }),
            payload: json!({}),
        }));
        db.upsert("docs", points).unwrap();

        let response = db
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: None,
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![42],
                        values: vec![1.0],
                    }),
                    k: 1,
                    filter: None,
                    budget_ms: None,
                    fusion: crate::HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .unwrap();

        assert_eq!(response.hits[0].id, "needle");
        assert_eq!(response.searched, 16);
        assert!(!response.degraded);
    }

    #[test]
    fn payload_index_limits_filtered_search_and_tracks_mutations() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();

        let mut points = (0..20)
            .map(|index| Point {
                id: format!("hay-{index:02}"),
                vector: vec![0.0, 1.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"tenant": "other", "tier": "bronze"}),
            })
            .collect::<Vec<_>>();
        points.push(Point {
            id: "needle".to_string(),
            vector: vec![1.0, 0.0],
            vectors: HashMap::new(),
            sparse_vector: None,
            payload: json!({"tenant": "acme", "tier": "gold"}),
        });
        db.upsert("docs", points).unwrap();

        let filter = Filter(json!({"tenant": "acme"}));
        let response = db
            .search(
                "docs",
                SearchRequest {
                    graph: None,
                    vector: vec![1.0, 0.0],
                    vector_name: None,
                    k: 5,
                    filter: Some(filter.clone()),
                    budget_ms: None,
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .unwrap();
        assert_eq!(response.hits[0].id, "needle");
        assert_eq!(response.searched, 1);
        assert_eq!(db.count("docs", Some(filter)).unwrap().count, 1);
        assert_eq!(
            db.scroll(
                "docs",
                None,
                10,
                Some(Filter(json!({"tier": {"in": ["gold", "silver"]}})))
            )
            .unwrap()
            .points[0]
                .id,
            "needle"
        );

        db.upsert(
            "docs",
            vec![Point {
                id: "needle".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"tenant": "other", "tier": "gold"}),
            }],
        )
        .unwrap();
        let moved = db
            .search(
                "docs",
                SearchRequest {
                    graph: None,
                    vector: vec![1.0, 0.0],
                    vector_name: None,
                    k: 5,
                    filter: Some(Filter(json!({"tenant": "acme"}))),
                    budget_ms: None,
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .unwrap();
        assert!(moved.hits.is_empty());
        assert_eq!(moved.searched, 0);

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(
            reopened
                .count("docs", Some(Filter(json!({"tier": "gold"}))))
                .unwrap()
                .count,
            1
        );
        reopened.delete("docs", &["needle".to_string()]).unwrap();
        assert_eq!(
            reopened
                .count("docs", Some(Filter(json!({"tier": "gold"}))))
                .unwrap()
                .count,
            0
        );
    }

    #[test]
    fn sealed_payload_candidates_remain_ordinal_native_across_mutation() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![
                Point {
                    id: "sealed-acme".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"tenant": "acme"}),
                },
                Point {
                    id: "sealed-other".to_string(),
                    vector: vec![0.0, 1.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"tenant": "other"}),
                },
            ],
        )
        .unwrap();
        db.compact_collection("docs").unwrap();

        let filter = Filter(json!({"tenant": "acme"}));
        {
            let inner = db.inner.read();
            let collection = inner.collections["docs"].read();
            let visibility = collection.overlay_read_state();
            let candidates = collection
                .payload_candidates(&visibility, Some(&filter))
                .unwrap();
            assert!(candidates.fallback.is_empty());
            assert_eq!(candidates.sealed.len(), 1);
            assert_eq!(
                collection
                    .iter_payload_candidates(&visibility, &candidates)
                    .map(|point| point.id.clone())
                    .collect::<Vec<_>>(),
                vec!["sealed-acme".to_string()]
            );
        }

        db.upsert(
            "docs",
            vec![Point {
                id: "sealed-acme".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"tenant": "other"}),
            }],
        )
        .unwrap();
        assert_eq!(db.count("docs", Some(filter)).unwrap().count, 0);
        let inner = db.inner.read();
        let collection = inner.collections["docs"].read();
        let visibility = collection.overlay_read_state();
        let other = collection
            .payload_candidates(&visibility, Some(&Filter(json!({"tenant": "other"}))))
            .unwrap();
        assert_eq!(other.fallback.len(), 1);
        assert_eq!(other.sealed.len(), 1);
    }

    #[test]
    fn payload_index_candidates_support_numeric_range_filters() {
        let points = [
            Point {
                id: "cheap".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"tenant": "acme", "price": 10}),
            },
            Point {
                id: "target".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"tenant": "acme", "price": 125}),
            },
            Point {
                id: "other".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"tenant": "other", "price": 150}),
            },
            Point {
                id: "expensive".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"tenant": "acme", "price": 250}),
            },
        ]
        .into_iter()
        .map(|point| (point.id.clone(), point))
        .collect();
        let index = build_payload_index(&points);

        let candidates = payload_filter_candidates(
            &index,
            Some(&Filter(json!({
                "tenant": "acme",
                "price": {"gte": 100, "lt": 200}
            }))),
        )
        .unwrap();
        assert_eq!(candidates, HashSet::from(["target".to_string()]));
    }

    #[test]
    fn payload_numeric_index_handles_signed_bounds_and_mutations() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![
                Point {
                    id: "low".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"score": -10}),
                },
                Point {
                    id: "mid".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"score": 0}),
                },
                Point {
                    id: "high".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"score": 10}),
                },
            ],
        )
        .unwrap();

        assert_eq!(
            db.count(
                "docs",
                Some(Filter(json!({"score": {"gt": -5, "lte": 10}})))
            )
            .unwrap()
            .count,
            2
        );
        db.upsert(
            "docs",
            vec![Point {
                id: "high".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"score": -20}),
            }],
        )
        .unwrap();
        assert_eq!(
            db.count(
                "docs",
                Some(Filter(json!({"score": {"gt": -5, "lte": 10}})))
            )
            .unwrap()
            .count,
            1
        );

        db.compact_collection("docs").unwrap();
        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(
            reopened
                .count(
                    "docs",
                    Some(Filter(json!({"score": {"gte": -20, "lt": 1}})))
                )
                .unwrap()
                .count,
            3
        );
    }

    #[test]
    fn payload_index_filters_nested_fields_and_reopens_from_payload_artifact() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![
                Point {
                    id: "target".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"profile": {"region": "us", "score": 42}}),
                },
                Point {
                    id: "wrong-region".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"profile": {"region": "eu", "score": 99}}),
                },
                Point {
                    id: "low-score".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"profile": {"region": "us", "score": 3}}),
                },
            ],
        )
        .unwrap();

        let filter = Filter(json!({
            "profile.region": "us",
            "profile.score": {"gte": 40}
        }));
        assert_eq!(db.count("docs", Some(filter.clone())).unwrap().count, 1);
        assert_eq!(
            db.search(
                "docs",
                SearchRequest {
                    graph: None,
                    vector: vec![1.0, 0.0],
                    vector_name: None,
                    k: 3,
                    filter: Some(filter.clone()),
                    budget_ms: None,
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .unwrap()
            .searched,
            1
        );

        db.compact_collection("docs").unwrap();
        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("docs", Some(filter)).unwrap().count, 1);
    }

    #[test]
    fn payload_index_filters_array_values_and_reopens_from_payload_artifact() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![
                Point {
                    id: "target".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({
                        "tags": ["featured", "sale"],
                        "diet": [{"food": "plants"}, {"food": "meat"}]
                    }),
                },
                Point {
                    id: "wrong-tag".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({
                        "tags": ["clearance"],
                        "diet": [{"food": "meat"}]
                    }),
                },
            ],
        )
        .unwrap();

        let filter = Filter(json!({"tags": "featured", "diet[].food": "meat"}));
        assert_eq!(db.count("docs", Some(filter.clone())).unwrap().count, 1);
        db.compact_collection("docs").unwrap();
        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("docs", Some(filter)).unwrap().count, 1);
    }

    #[test]
    fn payload_filters_correlate_conditions_within_same_array_element() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![
                Point {
                    id: "target".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({
                        "diet": [
                            {"food": "leaves", "likes": false},
                            {"food": "meat", "likes": true}
                        ]
                    }),
                },
                Point {
                    id: "cross-element".to_string(),
                    vector: vec![0.9, 0.1],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({
                        "diet": [
                            {"food": "leaves", "likes": true},
                            {"food": "meat", "likes": false}
                        ]
                    }),
                },
                Point {
                    id: "unrelated".to_string(),
                    vector: vec![0.0, 1.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({
                        "diet": [
                            {"food": "leaves", "likes": true}
                        ]
                    }),
                },
            ],
        )
        .unwrap();

        let flattened = Filter(json!({"diet[].food": "meat", "diet[].likes": true}));
        assert_eq!(db.count("docs", Some(flattened)).unwrap().count, 2);

        let nested = Filter(json!({"diet": {"nested": {"food": "meat", "likes": true}}}));
        let nested_candidates = {
            let inner = db.inner.read();
            let arc_coll = inner.collections.get("docs").unwrap();
            let collection = arc_coll.read();
            payload_filter_candidates(&collection.payload_index, Some(&nested)).unwrap()
        };
        assert_eq!(
            nested_candidates,
            HashSet::from(["target".to_string(), "cross-element".to_string()])
        );
        assert_eq!(db.count("docs", Some(nested.clone())).unwrap().count, 1);
        assert_eq!(
            db.search(
                "docs",
                SearchRequest {
                    graph: None,
                    vector: vec![1.0, 0.0],
                    vector_name: None,
                    k: 2,
                    filter: Some(nested.clone()),
                    budget_ms: None,
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .unwrap()
            .hits
            .into_iter()
            .map(|hit| hit.id)
            .collect::<Vec<_>>(),
            vec!["target".to_string()]
        );

        db.compact_collection("docs").unwrap();
        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        assert_eq!(reopened.count("docs", Some(nested)).unwrap().count, 1);
    }

    #[test]
    fn payload_index_loads_from_segment_artifact_and_applies_wal_suffix() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "old".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();
        let compact = db.compact_collection("docs").unwrap();
        assert!(
            temp.path()
                .join("collections/docs/searchers")
                .join(&compact.segment_id)
                .join("payload.gdx")
                .exists()
        );
        db.upsert(
            "docs",
            vec![
                Point {
                    id: "old".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"tenant": "other"}),
                },
                Point {
                    id: "new".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"tenant": "acme"}),
                },
            ],
        )
        .unwrap();
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let response = reopened
            .search(
                "docs",
                SearchRequest {
                    graph: None,
                    vector: vec![1.0, 0.0],
                    vector_name: None,
                    k: 10,
                    filter: Some(Filter(json!({"tenant": "acme"}))),
                    budget_ms: None,
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .unwrap();
        assert_eq!(
            response
                .hits
                .iter()
                .map(|hit| hit.id.as_str())
                .collect::<Vec<_>>(),
            vec!["new"]
        );
        assert_eq!(response.searched, 1);
    }

    #[test]
    fn payload_schema_rejects_missing_or_wrong_typed_fields() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
            name: "docs".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::Cosine,
            shards: 1,
            replicas: 1,
            quantization: None,
            payload_schema: [
                ("tenant".to_string(), PayloadType::String),
                ("price".to_string(), PayloadType::Number),
                ("active".to_string(), PayloadType::Bool),
            ]
            .into_iter()
            .collect(),
            named_vector_dims: Default::default(),
            hnsw_m: None,
            hnsw_ef_construction: None,
            hnsw_ef_search: None,
            recall_sla: None,
            index_kind: None,
            streamer_max_bytes: 0,
        })
        .unwrap();

        db.upsert(
            "docs",
            vec![Point {
                id: "valid".to_string(),
                vector: vec![1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"tenant": "acme", "price": 42, "active": true}),
            }],
        )
        .unwrap();

        let wrong_type = db.upsert(
            "docs",
            vec![Point {
                id: "wrong".to_string(),
                vector: vec![1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"tenant": "acme", "price": "42", "active": true}),
            }],
        );
        assert!(matches!(wrong_type, Err(GaussError::InvalidRequest(_))));

        let missing = db.upsert(
            "docs",
            vec![Point {
                id: "missing".to_string(),
                vector: vec![1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"tenant": "acme", "price": 42}),
            }],
        );
        assert!(matches!(missing, Err(GaussError::InvalidRequest(_))));
    }

    #[test]
    fn payload_schema_supports_optional_and_nullable_fields() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
            name: "docs".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::Cosine,
            shards: 1,
            replicas: 1,
            quantization: None,
            payload_schema: [
                ("tenant".to_string(), PayloadType::String),
                ("nickname".to_string(), PayloadType::OptionalString),
                ("score".to_string(), PayloadType::NullableNumber),
            ]
            .into_iter()
            .collect(),
            named_vector_dims: Default::default(),
            hnsw_m: None,
            hnsw_ef_construction: None,
            hnsw_ef_search: None,
            recall_sla: None,
            index_kind: None,
            streamer_max_bytes: 0,
        })
        .unwrap();

        db.upsert(
            "docs",
            vec![
                Point {
                    id: "missing_optional".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: Default::default(),
                    sparse_vector: None,
                    payload: json!({"tenant": "acme", "score": 42}),
                },
                Point {
                    id: "nullable".to_string(),
                    vector: vec![0.9, 0.1],
                    vectors: Default::default(),
                    sparse_vector: None,
                    payload: json!({"tenant": "acme", "nickname": null, "score": null}),
                },
            ],
        )
        .unwrap();

        let missing_required_nullable = db.upsert(
            "docs",
            vec![Point {
                id: "missing_score".to_string(),
                vector: vec![1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"tenant": "acme"}),
            }],
        );
        assert!(matches!(
            missing_required_nullable,
            Err(GaussError::InvalidRequest(_))
        ));

        let wrong_optional = db.upsert(
            "docs",
            vec![Point {
                id: "wrong_optional".to_string(),
                vector: vec![1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"tenant": "acme", "nickname": 7, "score": 1}),
            }],
        );
        assert!(matches!(wrong_optional, Err(GaussError::InvalidRequest(_))));

        let null_required_string = db.upsert(
            "docs",
            vec![Point {
                id: "null_required".to_string(),
                vector: vec![1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"tenant": null, "score": 1}),
            }],
        );
        assert!(matches!(
            null_required_string,
            Err(GaussError::InvalidRequest(_))
        ));
    }

    #[test]
    fn full_text_payload_filter_matches_count_and_search() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![
                Point {
                    id: "target".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"title": "Rust native vector search"}),
                },
                Point {
                    id: "other".to_string(),
                    vector: vec![0.0, 1.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"title": "Python dataframe analytics"}),
                },
            ],
        )
        .unwrap();
        let filter = Filter(json!({"title": {"text": "vector rust"}}));
        assert_eq!(db.count("docs", Some(filter.clone())).unwrap().count, 1);
        let response = db
            .search(
                "docs",
                SearchRequest {
                    graph: None,
                    vector: vec![1.0, 0.0],
                    vector_name: None,
                    k: 10,
                    filter: Some(filter),
                    budget_ms: None,
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .unwrap();
        assert_eq!(response.hits.len(), 1);
        assert_eq!(response.hits[0].id, "target");
    }

    #[test]
    fn max_points_per_collection_rejects_new_points_over_quota() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.set_max_points_per_collection(Some(1));
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "allowed".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            }],
        )
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "allowed".to_string(),
                vector: vec![0.9, 0.1],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            }],
        )
        .unwrap();
        let rejected = db
            .upsert(
                "docs",
                vec![Point {
                    id: "rejected".to_string(),
                    vector: vec![0.0, 1.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({}),
                }],
            )
            .unwrap_err();
        assert!(rejected.to_string().contains("max_points_per_collection"));
        assert_eq!(db.count("docs", None).unwrap().count, 1);
    }

    #[test]
    fn payload_schema_validates_nested_field_paths() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
            name: "docs".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::Cosine,
            shards: 1,
            replicas: 1,
            quantization: None,
            payload_schema: [
                ("profile.region".to_string(), PayloadType::String),
                ("profile.score".to_string(), PayloadType::Number),
            ]
            .into_iter()
            .collect(),
            named_vector_dims: Default::default(),
            hnsw_m: None,
            hnsw_ef_construction: None,
            hnsw_ef_search: None,
            recall_sla: None,
            index_kind: None,
            streamer_max_bytes: 0,
        })
        .unwrap();

        db.upsert(
            "docs",
            vec![Point {
                id: "valid".to_string(),
                vector: vec![1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"profile": {"region": "us", "score": 42}}),
            }],
        )
        .unwrap();

        let wrong_type = db.upsert(
            "docs",
            vec![Point {
                id: "wrong".to_string(),
                vector: vec![1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"profile": {"region": "us", "score": "42"}}),
            }],
        );
        assert!(matches!(wrong_type, Err(GaussError::InvalidRequest(_))));

        let missing = db.upsert(
            "docs",
            vec![Point {
                id: "missing".to_string(),
                vector: vec![1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"profile": {"region": "us"}}),
            }],
        );
        assert!(matches!(missing, Err(GaussError::InvalidRequest(_))));
    }

    #[test]
    fn payload_schema_validates_array_nested_field_paths() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
            name: "docs".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::Cosine,
            shards: 1,
            replicas: 1,
            quantization: None,
            payload_schema: [
                ("tags".to_string(), PayloadType::Array),
                ("diet[].food".to_string(), PayloadType::String),
            ]
            .into_iter()
            .collect(),
            named_vector_dims: Default::default(),
            hnsw_m: None,
            hnsw_ef_construction: None,
            hnsw_ef_search: None,
            recall_sla: None,
            index_kind: None,
            streamer_max_bytes: 0,
        })
        .unwrap();

        db.upsert(
            "docs",
            vec![Point {
                id: "valid".to_string(),
                vector: vec![1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({
                    "tags": ["featured"],
                    "diet": [{"food": "plants"}, {"food": "meat"}]
                }),
            }],
        )
        .unwrap();

        let wrong_type = db.upsert(
            "docs",
            vec![Point {
                id: "wrong".to_string(),
                vector: vec![1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({
                    "tags": ["featured"],
                    "diet": [{"food": "plants"}, {"food": 7}]
                }),
            }],
        );
        assert!(matches!(wrong_type, Err(GaussError::InvalidRequest(_))));

        let missing = db.upsert(
            "docs",
            vec![Point {
                id: "missing".to_string(),
                vector: vec![1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"tags": ["featured"], "diet": []}),
            }],
        );
        assert!(matches!(missing, Err(GaussError::InvalidRequest(_))));
    }

    #[test]
    fn update_payload_schema_validates_existing_points_before_commit() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "existing".to_string(),
                vector: vec![1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"tenant": "acme"}),
            }],
        )
        .unwrap();

        let updated = db
            .update_payload_schema(
                "docs",
                [("tenant".to_string(), PayloadType::String)]
                    .into_iter()
                    .collect(),
            )
            .unwrap();
        assert_eq!(updated.payload_schema["tenant"], PayloadType::String);
        let checkpoint = checkpoint::read_checkpoint(&temp.path().join("collections/docs"))
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.schema_epoch, 2);
        assert_eq!(checkpoint.points, 1);
        assert!(checkpoint.last_applied_lsn > 0);
        let records = crate::wal::Wal::load(&temp.path().join("collections/docs/wal")).unwrap();
        assert!(records.iter().any(|record| matches!(
            record.entry,
            WalEntry::Schema {
                schema_epoch: 2,
                ..
            }
        )));

        let rejected = db.update_payload_schema(
            "docs",
            [("tenant".to_string(), PayloadType::Number)]
                .into_iter()
                .collect(),
        );
        assert!(matches!(rejected, Err(GaussError::InvalidRequest(_))));
        assert_eq!(
            db.list_collections()[0].payload_schema["tenant"],
            PayloadType::String
        );
        let checkpoint = checkpoint::read_checkpoint(&temp.path().join("collections/docs"))
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.schema_epoch, 2);

        let missing_existing_field = db.update_payload_schema(
            "docs",
            [
                ("tenant".to_string(), PayloadType::String),
                ("price".to_string(), PayloadType::OptionalNumber),
            ]
            .into_iter()
            .collect(),
        );
        assert!(missing_existing_field.is_ok());
        assert_eq!(
            db.list_collections()[0].payload_schema["price"],
            PayloadType::OptionalNumber
        );
    }

    #[test]
    fn recommend_uses_positive_and_negative_examples() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        seed_recommendation_docs(&db);

        let response = db
            .recommend(
                "docs",
                RecommendRequest {
                    positive: vec!["anchor".to_string()],
                    negative: vec!["negative".to_string()],
                    vector_name: None,
                    k: 1,
                    filter: None,
                    budget_ms: None,
                },
            )
            .unwrap();

        assert_eq!(response.hits[0].id, "similar");
        assert!(!response.hits.iter().any(|hit| hit.id == "anchor"));
        assert!(!response.hits.iter().any(|hit| hit.id == "negative"));
    }

    #[test]
    fn search_and_recommend_can_target_named_vectors() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![
                Point {
                    id: "text-match".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::from([("image".to_string(), vec![0.0, 1.0])]),
                    sparse_vector: None,
                    payload: json!({}),
                },
                Point {
                    id: "image-match".to_string(),
                    vector: vec![0.0, 1.0],
                    vectors: HashMap::from([("image".to_string(), vec![1.0, 0.0])]),
                    sparse_vector: None,
                    payload: json!({}),
                },
                Point {
                    id: "image-near".to_string(),
                    vector: vec![0.0, 0.9],
                    vectors: HashMap::from([("image".to_string(), vec![0.9, 0.1])]),
                    sparse_vector: None,
                    payload: json!({}),
                },
            ],
        )
        .unwrap();

        let compact = db.compact_collection("docs").unwrap();
        assert_eq!(compact.named_h2qg_fields, 1);
        assert!(
            temp.path()
                .join("collections/docs/searchers")
                .join(&compact.segment_id)
                .join(crate::seal::named_ivf_file("image"))
                .exists()
        );
        // Post-compact the named graph serves from the sealed searcher
        // segment (multi-segment serving), not the streamer.
        assert!(
            db.inner.read().collections["docs"]
                .read()
                .searchers
                .iter()
                .any(|s| s.named_index.contains_key("image"))
        );

        let default_response = db
            .search(
                "docs",
                SearchRequest {
                    graph: None,
                    vector: vec![1.0, 0.0],
                    vector_name: None,
                    k: 1,
                    filter: None,
                    budget_ms: None,
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .unwrap();
        assert_eq!(default_response.hits[0].id, "text-match");

        let named_response = db
            .search(
                "docs",
                SearchRequest {
                    graph: None,
                    vector: vec![1.0, 0.0],
                    vector_name: Some("image".to_string()),
                    k: 1,
                    filter: None,
                    budget_ms: None,
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .unwrap();
        assert_eq!(named_response.hits[0].id, "image-match");

        let recommend = db
            .recommend(
                "docs",
                RecommendRequest {
                    positive: vec!["image-match".to_string()],
                    negative: vec!["text-match".to_string()],
                    vector_name: Some("image".to_string()),
                    k: 1,
                    filter: None,
                    budget_ms: None,
                },
            )
            .unwrap();
        assert_eq!(recommend.hits[0].id, "image-near");

        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        assert!(
            reopened.inner.read().collections["docs"]
                .read()
                .searchers
                .iter()
                .any(|s| s.named_index.contains_key("image"))
        );
        let reopened_named = reopened
            .search(
                "docs",
                SearchRequest {
                    graph: None,
                    vector: vec![1.0, 0.0],
                    vector_name: Some("image".to_string()),
                    k: 1,
                    filter: None,
                    budget_ms: None,
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .unwrap();
        assert_eq!(reopened_named.hits[0].id, "image-match");
    }

    fn seed_recommendation_docs(db: &Db) {
        db.create_collection(CollectionConfig {
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![
                Point {
                    id: "anchor".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({}),
                },
                Point {
                    id: "similar".to_string(),
                    vector: vec![0.9, 0.1],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({}),
                },
                Point {
                    id: "negative".to_string(),
                    vector: vec![0.0, 1.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({}),
                },
            ],
        )
        .unwrap();
    }

    #[test]
    fn named_vector_per_field_dimensions_are_validated() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
            name: "multi".to_string(),
            vector_dim: 3,
            metric: DistanceMetric::Cosine,
            shards: 1,
            replicas: 1,
            quantization: None,
            payload_schema: Default::default(),
            named_vector_dims: HashMap::from([("img".to_string(), 4)]),
            hnsw_m: None,
            hnsw_ef_construction: None,
            hnsw_ef_search: None,
            recall_sla: None,
            index_kind: None,
            streamer_max_bytes: 0,
        })
        .unwrap();

        let valid = db.upsert(
            "multi",
            vec![Point {
                id: "a".to_string(),
                vector: vec![1.0, 0.0, 0.0],
                vectors: HashMap::from([("img".to_string(), vec![0.0, 1.0, 0.0, 0.0])]),
                sparse_vector: None,
                payload: json!({}),
            }],
        );
        assert!(valid.is_ok(), "valid point should be accepted");

        let wrong_img_dim = db.upsert(
            "multi",
            vec![Point {
                id: "b".to_string(),
                vector: vec![1.0, 0.0, 0.0],
                vectors: HashMap::from([("img".to_string(), vec![0.0, 1.0, 0.0])]),
                sparse_vector: None,
                payload: json!({}),
            }],
        );
        assert!(
            wrong_img_dim.is_err(),
            "wrong img dimension should be rejected"
        );

        let wrong_default_dim = db.upsert(
            "multi",
            vec![Point {
                id: "c".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            }],
        );
        assert!(
            wrong_default_dim.is_err(),
            "wrong default dimension should be rejected"
        );
    }

    // ── Rerank tests ────────────────────────────────────────────────────────────

    fn seed_rerank_collection(db: &Db) {
        db.create_collection(CollectionConfig {
            name: "items".to_string(),
            vector_dim: 2,
            metric: crate::DistanceMetric::Cosine,
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
        })
        .unwrap();
        db.upsert(
            "items",
            vec![
                // Closest to [1, 0] query but not premium.
                Point {
                    id: "near-standard".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"tier": "standard"}),
                },
                // Slightly farther, premium tier.
                Point {
                    id: "mid-premium".to_string(),
                    vector: vec![0.9, 0.1],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"tier": "premium"}),
                },
                // Far away, premium tier.
                Point {
                    id: "far-premium".to_string(),
                    vector: vec![0.5, 0.5],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"tier": "premium"}),
                },
            ],
        )
        .unwrap();
    }

    #[test]
    fn rerank_without_boosts_returns_ann_order() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        seed_rerank_collection(&db);

        let response = db
            .rerank(
                "items",
                RerankRequest {
                    vector: vec![1.0, 0.0],
                    vector_name: None,
                    k: 2,
                    prefetch_k: None,
                    filter: None,
                    score_boosts: vec![],
                    budget_ms: None,
                },
            )
            .unwrap();

        assert_eq!(response.hits.len(), 2);
        // "near-standard" should be first (closest to query [1, 0]).
        assert_eq!(response.hits[0].id, "near-standard");
    }

    #[test]
    fn rerank_boosts_matching_payload_tier() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        seed_rerank_collection(&db);

        let response = db
            .rerank(
                "items",
                RerankRequest {
                    vector: vec![1.0, 0.0],
                    vector_name: None,
                    k: 3,
                    prefetch_k: Some(3),
                    filter: None,
                    score_boosts: vec![ScoreBoost {
                        field: "tier".to_string(),
                        value: json!("premium"),
                        boost: 2.0,
                    }],
                    budget_ms: None,
                },
            )
            .unwrap();

        assert_eq!(response.hits.len(), 3);
        // "mid-premium" has score ≈ 0.985 * 2 = 1.97; "near-standard" ≈ 1.0.
        // After boost, premium items should rank above standard.
        let premium_pos = response
            .hits
            .iter()
            .position(|h| h.id == "mid-premium")
            .unwrap();
        let standard_pos = response
            .hits
            .iter()
            .position(|h| h.id == "near-standard")
            .unwrap();
        assert!(
            premium_pos < standard_pos,
            "premium should rank above standard after 2× boost; hits={:?}",
            response.hits.iter().map(|h| &h.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn rerank_prefetch_k_controls_candidate_pool() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        seed_rerank_collection(&db);

        // With prefetch_k=1, only one candidate is fetched.
        let response = db
            .rerank(
                "items",
                RerankRequest {
                    vector: vec![1.0, 0.0],
                    vector_name: None,
                    k: 3,
                    prefetch_k: Some(1),
                    filter: None,
                    score_boosts: vec![],
                    budget_ms: None,
                },
            )
            .unwrap();

        // Final results capped by what was fetched.
        assert_eq!(response.hits.len(), 1);
    }

    #[test]
    fn rerank_missing_collection_returns_error() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let result = db.rerank(
            "does-not-exist",
            RerankRequest {
                vector: vec![1.0, 0.0],
                vector_name: None,
                k: 5,
                prefetch_k: None,
                filter: None,
                score_boosts: vec![],
                budget_ms: None,
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn compact_noop_when_no_mutations_since_last_compact() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
            name: "docs".to_string(),
            vector_dim: 4,
            metric: DistanceMetric::L2,
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
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "a".to_string(),
                vector: vec![1.0, 0.0, 0.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            }],
        )
        .unwrap();

        let first = db.compact_collection("docs").unwrap();
        // Second compact: no mutations → same segment_id, no rebuild.
        let second = db.compact_collection("docs").unwrap();
        assert_eq!(
            first.segment_id, second.segment_id,
            "no-op compact must reuse the existing segment"
        );
        // Search still works after no-op compact.
        let results = db
            .search(
                "docs",
                SearchRequest {
                    graph: None,
                    vector: vec![1.0, 0.0, 0.0, 0.0],
                    vector_name: None,
                    k: 1,
                    filter: None,
                    budget_ms: None,
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .unwrap();
        assert_eq!(results.hits.len(), 1);
        assert_eq!(results.hits[0].id, "a");
    }

    #[test]
    fn compact_migrates_legacy_v4_exact_rows_without_new_mutations() {
        let temp = TempDir::new().unwrap();
        let points = vec![
            Point {
                id: "a".to_string(),
                vector: vec![0.123_456_7, -0.765_432_1],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"version": "legacy"}),
            },
            Point {
                id: "b".to_string(),
                vector: vec![8.25, 4.125],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"version": "legacy"}),
            },
        ];
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert("docs", points.clone()).unwrap();
        let first = db.compact_collection("docs").unwrap();
        let collection_dir = temp.path().join("collections/docs");
        let segment_dir = collection_dir.join("searchers").join(&first.segment_id);
        assert_eq!(
            crate::seal::read_marker(&segment_dir.join(crate::seal::SEAL_FILE))
                .unwrap()
                .version,
            6
        );
        drop(db);

        fs::remove_dir_all(&segment_dir).unwrap();
        crate::seal::build_segment_with_encoding(
            points.as_slice(),
            &segment_dir,
            crate::seal::SealConfig {
                vector_dim: 2,
                metric: DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: crate::seal::SealIndexKind::Algorithm2,
                base_lsn: 0,
                end_lsn: 1,
            },
            crate::seal::DenseVectorEncoding::F32,
        )
        .unwrap();
        assert_eq!(
            crate::seal::read_marker(&segment_dir.join(crate::seal::SEAL_FILE))
                .unwrap()
                .version,
            4
        );

        let db = Db::open(temp.path()).unwrap();
        let migrated = db.compact_collection("docs").unwrap();
        assert_ne!(
            migrated.segment_id, first.segment_id,
            "legacy v4 rows must bypass the no-op compact path"
        );
        let migrated_dir = collection_dir.join("searchers").join(&migrated.segment_id);
        assert_eq!(
            crate::seal::read_marker(&migrated_dir.join(crate::seal::SEAL_FILE))
                .unwrap()
                .version,
            6
        );
        assert!(
            !segment_dir.exists(),
            "the manifest switch must retire the migrated v4 segment"
        );
        assert_eq!(db.get_points("docs", &["a".to_string()]).unwrap().len(), 1);
    }

    #[test]
    fn compact_migrates_legacy_v6_named_rows_without_new_mutations() {
        let temp = TempDir::new().unwrap();
        let points = vec![
            Point {
                id: "a".to_string(),
                vector: vec![0.0, 1.0],
                vectors: HashMap::from([("image".to_string(), vec![0.123_456_7, -0.765_432_1])]),
                sparse_vector: None,
                payload: json!({"version": "legacy-named"}),
            },
            Point {
                id: "b".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::from([("image".to_string(), vec![8.25, 4.125])]),
                sparse_vector: None,
                payload: json!({"version": "legacy-named"}),
            },
        ];
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("docs");
        config.named_vector_dims = HashMap::from([("image".to_string(), 2)]);
        db.create_collection(config).unwrap();
        db.upsert("docs", points.clone()).unwrap();
        let first = db.compact_collection("docs").unwrap();
        let collection_dir = temp.path().join("collections/docs");
        let segment_dir = collection_dir.join("searchers").join(&first.segment_id);
        assert_eq!(
            crate::seal::read_marker(&segment_dir.join(crate::seal::SEAL_FILE))
                .unwrap()
                .version,
            8
        );
        drop(db);

        fs::remove_dir_all(&segment_dir).unwrap();
        crate::seal::build_segment_with_legacy_named_rows(
            points.as_slice(),
            &segment_dir,
            crate::seal::SealConfig {
                vector_dim: 2,
                metric: DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: crate::seal::SealIndexKind::Algorithm2,
                base_lsn: 0,
                end_lsn: 1,
            },
        )
        .unwrap();
        assert_eq!(
            crate::seal::read_marker(&segment_dir.join(crate::seal::SEAL_FILE))
                .unwrap()
                .version,
            6
        );
        drop(points);

        let db = Db::open(temp.path()).unwrap();
        let migrated = db.compact_collection("docs").unwrap();
        assert_ne!(
            migrated.segment_id, first.segment_id,
            "legacy v6 named rows must bypass the no-op compact path"
        );
        let migrated_dir = collection_dir.join("searchers").join(&migrated.segment_id);
        assert_eq!(
            crate::seal::read_marker(&migrated_dir.join(crate::seal::SEAL_FILE))
                .unwrap()
                .version,
            8
        );
        assert!(
            !segment_dir.exists(),
            "the manifest switch must retire the migrated v6 named segment"
        );
        let fetched = db.get_points("docs", &["a".to_string()]).unwrap();
        assert_eq!(fetched[0].vectors["image"], vec![0.123_456_7, -0.765_432_1]);
    }

    /// W1 bugfix regression: setting `DbInner.cascade` did nothing for real
    /// collections because every freshly built/loaded `H2qgIndex`
    /// independently defaults its own cascade flag to `false`
    /// (`HnswGraph::new`). `Db::set_cascade` was the only thing that synced
    /// the two, and nothing called it automatically. This asserts the fix:
    /// a collection built via the normal threshold-crossing upsert path
    /// must end up with its `H2qgIndex` cascade flag matching whatever
    /// `Db::set_cascade` was told (cascade itself defaults OFF — see
    /// `DbInner.cascade` doc comment for why).
    #[test]
    fn cascade_default_wires_into_fresh_h2qg_after_threshold_crossing() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        assert!(!db.cascade(), "DbInner.cascade must default false (W1)");
        db.set_cascade(true);

        db.create_collection(CollectionConfig {
            name: "casc".to_string(),
            vector_dim: 8,
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
        })
        .unwrap();

        let points: Vec<Point> = (0..crate::h2qg::HNSW_THRESHOLD + 10)
            .map(|i| Point {
                id: format!("p{i}"),
                vector: vec![i as f32; 8],
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            })
            .collect();
        db.upsert("casc", points).unwrap();

        let coll = db.get_coll("casc").unwrap();
        // The threshold-crossing build now runs on the maintenance pool (see
        // `spawn_index_build`), so it may not have landed the instant
        // `upsert` returns. Poll for it instead of asserting immediately.
        wait_for_h2qg(&coll, BACKGROUND_INDEX_TEST_TIMEOUT);
        let guard = coll.read();
        let h2qg = guard
            .streamer
            .hnsw
            .as_ref()
            .expect("h2qg must be built after crossing HNSW_THRESHOLD");
        let flag = h2qg
            .cascade_flag()
            .expect("cascade flag must be present on a built H2qgIndex");
        assert!(
            flag.load(std::sync::atomic::Ordering::Relaxed),
            "cascade flag must be wired ON by the threshold-crossing build path"
        );
    }

    const BACKGROUND_INDEX_TEST_TIMEOUT: Duration = Duration::from_secs(90);

    fn wait_for_h2qg(coll: &Arc<RwLock<Collection>>, timeout: Duration) {
        let started = Instant::now();
        loop {
            let collection = coll.read();
            if collection.streamer.hnsw.is_some() && !collection.index_build_in_flight {
                return;
            }
            drop(collection);
            assert!(
                started.elapsed() < timeout,
                "background index build did not complete within {timeout:?}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn reopen_rebuilds_internal_streamer_hnsw_after_wal_replay() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("hot")).unwrap();
        db.upsert(
            "hot",
            (0..crate::h2qg::HNSW_THRESHOLD + 5)
                .map(|index| ls_vec_point(&format!("p{index:05}"), index as f32, "hot"))
                .collect(),
        )
        .unwrap();
        let coll = db.get_coll("hot").unwrap();
        wait_for_h2qg(&coll, BACKGROUND_INDEX_TEST_TIMEOUT);
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("hot").unwrap();
        wait_for_h2qg(&coll, BACKGROUND_INDEX_TEST_TIMEOUT);
        let status = reopened.index_status("hot").unwrap();
        assert!(!status.build_in_flight);
        assert_eq!(status.indexed_points, status.total_points);
    }

    #[test]
    fn reopen_rebuilds_subthreshold_streamer_hnsw_for_ann_sized_collection() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("tiered");
        config.hnsw_ef_construction = Some(32);
        // Collection quantization belongs to immutable LS-VEC artifacts; it
        // must not turn the live Streamer mini-HNSW into a second proxy tier.
        config.quantization = Some("sq8".to_string());
        db.create_collection(config).unwrap();
        db.upsert(
            "tiered",
            (0..crate::h2qg::HNSW_THRESHOLD)
                .map(|index| ls_vec_point(&format!("sealed-{index:05}"), index as f32, "sealed"))
                .collect(),
        )
        .unwrap();
        let coll = db.get_coll("tiered").unwrap();
        wait_for_h2qg(&coll, BACKGROUND_INDEX_TEST_TIMEOUT);
        assert!(
            !coll
                .read()
                .streamer
                .hnsw
                .as_ref()
                .expect("initial mutable mini-HNSW")
                .uses_sq8(),
            "the live Streamer must keep full-precision navigation"
        );
        db.compact_collection("tiered").unwrap();
        {
            let collection = coll.read();
            assert!(collection.streamer.points.is_empty());
            assert!(!collection.streamer_hnsw_required());
        }

        let tail_len = 1_000;
        db.upsert(
            "tiered",
            (0..tail_len)
                .map(|index| {
                    ls_vec_point(&format!("tail-{index:03}"), 50_000.0 + index as f32, "tail")
                })
                .collect(),
        )
        .unwrap();
        wait_for_h2qg(&coll, BACKGROUND_INDEX_TEST_TIMEOUT);
        {
            let collection = coll.read();
            assert_eq!(collection.streamer.points.len(), tail_len);
            assert!(collection.streamer.points.len() < crate::h2qg::HNSW_THRESHOLD);
            assert!(collection.streamer_hnsw_required());
        }
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("tiered").unwrap();
        wait_for_h2qg(&coll, BACKGROUND_INDEX_TEST_TIMEOUT);
        let tail_candidate_count = {
            let collection = coll.read();
            assert!(!collection.searchers.is_empty());
            assert_eq!(collection.streamer.points.len(), tail_len);
            let h2qg = collection
                .streamer
                .hnsw
                .as_ref()
                .expect("recovered subthreshold tail must have a mutable-tier HNSW");
            assert_eq!(crate::index::IndexBackend::indexed_points(h2qg), tail_len);
            assert!(h2qg.is_hnsw());
            assert!(
                !h2qg.uses_sq8(),
                "collection quantization must not change the mutable tier"
            );
            assert!(h2qg.contains("tail-000"));
            let candidates = h2qg.candidate_ids_with_ef(&[50_000.0, 0.0], 1, Some(32));
            assert!(
                candidates.len() < tail_len,
                "recovered mutable HNSW must not return the whole streamer"
            );
            candidates.len()
        };

        let mut request = ls_vec_search(50_000.0, 1);
        request.ef_search = Some(32);
        let response = reopened.search("tiered", request).unwrap();
        assert_eq!(response.hits[0].id, "tail-000");
        assert_eq!(
            response.searched,
            tail_candidate_count + 1,
            "the sealed leg needs one candidate for k=1; unrelated mutable candidates must not widen its requested k"
        );
    }

    #[test]
    fn reopen_keeps_subthreshold_collection_on_flat_search() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("small")).unwrap();
        db.upsert(
            "small",
            (0..64)
                .map(|index| ls_vec_point(&format!("p{index:03}"), index as f32, "small"))
                .collect(),
        )
        .unwrap();
        drop(db);

        let reopened = Db::open(temp.path()).unwrap();
        let coll = reopened.get_coll("small").unwrap();
        let collection = coll.read();
        assert!(!collection.streamer_hnsw_required());
        assert!(collection.streamer.hnsw.is_none());
        assert!(!collection.index_build_in_flight);
    }

    /// Regression test for the fix in this commit: the threshold-crossing
    /// index build used to run synchronously while holding the collection's
    /// write lock, stalling every read/write against the collection for the
    /// full build duration (measured 26s/55s/109s at 768/1536/3072-dim on a
    /// 20k-point corpus). The build now runs on a background thread. This
    /// test proves (a) the crossing upsert call itself doesn't block on the
    /// build, (b) a write issued immediately after doesn't stall waiting on
    /// the same lock, and (c) the build eventually lands and backfills any
    /// point inserted during the build window.
    #[test]
    fn threshold_crossing_build_runs_off_lock_and_concurrent_writes_succeed() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(CollectionConfig {
            name: "bulk".to_string(),
            vector_dim: 8,
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
        })
        .unwrap();

        // Same corpus shape as `cascade_default_wires_into_fresh_h2qg_after_
        // threshold_crossing` above -- at this size the index build alone
        // takes several seconds even in an unoptimized debug build, which is
        // exactly the window this test uses to prove the foreground upsert
        // path isn't blocked on it.
        let bulk: Vec<Point> = (0..crate::h2qg::HNSW_THRESHOLD + 10)
            .map(|i| Point {
                id: format!("p{i}"),
                vector: vec![i as f32; 8],
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            })
            .collect();

        let upsert_started = Instant::now();
        db.upsert("bulk", bulk).unwrap();
        assert!(
            upsert_started.elapsed() < Duration::from_secs(3),
            "the threshold-crossing upsert call must not block on the index build"
        );

        let extra = Point {
            id: "extra".to_string(),
            vector: vec![1.0; 8],
            vectors: Default::default(),
            sparse_vector: None,
            payload: serde_json::Value::Null,
        };
        let extra_started = Instant::now();
        db.upsert("bulk", vec![extra]).unwrap();
        assert!(
            extra_started.elapsed() < Duration::from_secs(1),
            "a write right after the threshold crossing must not stall on the background build's lock"
        );

        let coll = db.get_coll("bulk").unwrap();
        wait_for_h2qg(&coll, BACKGROUND_INDEX_TEST_TIMEOUT);
        let guard = coll.read();
        let h2qg = guard.streamer.hnsw.as_ref().unwrap();
        assert!(
            h2qg.contains("extra"),
            "point inserted during the background build must be backfilled into the index"
        );
    }

    #[test]
    fn streamer_freeze_restarts_background_hnsw_for_the_new_generation() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("generation");
        config.vector_dim = 8;
        config.hnsw_ef_construction = Some(32);
        db.create_collection(config).unwrap();

        let points = |prefix: &str, count: usize| {
            (0..count)
                .map(|index| Point {
                    id: format!("{prefix}-{index:05}"),
                    vector: vec![index as f32; 8],
                    vectors: Default::default(),
                    sparse_vector: None,
                    payload: serde_json::Value::Null,
                })
                .collect::<Vec<_>>()
        };
        db.upsert(
            "generation",
            points("old", crate::h2qg::HNSW_THRESHOLD + 10),
        )
        .unwrap();

        let coll = db.get_coll("generation").unwrap();
        let next_base_lsn = {
            let mut collection = coll.write();
            assert!(
                collection.index_build_in_flight,
                "threshold crossing must stage the initial mutable-tier build"
            );
            let end_lsn = collection.wal.len().unwrap();
            drop(freeze_streamer_for_seal(&mut collection, end_lsn));
            end_lsn
        };
        db.upsert("generation", points("new", 64)).unwrap();

        wait_for_h2qg(&coll, BACKGROUND_INDEX_TEST_TIMEOUT);
        let collection = coll.read();
        assert_eq!(collection.streamer.base_lsn, next_base_lsn);
        assert!(collection.streamer.points.len() < crate::h2qg::HNSW_THRESHOLD);
        assert!(collection.streamer_hnsw_required());
        let h2qg = collection.streamer.hnsw.as_ref().unwrap();
        assert!(h2qg.is_hnsw());
        assert_eq!(
            crate::index::IndexBackend::indexed_points(h2qg),
            collection.streamer.points.len(),
            "the replacement streamer index must contain only its own generation"
        );
        assert!(h2qg.contains("new-00000"));
        assert!(
            !h2qg.contains("old-00000"),
            "sealed-generation ids must not leak into the replacement streamer index"
        );
    }

    #[test]
    fn ann_sized_frozen_points_trigger_a_subthreshold_replacement_hnsw() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("threshold-tail");
        config.vector_dim = 8;
        config.streamer_max_bytes = usize::MAX;
        config.hnsw_m = Some(8);
        config.hnsw_ef_construction = Some(16);
        db.create_collection(config).unwrap();
        let coll = db.get_coll("threshold-tail").unwrap();
        coll.write().index_build_in_flight = true;
        db.upsert(
            "threshold-tail",
            (0..crate::h2qg::HNSW_THRESHOLD + 10)
                .map(|index| Point {
                    id: format!("frozen-{index:05}"),
                    vector: vec![(index + 1) as f32; 8],
                    vectors: Default::default(),
                    sparse_vector: None,
                    payload: serde_json::Value::Null,
                })
                .collect(),
        )
        .unwrap();
        {
            let mut collection = coll.write();
            collection.index_build_in_flight = false;
            let end_lsn = collection.wal.len().unwrap();
            drop(freeze_streamer_for_seal(&mut collection, end_lsn));
        }

        db.upsert(
            "threshold-tail",
            vec![Point {
                id: "tail-00000".to_string(),
                vector: vec![1.0; 8],
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            }],
        )
        .unwrap();
        wait_for_h2qg(&coll, BACKGROUND_INDEX_TEST_TIMEOUT);
        {
            let collection = coll.read();
            assert_eq!(collection.streamer.points.len(), 1);
            let h2qg = collection.streamer.hnsw.as_ref().unwrap();
            assert!(h2qg.is_hnsw());
            assert_eq!(crate::index::IndexBackend::indexed_points(h2qg), 1);
            assert!(h2qg.contains("tail-00000"));
            assert!(!collection.index_build_in_flight);
        }

        db.upsert(
            "threshold-tail",
            (1..crate::h2qg::HNSW_THRESHOLD + 10)
                .map(|index| Point {
                    id: format!("tail-{index:05}"),
                    vector: vec![(index + 1) as f32; 8],
                    vectors: Default::default(),
                    sparse_vector: None,
                    payload: serde_json::Value::Null,
                })
                .collect(),
        )
        .unwrap();
        wait_for_h2qg(&coll, BACKGROUND_INDEX_TEST_TIMEOUT);
        let collection = coll.read();
        let h2qg = collection.streamer.hnsw.as_ref().unwrap();
        assert_eq!(
            crate::index::IndexBackend::indexed_points(h2qg),
            collection.streamer.points.len()
        );
        assert!(h2qg.contains("tail-00000"));
        assert!(!h2qg.contains("frozen-00000"));
    }

    #[test]
    fn completed_seal_starts_hnsw_for_ann_sized_replacement_streamer() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("post-seal-tail");
        config.vector_dim = 8;
        config.streamer_max_bytes = usize::MAX;
        config.hnsw_m = Some(8);
        config.hnsw_ef_construction = Some(16);
        db.create_collection(config).unwrap();
        db.upsert(
            "post-seal-tail",
            (0..64)
                .map(|index| Point {
                    id: format!("sealed-{index:05}"),
                    vector: vec![(index + 1) as f32; 8],
                    vectors: Default::default(),
                    sparse_vector: None,
                    payload: serde_json::Value::Null,
                })
                .collect(),
        )
        .unwrap();

        let coll = db.get_coll("post-seal-tail").unwrap();
        let (frozen, end_lsn) = {
            let mut collection = coll.write();
            collection.wal.sync().unwrap();
            let end_lsn = collection.wal.len().unwrap();
            let frozen = freeze_streamer_for_seal(&mut collection, end_lsn);
            // Model the stale-generation build that has not retired yet: the
            // replacement-tail upsert must not start a duplicate build.
            collection.index_build_in_flight = true;
            (frozen, end_lsn)
        };
        let seal = PendingSeal {
            coll: Arc::clone(&coll),
            data_dir_lock: Arc::clone(&db._data_dir_lock),
            lifecycle: Arc::clone(&db.build_lifecycle),
            collection_dir: temp.path().join("collections/post-seal-tail"),
            frozen,
            end_lsn,
            graph: None,
            wal_archive_cut: None,
            wal_archive_policy: {
                let inner = db.inner.read();
                super::seal_wal_archive_policy(&inner, "post-seal-tail")
            },
            vector_dim: 8,
            metric: DistanceMetric::Cosine,
            hnsw_m: Some(8),
            hnsw_ef_construction: Some(16),
            index_kind: crate::seal::SealIndexKind::Algorithm2,
            cascade: Arc::clone(&db.cascade),
            intra_query_parallel: Arc::clone(&db.intra_query_parallel),
        };

        db.upsert(
            "post-seal-tail",
            (0..crate::h2qg::HNSW_THRESHOLD + 10)
                .map(|index| Point {
                    id: format!("tail-{index:05}"),
                    vector: vec![(index + 65) as f32; 8],
                    vectors: Default::default(),
                    sparse_vector: None,
                    payload: serde_json::Value::Null,
                })
                .collect(),
        )
        .unwrap();
        {
            let mut collection = coll.write();
            assert!(collection.streamer.hnsw.is_none());
            collection.index_build_in_flight = false;
        }

        run_segment_seal(&seal).unwrap();
        {
            let collection = coll.read();
            assert!(
                collection.index_build_in_flight || collection.streamer.hnsw.is_some(),
                "seal completion must stage exactly one build for the ANN-sized tail"
            );
        }
        wait_for_h2qg(&coll, BACKGROUND_INDEX_TEST_TIMEOUT);
        let collection = coll.read();
        let h2qg = collection.streamer.hnsw.as_ref().unwrap();
        assert_eq!(
            crate::index::IndexBackend::indexed_points(h2qg),
            collection.streamer.points.len()
        );
        assert!(h2qg.contains("tail-00000"));
        assert!(!h2qg.contains("sealed-00000"));
    }
}
