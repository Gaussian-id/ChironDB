use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crc32fast::Hasher;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    encryption::{self, FileType},
    error::{GaussError, Result},
    fs_util::{
        atomic_write, durable_copy, durable_remove_dir_all, durable_remove_file, durable_rename,
        sync_directory, sync_tree,
    },
    graph::{
        EdgeId, EdgeMutation, GraphEpoch, GraphNamespace, MAX_EDGE_PROPERTY_BYTES,
        MAX_GRAPH_BATCH_BYTES, MAX_GRAPH_CATALOG_NAME_BYTES, MAX_GRAPH_EDGES_PER_BATCH, Nid,
        TypeId,
    },
    model::{CollectionConfig, Point},
};

mod archive_replay;

const HEADER_LEN: usize = 8;
const DEFAULT_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
const WAL_BASE_FILE: &str = "wal.base";
#[cfg(windows)]
const WAL_BASE_PREVIOUS_FILE: &str = "wal.base.previous";
const WAL_BASE_MAGIC: &[u8; 8] = b"GAUSSWB1";
const WAL_BASE_LEN: usize = 28;
const WAL_ARCHIVE_MANIFEST_FILE: &str = "wal.manifest.json";
const WAL_ARCHIVE_MANIFEST_VERSION: u32 = 2;
/// Hard safety ceiling for a single serialized WAL record. This matches the
/// public request envelope and prevents corrupt length headers from causing an
/// unbounded allocation during recovery.
pub const MAX_WAL_RECORD_BYTES: usize = 64 * 1024 * 1024;
pub const GRAPH_BATCH_VERSION: u16 = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GraphPointMutation {
    Upsert { point: Point },
    Delete { point_id: String, nid: Nid },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphHandleAssignment {
    pub point_id: String,
    pub nid: Nid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphDeferredBind {
    /// Explicit bulk-load session. Older unsupported v1 frames decode with
    /// an empty value and then fail validation rather than binding outside a
    /// durable session window.
    #[serde(default)]
    pub session_id: String,
    pub edge_id: EdgeId,
    pub source_point_id: String,
    pub target_point_id: String,
    /// Endpoints already live when the pending edge is recorded are bound to
    /// their exact incarnation immediately. Missing endpoints remain None.
    #[serde(default)]
    pub source_nid: Option<Nid>,
    #[serde(default)]
    pub target_nid: Option<Nid>,
    pub type_id: TypeId,
    pub namespace: GraphNamespace,
    #[serde(default)]
    pub properties: serde_json::Value,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphDeferredEndpoint {
    Source,
    Target,
}

/// Immutable binding of one previously missing endpoint to the exact first
/// incarnation created inside its durable session window.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphEdgeBind {
    pub session_id: String,
    pub edge_id: EdgeId,
    pub endpoint: GraphDeferredEndpoint,
    pub point_id: String,
    pub nid: Nid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GraphDeferredSessionMutation {
    Open { session_id: String },
    Commit { session_id: String },
    Abort { session_id: String },
}

impl GraphDeferredSessionMutation {
    fn session_id(&self) -> &str {
        match self {
            Self::Open { session_id }
            | Self::Commit { session_id }
            | Self::Abort { session_id } => session_id,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphIdempotencyState {
    pub key: String,
    pub request_sha256: [u8; 32],
    /// Persisted wall-clock instants. These are deliberately not LSNs: time
    /// cannot be reconstructed from a log position after restart.
    #[serde(default)]
    pub created_at_unix_ms: u64,
    #[serde(default)]
    pub expires_at_unix_ms: u64,
    #[serde(default)]
    pub edge_ids: Vec<EdgeId>,
}

impl GraphIdempotencyState {
    /// Validate durable retry state independently of its originating batch.
    /// Batch validation additionally checks exact agreement with created IDs.
    pub(crate) fn validate_checkpoint(&self) -> Result<HashSet<EdgeId>> {
        validate_graph_key("idempotency key", &self.key)?;
        if self.request_sha256 == [0; 32] {
            return Err(invalid_graph_batch(
                "idempotency request SHA-256 cannot be all zero",
            ));
        }
        if self.created_at_unix_ms == 0 || self.expires_at_unix_ms <= self.created_at_unix_ms {
            return Err(invalid_graph_batch(
                "idempotency wall-clock instants require 0 < created_at < expires_at",
            ));
        }
        if self.edge_ids.is_empty() {
            return Err(invalid_graph_batch(
                "idempotency result must contain at least one created EdgeId",
            ));
        }
        if self.edge_ids.len() > MAX_GRAPH_EDGES_PER_BATCH {
            return Err(invalid_graph_batch(
                "idempotency result has too many EdgeIds",
            ));
        }
        let mut ids = HashSet::with_capacity(self.edge_ids.len());
        for id in &self.edge_ids {
            validate_edge_id(*id)?;
            if !ids.insert(*id) {
                return Err(invalid_graph_batch(
                    "idempotency result contains a duplicate EdgeId",
                ));
            }
        }
        Ok(ids)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphTypeConfiguration {
    pub type_id: TypeId,
    pub name: String,
    #[serde(default)]
    pub weight_property: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphBatch {
    pub version: u16,
    /// Collection graph incarnation this request was validated against.
    /// Older v1 frames created before lifecycle activation default to the
    /// initial epoch and therefore cannot cross a later drop/re-enable.
    #[serde(default = "initial_graph_epoch")]
    pub graph_epoch: GraphEpoch,
    #[serde(default)]
    pub type_configurations: Vec<GraphTypeConfiguration>,
    #[serde(default)]
    pub point_mutations: Vec<GraphPointMutation>,
    #[serde(default)]
    pub handle_assignments: Vec<GraphHandleAssignment>,
    #[serde(default)]
    pub edge_mutations: Vec<EdgeMutation>,
    #[serde(default)]
    pub deferred_binds: Vec<GraphDeferredBind>,
    #[serde(default)]
    pub edge_binds: Vec<GraphEdgeBind>,
    #[serde(default)]
    pub deferred_sessions: Vec<GraphDeferredSessionMutation>,
    #[serde(default)]
    pub idempotency: Option<GraphIdempotencyState>,
}

impl Default for GraphBatch {
    fn default() -> Self {
        Self {
            version: GRAPH_BATCH_VERSION,
            graph_epoch: GraphEpoch::INITIAL,
            type_configurations: Vec::new(),
            point_mutations: Vec::new(),
            handle_assignments: Vec::new(),
            edge_mutations: Vec::new(),
            deferred_binds: Vec::new(),
            edge_binds: Vec::new(),
            deferred_sessions: Vec::new(),
            idempotency: None,
        }
    }
}

impl GraphBatch {
    pub fn validate(&self) -> Result<()> {
        if self.version != GRAPH_BATCH_VERSION {
            return Err(invalid_graph_batch(format!(
                "unsupported version {}; expected {GRAPH_BATCH_VERSION}",
                self.version
            )));
        }
        if self.graph_epoch.raw() == 0 {
            return Err(invalid_graph_batch("graph epoch cannot be zero"));
        }
        if self.point_mutations.is_empty()
            && self.type_configurations.is_empty()
            && self.handle_assignments.is_empty()
            && self.edge_mutations.is_empty()
            && self.deferred_binds.is_empty()
            && self.edge_binds.is_empty()
            && self.deferred_sessions.is_empty()
            && self.idempotency.is_none()
        {
            return Err(invalid_graph_batch(
                "batch has no mutation or durable state",
            ));
        }
        let mut configured_type_ids = HashSet::with_capacity(self.type_configurations.len());
        let mut configured_type_names = HashSet::with_capacity(self.type_configurations.len());
        for configuration in &self.type_configurations {
            validate_type_id(configuration.type_id)?;
            validate_catalog_key("edge type name", &configuration.name)?;
            if let Some(weight_property) = configuration.weight_property.as_deref() {
                validate_catalog_key("edge weight property", weight_property)?;
            }
            if !configured_type_ids.insert(configuration.type_id) {
                return Err(invalid_graph_batch(
                    "one TypeId is configured more than once",
                ));
            }
            if !configured_type_names.insert(configuration.name.as_str()) {
                return Err(invalid_graph_batch(
                    "one edge type name is configured more than once",
                ));
            }
        }
        let edge_count = self
            .edge_mutations
            .len()
            .checked_add(self.deferred_binds.len())
            .and_then(|count| count.checked_add(self.edge_binds.len()))
            .ok_or_else(|| invalid_graph_batch("edge count overflow"))?;
        if edge_count > MAX_GRAPH_EDGES_PER_BATCH {
            return Err(invalid_graph_batch(format!(
                "{edge_count} edge operations exceed fixed limit {MAX_GRAPH_EDGES_PER_BATCH}"
            )));
        }

        let mut point_mutations = HashSet::with_capacity(self.point_mutations.len());
        for mutation in &self.point_mutations {
            let point_id = match mutation {
                GraphPointMutation::Upsert { point } => point.id.as_str(),
                GraphPointMutation::Delete { point_id, nid } => {
                    validate_nid(*nid)?;
                    point_id
                }
            };
            validate_graph_key("point ID", point_id)?;
            if !point_mutations.insert(point_id) {
                return Err(invalid_graph_batch(format!(
                    "point ID '{point_id}' has more than one mutation"
                )));
            }
        }

        let mut assignment_points = HashSet::with_capacity(self.handle_assignments.len());
        let mut assignment_nids = HashSet::with_capacity(self.handle_assignments.len());
        for assignment in &self.handle_assignments {
            validate_graph_key("assignment point ID", &assignment.point_id)?;
            validate_nid(assignment.nid)?;
            if !assignment_points.insert(assignment.point_id.as_str()) {
                return Err(invalid_graph_batch(format!(
                    "point ID '{}' has more than one handle assignment",
                    assignment.point_id
                )));
            }
            if !assignment_nids.insert(assignment.nid) {
                return Err(invalid_graph_batch("one Nid is assigned more than once"));
            }
        }

        let mut edge_ids = HashSet::with_capacity(edge_count);
        let mut created_edge_ids = HashSet::with_capacity(edge_count);
        for mutation in &self.edge_mutations {
            let edge_id = match mutation {
                EdgeMutation::Relate(relate) => {
                    validate_nid(relate.source)?;
                    validate_nid(relate.target)?;
                    validate_type_id(relate.type_id)?;
                    validate_namespace(&relate.namespace)?;
                    validate_properties(&relate.properties)?;
                    created_edge_ids.insert(relate.edge_id);
                    relate.edge_id
                }
                EdgeMutation::Unrelate(unrelate) => unrelate.edge_id,
                EdgeMutation::Properties(properties) => {
                    validate_properties(&properties.properties)?;
                    properties.edge_id
                }
            };
            validate_edge_id(edge_id)?;
            if !edge_ids.insert(edge_id) {
                return Err(invalid_graph_batch("one EdgeId is mutated more than once"));
            }
        }
        for bind in &self.deferred_binds {
            validate_graph_key("deferred session ID", &bind.session_id)?;
            validate_edge_id(bind.edge_id)?;
            validate_graph_key("deferred source point ID", &bind.source_point_id)?;
            validate_graph_key("deferred target point ID", &bind.target_point_id)?;
            if let Some(nid) = bind.source_nid {
                validate_nid(nid)?;
            }
            if let Some(nid) = bind.target_nid {
                validate_nid(nid)?;
            }
            validate_type_id(bind.type_id)?;
            validate_namespace(&bind.namespace)?;
            validate_properties(&bind.properties)?;
            created_edge_ids.insert(bind.edge_id);
            if !edge_ids.insert(bind.edge_id) {
                return Err(invalid_graph_batch("one EdgeId is mutated more than once"));
            }
        }
        let mut endpoint_binds = HashSet::with_capacity(self.edge_binds.len());
        for bind in &self.edge_binds {
            validate_graph_key("edge-bind session ID", &bind.session_id)?;
            validate_edge_id(bind.edge_id)?;
            validate_graph_key("edge-bind point ID", &bind.point_id)?;
            validate_nid(bind.nid)?;
            if !endpoint_binds.insert((bind.edge_id, bind.endpoint)) {
                return Err(invalid_graph_batch(
                    "one deferred edge endpoint is bound more than once",
                ));
            }
        }
        let mut session_ids = HashSet::with_capacity(self.deferred_sessions.len());
        for session in &self.deferred_sessions {
            validate_graph_key("deferred session ID", session.session_id())?;
            if !session_ids.insert(session.session_id()) {
                return Err(invalid_graph_batch(
                    "one deferred session is mutated more than once",
                ));
            }
        }
        if let Some(idempotency) = &self.idempotency {
            let result_edge_ids = idempotency.validate_checkpoint()?;
            if result_edge_ids != created_edge_ids {
                return Err(invalid_graph_batch(
                    "idempotency result must exactly match the EdgeIds created by this request",
                ));
            }
        }

        let encoded_bytes = serde_json::to_vec(self)?.len();
        if encoded_bytes > MAX_GRAPH_BATCH_BYTES {
            return Err(invalid_graph_batch(format!(
                "serialized GraphBatch is {encoded_bytes} bytes; maximum is {MAX_GRAPH_BATCH_BYTES}"
            )));
        }
        Ok(())
    }
}

fn initial_graph_epoch() -> GraphEpoch {
    GraphEpoch::INITIAL
}

fn validate_graph_key(label: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 1024 {
        return Err(invalid_graph_batch(format!(
            "{label} must contain 1..=1024 UTF-8 bytes"
        )));
    }
    Ok(())
}

fn validate_catalog_key(label: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_GRAPH_CATALOG_NAME_BYTES {
        return Err(invalid_graph_batch(format!(
            "{label} must contain 1..={MAX_GRAPH_CATALOG_NAME_BYTES} UTF-8 bytes"
        )));
    }
    Ok(())
}

fn validate_nid(nid: Nid) -> Result<()> {
    if Nid::from_parts(nid.epoch(), nid.counter()) != Some(nid) {
        return Err(invalid_graph_batch("invalid or unassigned Nid"));
    }
    Ok(())
}

fn validate_edge_id(edge_id: EdgeId) -> Result<()> {
    if EdgeId::from_parts(edge_id.epoch(), edge_id.counter()) != Some(edge_id) {
        return Err(invalid_graph_batch("invalid or unassigned EdgeId"));
    }
    Ok(())
}

fn validate_type_id(type_id: TypeId) -> Result<()> {
    if type_id.raw() == 0 {
        return Err(invalid_graph_batch("TypeId=0 is reserved"));
    }
    Ok(())
}

fn validate_namespace(namespace: &GraphNamespace) -> Result<()> {
    if let GraphNamespace::Tenant(tenant) = namespace {
        validate_graph_key("tenant namespace", tenant)?;
    }
    Ok(())
}

fn validate_properties(properties: &serde_json::Value) -> Result<()> {
    let bytes = serde_json::to_vec(properties)?.len();
    if bytes > MAX_EDGE_PROPERTY_BYTES {
        return Err(invalid_graph_batch(format!(
            "edge properties are {bytes} bytes; maximum is {MAX_EDGE_PROPERTY_BYTES}"
        )));
    }
    Ok(())
}

fn invalid_graph_batch(message: impl Into<String>) -> GaussError {
    GaussError::InvalidRequest(format!("invalid GraphBatch: {}", message.into()))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
// Schema variant is naturally heavier; payload size is bounded by config size.
#[allow(clippy::large_enum_variant)]
pub enum WalEntry {
    Upsert {
        point: Point,
    },
    /// Atomic request-level upsert. Existing single-point records remain
    /// readable for alpha-format compatibility.
    UpsertBatch {
        points: Vec<Point>,
    },
    Delete {
        id: String,
    },
    /// Atomic request-level delete. Existing single-id records remain
    /// readable for alpha-format compatibility.
    DeleteBatch {
        ids: Vec<String>,
    },
    /// Root catalog WAL entry. Collection WAL replay must reject this variant.
    CreateCollection {
        config: CollectionConfig,
    },
    /// Root catalog WAL entry. Collection WAL replay must reject this variant.
    DropCollection {
        name: String,
    },
    Schema {
        schema_epoch: u64,
        config: CollectionConfig,
        #[serde(default)]
        previous_config: Option<CollectionConfig>,
    },
    /// Update only the payload of an existing point.
    /// `merge=true`: merge fields into existing payload.
    /// `merge=false`: replace entire payload.
    SetPayload {
        id: String,
        payload: serde_json::Value,
        #[serde(default = "default_merge")]
        merge: bool,
    },
    /// Durable record of an immutable segment-generation switch. Recovery
    /// uses `segments.json` for the physical install and treats this entry as
    /// a no-op; archive/replication tooling retains it as lifecycle history.
    Compact {
        generation: u64,
        segments: Vec<String>,
    },
    /// Collection-global graph lifecycle transition. Every enable/drop moves
    /// to the exact next GraphEpoch; replay rejects gaps and duplicates.
    GraphEpochAdvance {
        epoch: GraphEpoch,
        enabled: bool,
    },
    /// One request-atomic property-graph mutation envelope. Older WAL
    /// variants remain readable; graph-aware mixed mutations use only this
    /// record after graph lifecycle activation.
    GraphBatch {
        batch: GraphBatch,
    },
}

fn default_merge() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalRecord {
    pub lsn: u64,
    #[serde(default)]
    pub unix_ms: u64,
    pub entry: WalEntry,
}

#[derive(Debug)]
pub struct Wal {
    dir: PathBuf,
    path: PathBuf,
    file: File,
    active_index: u64,
    base_lsn: u64,
    segment_bytes: u64,
    poisoned: AtomicBool,
    unsynced_bytes: AtomicU64,
    oldest_unsynced_unix_ms: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct WalBase {
    lsn: u64,
    first_segment: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalArchive {
    pub path: PathBuf,
    pub segments: usize,
    pub bytes: u64,
}

/// Immutable live-WAL prefix captured at a graph seal cut. The active WAL is
/// rotated before this descriptor is returned, so archive publication can
/// copy these exact bytes off-lock while mutations continue in its successor.
#[derive(Debug)]
pub(crate) struct FrozenWalArchive {
    base: WalBase,
    base_bytes: Option<Vec<u8>>,
    segments: Vec<FrozenWalSegment>,
    end_lsn: u64,
}

#[derive(Debug)]
struct FrozenWalSegment {
    index: u64,
    path: PathBuf,
    bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalArchivePrune {
    pub retained_archives: usize,
    pub pruned_archives: usize,
    pub pruned_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct WalArchiveManifest {
    version: u32,
    files: Vec<WalArchiveManifestFile>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct WalArchiveManifestFile {
    name: String,
    bytes: u64,
    sha256: String,
    #[serde(default)]
    encoding: String,
}

/// Statistics returned by streaming WAL scans and safe active-tail recovery.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WalScanStats {
    pub records: u64,
    pub bytes: u64,
    pub end_lsn: u64,
    /// Bytes removed from a torn final active segment. Strict scans always
    /// report zero.
    pub repaired_tail_bytes: u64,
}

impl Wal {
    pub fn open(dir: &Path) -> Result<Self> {
        #[cfg(feature = "fault-injection")]
        if let Some(raw_bytes) =
            std::env::var_os(crate::fs_util::fault_injection::TEST_WAL_SEGMENT_BYTES_ENV)
        {
            let bytes = raw_bytes
                .to_str()
                .ok_or_else(|| {
                    GaussError::InvalidRequest(format!(
                        "{} must be valid UTF-8",
                        crate::fs_util::fault_injection::TEST_WAL_SEGMENT_BYTES_ENV
                    ))
                })?
                .parse::<u64>()
                .map_err(|error| {
                    GaussError::InvalidRequest(format!(
                        "invalid {}: {error}",
                        crate::fs_util::fault_injection::TEST_WAL_SEGMENT_BYTES_ENV
                    ))
                })?;
            return Self::open_with_segment_bytes(dir, bytes);
        }
        Self::open_with_segment_bytes(dir, DEFAULT_SEGMENT_BYTES)
    }

    fn open_with_segment_bytes(dir: &Path, segment_bytes: u64) -> Result<Self> {
        let dir_created = !dir.exists();
        fs::create_dir_all(dir)?;
        if dir_created && let Some(parent) = dir.parent() {
            sync_directory(parent)?;
        }
        #[cfg(windows)]
        recover_interrupted_wal_base_publish(dir)?;
        let wal_base = read_wal_base(dir)?;
        for segment in all_wal_segments(dir)? {
            if segment.index < wal_base.first_segment {
                durable_remove_file(&segment.path)?;
            }
        }
        let segments = wal_segments(dir)?;
        let mut base_lsn = wal_base.lsn;
        for segment in segments.iter().take(segments.len().saturating_sub(1)) {
            base_lsn += fs::metadata(&segment.path)?.len();
        }
        let active_index = segments
            .last()
            .map(|segment| segment.index)
            .unwrap_or(wal_base.first_segment);
        let path = segments
            .last()
            .map(|segment| segment.path.clone())
            .unwrap_or_else(|| segment_path(dir, active_index));
        let created = !path.exists();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        if created {
            file.sync_all()?;
            sync_directory(dir)?;
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            path,
            file,
            active_index,
            base_lsn,
            segment_bytes: segment_bytes.max(HEADER_LEN as u64 + 1),
            poisoned: AtomicBool::new(false),
            unsynced_bytes: AtomicU64::new(0),
            oldest_unsynced_unix_ms: AtomicU64::new(0),
        })
    }

    pub fn append(&mut self, entry: &WalEntry) -> Result<u64> {
        self.append_inner(entry, true)
    }

    /// Write to WAL without fsync — lower latency, data may be lost on crash.
    pub fn append_no_sync(&mut self, entry: &WalEntry) -> Result<u64> {
        self.append_inner(entry, false)
    }

    /// Force-flush previously appended (un-synced) records to disk.
    /// Pairs with [`append_no_sync`] so callers can amortise a single fsync
    /// across a batch of records.
    pub fn sync(&self) -> Result<()> {
        self.ensure_available()?;
        let started = std::time::Instant::now();
        #[cfg(any(test, feature = "fault-injection"))]
        if let Some(fault) = crate::fs_util::fault_injection::take_if(|fault| {
            fault == crate::fs_util::fault_injection::Fault::Fsync
        }) {
            self.poisoned.store(true, Ordering::Release);
            return Err(GaussError::WalUnavailable(format!(
                "WAL sync failed: {}",
                crate::fs_util::fault_injection::injected_error(fault)
            )));
        }
        match self.file.sync_data() {
            Ok(()) => {
                if let Err(error) = crate::failpoint::check("wal.after_sync") {
                    self.poisoned.store(true, Ordering::Release);
                    return Err(GaussError::WalUnavailable(format!(
                        "WAL sync failpoint failed: {error}"
                    )));
                }
                #[cfg(any(test, feature = "fault-injection"))]
                if let Err(error) = crate::fs_util::fault_injection::crash_hook(
                    crate::fs_util::fault_injection::HOOK_WAL_AFTER_FSYNC,
                ) {
                    self.poisoned.store(true, Ordering::Release);
                    return Err(GaussError::WalUnavailable(format!(
                        "WAL fsync crash hook failed: {error}"
                    )));
                }
                self.unsynced_bytes.store(0, Ordering::Release);
                self.oldest_unsynced_unix_ms.store(0, Ordering::Release);
                metrics::histogram!("chirondb_wal_fsync_duration_seconds")
                    .record(started.elapsed().as_secs_f64());
                Ok(())
            }
            Err(err) => {
                self.poisoned.store(true, Ordering::Release);
                Err(GaussError::WalUnavailable(format!(
                    "WAL sync failed: {err}"
                )))
            }
        }
    }

    fn append_inner(&mut self, entry: &WalEntry, sync: bool) -> Result<u64> {
        self.ensure_available()?;
        if let WalEntry::GraphBatch { batch } = entry {
            batch.validate()?;
        }
        if let WalEntry::GraphEpochAdvance { epoch, .. } = entry
            && epoch.raw() == 0
        {
            return Err(GaussError::InvalidRequest(
                "GraphEpochAdvance cannot use epoch zero".to_string(),
            ));
        }
        let lsn = self
            .base_lsn
            .checked_add(self.file.metadata().map_err(|err| self.poison(err))?.len())
            .ok_or_else(|| GaussError::InvalidRequest("WAL LSN overflow".into()))?;
        let payload = encode_record(lsn, entry)?;
        self.append_payload(lsn, &payload, sync)
    }

    /// Also used by checked archive replay; do not renumber or re-encode its frames.
    fn append_payload(&mut self, lsn: u64, payload: &[u8], sync: bool) -> Result<u64> {
        self.ensure_available()?;
        let current_len = self.file.metadata().map_err(|err| self.poison(err))?.len();
        if self.base_lsn.checked_add(current_len) != Some(lsn) {
            return Err(wal_corruption(
                &self.path,
                "archive replay is not contiguous with WAL",
            ));
        }
        validate_append_payload_len(payload.len())?;
        if current_len > 0
            && current_len
                .checked_add(HEADER_LEN as u64)
                .and_then(|length| length.checked_add(payload.len() as u64))
                .is_none_or(|length| length > self.segment_bytes)
            && let Err(err) = self.rotate(current_len)
        {
            self.poisoned.store(true, Ordering::Release);
            return Err(GaussError::WalUnavailable(format!(
                "WAL rotation failed: {err}"
            )));
        }
        let len = u32::try_from(payload.len()).map_err(|_| {
            GaussError::InvalidRequest(format!(
                "WAL record is {} bytes; maximum is {MAX_WAL_RECORD_BYTES} bytes",
                payload.len()
            ))
        })?;
        let crc = checksum(payload);

        let write_result = (|| -> std::io::Result<()> {
            #[cfg(any(test, feature = "fault-injection"))]
            if let Some(fault) = crate::fs_util::fault_injection::take_if(|fault| {
                matches!(
                    fault,
                    crate::fs_util::fault_injection::Fault::Enospc
                        | crate::fs_util::fault_injection::Fault::PermissionDenied
                        | crate::fs_util::fault_injection::Fault::ShortWrite
                )
            }) {
                if fault == crate::fs_util::fault_injection::Fault::ShortWrite {
                    // Persist only half of the frame header so recovery tests
                    // exercise a real torn active tail, not a synthetic error
                    // that leaves the file untouched.
                    self.file.write_all(&len.to_le_bytes())?;
                }
                return Err(crate::fs_util::fault_injection::injected_error(fault));
            }
            self.file.write_all(&len.to_le_bytes())?;
            self.file.write_all(&crc.to_le_bytes())?;
            #[cfg(any(test, feature = "fault-injection"))]
            crate::fs_util::fault_injection::crash_hook(
                crate::fs_util::fault_injection::HOOK_WAL_AFTER_FRAME_HEADER,
            )?;
            self.file.write_all(payload)?;
            #[cfg(any(test, feature = "fault-injection"))]
            crate::fs_util::fault_injection::crash_hook(
                crate::fs_util::fault_injection::HOOK_WAL_AFTER_FRAME_WRITE,
            )?;
            Ok(())
        })();
        if let Err(err) = write_result {
            return Err(self.poison(err));
        }
        if let Err(error) = crate::failpoint::check("wal.after_record_write") {
            self.poisoned.store(true, Ordering::Release);
            return Err(GaussError::WalUnavailable(format!(
                "WAL append failpoint failed: {error}"
            )));
        }
        let record_bytes = HEADER_LEN as u64 + payload.len() as u64;
        self.unsynced_bytes
            .fetch_add(record_bytes, Ordering::AcqRel);
        let _ = self.oldest_unsynced_unix_ms.compare_exchange(
            0,
            current_unix_ms(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        if sync {
            self.sync()?;
        }
        metrics::counter!("chirondb_wal_append_records_total").increment(1);
        metrics::counter!("chirondb_wal_append_bytes_total").increment(record_bytes);
        lsn.checked_add(record_bytes)
            .ok_or_else(|| GaussError::InvalidRequest("WAL LSN overflow".to_string()))
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    pub fn is_dirty(&self) -> bool {
        self.unsynced_bytes() != 0
    }

    pub fn unsynced_bytes(&self) -> u64 {
        self.unsynced_bytes.load(Ordering::Acquire)
    }

    pub fn oldest_unsynced_age(&self) -> Option<Duration> {
        let oldest = self.oldest_unsynced_unix_ms.load(Ordering::Acquire);
        (oldest != 0).then(|| Duration::from_millis(current_unix_ms().saturating_sub(oldest)))
    }

    fn ensure_available(&self) -> Result<()> {
        if self.is_poisoned() {
            return Err(GaussError::WalUnavailable(
                "previous WAL write or sync failure poisoned this handle".to_string(),
            ));
        }
        Ok(())
    }

    fn poison(&self, err: std::io::Error) -> GaussError {
        self.poisoned.store(true, Ordering::Release);
        GaussError::WalUnavailable(format!("WAL write failed: {err}"))
    }

    #[cfg(test)]
    pub(crate) fn inject_write_failure(&self) {
        crate::fs_util::fault_injection::inject_once(
            crate::fs_util::fault_injection::Fault::Enospc,
        );
    }

    #[cfg(test)]
    pub(crate) fn inject_sync_failure(&self) {
        crate::fs_util::fault_injection::inject_once(crate::fs_util::fault_injection::Fault::Fsync);
    }

    pub fn reset(&mut self) -> Result<()> {
        self.ensure_available()?;
        let result = self.reset_inner();
        if let Err(error) = result {
            self.poisoned.store(true, Ordering::Release);
            return Err(GaussError::WalUnavailable(format!(
                "WAL reset failed: {error}"
            )));
        }
        Ok(())
    }

    fn reset_inner(&mut self) -> Result<()> {
        self.file.sync_all()?;
        let reset_lsn = self.len()?;

        // Never renumber an active segment back to zero in place. A crash
        // between creating 000000 and deleting an older active segment can
        // otherwise leave a permanent segment gap. Publish an empty monotonic
        // successor first, then atomically move wal.base to that generation.
        // Before the sidecar commit readers still see the complete old WAL;
        // afterwards they ignore every older segment. Keeping wal.base is what
        // makes both crash windows recoverable without a directory swap.
        let old_segments = all_wal_segments(&self.dir)?;
        let successor_index = old_segments.last().map_or(Ok(0), |segment| {
            segment.index.checked_add(1).ok_or_else(|| {
                GaussError::WalUnavailable("WAL segment index overflow during reset".into())
            })
        })?;
        let successor_path = segment_path(&self.dir, successor_index);
        let successor_file = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(&successor_path)
            .map_err(|err| self.poison(err))?;
        successor_file.sync_all().map_err(|err| self.poison(err))?;
        sync_directory(&self.dir)?;
        write_wal_base(
            &self.dir,
            WalBase {
                lsn: reset_lsn,
                first_segment: successor_index,
            },
        )?;

        self.path = successor_path;
        self.file = successor_file;
        self.active_index = successor_index;
        self.base_lsn = reset_lsn;
        self.unsynced_bytes.store(0, Ordering::Release);
        self.oldest_unsynced_unix_ms.store(0, Ordering::Release);
        for segment in old_segments {
            durable_remove_file(&segment.path)?;
        }
        Ok(())
    }

    pub fn archive_and_reset(&mut self, archive_root: &Path) -> Result<Option<WalArchive>> {
        let archive = self.archive_current(archive_root)?;
        self.reset()?;
        if archive.is_some() {
            crate::failpoint::check("wal_archive.after_reset")?;
        }
        Ok(archive)
    }

    /// Publish a durable archive without retiring any live replay authority.
    /// Callers serialize capture with append/retention using the collection lock.
    pub(crate) fn archive_current(&self, archive_root: &Path) -> Result<Option<WalArchive>> {
        self.ensure_available()?;
        self.file.sync_all().map_err(|err| self.poison(err))?;
        let segments = wal_segments(&self.dir)?;
        let frozen =
            FrozenWalArchive::capture(&self.dir, read_wal_base(&self.dir)?, segments, self.len()?)?;
        frozen.map_or(Ok(None), |frozen| frozen.publish(archive_root).map(Some))
    }

    /// Rotate the active WAL at `end_lsn` and retain a descriptor for every
    /// immutable segment in the still-live prefix. Rotation changes no LSN and
    /// retires no replay authority.
    pub(crate) fn freeze_archive_cut(&mut self, end_lsn: u64) -> Result<Option<FrozenWalArchive>> {
        self.ensure_available()?;
        let actual_end = self.len()?;
        if actual_end != end_lsn {
            return Err(GaussError::InvalidRequest(format!(
                "WAL archive cut {end_lsn} does not match current end LSN {actual_end}"
            )));
        }
        let active_len = self.file.metadata()?.len();
        if active_len == 0 {
            self.file.sync_all().map_err(|err| self.poison(err))?;
        } else {
            self.rotate(active_len)?;
        }
        let base = read_wal_base(&self.dir)?;
        let segments = wal_segments(&self.dir)?
            .into_iter()
            .filter(|segment| segment.index < self.active_index)
            .collect::<Vec<_>>();
        FrozenWalArchive::capture(&self.dir, base, segments, end_lsn)
    }

    pub fn len(&self) -> Result<u64> {
        Ok(self.base_lsn + self.file.metadata()?.len())
    }

    /// Bytes physically retained in the live WAL generation. Unlike [`len`],
    /// this is not an absolute LSN and therefore returns to zero after reset.
    /// Compaction thresholds and storage metrics should use this value.
    pub fn retained_bytes(&self) -> Result<u64> {
        wal_segments(&self.dir)?
            .iter()
            .try_fold(0_u64, |total, segment| {
                Ok::<_, GaussError>(total + fs::metadata(&segment.path)?.len())
            })
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.retained_bytes()? == 0)
    }

    pub fn load(dir: &Path) -> Result<Vec<WalRecord>> {
        Self::load_from(dir, 0)
    }

    /// Absolute LSN of the first byte still retained by this WAL generation.
    /// Replication uses this to reject requests that require a snapshot rather
    /// than silently returning a later suffix.
    pub fn retained_base_lsn(dir: &Path) -> Result<u64> {
        Ok(read_wal_base(dir)?.lsn)
    }

    /// Load records whose starting LSN is at or beyond `watermark`.
    /// Prefix-dropped WALs retain absolute LSNs through `wal.base`.
    pub fn load_from(dir: &Path, watermark: u64) -> Result<Vec<WalRecord>> {
        let mut entries = Vec::new();
        Self::scan_from(dir, watermark, |record| {
            entries.push(record);
            Ok(())
        })?;
        Ok(entries)
    }

    /// Strict, bounded-memory WAL scan. Any torn header or payload is
    /// corruption, including on the final active segment.
    pub fn scan_from<F>(dir: &Path, watermark: u64, visitor: F) -> Result<WalScanStats>
    where
        F: FnMut(WalRecord) -> Result<()>,
    {
        let result = scan_records(dir, watermark, TailPolicy::Strict, visitor);
        if matches!(&result, Err(GaussError::WalCorruption { .. })) {
            metrics::counter!("chirondb_wal_corruption_total").increment(1);
        }
        result
    }

    /// Recovery scan that repairs only a torn header or payload at the end of
    /// the final active segment. Sealed-segment tears, CRC/LSN mismatches,
    /// excessive lengths, duplicate indices, and segment gaps remain fatal.
    pub fn recover_from<F>(dir: &Path, watermark: u64, visitor: F) -> Result<WalScanStats>
    where
        F: FnMut(WalRecord) -> Result<()>,
    {
        let started = std::time::Instant::now();
        let result = scan_records(dir, watermark, TailPolicy::RepairFinalActive, visitor);
        match &result {
            Ok(stats) => {
                metrics::counter!("chirondb_wal_recovery_records_total").increment(stats.records);
                metrics::histogram!("chirondb_wal_recovery_duration_seconds")
                    .record(started.elapsed().as_secs_f64());
            }
            Err(GaussError::WalCorruption { .. }) => {
                metrics::counter!("chirondb_wal_corruption_total").increment(1);
            }
            Err(_) => {}
        }
        result
    }

    /// Drop only complete WAL segment files covered by `up_to_lsn` while
    /// preserving absolute LSNs for the surviving suffix.
    pub fn drop_prefix(&mut self, up_to_lsn: u64) -> Result<()> {
        self.ensure_available()?;
        let wal_base = read_wal_base(&self.dir)?;
        let end_lsn = self.len()?;
        if up_to_lsn < wal_base.lsn || up_to_lsn > end_lsn {
            return Err(GaussError::InvalidRequest(format!(
                "WAL prefix LSN {up_to_lsn} is outside {}..={end_lsn}",
                wal_base.lsn
            )));
        }
        validate_record_boundary(&self.dir, up_to_lsn)?;
        self.file.sync_all().map_err(|err| self.poison(err))?;

        let active_len = self.file.metadata()?.len();
        if active_len > 0 && end_lsn <= up_to_lsn {
            self.rotate(active_len)?;
        }

        let segments = wal_segments(&self.dir)?;
        let mut new_base_lsn = wal_base.lsn;
        let mut drop_count = 0_usize;
        for segment in &segments {
            if segment.path == self.path {
                break;
            }
            let len = fs::metadata(&segment.path)?.len();
            if new_base_lsn + len > up_to_lsn {
                break;
            }
            new_base_lsn += len;
            drop_count += 1;
        }
        if drop_count == 0 {
            return Ok(());
        }

        let first_segment = segments[drop_count].index;
        write_wal_base(
            &self.dir,
            WalBase {
                lsn: new_base_lsn,
                first_segment,
            },
        )?;
        for segment in segments.into_iter().take(drop_count) {
            durable_remove_file(&segment.path)?;
        }
        sync_directory(&self.dir)?;
        Ok(())
    }

    pub fn truncate_to_lsn(dir: &Path, target_lsn: u64) -> Result<()> {
        let wal_base = read_wal_base(dir)?;
        let segments = wal_segments(dir)?;
        if segments.is_empty() {
            if target_lsn == wal_base.lsn {
                return Ok(());
            }
            return Err(GaussError::InvalidRequest(format!(
                "WAL target LSN {target_lsn} exceeds empty WAL"
            )));
        }

        validate_record_boundary(dir, target_lsn)?;
        let mut remaining = target_lsn - wal_base.lsn;
        for (index, segment) in segments.iter().enumerate() {
            let len = fs::metadata(&segment.path)?.len();
            if remaining >= len {
                remaining -= len;
                continue;
            }

            let file = OpenOptions::new().write(true).open(&segment.path)?;
            file.set_len(remaining)?;
            file.sync_all()?;
            for later in segments.iter().skip(index + 1) {
                durable_remove_file(&later.path)?;
            }
            sync_directory(dir)?;
            return Ok(());
        }

        if remaining == 0 {
            return Ok(());
        }
        Err(GaussError::InvalidRequest(format!(
            "WAL target LSN {target_lsn} exceeds WAL length"
        )))
    }

    pub fn truncate_to_unix_ms(dir: &Path, target_unix_ms: u64) -> Result<u64> {
        let target_lsn = Self::lsn_for_unix_ms(dir, target_unix_ms)?;
        Self::truncate_to_lsn(dir, target_lsn)?;
        Ok(target_lsn)
    }

    /// Resolve time without mutating the WAL, so whole-state restore can
    /// validate checkpoint authority before truncation.
    pub(crate) fn lsn_for_unix_ms(dir: &Path, target_unix_ms: u64) -> Result<u64> {
        target_lsn_for_unix_ms(dir, target_unix_ms)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn rotate(&mut self, current_len: u64) -> Result<()> {
        self.file.sync_all()?;
        crate::failpoint::check("wal_rotation.after_old_sync")?;
        self.unsynced_bytes.store(0, Ordering::Release);
        self.oldest_unsynced_unix_ms.store(0, Ordering::Release);
        self.base_lsn += current_len;
        self.active_index += 1;
        self.path = segment_path(&self.dir, self.active_index);
        self.file = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(&self.path)?;
        self.file.sync_all()?;
        crate::failpoint::check("wal_rotation.after_new_sync")?;
        sync_directory(&self.dir)?;
        crate::failpoint::check("wal_rotation.after_directory_sync")?;
        #[cfg(any(test, feature = "fault-injection"))]
        crate::fs_util::fault_injection::crash_hook(
            crate::fs_util::fault_injection::HOOK_WAL_AFTER_ROTATION_PUBLISH,
        )?;
        Ok(())
    }
}

impl FrozenWalArchive {
    fn capture(
        wal_dir: &Path,
        base: WalBase,
        segments: Vec<WalSegment>,
        end_lsn: u64,
    ) -> Result<Option<Self>> {
        let mut data_bytes = 0_u64;
        let mut frozen_segments = Vec::with_capacity(segments.len());
        for segment in segments {
            let bytes = fs::metadata(&segment.path)?.len();
            data_bytes = data_bytes.checked_add(bytes).ok_or_else(|| {
                GaussError::InvalidRequest("WAL archive byte range overflow".to_string())
            })?;
            frozen_segments.push(FrozenWalSegment {
                index: segment.index,
                path: segment.path,
                bytes,
            });
        }
        let computed_end = base.lsn.checked_add(data_bytes).ok_or_else(|| {
            GaussError::InvalidRequest("WAL archive LSN range overflow".to_string())
        })?;
        if computed_end != end_lsn {
            return Err(GaussError::WalCorruption {
                path: wal_dir.display().to_string(),
                message: format!(
                    "frozen WAL archive spans {}..{computed_end}, expected end LSN {end_lsn}",
                    base.lsn
                ),
            });
        }
        if data_bytes == 0 {
            return Ok(None);
        }
        let base_path = wal_dir.join(WAL_BASE_FILE);
        let base_bytes = match fs::read(&base_path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        Ok(Some(Self {
            base,
            base_bytes,
            segments: frozen_segments,
            end_lsn,
        }))
    }

    pub(crate) fn publish(&self, archive_root: &Path) -> Result<WalArchive> {
        let archive_root_created = !archive_root.exists();
        fs::create_dir_all(archive_root)?;
        if archive_root_created && let Some(parent) = archive_root.parent() {
            sync_directory(parent)?;
        }
        sync_directory(archive_root)?;
        let archive_path = next_archive_path(archive_root, self.end_lsn)?;
        let tmp_path = archive_path.with_extension("tmp");
        if tmp_path.exists() {
            durable_remove_dir_all(&tmp_path)?;
        }
        fs::create_dir_all(&tmp_path)?;
        sync_directory(archive_root)?;
        for segment in &self.segments {
            let source_bytes = fs::metadata(&segment.path)?.len();
            if source_bytes != segment.bytes {
                return Err(GaussError::WalCorruption {
                    path: segment.path.display().to_string(),
                    message: format!(
                        "frozen WAL segment size changed from {} to {source_bytes}",
                        segment.bytes
                    ),
                });
            }
            durable_copy(&segment.path, &tmp_path.join(segment_name(segment.index)))?;
        }
        if let Some(base_bytes) = &self.base_bytes {
            atomic_write(&tmp_path.join(WAL_BASE_FILE), base_bytes)?;
        }
        if read_wal_base(&tmp_path)? != self.base {
            return Err(GaussError::WalCorruption {
                path: tmp_path.display().to_string(),
                message: "frozen WAL base changed while publishing archive".to_string(),
            });
        }
        write_archive_manifest(&tmp_path)?;
        let bytes = dir_size(&tmp_path)?;
        sync_tree(&tmp_path)?;
        crate::failpoint::check("wal_archive.after_staging_sync")?;
        #[cfg(any(test, feature = "fault-injection"))]
        if let Some(fault) = crate::fs_util::fault_injection::take_if(|fault| {
            fault == crate::fs_util::fault_injection::Fault::Rename
        }) {
            return Err(crate::fs_util::fault_injection::injected_error(fault).into());
        }
        fs::rename(&tmp_path, &archive_path)?;
        crate::failpoint::check("wal_archive.after_publish_before_dir_sync")?;
        sync_directory(archive_root)?;
        crate::failpoint::check("wal_archive.after_publish_sync")?;
        #[cfg(any(test, feature = "fault-injection"))]
        crate::fs_util::fault_injection::crash_hook(
            crate::fs_util::fault_injection::HOOK_WAL_AFTER_ARCHIVE_PUBLISH,
        )?;
        Ok(WalArchive {
            path: archive_path,
            segments: self.segments.len(),
            bytes,
        })
    }
}

pub fn prune_archives(archive_root: &Path, retain_last: usize) -> Result<WalArchivePrune> {
    let mut archives = archive_dirs(archive_root)?;
    archives.sort_by_key(|archive| archive.index);
    let pruned_count = archives.len().saturating_sub(retain_last);
    let mut pruned_bytes = 0_u64;
    for archive in archives.iter().take(pruned_count) {
        pruned_bytes += dir_size(&archive.path)?;
        durable_remove_dir_all(&archive.path)?;
    }

    Ok(WalArchivePrune {
        retained_archives: archives.len().saturating_sub(pruned_count),
        pruned_archives: pruned_count,
        pruned_bytes,
    })
}

pub fn prune_archives_over_bytes(archive_root: &Path, max_bytes: u64) -> Result<WalArchivePrune> {
    let mut archives = archive_dirs(archive_root)?;
    archives.sort_by_key(|archive| archive.index);
    let mut archives = archives
        .into_iter()
        .map(|archive| {
            let bytes = dir_size(&archive.path)?;
            Ok((archive, bytes))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut total_bytes = archives.iter().map(|(_, bytes)| *bytes).sum::<u64>();
    let mut pruned_archives = 0_usize;
    let mut pruned_bytes = 0_u64;

    for (archive, bytes) in archives.drain(..) {
        if total_bytes <= max_bytes {
            break;
        }
        durable_remove_dir_all(&archive.path)?;
        total_bytes = total_bytes.saturating_sub(bytes);
        pruned_archives += 1;
        pruned_bytes += bytes;
    }

    Ok(WalArchivePrune {
        retained_archives: archive_dirs(archive_root)?.len(),
        pruned_archives,
        pruned_bytes,
    })
}

pub fn prune_archives_older_than(
    archive_root: &Path,
    max_age: Duration,
) -> Result<WalArchivePrune> {
    let archives = archive_dirs(archive_root)?;
    let cutoff = SystemTime::now()
        .checked_sub(max_age)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let mut retained_archives = 0_usize;
    let mut pruned_archives = 0_usize;
    let mut pruned_bytes = 0_u64;

    for archive in archives {
        let modified = fs::metadata(&archive.path)?.modified()?;
        if modified <= cutoff {
            pruned_bytes += dir_size(&archive.path)?;
            durable_remove_dir_all(&archive.path)?;
            pruned_archives += 1;
        } else {
            retained_archives += 1;
        }
    }

    Ok(WalArchivePrune {
        retained_archives,
        pruned_archives,
        pruned_bytes,
    })
}

#[derive(Clone, Debug)]
struct WalSegment {
    index: u64,
    path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TailPolicy {
    Strict,
    RepairFinalActive,
}

fn scan_records<F>(
    dir: &Path,
    watermark: u64,
    tail_policy: TailPolicy,
    mut visitor: F,
) -> Result<WalScanStats>
where
    F: FnMut(WalRecord) -> Result<()>,
{
    scan_frames(dir, watermark, tail_policy, |record, payload| {
        // Ordinary streaming visitors do not retain both JSON and decoded state
        // while backpressure applies. Only archive replay needs the raw frame.
        drop(payload);
        visitor(record)
    })
}

fn scan_frames<F>(
    dir: &Path,
    watermark: u64,
    tail_policy: TailPolicy,
    mut visitor: F,
) -> Result<WalScanStats>
where
    F: FnMut(WalRecord, Vec<u8>) -> Result<()>,
{
    verify_archive_manifest_if_present(dir)?;
    let wal_base = read_wal_base(dir)?;
    let segments = wal_segments(dir)?;
    if segments.is_empty() {
        if watermark <= wal_base.lsn {
            return Ok(WalScanStats {
                end_lsn: wal_base.lsn,
                ..WalScanStats::default()
            });
        }
        return Err(GaussError::InvalidRequest(format!(
            "WAL watermark {watermark} exceeds WAL length {}",
            wal_base.lsn
        )));
    }

    let mut stats = WalScanStats::default();
    let mut offset = wal_base.lsn;
    let mut watermark_is_boundary = watermark <= wal_base.lsn;
    for (segment_position, segment) in segments.iter().enumerate() {
        let final_active = segment_position + 1 == segments.len();
        let (mut file, segment_len) = open_wal_reader(&segment.path)?;
        if segment_len == 0 && !final_active {
            return Err(wal_corruption(&segment.path, "empty sealed wal segment"));
        }
        let mut segment_offset = 0_u64;
        while segment_offset < segment_len {
            let record_lsn = offset;
            let remaining = segment_len - segment_offset;
            if remaining < HEADER_LEN as u64 {
                return repair_or_reject_torn_tail(
                    dir,
                    segment,
                    final_active,
                    tail_policy,
                    segment_offset,
                    remaining,
                    stats,
                    offset,
                    watermark,
                    "partial wal header",
                );
            }

            let mut header = [0_u8; HEADER_LEN];
            file.read_exact(&mut header)?;
            let len = u32::from_le_bytes(header[0..4].try_into().expect("length header"));
            let payload_len = len as usize;
            validate_payload_len(&segment.path, payload_len)?;
            let record_bytes = HEADER_LEN as u64 + len as u64;
            if remaining < record_bytes {
                return repair_or_reject_torn_tail(
                    dir,
                    segment,
                    final_active,
                    tail_policy,
                    segment_offset,
                    remaining,
                    stats,
                    offset,
                    watermark,
                    "torn wal record",
                );
            }

            let expected_crc = u32::from_le_bytes(header[4..8].try_into().expect("crc header"));
            let mut payload = vec![0_u8; payload_len];
            file.read_exact(&mut payload)?;
            if checksum(&payload) != expected_crc {
                return Err(wal_corruption(&segment.path, "crc mismatch"));
            }

            let record = decode_record(&segment.path, record_lsn, &payload)?;
            if record_lsn == watermark {
                watermark_is_boundary = true;
            }
            if record.lsn >= watermark {
                visitor(record, payload)?;
                stats.records += 1;
            }
            segment_offset += record_bytes;
            offset += record_bytes;
            stats.bytes += record_bytes;
            if offset == watermark {
                watermark_is_boundary = true;
            }
            if offset > watermark && !watermark_is_boundary && watermark > wal_base.lsn {
                return Err(GaussError::InvalidRequest(format!(
                    "WAL watermark {watermark} is not a record boundary"
                )));
            }
        }
    }

    if watermark > offset {
        return Err(GaussError::InvalidRequest(format!(
            "WAL watermark {watermark} exceeds WAL length {offset}"
        )));
    }
    stats.end_lsn = offset;
    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
fn repair_or_reject_torn_tail(
    dir: &Path,
    segment: &WalSegment,
    final_active: bool,
    tail_policy: TailPolicy,
    last_good_segment_offset: u64,
    torn_bytes: u64,
    mut stats: WalScanStats,
    end_lsn: u64,
    watermark: u64,
    message: &str,
) -> Result<WalScanStats> {
    if !final_active || tail_policy == TailPolicy::Strict {
        return Err(wal_corruption(&segment.path, message));
    }
    if watermark > end_lsn {
        return Err(GaussError::InvalidRequest(format!(
            "WAL watermark {watermark} exceeds repaired WAL length {end_lsn}"
        )));
    }

    let file = OpenOptions::new().write(true).open(&segment.path)?;
    file.set_len(last_good_segment_offset)?;
    file.sync_all()?;
    sync_directory(dir)?;
    tracing::warn!(
        path = %segment.path.display(),
        repaired_tail_bytes = torn_bytes,
        end_lsn,
        "repaired torn final active WAL tail"
    );
    stats.end_lsn = end_lsn;
    stats.repaired_tail_bytes = torn_bytes;
    metrics::counter!("chirondb_wal_tail_repairs_total").increment(1);
    Ok(stats)
}

fn validate_payload_len(path: &Path, payload_len: usize) -> Result<()> {
    if payload_len > MAX_WAL_RECORD_BYTES {
        return Err(wal_corruption(
            path,
            &format!("wal record length {payload_len} exceeds maximum {MAX_WAL_RECORD_BYTES}"),
        ));
    }
    Ok(())
}

fn validate_append_payload_len(payload_len: usize) -> Result<()> {
    if payload_len > MAX_WAL_RECORD_BYTES {
        return Err(GaussError::InvalidRequest(format!(
            "WAL record is {payload_len} bytes; maximum is {MAX_WAL_RECORD_BYTES} bytes"
        )));
    }
    Ok(())
}

fn wal_corruption(path: &Path, message: &str) -> GaussError {
    GaussError::WalCorruption {
        path: path.display().to_string(),
        message: message.to_string(),
    }
}

fn wal_segments(dir: &Path) -> Result<Vec<WalSegment>> {
    let wal_base = read_wal_base(dir)?;
    let segments = all_wal_segments(dir)?
        .into_iter()
        .filter(|segment| segment.index >= wal_base.first_segment)
        .collect::<Vec<_>>();
    for (position, segment) in segments.iter().enumerate() {
        let expected = wal_base
            .first_segment
            .checked_add(position as u64)
            .ok_or_else(|| wal_corruption(&segment.path, "wal segment index overflow"))?;
        if segment.index != expected {
            let message = if position > 0 && segment.index == segments[position - 1].index {
                format!("duplicate wal segment index {}", segment.index)
            } else {
                format!(
                    "wal segment gap: expected index {expected}, found {}",
                    segment.index
                )
            };
            return Err(wal_corruption(&segment.path, &message));
        }
    }
    Ok(segments)
}

fn all_wal_segments(dir: &Path) -> Result<Vec<WalSegment>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut segments = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        if path
            .extension()
            .is_none_or(|extension| extension != "gdwal")
        {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| wal_corruption(&path, "WAL segment name is not valid UTF-8"))?;
        let index = file_name
            .strip_suffix(".gdwal")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| wal_corruption(&path, "invalid WAL segment index"))?;
        segments.push(WalSegment { index, path });
    }
    segments.sort_by_key(|segment| segment.index);
    Ok(segments)
}

fn read_wal_base(dir: &Path) -> Result<WalBase> {
    let primary = dir.join(WAL_BASE_FILE);
    #[cfg(windows)]
    let path = if primary.exists() {
        primary
    } else {
        let previous = dir.join(WAL_BASE_PREVIOUS_FILE);
        if previous.exists() {
            previous
        } else {
            return Ok(WalBase::default());
        }
    };
    #[cfg(not(windows))]
    let path = primary;
    if !path.exists() {
        return Ok(WalBase::default());
    }
    if fs::metadata(&path)?.len() > 1024 * 1024 {
        return Err(wal_corruption(
            &path,
            "wal.base exceeds maximum encoded size",
        ));
    }
    let bytes = encryption::read_persistent(&path)
        .map_err(|error| wal_corruption(&path, &format!("cannot decode wal.base: {error}")))?;
    if bytes.len() != WAL_BASE_LEN || &bytes[..8] != WAL_BASE_MAGIC {
        return Err(GaussError::WalCorruption {
            path: path.display().to_string(),
            message: "invalid wal.base header".to_string(),
        });
    }
    let payload = &bytes[8..24];
    let expected_crc = u32::from_le_bytes(bytes[24..28].try_into().expect("wal.base crc"));
    if checksum(payload) != expected_crc {
        return Err(GaussError::WalCorruption {
            path: path.display().to_string(),
            message: "wal.base crc mismatch".to_string(),
        });
    }
    Ok(WalBase {
        lsn: u64::from_le_bytes(payload[..8].try_into().expect("wal.base lsn")),
        first_segment: u64::from_le_bytes(
            payload[8..16].try_into().expect("wal.base first segment"),
        ),
    })
}

fn write_wal_base(dir: &Path, wal_base: WalBase) -> Result<()> {
    let path = dir.join(WAL_BASE_FILE);
    let tmp_path = dir.join(format!("{WAL_BASE_FILE}.tmp"));
    let mut payload = [0_u8; 16];
    payload[..8].copy_from_slice(&wal_base.lsn.to_le_bytes());
    payload[8..].copy_from_slice(&wal_base.first_segment.to_le_bytes());
    let mut plaintext = Vec::with_capacity(WAL_BASE_LEN);
    plaintext.extend_from_slice(WAL_BASE_MAGIC);
    plaintext.extend_from_slice(&payload);
    plaintext.extend_from_slice(&checksum(&payload).to_le_bytes());
    let encoded = encryption::encode_persistent(FileType::Wal, &plaintext)?;
    let mut file = File::create(&tmp_path)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    publish_wal_base(&tmp_path, &path, dir)?;
    Ok(())
}

#[cfg(not(windows))]
fn publish_wal_base(tmp_path: &Path, path: &Path, _dir: &Path) -> Result<()> {
    durable_rename(tmp_path, path)
}

#[cfg(windows)]
fn publish_wal_base(tmp_path: &Path, path: &Path, dir: &Path) -> Result<()> {
    let previous = dir.join(WAL_BASE_PREVIOUS_FILE);
    if previous.exists() {
        durable_remove_file(&previous)?;
    }
    if path.exists() {
        durable_rename(path, &previous)?;
    }
    if let Err(error) = durable_rename(tmp_path, path) {
        if previous.exists() {
            let _ = durable_rename(&previous, path);
        }
        return Err(error);
    }
    if previous.exists() {
        durable_remove_file(&previous)?;
    }
    Ok(())
}

#[cfg(windows)]
fn recover_interrupted_wal_base_publish(dir: &Path) -> Result<()> {
    let primary = dir.join(WAL_BASE_FILE);
    let previous = dir.join(WAL_BASE_PREVIOUS_FILE);
    match (primary.exists(), previous.exists()) {
        (false, true) => durable_rename(&previous, &primary),
        (true, true) => durable_remove_file(&previous),
        _ => Ok(()),
    }
}

fn validate_record_boundary(dir: &Path, target_lsn: u64) -> Result<()> {
    let wal_base = read_wal_base(dir)?;
    if target_lsn == wal_base.lsn {
        return Ok(());
    }
    if target_lsn < wal_base.lsn {
        return Err(GaussError::InvalidRequest(format!(
            "WAL target LSN {target_lsn} precedes retained WAL base {}",
            wal_base.lsn
        )));
    }
    scan_records(dir, target_lsn, TailPolicy::Strict, |_| Ok(()))?;
    Ok(())
}

fn target_lsn_for_unix_ms(dir: &Path, target_unix_ms: u64) -> Result<u64> {
    let wal_base = read_wal_base(dir)?;
    let mut last_included_lsn = wal_base.lsn;
    let mut previous_was_included = false;
    let mut cutoff_seen = false;
    let stats = scan_records(dir, wal_base.lsn, TailPolicy::Strict, |record| {
        if previous_was_included {
            last_included_lsn = record.lsn;
        }
        if !cutoff_seen && record.unix_ms <= target_unix_ms {
            previous_was_included = true;
        } else {
            previous_was_included = false;
            cutoff_seen = true;
        }
        Ok(())
    })?;
    if previous_was_included {
        last_included_lsn = stats.end_lsn;
    }
    Ok(last_included_lsn)
}

fn write_archive_manifest(dir: &Path) -> Result<()> {
    let manifest = archive_manifest_for_dir(dir)?;
    let path = dir.join(WAL_ARCHIVE_MANIFEST_FILE);
    let mut bytes = serde_json::to_vec(&manifest)?;
    bytes.push(b'\n');
    encryption::atomic_write_persistent(&path, FileType::Metadata, &bytes)
}

fn archive_manifest_for_dir(dir: &Path) -> Result<WalArchiveManifest> {
    let mut names = wal_segments(dir)?
        .into_iter()
        .map(|segment| segment_name(segment.index))
        .collect::<Vec<_>>();
    archive_manifest_for_names(dir, &mut names)
}

fn archive_manifest_for_encrypted_dir(dir: &Path) -> Result<WalArchiveManifest> {
    // The wal.base sidecar is already encrypted and cannot use the
    // process-global reader during an offline private-generation rewrite.
    // Archive directories are immutable, so their on-disk segment set is the
    // exact set that the rebuilt manifest must bind.
    let mut names = all_wal_segments(dir)?
        .into_iter()
        .map(|segment| segment_name(segment.index))
        .collect::<Vec<_>>();
    archive_manifest_for_names(dir, &mut names)
}

fn archive_manifest_for_names(dir: &Path, names: &mut Vec<String>) -> Result<WalArchiveManifest> {
    if dir.join(WAL_BASE_FILE).exists() {
        names.push(WAL_BASE_FILE.to_string());
    }
    names.sort();
    let mut files = Vec::with_capacity(names.len());
    for name in names.drain(..) {
        let path = dir.join(&name);
        files.push(WalArchiveManifestFile {
            name,
            bytes: fs::metadata(&path)?.len(),
            sha256: sha256_file(&path)?,
            encoding: archive_file_encoding(&path),
        });
    }
    Ok(WalArchiveManifest {
        version: WAL_ARCHIVE_MANIFEST_VERSION,
        files,
    })
}

/// Rebuild every local archive manifest after encryption migration or KEK
/// rewrap changes the raw child bytes. External mirrors are intentionally not
/// traversed by this local-tree operation.
pub(crate) fn refresh_archive_manifests_for_encryption(
    root: &Path,
    keyring: &encryption::Keyring,
) -> Result<usize> {
    let mut directories = Vec::new();
    collect_archive_manifest_directories(root, &mut directories)?;
    directories.sort();
    directories.dedup();
    for directory in &directories {
        let expected = archive_manifest_for_encrypted_dir(directory)?;
        let mut plaintext = serde_json::to_vec(&expected)?;
        plaintext.push(b'\n');
        let path = directory.join(WAL_ARCHIVE_MANIFEST_FILE);
        let envelope = encryption::encrypt_bytes(keyring, FileType::Metadata, &plaintext)?;
        atomic_write(&path, &envelope)?;
        let (_, decoded) = encryption::decrypt_bytes(keyring, &fs::read(&path)?)?;
        let actual: WalArchiveManifest = serde_json::from_slice(&decoded).map_err(|error| {
            wal_corruption(&path, &format!("invalid rebuilt manifest: {error}"))
        })?;
        if actual != expected {
            return Err(wal_corruption(
                &path,
                "rebuilt archive manifest does not match rewritten WAL files",
            ));
        }
    }
    Ok(directories.len())
}

fn collect_archive_manifest_directories(root: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(GaussError::InvalidRequest(format!(
                "refusing symbolic link while refreshing WAL archives: {}",
                entry.path().display()
            )));
        }
        if file_type.is_dir() {
            collect_archive_manifest_directories(&entry.path(), output)?;
        } else if file_type.is_file()
            && entry.file_name().to_str() == Some(WAL_ARCHIVE_MANIFEST_FILE)
        {
            output.push(root.to_path_buf());
        }
    }
    Ok(())
}

fn verify_archive_manifest_if_present(dir: &Path) -> Result<()> {
    let path = dir.join(WAL_ARCHIVE_MANIFEST_FILE);
    if !path.exists() {
        if is_probable_archive_dir(dir) {
            tracing::warn!(
                path = %dir.display(),
                "legacy WAL archive has no integrity manifest; validating WAL framing only"
            );
        }
        return Ok(());
    }
    let manifest_bytes = encryption::read_persistent(&path)
        .map_err(|err| wal_corruption(&path, &format!("cannot decode archive manifest: {err}")))?;
    let manifest: WalArchiveManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|err| wal_corruption(&path, &format!("invalid archive manifest: {err}")))?;
    if !matches!(manifest.version, 1 | WAL_ARCHIVE_MANIFEST_VERSION) {
        return Err(wal_corruption(
            &path,
            &format!("unsupported archive manifest version {}", manifest.version),
        ));
    }

    let mut expected_names = wal_segments(dir)?
        .into_iter()
        .map(|segment| segment_name(segment.index))
        .collect::<Vec<_>>();
    if dir.join(WAL_BASE_FILE).exists() {
        expected_names.push(WAL_BASE_FILE.to_string());
    }
    expected_names.sort();
    let mut manifest_names = manifest
        .files
        .iter()
        .map(|file| file.name.clone())
        .collect::<Vec<_>>();
    manifest_names.sort();
    if manifest_names != expected_names {
        return Err(wal_corruption(
            &path,
            "archive manifest file set does not match WAL contents",
        ));
    }

    for entry in manifest.files {
        if entry.name.contains('/') || entry.name.contains('\\') || entry.name == "." {
            return Err(wal_corruption(&path, "unsafe archive manifest file name"));
        }
        let file_path = dir.join(&entry.name);
        let actual_bytes = fs::metadata(&file_path)?.len();
        if actual_bytes != entry.bytes {
            return Err(wal_corruption(
                &file_path,
                &format!(
                    "archive manifest size mismatch: expected {}, found {actual_bytes}",
                    entry.bytes
                ),
            ));
        }
        let actual_sha256 = sha256_file(&file_path)?;
        if actual_sha256 != entry.sha256 {
            return Err(wal_corruption(
                &file_path,
                "archive manifest sha256 mismatch",
            ));
        }
        if manifest.version >= 2 {
            let expected_encoding = archive_file_encoding(&file_path);
            if entry.encoding != expected_encoding {
                return Err(wal_corruption(
                    &file_path,
                    &format!(
                        "archive manifest encoding mismatch: expected {}, found {}",
                        entry.encoding, expected_encoding
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn archive_file_encoding(path: &Path) -> String {
    let mut prefix = [0_u8; 16];
    let read = File::open(path)
        .and_then(|mut file| file.read(&mut prefix))
        .unwrap_or(0);
    if read >= encryption::MAGIC.len() && prefix[..8] == *encryption::MAGIC {
        return "chirenc1".to_string();
    }
    if path.extension().and_then(|extension| extension.to_str()) == Some("gdwal") {
        if read == 0 {
            return "wal-framed-empty".to_string();
        }
        if read >= 16 && prefix[8..16] == *encryption::MAGIC {
            return "wal-framed-chirenc1".to_string();
        }
        return "wal-framed-json".to_string();
    }
    "plaintext".to_string()
}

fn is_probable_archive_dir(dir: &Path) -> bool {
    dir.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.split_once('-'))
        .is_some_and(|(prefix, _)| {
            !prefix.is_empty() && prefix.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[derive(Clone, Debug)]
struct WalArchiveDir {
    index: u64,
    path: PathBuf,
}

fn archive_dirs(archive_root: &Path) -> Result<Vec<WalArchiveDir>> {
    if !archive_root.exists() {
        return Ok(Vec::new());
    }
    let mut archives = Vec::new();
    for entry in fs::read_dir(archive_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if file_name.ends_with(".tmp") {
            continue;
        }
        let Some(prefix) = file_name.split('-').next() else {
            continue;
        };
        let Ok(index) = prefix.parse::<u64>() else {
            continue;
        };
        archives.push(WalArchiveDir {
            index,
            path: entry.path(),
        });
    }
    Ok(archives)
}

fn dir_size(path: &Path) -> Result<u64> {
    let mut size = 0_u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            size += dir_size(&entry.path())?;
        } else if file_type.is_file() {
            size += entry.metadata()?.len();
        }
    }
    Ok(size)
}

fn segment_path(dir: &Path, index: u64) -> PathBuf {
    dir.join(segment_name(index))
}

fn segment_name(index: u64) -> String {
    format!("{index:06}.gdwal")
}

fn next_archive_path(archive_root: &Path, end_lsn: u64) -> Result<PathBuf> {
    let mut next_index = 0_u64;
    for archive in archive_dirs(archive_root)? {
        next_index = next_index.max(archive.index.saturating_add(1));
    }
    Ok(archive_root.join(format!("{next_index:06}-{end_lsn:020}")))
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PersistedWalRecord {
    Record(WalRecord),
    Legacy(WalEntry),
}

fn open_wal_reader(path: &Path) -> Result<(Box<dyn Read>, u64)> {
    let mut file = File::open(path)?;
    let mut prefix = [0_u8; 8];
    let read = file.read(&mut prefix)?;
    if read == encryption::MAGIC.len() && prefix == *encryption::MAGIC {
        let length = encryption::persistent_plaintext_len(path)
            .map_err(|error| wal_corruption(path, &format!("cannot inspect WAL: {error}")))?;
        let reader = encryption::open_persistent_reader(path)
            .map_err(|error| wal_corruption(path, &format!("cannot decrypt WAL: {error}")))?;
        return Ok((reader, length));
    }
    file.rewind()?;
    let length = file.metadata()?.len();
    Ok((Box::new(file), length))
}

fn decode_record(path: &Path, record_lsn: u64, payload: &[u8]) -> Result<WalRecord> {
    let plaintext = encryption::decode_persistent(payload).map_err(|error| {
        wal_corruption(path, &format!("cannot authenticate WAL record: {error}"))
    })?;
    let persisted = serde_json::from_slice::<PersistedWalRecord>(&plaintext)
        .map_err(|error| wal_corruption(path, &format!("invalid WAL record JSON: {error}")))?;
    match persisted {
        PersistedWalRecord::Record(record) => {
            if record.lsn != record_lsn {
                return Err(GaussError::WalCorruption {
                    path: path.display().to_string(),
                    message: "lsn mismatch".to_string(),
                });
            }
            Ok(record)
        }
        PersistedWalRecord::Legacy(entry) => Ok(WalRecord {
            lsn: record_lsn,
            unix_ms: 0,
            entry,
        }),
    }
}

fn encode_record(lsn: u64, entry: &WalEntry) -> Result<Vec<u8>> {
    let plaintext = serde_json::to_vec(&WalRecord {
        lsn,
        unix_ms: current_unix_ms(),
        entry: entry.clone(),
    })?;
    encryption::encode_persistent(FileType::Wal, &plaintext).map(|payload| payload.into_owned())
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn checksum(payload: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(payload);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{File, OpenOptions},
        io::Write,
        time::Duration,
    };

    use serde_json::json;
    use tempfile::TempDir;

    use crate::{
        DistanceMetric,
        fs_util::fault_injection::{Fault, inject_once},
        graph::{
            EdgeId, EdgeMutation, GraphEpoch, GraphNamespace, MAX_EDGE_PROPERTY_BYTES,
            MAX_GRAPH_EDGES_PER_BATCH, Nid, TypeId,
        },
        model::{CollectionConfig, Point},
        wal::{
            GraphBatch, GraphDeferredBind, GraphDeferredEndpoint, GraphDeferredSessionMutation,
            GraphEdgeBind, GraphHandleAssignment, GraphIdempotencyState, GraphPointMutation,
            GraphTypeConfiguration, Wal, WalEntry, WalRecord, checksum,
        },
    };

    #[test]
    fn appends_lsn_records() {
        let temp = TempDir::new().unwrap();
        let mut wal = Wal::open(temp.path()).unwrap();
        let first_end = wal
            .append(&WalEntry::Delete {
                id: "old".to_string(),
            })
            .unwrap();
        let second_end = wal
            .append(&WalEntry::Delete {
                id: "new".to_string(),
            })
            .unwrap();
        assert!(second_end > first_end);

        let records = Wal::load(temp.path()).unwrap();
        assert_eq!(records[0].lsn, 0);
        assert_eq!(records[1].lsn, first_end);
    }

    #[test]
    fn batch_and_catalog_entries_round_trip_without_changing_legacy_variants() {
        let point = Point {
            id: "batch-point".to_string(),
            vector: vec![1.0, 0.0],
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({"kind": "test"}),
        };
        let config = test_config("catalog");
        let graph_batch = GraphBatch {
            point_mutations: vec![GraphPointMutation::Upsert {
                point: point.clone(),
            }],
            handle_assignments: vec![GraphHandleAssignment {
                point_id: point.id.clone(),
                nid: Nid::from_parts(1, 1).unwrap(),
            }],
            ..GraphBatch::default()
        };
        let entries = [
            WalEntry::UpsertBatch {
                points: vec![point],
            },
            WalEntry::DeleteBatch {
                ids: vec!["batch-point".to_string()],
            },
            WalEntry::CreateCollection { config },
            WalEntry::DropCollection {
                name: "catalog".to_string(),
            },
            WalEntry::GraphBatch { batch: graph_batch },
            WalEntry::GraphEpochAdvance {
                epoch: GraphEpoch::INITIAL,
                enabled: true,
            },
        ];

        for entry in entries {
            let encoded = serde_json::to_vec(&entry).unwrap();
            let decoded: WalEntry = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(
                std::mem::discriminant(&decoded),
                std::mem::discriminant(&entry)
            );
        }

        let legacy: WalEntry = serde_json::from_str(r#"{"Delete":{"id":"legacy"}}"#).unwrap();
        assert!(matches!(legacy, WalEntry::Delete { id } if id == "legacy"));
    }

    #[test]
    fn graph_batch_validates_every_group_and_rejects_unknown_fields() {
        let point = Point {
            id: "node-a".to_string(),
            vector: vec![1.0, 0.0],
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({"kind": "test"}),
        };
        let edge_id = EdgeId::from_parts(3, 1).unwrap();
        let batch = GraphBatch {
            type_configurations: vec![GraphTypeConfiguration {
                type_id: TypeId::from_raw(1),
                name: "cites".to_string(),
                weight_property: Some("weight".to_string()),
            }],
            point_mutations: vec![GraphPointMutation::Upsert {
                point: point.clone(),
            }],
            handle_assignments: vec![GraphHandleAssignment {
                point_id: point.id,
                nid: Nid::from_parts(3, 1).unwrap(),
            }],
            edge_mutations: vec![EdgeMutation::Relate(crate::graph::RelateMutation {
                edge_id,
                source: Nid::from_parts(3, 1).unwrap(),
                target: Nid::from_parts(3, 2).unwrap(),
                type_id: TypeId::from_raw(1),
                namespace: GraphNamespace::Tenant("tenant-a".to_string()),
                properties: json!({"since": 2026}),
            })],
            deferred_binds: vec![GraphDeferredBind {
                session_id: "load-1".to_string(),
                edge_id: EdgeId::from_parts(3, 2).unwrap(),
                source_point_id: "node-a".to_string(),
                target_point_id: "node-later".to_string(),
                source_nid: Some(Nid::from_parts(3, 1).unwrap()),
                target_nid: None,
                type_id: TypeId::from_raw(1),
                namespace: GraphNamespace::Tenant("tenant-a".to_string()),
                properties: json!({}),
            }],
            edge_binds: vec![GraphEdgeBind {
                session_id: "load-1".to_string(),
                edge_id: EdgeId::from_parts(3, 2).unwrap(),
                endpoint: GraphDeferredEndpoint::Target,
                point_id: "node-later".to_string(),
                nid: Nid::from_parts(3, 2).unwrap(),
            }],
            deferred_sessions: vec![GraphDeferredSessionMutation::Open {
                session_id: "load-1".to_string(),
            }],
            idempotency: Some(GraphIdempotencyState {
                key: "request-1".to_string(),
                request_sha256: [7; 32],
                created_at_unix_ms: 1_700_000_000_000,
                expires_at_unix_ms: 1_700_086_400_000,
                edge_ids: vec![edge_id, EdgeId::from_parts(3, 2).unwrap()],
            }),
            ..GraphBatch::default()
        };
        batch.validate().unwrap();

        let mut zero_request_hash = batch.clone();
        zero_request_hash
            .idempotency
            .as_mut()
            .unwrap()
            .request_sha256 = [0; 32];
        assert!(zero_request_hash.validate().is_err());

        let mut incomplete_result = batch.clone();
        incomplete_result.idempotency.as_mut().unwrap().edge_ids = vec![edge_id];
        assert!(incomplete_result.validate().is_err());

        let mut unsupported_legacy_deferred = serde_json::to_value(&batch).unwrap();
        let deferred = unsupported_legacy_deferred["deferred_binds"][0]
            .as_object_mut()
            .unwrap();
        deferred.remove("session_id");
        deferred.remove("source_nid");
        deferred.remove("target_nid");
        let decoded = serde_json::from_value::<GraphBatch>(unsupported_legacy_deferred).unwrap();
        assert!(decoded.validate().is_err());

        let mut encoded = serde_json::to_value(&batch).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .insert("future_group".to_string(), json!([]));
        assert!(serde_json::from_value::<GraphBatch>(encoded).is_err());

        let mut legacy = serde_json::to_value(&batch).unwrap();
        legacy.as_object_mut().unwrap().remove("graph_epoch");
        assert_eq!(
            serde_json::from_value::<GraphBatch>(legacy)
                .unwrap()
                .graph_epoch,
            GraphEpoch::INITIAL
        );

        let mut zero_epoch = serde_json::to_value(&batch).unwrap();
        zero_epoch
            .as_object_mut()
            .unwrap()
            .insert("graph_epoch".to_string(), json!(0));
        assert!(
            serde_json::from_value::<GraphBatch>(zero_epoch)
                .unwrap()
                .validate()
                .is_err()
        );

        let duplicate_type = GraphBatch {
            type_configurations: vec![
                GraphTypeConfiguration {
                    type_id: TypeId::from_raw(1),
                    name: "cites".to_string(),
                    weight_property: None,
                },
                GraphTypeConfiguration {
                    type_id: TypeId::from_raw(1),
                    name: "mentions".to_string(),
                    weight_property: None,
                },
            ],
            ..GraphBatch::default()
        };
        assert!(duplicate_type.validate().is_err());

        let missing_wall_clock = GraphBatch {
            edge_mutations: vec![EdgeMutation::Relate(crate::graph::RelateMutation {
                edge_id,
                source: Nid::from_parts(3, 1).unwrap(),
                target: Nid::from_parts(3, 2).unwrap(),
                type_id: TypeId::from_raw(1),
                namespace: GraphNamespace::Tenant("tenant-a".to_string()),
                properties: json!({}),
            })],
            idempotency: Some(GraphIdempotencyState {
                key: "legacy-without-instants".to_string(),
                request_sha256: [8; 32],
                created_at_unix_ms: 0,
                expires_at_unix_ms: 0,
                edge_ids: vec![edge_id],
            }),
            ..GraphBatch::default()
        };
        let mut encoded = serde_json::to_value(&missing_wall_clock).unwrap();
        let idempotency = encoded["idempotency"].as_object_mut().unwrap();
        idempotency.remove("created_at_unix_ms");
        idempotency.remove("expires_at_unix_ms");
        let decoded = serde_json::from_value::<GraphBatch>(encoded).unwrap();
        assert!(decoded.validate().is_err());
    }

    #[test]
    fn graph_batch_rejects_invalid_envelopes_before_wal_append() {
        let temp = TempDir::new().unwrap();
        let mut wal = Wal::open(temp.path()).unwrap();
        let before = wal.len().unwrap();
        let error = wal
            .append(&WalEntry::GraphBatch {
                batch: GraphBatch::default(),
            })
            .unwrap_err();
        assert!(error.to_string().contains("no mutation"));
        assert_eq!(wal.len().unwrap(), before);

        let oversized_properties = GraphBatch {
            edge_mutations: vec![EdgeMutation::Properties(
                crate::graph::EdgePropertyMutation {
                    edge_id: EdgeId::from_parts(1, 1).unwrap(),
                    mode: crate::graph::EdgePropertyMode::Replace,
                    properties: json!({"value": "x".repeat(MAX_EDGE_PROPERTY_BYTES)}),
                },
            )],
            ..GraphBatch::default()
        };
        assert!(oversized_properties.validate().is_err());
        assert_eq!(wal.len().unwrap(), before);

        let oversized_type_name = GraphBatch {
            type_configurations: vec![GraphTypeConfiguration {
                type_id: TypeId::from_raw(1),
                name: "x".repeat(crate::graph::MAX_GRAPH_CATALOG_NAME_BYTES + 1),
                weight_property: None,
            }],
            ..GraphBatch::default()
        };
        assert!(oversized_type_name.validate().is_err());
        assert_eq!(wal.len().unwrap(), before);
    }

    #[test]
    fn graph_batch_enforces_the_fixed_edge_count() {
        let edge_mutations = (1..=(MAX_GRAPH_EDGES_PER_BATCH as u64 + 1))
            .map(|counter| {
                EdgeMutation::Unrelate(crate::graph::UnrelateMutation {
                    edge_id: EdgeId::from_parts(1, counter).unwrap(),
                })
            })
            .collect();
        let batch = GraphBatch {
            edge_mutations,
            ..GraphBatch::default()
        };
        assert!(batch.validate().is_err());
    }

    #[test]
    fn strict_scan_rejects_partial_header_but_recovery_repairs_final_tail() {
        let temp = TempDir::new().unwrap();
        let mut wal = Wal::open(temp.path()).unwrap();
        let end_lsn = wal
            .append(&WalEntry::Delete {
                id: "durable".to_string(),
            })
            .unwrap();
        let path = wal.path().to_path_buf();
        drop(wal);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[1, 2, 3])
            .unwrap();

        let error = Wal::load(temp.path()).unwrap_err();
        assert!(error.to_string().contains("partial wal header"));

        let mut recovered = Vec::new();
        let stats = Wal::recover_from(temp.path(), 0, |record| {
            recovered.push(record);
            Ok(())
        })
        .unwrap();
        assert_eq!(stats.records, 1);
        assert_eq!(stats.end_lsn, end_lsn);
        assert_eq!(stats.repaired_tail_bytes, 3);
        assert_eq!(std::fs::metadata(path).unwrap().len(), end_lsn);
        assert_eq!(Wal::load(temp.path()).unwrap().len(), 1);
    }

    #[test]
    fn recovery_repairs_torn_payload_only_on_final_active_segment() {
        let temp = TempDir::new().unwrap();
        let mut wal = Wal::open_with_segment_bytes(temp.path(), 100).unwrap();
        wal.append(&WalEntry::Delete {
            id: "sealed".to_string(),
        })
        .unwrap();
        wal.append(&WalEntry::Delete {
            id: "active".to_string(),
        })
        .unwrap();
        drop(wal);

        let sealed = temp.path().join("000000.gdwal");
        let mut file = OpenOptions::new().append(true).open(sealed).unwrap();
        file.write_all(&12_u32.to_le_bytes()).unwrap();
        file.write_all(&0_u32.to_le_bytes()).unwrap();
        file.write_all(b"short").unwrap();
        drop(file);

        let error = Wal::recover_from(temp.path(), 0, |_| Ok(())).unwrap_err();
        assert!(error.to_string().contains("torn wal record"));
    }

    #[test]
    fn recovery_repairs_torn_payload_on_final_active_segment() {
        let temp = TempDir::new().unwrap();
        let mut wal = Wal::open(temp.path()).unwrap();
        let durable_end = wal
            .append(&WalEntry::Delete {
                id: "durable".to_string(),
            })
            .unwrap();
        let path = wal.path().to_path_buf();
        drop(wal);

        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&12_u32.to_le_bytes()).unwrap();
        file.write_all(&0_u32.to_le_bytes()).unwrap();
        file.write_all(b"short").unwrap();
        drop(file);

        let stats = Wal::recover_from(temp.path(), 0, |_| Ok(())).unwrap();
        assert_eq!(stats.end_lsn, durable_end);
        assert_eq!(stats.repaired_tail_bytes, 13);
        assert_eq!(std::fs::metadata(path).unwrap().len(), durable_end);
    }

    #[test]
    fn rejects_excessive_record_length_before_allocating() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("000000.gdwal");
        let mut file = File::create(&path).unwrap();
        let excessive = u32::try_from(super::MAX_WAL_RECORD_BYTES + 1).unwrap();
        file.write_all(&excessive.to_le_bytes()).unwrap();
        file.write_all(&0_u32.to_le_bytes()).unwrap();
        drop(file);

        let error = Wal::load(temp.path()).unwrap_err();
        assert!(error.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn rejects_segment_gaps_and_duplicate_indices() {
        let gap = TempDir::new().unwrap();
        File::create(gap.path().join("000001.gdwal")).unwrap();
        let error = Wal::load(gap.path()).unwrap_err();
        assert!(error.to_string().contains("segment gap"));

        let duplicate = TempDir::new().unwrap();
        File::create(duplicate.path().join("000000.gdwal")).unwrap();
        File::create(duplicate.path().join("0.gdwal")).unwrap();
        let error = Wal::load(duplicate.path()).unwrap_err();
        assert!(error.to_string().contains("duplicate wal segment index"));

        let invalid = TempDir::new().unwrap();
        File::create(invalid.path().join("not-an-index.gdwal")).unwrap();
        let error = Wal::load(invalid.path()).unwrap_err();
        assert!(error.to_string().contains("invalid WAL segment index"));
    }

    #[test]
    fn streaming_scan_reports_progress_without_collecting_records() {
        let temp = TempDir::new().unwrap();
        let mut wal = Wal::open(temp.path()).unwrap();
        let first_end = wal
            .append(&WalEntry::Delete {
                id: "first".to_string(),
            })
            .unwrap();
        let final_end = wal
            .append(&WalEntry::Delete {
                id: "second".to_string(),
            })
            .unwrap();
        let mut ids = Vec::new();
        let stats = Wal::scan_from(temp.path(), first_end, |record| {
            if let WalEntry::Delete { id } = record.entry {
                ids.push(id);
            }
            Ok(())
        })
        .unwrap();

        assert_eq!(ids, ["second"]);
        assert_eq!(stats.records, 1);
        assert_eq!(stats.end_lsn, final_end);
        assert_eq!(stats.repaired_tail_bytes, 0);
    }

    #[test]
    fn tracks_unsynced_bytes_and_poison_rejects_later_writes() {
        let temp = TempDir::new().unwrap();
        let mut wal = Wal::open(temp.path()).unwrap();
        wal.append_no_sync(&WalEntry::Delete {
            id: "async".to_string(),
        })
        .unwrap();
        assert!(wal.is_dirty());
        assert!(wal.unsynced_bytes() > 0);
        assert!(wal.oldest_unsynced_age().is_some());
        wal.sync().unwrap();
        assert!(!wal.is_dirty());

        wal.inject_write_failure();
        let error = wal
            .append(&WalEntry::Delete {
                id: "fails".to_string(),
            })
            .unwrap_err();
        assert!(error.to_string().contains("injected Enospc failure"));
        assert!(wal.is_poisoned());
        let error = wal
            .append(&WalEntry::Delete {
                id: "rejected".to_string(),
            })
            .unwrap_err();
        assert!(error.to_string().contains("wal unavailable"));
        let error = wal.drop_prefix(0).unwrap_err();
        assert!(error.to_string().contains("wal unavailable"));
    }

    #[test]
    fn sync_failure_poisons_wal_and_preserves_dirty_accounting() {
        let temp = TempDir::new().unwrap();
        let mut wal = Wal::open(temp.path()).unwrap();
        wal.append_no_sync(&WalEntry::Delete {
            id: "async".to_string(),
        })
        .unwrap();
        let dirty_bytes = wal.unsynced_bytes();
        wal.inject_sync_failure();

        let error = wal.sync().unwrap_err();
        assert!(error.to_string().contains("injected Fsync failure"));
        assert!(wal.is_poisoned());
        assert_eq!(wal.unsynced_bytes(), dirty_bytes);
        assert!(
            wal.append_no_sync(&WalEntry::Delete {
                id: "rejected".to_string(),
            })
            .is_err()
        );
    }

    #[test]
    fn enospc_and_permission_failures_poison_without_complete_record() {
        for fault in [Fault::Enospc, Fault::PermissionDenied] {
            let temp = TempDir::new().unwrap();
            let mut wal = Wal::open(temp.path()).unwrap();
            inject_once(fault);

            let error = wal
                .append(&WalEntry::Delete {
                    id: "must-not-be-acknowledged".to_string(),
                })
                .unwrap_err();

            assert!(matches!(error, crate::GaussError::WalUnavailable(_)));
            assert!(wal.is_poisoned());
            assert!(
                wal.append(&WalEntry::Delete {
                    id: "rejected-after-poison".to_string(),
                })
                .is_err()
            );
            drop(wal);
            assert!(Wal::load(temp.path()).unwrap().is_empty());
        }
    }

    #[test]
    fn short_write_is_unacknowledged_and_repaired_only_as_active_tail() {
        let temp = TempDir::new().unwrap();
        let mut wal = Wal::open(temp.path()).unwrap();
        let path = wal.path().to_path_buf();
        inject_once(Fault::ShortWrite);

        let error = wal
            .append(&WalEntry::Delete {
                id: "torn".to_string(),
            })
            .unwrap_err();
        assert!(matches!(error, crate::GaussError::WalUnavailable(_)));
        assert!(wal.is_poisoned());
        drop(wal);

        assert_eq!(std::fs::metadata(&path).unwrap().len(), 4);
        assert!(matches!(
            Wal::load(temp.path()),
            Err(crate::GaussError::WalCorruption { .. })
        ));
        let stats = Wal::recover_from(temp.path(), 0, |_| Ok(())).unwrap();
        assert_eq!(stats.records, 0);
        assert_eq!(stats.repaired_tail_bytes, 4);
        assert_eq!(std::fs::metadata(path).unwrap().len(), 0);
    }

    #[test]
    fn rotates_segments_and_loads_in_lsn_order() {
        let temp = TempDir::new().unwrap();
        let mut wal = Wal::open_with_segment_bytes(temp.path(), 100).unwrap();
        let first_end = wal
            .append(&WalEntry::Delete {
                id: "first".to_string(),
            })
            .unwrap();
        let second_end = wal
            .append(&WalEntry::Delete {
                id: "second".to_string(),
            })
            .unwrap();
        assert!(second_end > first_end);
        assert!(temp.path().join("000000.gdwal").exists());
        assert!(temp.path().join("000001.gdwal").exists());

        let records = Wal::load(temp.path()).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].lsn, 0);
        assert_eq!(records[1].lsn, first_end);

        wal.reset().unwrap();
        let wal_base = super::read_wal_base(temp.path()).unwrap();
        assert_eq!(wal_base.lsn, second_end);
        assert_eq!(wal_base.first_segment, 2);
        assert!(temp.path().join("000002.gdwal").exists());
        assert!(!temp.path().join("000000.gdwal").exists());
        assert!(!temp.path().join("000001.gdwal").exists());
        assert_eq!(Wal::load(temp.path()).unwrap().len(), 0);
        assert_eq!(wal.len().unwrap(), second_end);
        assert_eq!(wal.retained_bytes().unwrap(), 0);
    }

    #[test]
    fn reset_successor_and_wal_base_make_both_crash_windows_recoverable() {
        let temp = TempDir::new().unwrap();
        let mut wal = Wal::open_with_segment_bytes(temp.path(), 100).unwrap();
        wal.append(&WalEntry::Delete {
            id: "old-first".to_string(),
        })
        .unwrap();
        let reset_lsn = wal
            .append(&WalEntry::Delete {
                id: "old-second".to_string(),
            })
            .unwrap();
        drop(wal);

        // Crash before the wal.base commit: the empty successor is simply the
        // new active tail and the complete old WAL remains readable.
        let successor = temp.path().join("000002.gdwal");
        File::create(&successor).unwrap().sync_all().unwrap();
        assert_eq!(Wal::load(temp.path()).unwrap().len(), 2);

        // Crash after the wal.base commit but before old-segment cleanup: the
        // reset generation is authoritative and startup garbage-collects old
        // files without observing a segment gap.
        super::write_wal_base(
            temp.path(),
            super::WalBase {
                lsn: reset_lsn,
                first_segment: 2,
            },
        )
        .unwrap();
        assert!(Wal::load(temp.path()).unwrap().is_empty());
        let reopened = Wal::open(temp.path()).unwrap();
        assert!(reopened.is_empty().unwrap());
        assert_eq!(reopened.len().unwrap(), reset_lsn);
        assert!(!temp.path().join("000000.gdwal").exists());
        assert!(!temp.path().join("000001.gdwal").exists());
        assert!(successor.exists());

        let mut reopened = reopened;
        let next_end = reopened
            .append(&WalEntry::Delete {
                id: "new-generation".to_string(),
            })
            .unwrap();
        assert!(next_end > reset_lsn);
        let records = Wal::load(temp.path()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].lsn, reset_lsn);
    }

    #[test]
    fn invalid_json_is_classified_as_wal_corruption() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("000000.gdwal");
        let payload = b"{not-json";
        let mut file = File::create(&path).unwrap();
        file.write_all(&(payload.len() as u32).to_le_bytes())
            .unwrap();
        file.write_all(&checksum(payload).to_le_bytes()).unwrap();
        file.write_all(payload).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let error = Wal::load(temp.path()).unwrap_err();
        assert!(matches!(error, crate::GaussError::WalCorruption { .. }));
        assert!(error.to_string().contains("invalid WAL record JSON"));
    }

    #[test]
    fn drop_prefix_deletes_complete_segments_and_preserves_absolute_lsns() {
        let temp = TempDir::new().unwrap();
        let mut wal = Wal::open_with_segment_bytes(temp.path(), 100).unwrap();
        let first_end = wal
            .append(&WalEntry::Delete {
                id: "first".to_string(),
            })
            .unwrap();
        let second_end = wal
            .append(&WalEntry::Delete {
                id: "second".to_string(),
            })
            .unwrap();
        let third_end = wal
            .append(&WalEntry::Delete {
                id: "third".to_string(),
            })
            .unwrap();
        assert!(second_end > first_end);

        wal.drop_prefix(second_end).unwrap();

        assert!(!temp.path().join("000000.gdwal").exists());
        assert!(!temp.path().join("000001.gdwal").exists());
        assert!(temp.path().join("000002.gdwal").exists());
        assert!(temp.path().join(super::WAL_BASE_FILE).exists());
        let records = Wal::load(temp.path()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].lsn, second_end);
        assert!(matches!(
            &records[0].entry,
            WalEntry::Delete { id } if id == "third"
        ));

        drop(wal);
        let mut reopened = Wal::open(temp.path()).unwrap();
        assert_eq!(reopened.len().unwrap(), third_end);
        let fourth_end = reopened
            .append(&WalEntry::Delete {
                id: "fourth".to_string(),
            })
            .unwrap();
        assert!(fourth_end > third_end);
        let records = Wal::load_from(temp.path(), third_end).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].lsn, third_end);
    }

    #[test]
    fn wal_base_makes_sidecar_before_delete_crash_recoverable() {
        let temp = TempDir::new().unwrap();
        let mut wal = Wal::open_with_segment_bytes(temp.path(), 100).unwrap();
        let first_end = wal
            .append(&WalEntry::Delete {
                id: "covered".to_string(),
            })
            .unwrap();
        wal.append(&WalEntry::Delete {
            id: "survives".to_string(),
        })
        .unwrap();
        drop(wal);

        super::write_wal_base(
            temp.path(),
            super::WalBase {
                lsn: first_end,
                first_segment: 1,
            },
        )
        .unwrap();

        assert!(temp.path().join("000000.gdwal").exists());
        let records = Wal::load(temp.path()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].lsn, first_end);
        assert!(matches!(
            &records[0].entry,
            WalEntry::Delete { id } if id == "survives"
        ));
        let _reopened = Wal::open(temp.path()).unwrap();
        assert!(!temp.path().join("000000.gdwal").exists());
    }

    #[test]
    fn drop_prefix_of_entire_wal_rotates_empty_active_segment() {
        let temp = TempDir::new().unwrap();
        let mut wal = Wal::open_with_segment_bytes(temp.path(), 100).unwrap();
        let end = wal
            .append(&WalEntry::Delete {
                id: "covered".to_string(),
            })
            .unwrap();

        wal.drop_prefix(end).unwrap();

        assert!(wal.is_empty().unwrap());
        assert_eq!(wal.len().unwrap(), end);
        assert!(Wal::load(temp.path()).unwrap().is_empty());
        let next_end = wal
            .append(&WalEntry::Delete {
                id: "tail".to_string(),
            })
            .unwrap();
        assert!(next_end > end);
        assert_eq!(Wal::load(temp.path()).unwrap()[0].lsn, end);
    }

    #[test]
    fn drop_prefix_rejects_non_record_boundary() {
        let temp = TempDir::new().unwrap();
        let mut wal = Wal::open(temp.path()).unwrap();
        wal.append(&WalEntry::Delete {
            id: "point".to_string(),
        })
        .unwrap();

        let error = wal.drop_prefix(1).unwrap_err();

        assert!(error.to_string().contains("not a record boundary"));
        assert_eq!(Wal::load(temp.path()).unwrap().len(), 1);
    }

    #[test]
    fn archive_preserves_wal_base_for_prefix_dropped_suffix() {
        let temp = TempDir::new().unwrap();
        let archive_root = temp.path().join("archive");
        let mut wal = Wal::open_with_segment_bytes(temp.path(), 100).unwrap();
        let first_end = wal
            .append(&WalEntry::Delete {
                id: "covered".to_string(),
            })
            .unwrap();
        let end_lsn = wal
            .append(&WalEntry::Delete {
                id: "tail".to_string(),
            })
            .unwrap();
        wal.drop_prefix(first_end).unwrap();

        let archive = wal.archive_and_reset(&archive_root).unwrap().unwrap();

        assert!(archive.path.join(super::WAL_BASE_FILE).exists());
        let archived = Wal::load(&archive.path).unwrap();
        assert_eq!(archived.len(), 1);
        assert_eq!(archived[0].lsn, first_end);
        assert!(wal.is_empty().unwrap());
        assert_eq!(wal.len().unwrap(), end_lsn);
    }

    #[test]
    fn archives_segments_before_reset() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("archive");
        let mut wal = Wal::open_with_segment_bytes(temp.path(), 100).unwrap();
        wal.append(&WalEntry::Delete {
            id: "first".to_string(),
        })
        .unwrap();
        let first_archive_end = wal
            .append(&WalEntry::Delete {
                id: "second".to_string(),
            })
            .unwrap();

        let archived = wal.archive_and_reset(&archive).unwrap().unwrap();
        assert_eq!(archived.segments, 2);
        assert!(archived.bytes > 0);
        assert!(archived.path.join("000000.gdwal").exists());
        assert!(archived.path.join("000001.gdwal").exists());
        assert_eq!(Wal::load(&archived.path).unwrap().len(), 2);
        assert_eq!(Wal::load(temp.path()).unwrap().len(), 0);
        assert_eq!(wal.len().unwrap(), first_archive_end);
        assert_eq!(std::fs::metadata(wal.path()).unwrap().len(), 0);

        let second_archive_end = wal
            .append(&WalEntry::Delete {
                id: "third".to_string(),
            })
            .unwrap();
        let second_archive = wal.archive_and_reset(&archive).unwrap().unwrap();
        assert_ne!(second_archive.path, archived.path);
        let second_records = Wal::load(&second_archive.path).unwrap();
        assert_eq!(second_records.len(), 1);
        assert_eq!(second_records[0].lsn, first_archive_end);
        assert_eq!(wal.len().unwrap(), second_archive_end);
    }

    #[test]
    fn frozen_archive_cut_excludes_successor_tail_and_survives_prefix_retirement() {
        let temp = TempDir::new().unwrap();
        let wal_dir = temp.path().join("wal");
        let archive_root = temp.path().join("archive");
        let mut wal = Wal::open(&wal_dir).unwrap();
        wal.append(&WalEntry::Delete {
            id: "before-a".to_string(),
        })
        .unwrap();
        let cut = wal
            .append(&WalEntry::Delete {
                id: "before-b".to_string(),
            })
            .unwrap();

        let frozen = wal.freeze_archive_cut(cut).unwrap().unwrap();
        assert_eq!(wal.len().unwrap(), cut);
        let tail_end = wal
            .append(&WalEntry::Delete {
                id: "after-cut".to_string(),
            })
            .unwrap();
        assert!(tail_end > cut);

        let archive = frozen.publish(&archive_root).unwrap();
        let archived = Wal::load(&archive.path).unwrap();
        assert_eq!(archived.len(), 2);
        assert!(matches!(
            &archived[1].entry,
            WalEntry::Delete { id } if id == "before-b"
        ));
        assert_eq!(Wal::load(&wal_dir).unwrap().len(), 3);

        wal.drop_prefix(cut).unwrap();
        assert_eq!(Wal::retained_base_lsn(&wal_dir).unwrap(), cut);
        let retained = Wal::load(&wal_dir).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].lsn, cut);
        assert!(matches!(
            &retained[0].entry,
            WalEntry::Delete { id } if id == "after-cut"
        ));
        assert_eq!(
            serde_json::to_value(Wal::load(&archive.path).unwrap()).unwrap(),
            serde_json::to_value(archived).unwrap()
        );
    }

    #[test]
    fn archive_copy_and_rename_failures_keep_live_wal_recoverable() {
        for fault in [Fault::Copy, Fault::Rename] {
            let temp = TempDir::new().unwrap();
            let wal_dir = temp.path().join("wal");
            let archive_root = temp.path().join("archive");
            let mut wal = Wal::open(&wal_dir).unwrap();
            let end_lsn = wal
                .append(&WalEntry::Delete {
                    id: "still-live".to_string(),
                })
                .unwrap();
            inject_once(fault);

            let error = wal.archive_and_reset(&archive_root).unwrap_err();

            assert!(error.to_string().contains("injected"));
            assert_eq!(wal.len().unwrap(), end_lsn);
            assert_eq!(Wal::load(&wal_dir).unwrap().len(), 1);

            // The failed publish is retryable after the one-shot fault is
            // consumed; only the successful retry resets the live WAL.
            let archive = wal.archive_and_reset(&archive_root).unwrap().unwrap();
            assert_eq!(Wal::load(&archive.path).unwrap().len(), 1);
            assert!(Wal::load(&wal_dir).unwrap().is_empty());
        }
    }

    #[test]
    fn archive_manifest_detects_tampered_segment() {
        let temp = TempDir::new().unwrap();
        let archive_root = temp.path().join("archive");
        let mut wal = Wal::open(temp.path()).unwrap();
        wal.append(&WalEntry::Delete {
            id: "protected".to_string(),
        })
        .unwrap();
        let archive = wal.archive_and_reset(&archive_root).unwrap().unwrap();
        assert!(archive.path.join(super::WAL_ARCHIVE_MANIFEST_FILE).exists());
        assert_eq!(Wal::load(&archive.path).unwrap().len(), 1);

        OpenOptions::new()
            .append(true)
            .open(archive.path.join("000000.gdwal"))
            .unwrap()
            .write_all(b"tamper")
            .unwrap();
        let error = Wal::load(&archive.path).unwrap_err();
        assert!(error.to_string().contains("manifest size mismatch"));
    }

    #[test]
    fn prunes_oldest_archives_by_retained_count() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("archive");
        let mut wal = Wal::open_with_segment_bytes(temp.path(), 100).unwrap();
        wal.append(&WalEntry::Delete {
            id: "first".to_string(),
        })
        .unwrap();
        let first_archive = wal.archive_and_reset(&archive).unwrap().unwrap();
        wal.append(&WalEntry::Delete {
            id: "second".to_string(),
        })
        .unwrap();
        let second_archive = wal.archive_and_reset(&archive).unwrap().unwrap();
        wal.append(&WalEntry::Delete {
            id: "third".to_string(),
        })
        .unwrap();
        let third_archive = wal.archive_and_reset(&archive).unwrap().unwrap();

        let pruned = super::prune_archives(&archive, 2).unwrap();
        assert_eq!(pruned.retained_archives, 2);
        assert_eq!(pruned.pruned_archives, 1);
        assert!(pruned.pruned_bytes > 0);
        assert!(!first_archive.path.exists());
        assert!(second_archive.path.exists());
        assert!(third_archive.path.exists());

        let pruned = super::prune_archives(&archive, 0).unwrap();
        assert_eq!(pruned.retained_archives, 0);
        assert_eq!(pruned.pruned_archives, 2);
        assert!(!second_archive.path.exists());
        assert!(!third_archive.path.exists());
    }

    #[test]
    fn prunes_oldest_archives_by_total_bytes() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("archive");
        let mut wal = Wal::open_with_segment_bytes(temp.path(), 100).unwrap();
        wal.append(&WalEntry::Delete {
            id: "first".to_string(),
        })
        .unwrap();
        let first_archive = wal.archive_and_reset(&archive).unwrap().unwrap();
        wal.append(&WalEntry::Delete {
            id: "second".to_string(),
        })
        .unwrap();
        let second_archive = wal.archive_and_reset(&archive).unwrap().unwrap();
        let second_size = super::dir_size(&second_archive.path).unwrap();
        wal.append(&WalEntry::Delete {
            id: "third".to_string(),
        })
        .unwrap();
        let third_archive = wal.archive_and_reset(&archive).unwrap().unwrap();
        let third_size = super::dir_size(&third_archive.path).unwrap();

        let pruned = super::prune_archives_over_bytes(&archive, second_size + third_size).unwrap();
        assert_eq!(pruned.retained_archives, 2);
        assert_eq!(pruned.pruned_archives, 1);
        assert!(pruned.pruned_bytes > 0);
        assert!(!first_archive.path.exists());
        assert!(second_archive.path.exists());
        assert!(third_archive.path.exists());

        let pruned = super::prune_archives_over_bytes(&archive, 0).unwrap();
        assert_eq!(pruned.retained_archives, 0);
        assert_eq!(pruned.pruned_archives, 2);
        assert!(!second_archive.path.exists());
        assert!(!third_archive.path.exists());
    }

    #[test]
    fn prunes_archives_older_than_age_window() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("archive");
        let mut wal = Wal::open_with_segment_bytes(temp.path(), 100).unwrap();
        wal.append(&WalEntry::Delete {
            id: "first".to_string(),
        })
        .unwrap();
        let first_archive = wal.archive_and_reset(&archive).unwrap().unwrap();
        wal.append(&WalEntry::Delete {
            id: "second".to_string(),
        })
        .unwrap();
        let second_archive = wal.archive_and_reset(&archive).unwrap().unwrap();

        let retained =
            super::prune_archives_older_than(&archive, Duration::from_secs(86_400)).unwrap();
        assert_eq!(retained.retained_archives, 2);
        assert_eq!(retained.pruned_archives, 0);
        assert!(first_archive.path.exists());
        assert!(second_archive.path.exists());

        let pruned = super::prune_archives_older_than(&archive, Duration::ZERO).unwrap();
        assert_eq!(pruned.retained_archives, 0);
        assert_eq!(pruned.pruned_archives, 2);
        assert!(pruned.pruned_bytes > 0);
        assert!(!first_archive.path.exists());
        assert!(!second_archive.path.exists());
    }

    #[test]
    fn reads_legacy_entries_with_inferred_lsn() {
        let temp = TempDir::new().unwrap();
        std::fs::create_dir_all(temp.path()).unwrap();
        let path = temp.path().join("000000.gdwal");
        let payload = serde_json::to_vec(&WalEntry::Upsert {
            point: Point {
                id: "a".to_string(),
                vector: vec![1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({}),
            },
        })
        .unwrap();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        file.write_all(&(payload.len() as u32).to_le_bytes())
            .unwrap();
        file.write_all(&checksum(&payload).to_le_bytes()).unwrap();
        file.write_all(&payload).unwrap();

        let records = Wal::load(temp.path()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].lsn, 0);
    }

    #[test]
    fn rejects_mismatched_lsn() {
        let temp = TempDir::new().unwrap();
        std::fs::create_dir_all(temp.path()).unwrap();
        let path = temp.path().join("000000.gdwal");
        let payload = serde_json::to_vec(&WalRecord {
            lsn: 99,
            unix_ms: 1,
            entry: WalEntry::Schema {
                schema_epoch: 2,
                config: CollectionConfig {
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
                },
                previous_config: None,
            },
        })
        .unwrap();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        file.write_all(&(payload.len() as u32).to_le_bytes())
            .unwrap();
        file.write_all(&checksum(&payload).to_le_bytes()).unwrap();
        file.write_all(&payload).unwrap();

        let error = Wal::load(temp.path()).unwrap_err();
        assert!(error.to_string().contains("lsn mismatch"));
    }

    #[test]
    fn truncate_to_unix_ms_keeps_records_at_or_before_target() {
        let temp = TempDir::new().unwrap();
        std::fs::create_dir_all(temp.path()).unwrap();
        let path = temp.path().join("000000.gdwal");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        let first_end = write_test_record(&mut file, 0, 100, "first");
        let second_end = write_test_record(&mut file, first_end, 200, "second");
        let _third_end = write_test_record(&mut file, second_end, 300, "third");
        drop(file);

        let target_lsn = Wal::truncate_to_unix_ms(temp.path(), 200).unwrap();

        assert_eq!(target_lsn, second_end);
        let records = Wal::load(temp.path()).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].unix_ms, 100);
        assert_eq!(records[1].unix_ms, 200);
        assert!(matches!(
            &records[1].entry,
            WalEntry::Delete { id } if id == "second"
        ));
    }

    #[test]
    fn time_target_resolution_is_non_mutating_and_keeps_only_a_contiguous_prefix() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("000000.gdwal");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        let first_end = write_test_record(&mut file, 0, 100, "first");
        let second_end = write_test_record(&mut file, first_end, 300, "later");
        let end = write_test_record(&mut file, second_end, 150, "clock-moved-back");
        drop(file);
        let original = std::fs::read(&path).unwrap();
        assert_eq!(Wal::lsn_for_unix_ms(temp.path(), 0).unwrap(), 0);
        assert_eq!(Wal::lsn_for_unix_ms(temp.path(), 200).unwrap(), first_end);
        assert_eq!(Wal::lsn_for_unix_ms(temp.path(), 300).unwrap(), end);
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(Wal::load(temp.path()).unwrap().len(), 3);
        assert_eq!(
            Wal::truncate_to_unix_ms(temp.path(), 200).unwrap(),
            first_end
        );
        assert_eq!(Wal::load(temp.path()).unwrap().len(), 1);
    }

    fn write_test_record(file: &mut std::fs::File, lsn: u64, unix_ms: u64, id: &str) -> u64 {
        let payload = serde_json::to_vec(&WalRecord {
            lsn,
            unix_ms,
            entry: WalEntry::Delete { id: id.to_string() },
        })
        .unwrap();
        file.write_all(&(payload.len() as u32).to_le_bytes())
            .unwrap();
        file.write_all(&checksum(&payload).to_le_bytes()).unwrap();
        file.write_all(&payload).unwrap();
        lsn + super::HEADER_LEN as u64 + payload.len() as u64
    }

    fn test_config(name: &str) -> CollectionConfig {
        CollectionConfig {
            name: name.to_string(),
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
        }
    }
}
