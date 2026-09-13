use std::{
    fs,
    num::NonZeroU64,
    path::{Path, PathBuf},
};

use parking_lot::Mutex;
use uuid::Uuid;

use crate::{
    GaussError, Result,
    encryption::{FileType, atomic_write_persistent, read_persistent},
    fs_util::durable_remove_file,
    graph::{
        EdgeId, GRAPH_ALLOCATOR_MAX_COUNTER, GRAPH_ALLOCATOR_MAX_EPOCH, GraphError, GraphErrorCode,
        Nid,
    },
};

pub const GRAPH_IDENTITY_FILE: &str = "graph_identity.gdx";
pub const GRAPH_IDENTITY_MAGIC: &[u8; 8] = b"GAUSGI01";

const GRAPH_IDENTITY_VERSION: u16 = 1;
const GRAPH_IDENTITY_BYTES: usize = 64;
const MAX_ENCODED_IDENTITY_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GraphIdentitySnapshot {
    pub database_id: Uuid,
    pub allocator_epoch: u32,
    pub node_high_water: u64,
    pub edge_high_water: u64,
}

impl GraphIdentitySnapshot {
    fn fresh() -> Self {
        Self {
            database_id: Uuid::new_v4(),
            allocator_epoch: 1,
            node_high_water: 0,
            edge_high_water: 0,
        }
    }

    fn successor_epoch(self) -> Result<Self> {
        let allocator_epoch = self.allocator_epoch.checked_add(1).ok_or_else(|| {
            GraphError::new(
                GraphErrorCode::AllocatorExhausted,
                "graph allocator epoch space is exhausted",
            )
        })?;
        if allocator_epoch > GRAPH_ALLOCATOR_MAX_EPOCH {
            return Err(GraphError::new(
                GraphErrorCode::AllocatorExhausted,
                "graph allocator epoch space is exhausted",
            )
            .into());
        }
        Ok(Self {
            database_id: self.database_id,
            allocator_epoch,
            node_high_water: 0,
            edge_high_water: 0,
        })
    }
}

#[derive(Debug)]
pub(crate) struct GraphIdentityStore {
    path: PathBuf,
    state: Mutex<GraphIdentitySnapshot>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "consumed by the following GraphBatch slice")
)]
pub(crate) struct AllocatedGraphIdRange {
    epoch: u32,
    first_counter: u64,
    last_counter: u64,
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "consumed by the following GraphBatch slice")
)]
impl AllocatedGraphIdRange {
    pub(crate) fn len(self) -> u64 {
        self.last_counter - self.first_counter + 1
    }

    pub(crate) fn nids(self) -> impl Iterator<Item = Nid> {
        let epoch = self.epoch;
        (self.first_counter..=self.last_counter).map(move |counter| {
            Nid::from_parts(epoch, counter).expect("allocated Nid range is validated")
        })
    }

    pub(crate) fn edge_ids(self) -> impl Iterator<Item = EdgeId> {
        let epoch = self.epoch;
        (self.first_counter..=self.last_counter).map(move |counter| {
            EdgeId::from_parts(epoch, counter).expect("allocated EdgeId range is validated")
        })
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "consumed by the following GraphBatch slice")
)]
enum CounterKind {
    Node,
    Edge,
}

impl GraphIdentityStore {
    /// Open installation identity and durably reserve an allocator epoch.
    /// Missing metadata denotes a fork/new installation and receives a fresh
    /// database UUID; existing metadata retains its UUID and advances epoch.
    pub(crate) fn open(data_dir: &Path) -> Result<Self> {
        fs::create_dir_all(data_dir)?;
        let path = data_dir.join(GRAPH_IDENTITY_FILE);
        let state = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(corruption(&path, "identity path is not a regular file"));
                }
                if metadata.len() > MAX_ENCODED_IDENTITY_BYTES {
                    return Err(corruption(&path, "encoded identity exceeds fixed cap"));
                }
                decode(&path, &read_persistent(&path)?)?.successor_epoch()?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                GraphIdentitySnapshot::fresh()
            }
            Err(error) => return Err(error.into()),
        };
        write_state(&path, state)?;
        crate::failpoint::check("graph_identity.after_open_epoch_reservation")?;
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }

    pub(crate) fn snapshot(&self) -> GraphIdentitySnapshot {
        *self.state.lock()
    }

    /// Burn the current allocation range before installing a collection PITR
    /// state. Failure leaves the in-memory epoch unchanged.
    pub(crate) fn reserve_new_epoch(&self) -> Result<u32> {
        let mut state = self.state.lock();
        let next = state.successor_epoch()?;
        write_state(&self.path, next)?;
        crate::failpoint::check("graph_identity.after_explicit_epoch_reservation")?;
        *state = next;
        Ok(next.allocator_epoch)
    }

    /// Durably reserve a contiguous Nid range before returning any identity
    /// to a caller. A failed write issues no range; a crash after the write may
    /// burn an unused range but cannot cause reuse.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "consumed by the following GraphBatch slice")
    )]
    pub(crate) fn allocate_nids(&self, count: NonZeroU64) -> Result<AllocatedGraphIdRange> {
        self.allocate_range(count, CounterKind::Node)
    }

    /// Edge and node counters are independent but share the installation's
    /// current durable allocator epoch.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "consumed by the following GraphBatch slice")
    )]
    pub(crate) fn allocate_edge_ids(&self, count: NonZeroU64) -> Result<AllocatedGraphIdRange> {
        self.allocate_range(count, CounterKind::Edge)
    }

    fn allocate_range(
        &self,
        count: NonZeroU64,
        kind: CounterKind,
    ) -> Result<AllocatedGraphIdRange> {
        let count = count.get();
        let mut state = self.state.lock();
        let high_water = match kind {
            CounterKind::Node => state.node_high_water,
            CounterKind::Edge => state.edge_high_water,
        };
        let next_high_water = high_water.checked_add(count).ok_or_else(exhausted)?;
        if next_high_water > GRAPH_ALLOCATOR_MAX_COUNTER {
            return Err(exhausted().into());
        }

        let mut next = *state;
        match kind {
            CounterKind::Node => next.node_high_water = next_high_water,
            CounterKind::Edge => next.edge_high_water = next_high_water,
        }
        write_state(&self.path, next)?;
        crate::failpoint::check(match kind {
            CounterKind::Node => "graph_identity.after_node_range_reservation",
            CounterKind::Edge => "graph_identity.after_edge_range_reservation",
        })?;
        *state = next;

        Ok(AllocatedGraphIdRange {
            epoch: next.allocator_epoch,
            first_counter: high_water + 1,
            last_counter: next_high_water,
        })
    }

    /// A legacy-layout restore swaps the root directory itself. Re-materialize
    /// installation metadata from the live store into staging; never trust or
    /// import identity from the snapshot being restored.
    pub(crate) fn preserve_for_root_swap(&self, staged_root: &Path) -> Result<()> {
        write_state(&staged_root.join(GRAPH_IDENTITY_FILE), self.snapshot())
    }

    /// Snapshot input is collection state, never installation state. Remove a
    /// root identity if an older or externally modified snapshot contains one.
    pub(crate) fn discard_imported_from(staged_root: &Path) -> Result<()> {
        let path = staged_root.join(GRAPH_IDENTITY_FILE);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
                durable_remove_file(&path)
            }
            Ok(_) => Err(corruption(
                &path,
                "imported graph identity path is not removable metadata",
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

fn encode(state: GraphIdentitySnapshot) -> [u8; GRAPH_IDENTITY_BYTES] {
    let mut bytes = [0_u8; GRAPH_IDENTITY_BYTES];
    bytes[0..8].copy_from_slice(GRAPH_IDENTITY_MAGIC);
    bytes[8..10].copy_from_slice(&GRAPH_IDENTITY_VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&(GRAPH_IDENTITY_BYTES as u16).to_le_bytes());
    bytes[16..32].copy_from_slice(state.database_id.as_bytes());
    bytes[32..36].copy_from_slice(&state.allocator_epoch.to_le_bytes());
    bytes[40..48].copy_from_slice(&state.node_high_water.to_le_bytes());
    bytes[48..56].copy_from_slice(&state.edge_high_water.to_le_bytes());
    let crc = crc_fast::crc32_iscsi(&bytes[..60]);
    bytes[60..64].copy_from_slice(&crc.to_le_bytes());
    bytes
}

fn decode(path: &Path, bytes: &[u8]) -> Result<GraphIdentitySnapshot> {
    if bytes.len() != GRAPH_IDENTITY_BYTES {
        return Err(corruption(
            path,
            "identity plaintext length is not 64 bytes",
        ));
    }
    if &bytes[0..8] != GRAPH_IDENTITY_MAGIC {
        return Err(corruption(path, "bad graph identity magic"));
    }
    if u16::from_le_bytes(bytes[8..10].try_into().expect("identity version"))
        != GRAPH_IDENTITY_VERSION
    {
        return Err(corruption(path, "unsupported graph identity version"));
    }
    if u16::from_le_bytes(bytes[10..12].try_into().expect("identity length")) as usize
        != GRAPH_IDENTITY_BYTES
    {
        return Err(corruption(path, "graph identity header length mismatch"));
    }
    if bytes[12..16] != [0; 4] || bytes[36..40] != [0; 4] || bytes[56..60] != [0; 4] {
        return Err(corruption(
            path,
            "unknown graph identity flags or reserved fields",
        ));
    }
    let expected_crc = u32::from_le_bytes(bytes[60..64].try_into().expect("identity CRC"));
    if crc_fast::crc32_iscsi(&bytes[..60]) != expected_crc {
        return Err(corruption(path, "graph identity CRC32C mismatch"));
    }
    let database_id = Uuid::from_slice(&bytes[16..32])
        .map_err(|_| corruption(path, "invalid graph database UUID"))?;
    if database_id.is_nil() {
        return Err(corruption(path, "graph database UUID is nil"));
    }
    let allocator_epoch = u32::from_le_bytes(bytes[32..36].try_into().expect("allocator epoch"));
    let node_high_water = u64::from_le_bytes(bytes[40..48].try_into().expect("node high water"));
    let edge_high_water = u64::from_le_bytes(bytes[48..56].try_into().expect("edge high water"));
    if allocator_epoch == 0 || allocator_epoch > GRAPH_ALLOCATOR_MAX_EPOCH {
        return Err(corruption(
            path,
            "allocator epoch is outside the 24-bit range",
        ));
    }
    if node_high_water > GRAPH_ALLOCATOR_MAX_COUNTER
        || edge_high_water > GRAPH_ALLOCATOR_MAX_COUNTER
    {
        return Err(corruption(
            path,
            "allocator high water is outside the 40-bit range",
        ));
    }
    Ok(GraphIdentitySnapshot {
        database_id,
        allocator_epoch,
        node_high_water,
        edge_high_water,
    })
}

fn write_state(path: &Path, state: GraphIdentitySnapshot) -> Result<()> {
    atomic_write_persistent(path, FileType::Metadata, &encode(state))
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "consumed by the following GraphBatch slice")
)]
fn exhausted() -> GraphError {
    GraphError::new(
        GraphErrorCode::AllocatorExhausted,
        "graph allocator counter space is exhausted",
    )
}

fn corruption(path: &Path, message: &str) -> GaussError {
    GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};
    #[cfg(all(unix, feature = "fault-injection"))]
    use std::{
        os::unix::process::ExitStatusExt,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    use super::*;

    #[test]
    fn open_retains_database_id_and_reserves_a_fresh_epoch() {
        let temp = tempfile::tempdir().unwrap();
        let first = GraphIdentityStore::open(temp.path()).unwrap();
        let first_state = first.snapshot();
        assert_eq!(first_state.allocator_epoch, 1);
        drop(first);

        let reopened = GraphIdentityStore::open(temp.path()).unwrap();
        let reopened_state = reopened.snapshot();
        assert_eq!(reopened_state.database_id, first_state.database_id);
        assert_eq!(reopened_state.allocator_epoch, 2);
        assert_eq!(reopened_state.node_high_water, 0);
        assert_eq!(reopened_state.edge_high_water, 0);
    }

    #[test]
    fn explicit_reservation_is_durable() {
        let temp = tempfile::tempdir().unwrap();
        let store = GraphIdentityStore::open(temp.path()).unwrap();
        assert_eq!(store.reserve_new_epoch().unwrap(), 2);
        drop(store);

        let reopened = GraphIdentityStore::open(temp.path()).unwrap();
        assert_eq!(reopened.snapshot().allocator_epoch, 3);
    }

    #[test]
    fn node_and_edge_ranges_are_durable_and_independent() {
        let temp = tempfile::tempdir().unwrap();
        let store = GraphIdentityStore::open(temp.path()).unwrap();

        let node_range = store.allocate_nids(NonZeroU64::new(3).unwrap()).unwrap();
        let edge_range = store
            .allocate_edge_ids(NonZeroU64::new(2).unwrap())
            .unwrap();
        assert_eq!(node_range.len(), 3);
        assert_eq!(
            node_range.nids().map(Nid::counter).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(
            edge_range
                .edge_ids()
                .map(EdgeId::counter)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(store.snapshot().node_high_water, 3);
        assert_eq!(store.snapshot().edge_high_water, 2);

        let stored = decode(
            &temp.path().join(GRAPH_IDENTITY_FILE),
            &read_persistent(&temp.path().join(GRAPH_IDENTITY_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(stored, store.snapshot());
    }

    #[test]
    fn allocation_exhaustion_fails_without_changing_durable_state() {
        let temp = tempfile::tempdir().unwrap();
        let store = GraphIdentityStore::open(temp.path()).unwrap();
        let all = store
            .allocate_nids(NonZeroU64::new(GRAPH_ALLOCATOR_MAX_COUNTER).unwrap())
            .unwrap();
        assert_eq!(all.len(), GRAPH_ALLOCATOR_MAX_COUNTER);
        let before = store.snapshot();

        let error = store
            .allocate_nids(NonZeroU64::new(1).unwrap())
            .unwrap_err();
        assert!(matches!(error, GaussError::Graph(_)));
        assert_eq!(store.snapshot(), before);
        assert_eq!(
            decode(
                &temp.path().join(GRAPH_IDENTITY_FILE),
                &read_persistent(&temp.path().join(GRAPH_IDENTITY_FILE)).unwrap(),
            )
            .unwrap(),
            before
        );
    }

    #[test]
    fn corrupt_crc_fails_closed_without_replacing_identity() {
        let temp = tempfile::tempdir().unwrap();
        let store = GraphIdentityStore::open(temp.path()).unwrap();
        let database_id = store.snapshot().database_id;
        drop(store);
        let path = temp.path().join(GRAPH_IDENTITY_FILE);
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(40)).unwrap();
        file.write_all(&[1]).unwrap();
        file.sync_all().unwrap();

        let error = GraphIdentityStore::open(temp.path()).unwrap_err();
        assert!(error.to_string().contains("CRC32C mismatch"));
        let bytes = read_persistent(&path).unwrap();
        assert_eq!(Uuid::from_slice(&bytes[16..32]).unwrap(), database_id);
    }

    #[test]
    fn preserve_for_root_swap_uses_live_identity() {
        let live = tempfile::tempdir().unwrap();
        let staged = tempfile::tempdir().unwrap();
        let store = GraphIdentityStore::open(live.path()).unwrap();
        let expected = store.snapshot();
        store.preserve_for_root_swap(staged.path()).unwrap();

        let bytes = read_persistent(&staged.path().join(GRAPH_IDENTITY_FILE)).unwrap();
        assert_eq!(decode(Path::new("staged"), &bytes).unwrap(), expected);
    }

    #[cfg(all(unix, feature = "fault-injection"))]
    #[test]
    fn g0_c2_sigkill_identity_reservations_never_repeat_handles() {
        const TEST_NAME: &str =
            "graph_identity::tests::g0_c2_sigkill_identity_reservations_never_repeat_handles";
        const CHILD_MODE_ENV: &str = "CHIRONDB_G0_C2_IDENTITY_MODE";
        const DATA_DIR_ENV: &str = "CHIRONDB_G0_C2_IDENTITY_DATA_DIR";

        if let Ok(mode) = std::env::var(CHILD_MODE_ENV) {
            let data_dir = PathBuf::from(std::env::var_os(DATA_DIR_ENV).unwrap());
            let store = GraphIdentityStore::open(&data_dir).unwrap();
            match mode.as_str() {
                "open" => {}
                "explicit" => {
                    store.reserve_new_epoch().unwrap();
                }
                "node" => {
                    store
                        .allocate_nids(std::num::NonZeroU64::new(1).unwrap())
                        .unwrap();
                }
                "edge" => {
                    store
                        .allocate_edge_ids(std::num::NonZeroU64::new(1).unwrap())
                        .unwrap();
                }
                other => panic!("unknown C2 identity child mode {other}"),
            }
            panic!("C2 identity failpoint returned instead of blocking");
        }

        for (mode, boundary) in [
            ("open", "atomic.after_temp_sync"),
            ("open", "atomic.after_rename_before_dir_sync"),
            ("open", "graph_identity.after_open_epoch_reservation"),
            (
                "explicit",
                "graph_identity.after_explicit_epoch_reservation",
            ),
            ("node", "graph_identity.after_node_range_reservation"),
            ("edge", "graph_identity.after_edge_range_reservation"),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let seed = GraphIdentityStore::open(temp.path()).unwrap();
            let database_id = seed.snapshot().database_id;
            let seed_nid = seed
                .allocate_nids(std::num::NonZeroU64::new(1).unwrap())
                .unwrap()
                .nids()
                .next()
                .unwrap();
            let seed_edge = seed
                .allocate_edge_ids(std::num::NonZeroU64::new(1).unwrap())
                .unwrap()
                .edge_ids()
                .next()
                .unwrap();
            drop(seed);

            let marker = temp
                .path()
                .join(format!("{mode}-{}.marker", boundary.replace('.', "-")));
            let mut child = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(TEST_NAME)
                .arg("--nocapture")
                .env(CHILD_MODE_ENV, mode)
                .env(DATA_DIR_ENV, temp.path())
                .env("CHIRONDB_FAILPOINT", format!("pause:{boundary}"))
                .env("CHIRONDB_FAILPOINT_MARKER", &marker)
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            while !marker.exists() && Instant::now() < deadline {
                if let Some(status) = child.try_wait().unwrap() {
                    panic!("identity child exited before {boundary}: {status}");
                }
                thread::sleep(Duration::from_millis(10));
            }
            assert!(marker.exists(), "identity child missed {boundary}");
            child.kill().unwrap();
            let status = child.wait().unwrap();
            assert_eq!(status.signal(), Some(9), "identity child was not SIGKILLed");

            let recovered = GraphIdentityStore::open(temp.path()).unwrap();
            assert_eq!(recovered.snapshot().database_id, database_id);
            assert!(recovered.snapshot().allocator_epoch >= 2);
            let recovered_nid = recovered
                .allocate_nids(std::num::NonZeroU64::new(1).unwrap())
                .unwrap()
                .nids()
                .next()
                .unwrap();
            let recovered_edge = recovered
                .allocate_edge_ids(std::num::NonZeroU64::new(1).unwrap())
                .unwrap()
                .edge_ids()
                .next()
                .unwrap();
            assert_ne!(recovered_nid, seed_nid, "Nid repeated at {boundary}");
            assert_ne!(recovered_edge, seed_edge, "EdgeId repeated at {boundary}");
            if mode == "node" {
                assert_ne!(
                    recovered_nid,
                    Nid::from_parts(2, 1).unwrap(),
                    "unreturned child Nid repeated at {boundary}"
                );
            }
            if mode == "edge" {
                assert_ne!(
                    recovered_edge,
                    EdgeId::from_parts(2, 1).unwrap(),
                    "unreturned child EdgeId repeated at {boundary}"
                );
            }
        }
    }
}
