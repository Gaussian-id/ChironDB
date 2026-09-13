//! Process-crash recovery regression for the single-node WAL contract.
//!
//! This deliberately exercises an OS process kill, not simulated storage
//! power loss. The asynchronous suffix is therefore allowed, but not required,
//! to be lost because the kernel may already have persisted dirty pages.

#[cfg(all(unix, feature = "fault-injection"))]
use std::fs;
use std::{collections::HashMap, env, io::Write, path::PathBuf, thread};
#[cfg(unix)]
use std::{
    collections::HashSet,
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, RecvTimeoutError},
    time::{Duration, Instant},
};

use chirondb::{CollectionConfig, Db, DistanceMetric, Point};
#[cfg(all(unix, feature = "fault-injection"))]
use chirondb::{
    fs_util::fault_injection::{
        CRASH_HOOK_ENV, CRASH_HOOK_MARKER_ENV, CRASH_HOOK_RELEASE_ENV,
        HOOK_CATALOG_AFTER_DURABLE_COMMIT, HOOK_COMPACT_AFTER_CHECKPOINT_PUBLISH,
        HOOK_COMPACT_AFTER_MANIFEST_PUBLISH, HOOK_COMPACT_AFTER_SEGMENT_PUBLISH,
        HOOK_COMPACT_AFTER_SEGMENT_TREE_SYNC, HOOK_COMPACT_AFTER_WAL_FSYNC,
        HOOK_RESTORE_AFTER_NEW_INSTALLED, HOOK_RESTORE_AFTER_OLD_MOVED,
        HOOK_RESTORE_AFTER_PREPARED, HOOK_SNAPSHOT_AFTER_DESTINATION_PUBLISH,
        HOOK_SNAPSHOT_AFTER_STAGING_SYNC, HOOK_WAL_AFTER_ARCHIVE_PUBLISH,
        HOOK_WAL_AFTER_FRAME_HEADER, HOOK_WAL_AFTER_FRAME_WRITE, HOOK_WAL_AFTER_FSYNC,
        HOOK_WAL_AFTER_ROTATION_PUBLISH, TEST_WAL_SEGMENT_BYTES_ENV,
    },
    wal::{Wal, WalEntry},
};
use serde_json::json;
#[cfg(unix)]
use tempfile::TempDir;

const HELPER_ENV: &str = "CHIRONDB_PROCESS_KILL_HELPER";
const DATA_DIR_ENV: &str = "CHIRONDB_PROCESS_KILL_DATA_DIR";
const SYNC_POINTS: usize = 24;
const ASYNC_POINTS: usize = 64;
const ASYNC_ACK_MARKER: &str = "CHIRONDB_ASYNC_ACKNOWLEDGED";
#[cfg(all(unix, feature = "fault-injection"))]
const RESTORE_SOURCE_ENV: &str = "CHIRONDB_PROCESS_KILL_RESTORE_SOURCE";
#[cfg(all(unix, feature = "fault-injection"))]
const WAL_ARCHIVE_DIR_ENV: &str = "CHIRONDB_PROCESS_KILL_WAL_ARCHIVE_DIR";
#[cfg(unix)]
const HELPER_TIMEOUT: Duration = Duration::from_secs(30);

/// Invoked only by `process_kill_preserves_sync_prefix_and_at_most_loses_async_suffix`.
///
/// Keeping the writer inside this integration-test binary gives the parent a
/// real process to kill without introducing failpoints into the production DB.
#[test]
#[ignore = "subprocess helper; invoked by the process-kill regression"]
fn process_kill_writer_helper() {
    if env::var_os(HELPER_ENV).is_none() {
        return;
    }

    let data_dir = PathBuf::from(env::var_os(DATA_DIR_ENV).expect("helper data directory"));
    let db = Db::open(&data_dir).expect("open helper database");
    db.create_collection(test_collection())
        .expect("create helper collection");

    for ordinal in 0..SYNC_POINTS {
        db.upsert_wait("docs", vec![test_point("sync", ordinal)], true)
            .expect("durable upsert");
    }

    for ordinal in 0..ASYNC_POINTS {
        db.upsert_wait("docs", vec![test_point("async", ordinal)], false)
            .expect("asynchronous upsert");
    }

    println!("{ASYNC_ACK_MARKER}");
    std::io::stdout()
        .flush()
        .expect("flush acknowledgement marker");

    // Do not drop Db: the parent must terminate this process before graceful
    // shutdown can flush the outstanding asynchronous WAL suffix.
    loop {
        thread::park();
    }
}

#[cfg(unix)]
#[test]
fn process_kill_preserves_sync_prefix_and_at_most_loses_async_suffix() {
    let data_dir = TempDir::new().unwrap();
    let mut child = spawn_writer(data_dir.path());
    wait_for_async_acknowledgement(&mut child);

    child.kill().expect("SIGKILL writer subprocess");
    let status = child.wait().expect("reap writer subprocess");
    assert!(
        !status.success(),
        "writer must be terminated rather than exit gracefully"
    );

    let recovered = Db::open(data_dir.path()).expect("recover after process kill");
    let points = recovered
        .scroll("docs", None, SYNC_POINTS + ASYNC_POINTS + 1, None)
        .expect("read recovered points")
        .points;
    assert_recovered_prefix(&points);
}

#[cfg(unix)]
fn spawn_writer(data_dir: &Path) -> Child {
    Command::new(env::current_exe().expect("current test executable"))
        .arg("--ignored")
        .arg("--exact")
        .arg("process_kill_writer_helper")
        .arg("--nocapture")
        .env(HELPER_ENV, "1")
        .env(DATA_DIR_ENV, data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn writer subprocess")
}

#[cfg(unix)]
fn wait_for_async_acknowledgement(child: &mut Child) {
    let stdout = child.stdout.take().expect("writer stdout pipe");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let line = match line {
                Ok(line) => line,
                Err(_) => break,
            };
            if sender.send(line).is_err() {
                break;
            }
        }
    });

    let deadline = Instant::now() + HELPER_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(line) if line.trim() == ASYNC_ACK_MARKER => return,
            Ok(_) => {}
            Err(RecvTimeoutError::Timeout) => {
                terminate_and_reap(child);
                panic!(
                    "writer did not acknowledge the asynchronous suffix within {HELPER_TIMEOUT:?}"
                );
            }
            Err(RecvTimeoutError::Disconnected) => {
                let status = child.wait().expect("reap failed writer subprocess");
                panic!("writer exited before acknowledgement marker: {status}");
            }
        }
    }
}

#[cfg(unix)]
fn terminate_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn assert_recovered_prefix(points: &[Point]) {
    let actual_ids = points
        .iter()
        .map(|point| point.id.as_str())
        .collect::<HashSet<_>>();
    assert_eq!(
        actual_ids.len(),
        points.len(),
        "duplicate recovered point ID"
    );

    for ordinal in 0..SYNC_POINTS {
        let id = point_id("sync", ordinal);
        assert!(
            actual_ids.contains(id.as_str()),
            "acknowledged wait=true point {id} was lost"
        );
    }

    let recovered_async = (0..ASYNC_POINTS)
        .take_while(|ordinal| actual_ids.contains(point_id("async", *ordinal).as_str()))
        .count();
    for ordinal in recovered_async..ASYNC_POINTS {
        let id = point_id("async", ordinal);
        assert!(
            !actual_ids.contains(id.as_str()),
            "wait=false recovery contains a hole before {id}"
        );
    }

    let expected = (0..SYNC_POINTS)
        .map(|ordinal| point_id("sync", ordinal))
        .chain((0..recovered_async).map(|ordinal| point_id("async", ordinal)))
        .collect::<HashSet<_>>();
    let unexpected = actual_ids
        .iter()
        .filter(|id| !expected.contains(**id))
        .copied()
        .collect::<Vec<_>>();
    assert!(
        unexpected.is_empty(),
        "phantom recovered IDs: {unexpected:?}"
    );
    assert_eq!(points.len(), SYNC_POINTS + recovered_async);
}

/// Feature-only helper used by the phase-specific crash matrix below.
/// The configured core hook writes a durable marker and blocks inside the
/// selected operation, so reaching the end of this helper is always a bug.
#[cfg(all(unix, feature = "fault-injection"))]
#[test]
#[ignore = "subprocess helper; invoked by the phase-specific crash matrix"]
fn phase_crash_helper() {
    let hook = env::var(CRASH_HOOK_ENV).expect("phase crash hook name");
    let target = PathBuf::from(env::var_os(DATA_DIR_ENV).expect("phase crash target"));

    match hook.as_str() {
        HOOK_WAL_AFTER_FRAME_HEADER
        | HOOK_WAL_AFTER_FRAME_WRITE
        | HOOK_WAL_AFTER_FSYNC
        | HOOK_WAL_AFTER_ROTATION_PUBLISH => {
            let mut wal = Wal::open(&target).expect("open phase WAL");
            wal.append(&WalEntry::Delete {
                id: "issued-after-boundary".to_string(),
            })
            .expect("append phase WAL record");
        }
        HOOK_WAL_AFTER_ARCHIVE_PUBLISH => {
            let archive_dir =
                PathBuf::from(env::var_os(WAL_ARCHIVE_DIR_ENV).expect("phase archive directory"));
            let mut wal = Wal::open(&target).expect("open archive phase WAL");
            wal.archive_and_reset(&archive_dir)
                .expect("archive phase WAL");
        }
        HOOK_CATALOG_AFTER_DURABLE_COMMIT => {
            let db = Db::open(&target).expect("open catalog phase database");
            db.create_collection(test_collection())
                .expect("create phase collection");
        }
        HOOK_COMPACT_AFTER_SEGMENT_TREE_SYNC
        | HOOK_COMPACT_AFTER_SEGMENT_PUBLISH
        | HOOK_COMPACT_AFTER_WAL_FSYNC
        | HOOK_COMPACT_AFTER_MANIFEST_PUBLISH
        | HOOK_COMPACT_AFTER_CHECKPOINT_PUBLISH => {
            let db = Db::open(&target).expect("open compaction phase database");
            db.compact_collection("docs").expect("phase compaction");
        }
        HOOK_SNAPSHOT_AFTER_STAGING_SYNC | HOOK_SNAPSHOT_AFTER_DESTINATION_PUBLISH => {
            let destination = target.with_extension("snapshot");
            let db = Db::open(&target).expect("open snapshot phase database");
            db.snapshot(destination).expect("phase snapshot");
        }
        HOOK_RESTORE_AFTER_PREPARED
        | HOOK_RESTORE_AFTER_OLD_MOVED
        | HOOK_RESTORE_AFTER_NEW_INSTALLED => {
            let source =
                PathBuf::from(env::var_os(RESTORE_SOURCE_ENV).expect("phase restore source"));
            let db = Db::open(&target).expect("open restore phase database");
            db.restore(&source).expect("phase restore");
        }
        other => panic!("unsupported phase crash hook {other}"),
    }

    panic!("phase crash hook {hook} returned instead of blocking");
}

#[cfg(all(unix, feature = "fault-injection"))]
#[test]
fn phase_crash_wal_header_repairs_only_the_unacknowledged_tail() {
    let sandbox = TempDir::new().unwrap();
    let wal_dir = sandbox.path().join("wal");
    seed_phase_wal(&wal_dir);
    run_phase_crash(&wal_dir, HOOK_WAL_AFTER_FRAME_HEADER, None, None, None);

    let mut ids = Vec::new();
    let stats = Wal::recover_from(&wal_dir, 0, |record| {
        if let WalEntry::Delete { id } = record.entry {
            ids.push(id);
        }
        Ok(())
    })
    .expect("repair header-only active tail");
    assert_eq!(ids, ["durable-prefix"]);
    assert_eq!(stats.records, 1);
    assert_eq!(stats.repaired_tail_bytes, 8);
    assert_eq!(phase_wal_ids(&wal_dir), ["durable-prefix"]);
}

#[cfg(all(unix, feature = "fault-injection"))]
#[test]
fn phase_crash_wal_frame_write_recovers_the_complete_issued_record() {
    let sandbox = TempDir::new().unwrap();
    let wal_dir = sandbox.path().join("wal");
    seed_phase_wal(&wal_dir);
    run_phase_crash(&wal_dir, HOOK_WAL_AFTER_FRAME_WRITE, None, None, None);

    assert_eq!(
        phase_wal_ids(&wal_dir),
        ["durable-prefix", "issued-after-boundary"]
    );
}

#[cfg(all(unix, feature = "fault-injection"))]
#[test]
fn phase_crash_wal_fsync_recovers_the_durable_record() {
    let sandbox = TempDir::new().unwrap();
    let wal_dir = sandbox.path().join("wal");
    seed_phase_wal(&wal_dir);
    run_phase_crash(&wal_dir, HOOK_WAL_AFTER_FSYNC, None, None, None);

    assert_eq!(
        phase_wal_ids(&wal_dir),
        ["durable-prefix", "issued-after-boundary"]
    );
}

#[cfg(all(unix, feature = "fault-injection"))]
#[test]
fn phase_crash_wal_rotation_publish_keeps_history_contiguous() {
    let sandbox = TempDir::new().unwrap();
    let wal_dir = sandbox.path().join("wal");
    seed_phase_wal(&wal_dir);
    run_phase_crash(
        &wal_dir,
        HOOK_WAL_AFTER_ROTATION_PUBLISH,
        None,
        None,
        Some("9"),
    );

    assert_eq!(phase_wal_ids(&wal_dir), ["durable-prefix"]);
    let mut segments = fs::read_dir(&wal_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".gdwal"))
        .collect::<Vec<_>>();
    segments.sort();
    assert_eq!(segments, ["000000.gdwal", "000001.gdwal"]);
}

#[cfg(all(unix, feature = "fault-injection"))]
#[test]
fn phase_crash_archive_publish_keeps_live_and_archive_copies_recoverable() {
    let sandbox = TempDir::new().unwrap();
    let wal_dir = sandbox.path().join("wal");
    let archive_root = sandbox.path().join("archive");
    seed_phase_wal(&wal_dir);
    run_phase_crash(
        &wal_dir,
        HOOK_WAL_AFTER_ARCHIVE_PUBLISH,
        None,
        Some(&archive_root),
        None,
    );

    assert_eq!(phase_wal_ids(&wal_dir), ["durable-prefix"]);
    let archives = fs::read_dir(&archive_root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    assert_eq!(archives.len(), 1);
    assert_eq!(phase_wal_ids(&archives[0]), ["durable-prefix"]);
}

#[cfg(all(unix, feature = "fault-injection"))]
#[test]
fn phase_crash_catalog_commit_replays_the_durable_create() {
    let sandbox = TempDir::new().unwrap();
    let db_root = sandbox.path().join("db");
    drop(Db::open(&db_root).unwrap());
    run_phase_crash(
        &db_root,
        HOOK_CATALOG_AFTER_DURABLE_COMMIT,
        None,
        None,
        None,
    );

    let recovered = Db::open(&db_root).expect("replay durable catalog create");
    let names = recovered
        .list_collections()
        .into_iter()
        .map(|config| config.name)
        .collect::<Vec<_>>();
    assert_eq!(names, ["docs"]);
    assert_eq!(recovered.count("docs", None).unwrap().count, 0);
}

#[cfg(all(unix, feature = "fault-injection"))]
#[test]
fn phase_crash_compaction_boundaries_recover_one_complete_generation() {
    for hook in [
        HOOK_COMPACT_AFTER_SEGMENT_TREE_SYNC,
        HOOK_COMPACT_AFTER_SEGMENT_PUBLISH,
        HOOK_COMPACT_AFTER_WAL_FSYNC,
        HOOK_COMPACT_AFTER_MANIFEST_PUBLISH,
        HOOK_COMPACT_AFTER_CHECKPOINT_PUBLISH,
    ] {
        let sandbox = TempDir::new().unwrap();
        let db_root = sandbox.path().join("db");
        let db = Db::open(&db_root).unwrap();
        db.create_collection(test_collection()).unwrap();
        db.upsert_wait("docs", vec![test_point("stable", 0)], true)
            .unwrap();
        drop(db);

        run_phase_crash(&db_root, hook, None, None, None);

        let recovered = Db::open(&db_root).expect("recover compaction boundary");
        let points = recovered
            .scroll("docs", None, 10, None)
            .expect("read recovered compaction generation")
            .points;
        assert_eq!(points.len(), 1, "mixed compaction generation at {hook}");
        assert_eq!(points[0].id, point_id("stable", 0));
        let searchers = db_root.join("collections/docs/searchers");
        assert!(
            fs::read_dir(searchers).unwrap().all(|entry| {
                let name = entry.unwrap().file_name().to_string_lossy().into_owned();
                !name.starts_with('.') || name == ".builds"
            }),
            "orphan compaction staging survived recovery at {hook}"
        );
    }
}

#[cfg(all(unix, feature = "fault-injection"))]
#[test]
fn phase_crash_snapshot_boundaries_leave_live_and_snapshot_generations_complete() {
    for hook in [
        HOOK_SNAPSHOT_AFTER_STAGING_SYNC,
        HOOK_SNAPSHOT_AFTER_DESTINATION_PUBLISH,
    ] {
        let sandbox = TempDir::new().unwrap();
        let db_root = sandbox.path().join("db");
        let destination = db_root.with_extension("snapshot");
        let db = Db::open(&db_root).unwrap();
        db.create_collection(test_collection()).unwrap();
        db.upsert_wait("docs", vec![test_point("stable", 0)], true)
            .unwrap();
        drop(db);

        run_phase_crash(&db_root, hook, None, None, None);

        let recovered = Db::open(&db_root).expect("live database remains complete");
        assert_eq!(recovered.count("docs", None).unwrap().count, 1);
        if hook == HOOK_SNAPSHOT_AFTER_STAGING_SYNC {
            assert!(!destination.exists());
            recovered
                .snapshot(&destination)
                .expect("retry cleans staging and publishes snapshot");
        }
        drop(recovered);
        let snapshot = Db::open(&destination).expect("published snapshot is complete");
        assert_eq!(snapshot.count("docs", None).unwrap().count, 1);
    }
}

#[cfg(all(unix, feature = "fault-injection"))]
#[test]
fn phase_crash_restore_prepared_recovers_the_old_generation() {
    assert_restore_phase(HOOK_RESTORE_AFTER_PREPARED, "old");
}

#[cfg(all(unix, feature = "fault-injection"))]
#[test]
fn phase_crash_restore_old_moved_finishes_the_new_generation() {
    assert_restore_phase(HOOK_RESTORE_AFTER_OLD_MOVED, "new");
}

#[cfg(all(unix, feature = "fault-injection"))]
#[test]
fn phase_crash_restore_new_installed_keeps_the_new_generation() {
    assert_restore_phase(HOOK_RESTORE_AFTER_NEW_INSTALLED, "new");
}

#[cfg(all(unix, feature = "fault-injection"))]
fn run_phase_crash(
    target: &Path,
    hook: &str,
    restore_source: Option<&Path>,
    archive_dir: Option<&Path>,
    segment_bytes: Option<&str>,
) {
    let marker = target
        .parent()
        .expect("phase target parent")
        .join(format!("{hook}.marker"));
    let mut command = Command::new(env::current_exe().expect("current test executable"));
    command
        .arg("--ignored")
        .arg("--exact")
        .arg("phase_crash_helper")
        .arg("--nocapture")
        .env(DATA_DIR_ENV, target)
        .env(CRASH_HOOK_ENV, hook)
        .env(CRASH_HOOK_MARKER_ENV, &marker)
        .env_remove(CRASH_HOOK_RELEASE_ENV)
        .env_remove(TEST_WAL_SEGMENT_BYTES_ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if let Some(source) = restore_source {
        command.env(RESTORE_SOURCE_ENV, source);
    }
    if let Some(archive_dir) = archive_dir {
        command.env(WAL_ARCHIVE_DIR_ENV, archive_dir);
    }
    if let Some(segment_bytes) = segment_bytes {
        command.env(TEST_WAL_SEGMENT_BYTES_ENV, segment_bytes);
    }
    let mut child = command.spawn().expect("spawn phase crash helper");
    wait_for_hook_marker_and_kill(&mut child, &marker, hook);
}

#[cfg(all(unix, feature = "fault-injection"))]
fn wait_for_hook_marker_and_kill(child: &mut Child, marker: &Path, hook: &str) {
    let deadline = Instant::now() + HELPER_TIMEOUT;
    loop {
        if fs::read_to_string(marker).is_ok_and(|contents| contents.trim() == hook) {
            child.kill().expect("SIGKILL phase helper");
            let status = child.wait().expect("reap phase helper");
            assert!(!status.success(), "phase helper exited gracefully");
            return;
        }
        if let Some(status) = child.try_wait().expect("poll phase helper") {
            panic!("phase helper exited before {hook} marker: {status}");
        }
        if Instant::now() >= deadline {
            terminate_and_reap(child);
            panic!("phase helper did not reach {hook} within {HELPER_TIMEOUT:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(all(unix, feature = "fault-injection"))]
fn seed_phase_wal(wal_dir: &Path) {
    let mut wal = Wal::open(wal_dir).expect("open seed WAL");
    wal.append(&WalEntry::Delete {
        id: "durable-prefix".to_string(),
    })
    .expect("append durable seed record");
}

#[cfg(all(unix, feature = "fault-injection"))]
fn phase_wal_ids(wal_dir: &Path) -> Vec<String> {
    Wal::load(wal_dir)
        .expect("strictly load phase WAL")
        .into_iter()
        .filter_map(|record| match record.entry {
            WalEntry::Delete { id } => Some(id),
            _ => None,
        })
        .collect()
}

#[cfg(all(unix, feature = "fault-injection"))]
fn assert_restore_phase(hook: &str, expected_kind: &str) {
    let sandbox = TempDir::new().unwrap();
    let live = sandbox.path().join("live");
    let source_root = sandbox.path().join("source-db");
    let snapshot = sandbox.path().join("snapshot");

    let old = Db::open(&live).unwrap();
    old.create_collection(test_collection()).unwrap();
    old.upsert_wait("docs", vec![test_point("old", 0)], true)
        .unwrap();
    drop(old);

    let new = Db::open(&source_root).unwrap();
    new.create_collection(test_collection()).unwrap();
    new.upsert_wait("docs", vec![test_point("new", 0)], true)
        .unwrap();
    new.snapshot(&snapshot).unwrap();
    drop(new);

    run_phase_crash(&live, hook, Some(&snapshot), None, None);

    let recovered = Db::open(&live).expect("recover interrupted restore");
    let points = recovered
        .scroll("docs", None, 10, None)
        .expect("read recovered restore generation")
        .points;
    assert_eq!(points.len(), 1);
    assert_eq!(points[0].id, point_id(expected_kind, 0));
}

fn test_collection() -> CollectionConfig {
    CollectionConfig {
        name: "docs".to_string(),
        vector_dim: 2,
        metric: DistanceMetric::Cosine,
        shards: 1,
        replicas: 1,
        quantization: None,
        payload_schema: HashMap::new(),
        named_vector_dims: HashMap::new(),
        hnsw_m: None,
        hnsw_ef_construction: None,
        hnsw_ef_search: None,
        recall_sla: None,
        index_kind: None,
        // Keep the crash fixture mutable until the explicit compaction below;
        // otherwise the background sealer can make compaction a no-op before
        // the child reaches the requested durability boundary.
        streamer_max_bytes: usize::MAX,
    }
}

fn test_point(kind: &str, ordinal: usize) -> Point {
    Point {
        id: point_id(kind, ordinal),
        vector: vec![1.0, ordinal as f32 + 1.0],
        vectors: HashMap::new(),
        sparse_vector: None,
        payload: json!({"kind": kind, "ordinal": ordinal}),
    }
}

fn point_id(kind: &str, ordinal: usize) -> String {
    format!("{kind}-{ordinal:03}")
}
