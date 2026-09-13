#![cfg(target_os = "linux")]

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use chirondb_core::{CollectionConfig, Db, DistanceMetric, Point};
use serde_json::json;

const SAFETY_MARKER: &str = ".chirondb-enospc-test-device";

#[test]
#[ignore = "requires CHIRONDB_ENOSPC_ROOT on a dedicated marked filesystem"]
fn real_enospc_rejects_unacknowledged_write_and_reopens_acknowledged_state() {
    let root = fs::canonicalize(
        std::env::var_os("CHIRONDB_ENOSPC_ROOT")
            .expect("CHIRONDB_ENOSPC_ROOT must name the dedicated filesystem"),
    )
    .unwrap();
    assert_ne!(root, Path::new("/"), "refusing to fill the root filesystem");
    assert!(
        root.join(SAFETY_MARKER).is_file(),
        "dedicated filesystem is missing the ENOSPC safety marker"
    );
    let data_dir = root.join("data");
    let filler = root.join("fill.bin");
    let db = Db::open(&data_dir).unwrap();
    db.create_collection(collection_config()).unwrap();
    db.upsert("docs", vec![point("acknowledged")]).unwrap();

    fill_until_enospc(&filler);
    let mut acknowledged = vec!["acknowledged".to_string()];
    let rejected = (0..100_000)
        .find_map(|attempt| {
            let id = format!("enospc-{attempt:06}");
            match db.upsert("docs", vec![point(&id)]) {
                Ok(_) => {
                    acknowledged.push(id);
                    None
                }
                Err(_) => Some(id),
            }
        })
        .expect("wait=true writes never reached a durable ENOSPC rejection");
    drop(db);
    fs::remove_file(&filler).unwrap();
    File::open(&root).unwrap().sync_all().unwrap();

    let reopened = Db::open(&data_dir).unwrap();
    let mut requested = acknowledged.clone();
    requested.push(rejected.clone());
    let reopened_ids = reopened
        .get_points("docs", &requested)
        .unwrap()
        .into_iter()
        .map(|point| point.id)
        .collect::<HashSet<_>>();
    assert_eq!(reopened_ids.len(), acknowledged.len());
    assert!(
        acknowledged.iter().all(|id| reopened_ids.contains(id)),
        "an acknowledged wait=true write was lost after restart"
    );
    assert!(
        !reopened_ids.contains(&rejected),
        "the rejected write became visible after restart"
    );

    if let Some(path) = std::env::var_os("CHIRONDB_ENOSPC_EVIDENCE") {
        let evidence = json!({
            "schema_version": 2,
            "verdict": "passed",
            "fault": "real-enospc-loopback",
            "tested_sha": std::env::var("GITHUB_SHA").ok(),
            "core_tree_hash": std::env::var("CHIRONDB_CORE_TREE_HASH").ok(),
            "server_tree_hash": std::env::var("CHIRONDB_SERVER_TREE_HASH").ok(),
            "actions_run_id": std::env::var("GITHUB_RUN_ID").ok(),
            "acknowledged_points_after_restart": acknowledged.len(),
            "acknowledged_writes_preserved": true,
            "first_rejected_point": rejected,
            "rejected_write_absent_after_restart": true,
        });
        fs::write(path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    }
}

#[test]
#[ignore = "requires CHIRONDB_ENOSPC_ROOT on a dedicated marked filesystem"]
fn real_enospc_preserves_build_checkpoint_and_resumes_after_space_returns() {
    let root = enospc_root();
    let data_dir = root.join("build-data");
    if let Ok(mode) = std::env::var("CHIRONDB_ENOSPC_BUILD_CHILD") {
        let db = Db::open(&data_dir).unwrap();
        match mode.as_str() {
            "fail" => assert!(
                db.compact_collection("docs").is_err(),
                "build unexpectedly completed after the parent filled the filesystem"
            ),
            "resume" => {
                db.compact_collection("docs")
                    .expect("build must resume after filesystem space returns");
            }
            other => panic!("unknown ENOSPC build child mode {other}"),
        }
        return;
    }

    let mut config = collection_config();
    config.vector_dim = 16;
    config.streamer_max_bytes = usize::MAX;
    {
        let db = Db::open(&data_dir).unwrap();
        db.create_collection(config).unwrap();
        db.upsert(
            "docs",
            (0..256)
                .map(|index| Point {
                    id: format!("p{index:04}"),
                    vector: (0..16)
                        .map(|dim| (index * 17 + dim) as f32 / 257.0)
                        .collect(),
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({"index": index}),
                })
                .collect(),
        )
        .unwrap();
        db.flush_wals().unwrap();
    }

    let control_root =
        std::env::temp_dir().join(format!("chirondb-enospc-build-{}", std::process::id()));
    if control_root.exists() {
        fs::remove_dir_all(&control_root).unwrap();
    }
    fs::create_dir_all(&control_root).unwrap();
    let marker = control_root.join("cell.marker");
    let release = control_root.join("release.marker");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "real_enospc_preserves_build_checkpoint_and_resumes_after_space_returns",
            "--nocapture",
        ])
        .env("CHIRONDB_ENOSPC_ROOT", &root)
        .env("CHIRONDB_ENOSPC_BUILD_CHILD", "fail")
        .env("CHIRONDB_FAILPOINT", "pause:seal.after_vamana_cell")
        .env("CHIRONDB_FAILPOINT_MARKER", &marker)
        .env("CHIRONDB_FAILPOINT_RELEASE", &release)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    wait_for_marker_or_child_exit(&marker, &mut child);

    let checkpoint_cell = first_build_cell(&data_dir);
    let checkpoint_bytes = fs::read(&checkpoint_cell).unwrap();
    let checkpoint_modified = fs::metadata(&checkpoint_cell).unwrap().modified().unwrap();
    let filler = root.join("build-fill.bin");
    fill_until_enospc(&filler);
    fs::write(&release, b"continue").unwrap();
    let status = child.wait().unwrap();
    assert!(status.success(), "ENOSPC build child failed: {status}");

    fs::remove_file(&filler).unwrap();
    File::open(&root).unwrap().sync_all().unwrap();
    fs::remove_file(&marker).unwrap();
    fs::remove_file(&release).unwrap();
    let mut resume_child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "real_enospc_preserves_build_checkpoint_and_resumes_after_space_returns",
            "--nocapture",
        ])
        .env("CHIRONDB_ENOSPC_ROOT", &root)
        .env("CHIRONDB_ENOSPC_BUILD_CHILD", "resume")
        .env("CHIRONDB_FAILPOINT", "pause:seal.after_vamana_cell")
        .env("CHIRONDB_FAILPOINT_MARKER", &marker)
        .env("CHIRONDB_FAILPOINT_RELEASE", &release)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    wait_for_marker_or_child_exit(&marker, &mut resume_child);
    assert_eq!(
        fs::read(&checkpoint_cell).unwrap(),
        checkpoint_bytes,
        "validated cell checkpoint bytes changed during resume"
    );
    assert_eq!(
        fs::metadata(&checkpoint_cell).unwrap().modified().unwrap(),
        checkpoint_modified,
        "validated cell checkpoint was rewritten instead of reused"
    );
    fs::write(&release, b"continue").unwrap();
    let status = resume_child.wait().unwrap();
    assert!(status.success(), "ENOSPC resume child failed: {status}");

    let reopened = Db::open(&data_dir).unwrap();
    assert_eq!(reopened.count("docs", None).unwrap().count, 256);

    if let Some(path) = std::env::var_os("CHIRONDB_ENOSPC_EVIDENCE") {
        let evidence = json!({
            "schema_version": 2,
            "verdict": "passed",
            "fault": "real-enospc-loopback",
            "tested_sha": std::env::var("GITHUB_SHA").ok(),
            "core_tree_hash": std::env::var("CHIRONDB_CORE_TREE_HASH").ok(),
            "server_tree_hash": std::env::var("CHIRONDB_SERVER_TREE_HASH").ok(),
            "actions_run_id": std::env::var("GITHUB_RUN_ID").ok(),
            "wal_unacknowledged_write_gate": true,
            "build_cell_checkpoint_observed": true,
            "build_resumed_after_space_returned": true,
            "points_after_restart": 256,
        });
        fs::write(path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    }
    fs::remove_dir_all(control_root).unwrap();
}

fn enospc_root() -> std::path::PathBuf {
    let root = fs::canonicalize(
        std::env::var_os("CHIRONDB_ENOSPC_ROOT")
            .expect("CHIRONDB_ENOSPC_ROOT must name the dedicated filesystem"),
    )
    .unwrap();
    assert_ne!(root, Path::new("/"), "refusing to fill the root filesystem");
    assert!(
        root.join(SAFETY_MARKER).is_file(),
        "dedicated filesystem is missing the ENOSPC safety marker"
    );
    root
}

fn wait_for_marker_or_child_exit(marker: &Path, child: &mut std::process::Child) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !marker.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("build child exited before checkpoint marker: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for build checkpoint"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn first_build_cell(data_dir: &Path) -> std::path::PathBuf {
    let builds = data_dir.join("collections/docs/searchers/.builds");
    fs::read_dir(builds)
        .unwrap()
        .flat_map(|build| {
            fs::read_dir(build.unwrap().path().join("vamana-cells"))
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .collect::<Vec<_>>()
        })
        .min()
        .expect("checkpointed Vamana cell")
}

fn fill_until_enospc(path: &Path) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .unwrap();
    let block = vec![0xa5_u8; 1024 * 1024];
    loop {
        match file.write_all(&block) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(28) => break,
            Err(error) => panic!("expected ENOSPC, got {error}"),
        }
    }
    let _ = file.sync_all();
}

fn point(id: &str) -> Point {
    Point {
        id: id.to_string(),
        vector: vec![1.0, 2.0],
        vectors: HashMap::new(),
        sparse_vector: None,
        payload: json!({"source": id}),
    }
}

fn collection_config() -> CollectionConfig {
    CollectionConfig {
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
    }
}
