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

use chirondb_core::{
    CollectionConfig, Db, DistanceMetric, Point, TransactionState,
    audit::{AUDIT_LOG_FILE, AuditContext, AuditEvent, AuditWriter},
};
use serde_json::json;

const SAFETY_MARKER: &str = ".chirondb-enospc-test-device";
const AUDIT_CHILD_ENV: &str = "CHIRONDB_ENOSPC_AUDIT_CHILD";

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
    let (rejected, unknown_transaction_id) = (0..100_000)
        .find_map(|attempt| {
            let id = format!("enospc-{attempt:06}");
            match db.upsert("docs", vec![point(&id)]) {
                Ok(_) => {
                    acknowledged.push(id);
                    None
                }
                Err(error) => {
                    eprintln!("first rejected write {id}: {error}");
                    let transaction_id = match error {
                        chirondb_core::GaussError::CommitOutcomeUnknown { transaction_id } => {
                            Some(transaction_id)
                        }
                        _ => None,
                    };
                    Some((id, transaction_id))
                }
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
    let reconciled_state = unknown_transaction_id
        .as_deref()
        .map(|transaction_id| reopened.transaction_status(transaction_id).unwrap());
    let unknown_committed = reconciled_state
        .as_ref()
        .is_some_and(|status| status.state == TransactionState::Committed);
    assert_eq!(
        reopened_ids.len(),
        acknowledged.len() + usize::from(unknown_committed)
    );
    assert!(
        acknowledged.iter().all(|id| reopened_ids.contains(id)),
        "an acknowledged wait=true write was lost after restart"
    );
    assert_eq!(reopened_ids.contains(&rejected), unknown_committed);
    if let Some(status) = &reconciled_state {
        assert!(matches!(
            status.state,
            TransactionState::Committed | TransactionState::Rejected
        ));
        if status.state == TransactionState::Committed {
            assert!(status.storage_projected);
            assert!(status.audit_projected);
        }
    }

    if let Some(path) = std::env::var_os("CHIRONDB_ENOSPC_EVIDENCE") {
        let evidence = json!({
            "schema_version": 2,
            "test_case": "wal_write_recovery",
            "verdict": "passed",
            "fault": "real-enospc-loopback",
            "tested_sha": std::env::var("GITHUB_SHA").ok(),
            "core_tree_hash": std::env::var("CHIRONDB_CORE_TREE_HASH").ok(),
            "server_tree_hash": std::env::var("CHIRONDB_SERVER_TREE_HASH").ok(),
            "actions_run_id": std::env::var("GITHUB_RUN_ID").ok(),
            "acknowledged_points_after_restart": acknowledged.len(),
            "acknowledged_writes_preserved": true,
            "first_rejected_point": rejected,
            "unknown_transaction_id": unknown_transaction_id,
            "unknown_reconciled_state": reconciled_state.map(|status| status.state),
            "rejected_write_absent_after_restart": !unknown_committed,
        });
        fs::write(path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    }
}

#[test]
#[ignore = "requires CHIRONDB_ENOSPC_ROOT on a dedicated marked filesystem"]
fn real_enospc_recovers_committed_audit_projection_exactly_once() {
    let root = enospc_root();
    let data_dir = root.join("audit-data");
    if std::env::var_os(AUDIT_CHILD_ENV).is_some() {
        let db = Db::open(&data_dir).unwrap();
        db.upsert("docs", vec![point("committed-during-enospc")])
            .expect("durable COMMIT must not become a rejected response");
        assert!(!db.durability_ready());
        fs::write(
            std::env::var_os("CHIRONDB_ENOSPC_AUDIT_CHILD_RESULT").unwrap(),
            b"committed-degraded\n",
        )
        .unwrap();
        return;
    }

    {
        let db = Db::open(&data_dir).unwrap();
        db.create_collection(collection_config()).unwrap();
        db.upsert("docs", vec![point("stable")]).unwrap();
    }
    align_audit_for_next_upsert_enospc(&data_dir);

    let control_root =
        std::env::temp_dir().join(format!("chirondb-enospc-audit-{}", std::process::id()));
    if control_root.exists() {
        fs::remove_dir_all(&control_root).unwrap();
    }
    fs::create_dir_all(&control_root).unwrap();
    let marker = control_root.join("audit.marker");
    let release = control_root.join("release.marker");
    let child_result = control_root.join("child.result");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "real_enospc_recovers_committed_audit_projection_exactly_once",
            "--nocapture",
        ])
        .env("CHIRONDB_ENOSPC_ROOT", &root)
        .env(AUDIT_CHILD_ENV, "1")
        .env("CHIRONDB_ENOSPC_AUDIT_CHILD_RESULT", &child_result)
        .env(
            "CHIRONDB_FAILPOINT",
            "pause:transaction.before_audit_projection",
        )
        .env("CHIRONDB_FAILPOINT_MARKER", &marker)
        .env("CHIRONDB_FAILPOINT_RELEASE", &release)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    wait_for_marker_or_child_exit(&marker, &mut child);

    let filler = root.join("audit-fill.bin");
    fill_until_enospc(&filler);
    fs::write(&release, b"continue").unwrap();
    let status = child.wait().unwrap();
    assert!(status.success(), "ENOSPC audit child failed: {status}");
    assert_eq!(fs::read(&child_result).unwrap(), b"committed-degraded\n");

    fs::remove_file(&filler).unwrap();
    File::open(&root).unwrap().sync_all().unwrap();
    let journal = chirondb_core::transaction_journal::TransactionJournal::open(&data_dir).unwrap();
    let transaction_id = journal
        .committed()
        .unwrap()
        .last()
        .unwrap()
        .prepare
        .transaction_id
        .to_string();
    drop(journal);

    let reopened = Db::open(&data_dir).unwrap();
    assert_eq!(reopened.count("docs", None).unwrap().count, 2);
    let reconciled = reopened.transaction_status(&transaction_id).unwrap();
    assert_eq!(reconciled.state, TransactionState::Committed);
    assert!(reconciled.storage_projected);
    assert!(reconciled.audit_projected);
    chirondb_core::audit::verify_hash_chain(&data_dir).unwrap();
    drop(reopened);
    let audit_path = data_dir.join(chirondb_core::audit::AUDIT_LOG_FILE);
    let recovered_audit = fs::read(&audit_path).unwrap();

    drop(Db::open(&data_dir).unwrap());
    assert_eq!(fs::read(&audit_path).unwrap(), recovered_audit);
    chirondb_core::audit::verify_hash_chain(&data_dir).unwrap();

    if let Some(path) = std::env::var_os("CHIRONDB_ENOSPC_EVIDENCE") {
        let evidence = json!({
            "schema_version": 2,
            "test_case": "committed_audit_projection_recovery",
            "verdict": "passed",
            "fault": "real-enospc-loopback-after-commit",
            "tested_sha": std::env::var("GITHUB_SHA").ok(),
            "core_tree_hash": std::env::var("CHIRONDB_CORE_TREE_HASH").ok(),
            "server_tree_hash": std::env::var("CHIRONDB_SERVER_TREE_HASH").ok(),
            "actions_run_id": std::env::var("GITHUB_RUN_ID").ok(),
            "transaction_id": transaction_id,
            "committed_response_before_space_returned": true,
            "degraded_before_space_returned": true,
            "storage_projected_after_restart": true,
            "audit_projected_after_restart": true,
            "audit_projection_exactly_once": true,
            "points_after_restart": 2,
        });
        fs::write(path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    }
    fs::remove_dir_all(control_root).unwrap();
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
            "test_case": "build_checkpoint_resume",
            "verdict": "passed",
            "fault": "real-enospc-loopback",
            "tested_sha": std::env::var("GITHUB_SHA").ok(),
            "core_tree_hash": std::env::var("CHIRONDB_CORE_TREE_HASH").ok(),
            "server_tree_hash": std::env::var("CHIRONDB_SERVER_TREE_HASH").ok(),
            "actions_run_id": std::env::var("GITHUB_RUN_ID").ok(),
            "build_cell_checkpoint_observed": true,
            "build_cell_checkpoint_reused": true,
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

fn align_audit_for_next_upsert_enospc(data_dir: &Path) {
    const BLOCK_BYTES: u64 = 4096;
    const AFTER_INTENT_TARGET: u64 = BLOCK_BYTES - 32;

    let audit_path = data_dir.join(AUDIT_LOG_FILE);
    let writer = AuditWriter::open(data_dir).unwrap();
    let before_intent = fs::metadata(&audit_path).unwrap().len();
    let intent = writer
        .begin("upsert", Some("docs"), AuditContext::embedded())
        .unwrap();
    let predicted_intent_bytes = fs::metadata(&audit_path).unwrap().len() - before_intent;
    writer
        .finish(&intent, "success", None, json!({"calibration": true}))
        .unwrap();

    for _ in 0..4 {
        let before_probe = fs::metadata(&audit_path).unwrap().len();
        writer
            .record(AuditEvent {
                category: "security",
                operation: "enospc_test_alignment",
                outcome: "success",
                collection: None,
                context: &AuditContext::embedded(),
                error_code: None,
                details: json!({"padding": ""}),
                durable: true,
            })
            .unwrap();
        let empty_record_bytes = fs::metadata(&audit_path).unwrap().len() - before_probe;
        let current = fs::metadata(&audit_path).unwrap().len();
        let before_child_intent_target = (AFTER_INTENT_TARGET + BLOCK_BYTES
            - predicted_intent_bytes % BLOCK_BYTES)
            % BLOCK_BYTES;
        let padding_bytes = (before_child_intent_target + BLOCK_BYTES
            - (current + empty_record_bytes) % BLOCK_BYTES)
            % BLOCK_BYTES;
        writer
            .record(AuditEvent {
                category: "security",
                operation: "enospc_test_alignment",
                outcome: "success",
                collection: None,
                context: &AuditContext::embedded(),
                error_code: None,
                details: json!({"padding": "x".repeat(padding_bytes as usize)}),
                durable: true,
            })
            .unwrap();
        let after_child_intent =
            (fs::metadata(&audit_path).unwrap().len() + predicted_intent_bytes) % BLOCK_BYTES;
        if after_child_intent >= AFTER_INTENT_TARGET {
            drop(writer);
            chirondb_core::audit::verify_hash_chain(data_dir).unwrap();
            return;
        }
    }
    panic!("could not align audit tail for deterministic ENOSPC projection failure");
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
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .custom_flags(libc::O_SYNC)
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
    // A failed large write can leave a few free blocks. Exhaust those too so
    // the paused projection encounters ENOSPC even for a small audit record.
    loop {
        match file.write_all(&block[..512]) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(28) => break,
            Err(error) => panic!("expected ENOSPC, got {error}"),
        }
    }
    file.sync_all().unwrap();
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
