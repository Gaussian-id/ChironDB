//! Kill the owning process after its caller observed a durable ACK. Each child
//! gets its own encryption context. Keep the witness outside the database.
use chirondb::{
    Db,
    db::temporal::{SensorValue, TemporalAccess, TemporalSample},
    encryption, storage_layout,
    tenant::TenantScope,
};
use std::{
    fs,
    path::Path,
    process::{Child, Command},
    time::{Duration, Instant},
};

fn child(root: &Path, phase: &str, encrypted: bool, sealed: bool) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "temporal_process_helper",
            "--ignored",
            "--nocapture",
        ])
        .env("TEMPORAL_ROOT", root)
        .env("TEMPORAL_PHASE", phase)
        .env("TEMPORAL_ENCRYPTED", if encrypted { "1" } else { "0" })
        .env("TEMPORAL_SEALED", if sealed { "1" } else { "0" })
        .spawn()
        .unwrap()
}
#[test]
#[ignore = "invoked by durable_temporal_ack_survives_real_process_death"]
fn temporal_process_helper() {
    let dir = std::path::PathBuf::from(std::env::var_os("TEMPORAL_ROOT").unwrap());
    let path = dir.join("live");
    let write = std::env::var("TEMPORAL_PHASE").unwrap() == "write";
    let sealed = std::env::var("TEMPORAL_SEALED").unwrap() == "1";
    let graph_cut = std::env::var_os("TEMPORAL_GRAPH_CUT").is_some();
    if std::env::var("TEMPORAL_ENCRYPTED").unwrap() == "1" {
        let key = dir.join("key.json");
        if write {
            fs::write(&key,r#"{"version":1,"active_key_id":"fixture","keys":[{"id":"fixture","key_base64":"ERERERERERERERERERERERERERERERERERERERERERE="}]}"#).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
            }
            storage_layout::initialize_empty(&path).unwrap();
        }
        encryption::install_process_keyring(encryption::Keyring::load(&key).unwrap(), true)
            .unwrap();
    }
    let db = Db::open(&path).unwrap();
    let t = TenantScope::tenant("driver", "fleet");
    let access = TemporalAccess::Scoped(&t);
    let p = |t, v| TemporalSample::new("truck", "speed", t, SensorValue::Float(v));
    if write {
        db.create_collection(
            serde_json::from_value(
                serde_json::json!({"name":"fleet","vector_dim":2,"streamer_max_bytes":1}),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            db.append_temporal_batch("fleet", access, vec![p(5, 5.), p(7, 7.)])
                .unwrap(),
            2
        );
        if graph_cut {
            db.set_graph_lifecycle_scoped("fleet", true, true, &TenantScope::system())
                .unwrap();
            db.append_temporal_batch("fleet", access, vec![p(6, 6.)])
                .unwrap();
            fs::File::create(dir.join("acked"))
                .unwrap()
                .sync_all()
                .unwrap();
        }
        if sealed {
            db.upsert(
                "fleet",
                vec![
                    serde_json::from_value(serde_json::json!({"id":"asset","vector":[1.,0.]}))
                        .unwrap(),
                ],
            )
            .unwrap();
            if graph_cut {
                loop {
                    std::thread::park();
                }
            }
            let deadline = Instant::now() + Duration::from_secs(30);
            while db.seal_in_progress("fleet").unwrap() {
                assert!(Instant::now() < deadline, "automatic seal timed out");
                std::thread::sleep(Duration::from_millis(10));
            }
            let coll = storage_layout::resolve(&path)
                .unwrap()
                .active_root
                .join("collections/fleet");
            assert!(
                fs::read_dir(coll.join("temporal"))
                    .unwrap()
                    .next()
                    .is_some(),
                "automatic seal must publish a temporal run"
            );
            db.compact_collection("fleet").unwrap();
        }
        assert_eq!(
            db.append_temporal_batch("fleet", access, vec![p(6, 6.)])
                .unwrap(),
            1
        );
        let f = fs::File::create(dir.join("acked")).unwrap();
        f.sync_all().unwrap();
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    } else {
        let rows = db
            .scan_temporal("fleet", access, "truck", "speed", 0..10, 100)
            .unwrap();
        assert_eq!(
            rows.iter().map(|p| (p.time, p.value)).collect::<Vec<_>>(),
            vec![
                (5, SensorValue::Float(5.)),
                (6, SensorValue::Float(6.)),
                (7, SensorValue::Float(7.))
            ]
        );
        assert_eq!(
            db.latest_temporal("fleet", access, "truck", "speed")
                .unwrap(),
            rows.last().copied()
        );
        assert_eq!(
            db.append_temporal_batch("fleet", access, vec![p(7, 7.)])
                .unwrap(),
            0
        );
    }
}
#[test]
fn durable_temporal_ack_survives_real_process_death() {
    for encrypted in [false, true] {
        for sealed in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let mut writer = child(tmp.path(), "write", encrypted, sealed);
            let deadline = Instant::now() + Duration::from_secs(45);
            while !tmp.path().join("acked").exists() {
                if let Some(status) = writer.try_wait().unwrap() {
                    panic!("writer exited before ACK: {status}");
                }
                if Instant::now() > deadline {
                    writer.kill().unwrap();
                    writer.wait().unwrap();
                    panic!("writer missed ACK deadline");
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            writer.kill().unwrap();
            writer.wait().unwrap();
            for _ in 0..2 {
                assert!(
                    child(tmp.path(), "verify", encrypted, sealed)
                        .wait()
                        .unwrap()
                        .success()
                );
            }
        }
    }
}

/// Run explicitly with the server built from the qualified pre-feature commit.
#[test]
#[ignore = "requires CHIRON_TEMPORAL_OLD_SERVER from a5e535d"]
fn pre_feature_binary_writes_legacy_data_and_refuses_activated_copy() {
    use std::net::TcpListener;
    let bin = std::env::var_os("CHIRON_TEMPORAL_OLD_SERVER").expect("old server path");
    let temp = tempfile::tempdir().unwrap();
    let live = temp.path().join("live");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let old = || {
        Command::new(&bin)
            .arg("--data-dir")
            .arg(&live)
            .args([
                "--listen-http",
                &addr.to_string(),
                "--listen-grpc",
                "127.0.0.1:0",
                "--listen-wire",
                "127.0.0.1:0",
                "--api-key",
                "local-test-only",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    };
    let mut writer = old();
    let client = reqwest::blocking::Client::new();
    let url = format!("http://{addr}/v1/chironql");
    let deadline = Instant::now() + Duration::from_secs(30);
    for sql in [
        "CREATE COLLECTION fleet DIM 2 METRIC l2;",
        "UPSERT INTO fleet {id:'asset',vector:[1,0]};",
    ] {
        loop {
            assert!(writer.try_wait().unwrap().is_none(), "old writer stopped");
            if let Ok(resp) = client
                .post(&url)
                .bearer_auth("local-test-only")
                .json(&serde_json::json!({"query":sql,"confirm":true}))
                .send()
            {
                assert!(
                    resp.status().is_success(),
                    "old writer: {}",
                    resp.text().unwrap()
                );
                break;
            }
            if Instant::now() > deadline {
                writer.kill().unwrap();
                writer.wait().unwrap();
                panic!("old writer timed out");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    writer.kill().unwrap();
    writer.wait().unwrap();
    let db = Db::open(&live).unwrap();
    assert_eq!(db.get_points("fleet", &["asset".into()]).unwrap().len(), 1);
    let before = temp.path().join("before");
    db.snapshot(&before).unwrap();
    let t = TenantScope::tenant("driver", "fleet");
    db.append_temporal_batch(
        "fleet",
        TemporalAccess::Scoped(&t),
        vec![TemporalSample::new(
            "asset",
            "speed",
            1,
            SensorValue::Boolean(true),
        )],
    )
    .unwrap();
    db.compact_collection("fleet").unwrap();
    drop(db);
    let mut old_reader = old();
    let deadline = Instant::now() + Duration::from_secs(20);
    while old_reader.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            old_reader.kill().unwrap();
            old_reader.wait().unwrap();
            panic!("old reader accepted incompatible root");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = old_reader.wait_with_output().unwrap();
    assert!(!out.status.success());
    let msg = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        msg.contains("TemporalBatch")
            || msg.contains("temporal_batch")
            || msg.contains("bad checkpoint magic"),
        "unexpected refusal: {msg}"
    );
    let db = Db::open(&live).unwrap();
    assert!(
        db.latest_temporal("fleet", TemporalAccess::Scoped(&t), "asset", "speed")
            .unwrap()
            .is_some()
    );
    db.restore(&before).unwrap();
    assert!(
        db.latest_temporal("fleet", TemporalAccess::Scoped(&t), "asset", "speed")
            .unwrap()
            .is_none()
    );
    assert_eq!(db.get_points("fleet", &["asset".into()]).unwrap().len(), 1);
}

#[cfg(feature = "fault-injection")]
#[test]
fn graph_manifest_ahead_of_temporal_checkpoint_preserves_durable_history() {
    for encrypted in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("graph-published");
        let mut writer = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "temporal_process_helper",
                "--ignored",
                "--nocapture",
            ])
            .env("TEMPORAL_ROOT", tmp.path())
            .env("TEMPORAL_PHASE", "write")
            .env("TEMPORAL_ENCRYPTED", if encrypted { "1" } else { "0" })
            .env("TEMPORAL_SEALED", "1")
            .env("TEMPORAL_GRAPH_CUT", "1")
            .env("CHIRONDB_FAILPOINT", "pause:graph_generation.after_install")
            .env("CHIRONDB_FAILPOINT_MARKER", &marker)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(40);
        while !marker.exists() {
            if let Some(status) = writer.try_wait().unwrap() {
                panic!("writer stopped: {status}");
            }
            if Instant::now() > deadline {
                writer.kill().unwrap();
                writer.wait().unwrap();
                panic!("graph publication failpoint not reached");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(tmp.path().join("acked").exists());
        writer.kill().unwrap();
        writer.wait().unwrap();
        for _ in 0..2 {
            assert!(
                child(tmp.path(), "verify", encrypted, true)
                    .wait()
                    .unwrap()
                    .success()
            );
        }
    }
}
