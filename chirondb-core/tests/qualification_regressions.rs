//! Regressions from the 10–13 November 2026 qualification campaign.
use chirondb_core::Db;

#[test]
fn restore_rejects_corrupt_transaction_journal_without_replacing_live_data() {
    for file in ["000000.gdwal", "wal.base", "torn", "missing"] {
        let root = tempfile::tempdir().unwrap();
        let backup = tempfile::tempdir().unwrap();
        let db = Db::open(root.path()).unwrap();
        let config = |name: &str| {
            serde_json::from_value(serde_json::json!({"name":name,"vector_dim":2})).unwrap()
        };
        db.create_collection(config("before")).unwrap();
        db.snapshot(backup.path()).unwrap();
        db.create_collection(config("after")).unwrap();
        let path = backup.path().join("transactions/journal").join(
            if matches!(file, "torn" | "missing") {
                "000000.gdwal"
            } else {
                file
            },
        );
        let mut bytes = std::fs::read(&path).unwrap();
        match file {
            "torn" => {
                bytes.pop();
                std::fs::write(&path, &bytes).unwrap();
            }
            "missing" => std::fs::remove_file(&path).unwrap(),
            _ => {
                bytes[0] ^= 0xff;
                std::fs::write(&path, &bytes).unwrap();
            }
        }
        assert!(
            db.restore(backup.path()).is_err(),
            "accepted corrupt {file}"
        );
        assert_eq!(db.list_collections().len(), 2, "{file}");
        if file != "missing" {
            assert_eq!(std::fs::read(&path).unwrap(), bytes, "source changed");
        }
        drop(db);
        assert_eq!(Db::open(root.path()).unwrap().list_collections().len(), 2);
    }
}

#[cfg(feature = "fault-injection")]
#[test]
fn temporal_merge_survives_process_kill_in_plain_and_encrypted_storage() {
    use chirondb_core::{
        db::temporal::{SensorValue, TemporalAccess, TemporalSample},
        encryption, storage_layout,
        tenant::TenantScope,
    };
    use std::{
        fs,
        process::Command,
        time::{Duration, Instant},
    };
    const CASE: &str = "CHIRON_QUAL_MERGE_PHASE";
    const TEST: &str = "temporal_merge_survives_process_kill_in_plain_and_encrypted_storage";
    if let Ok(phase) = std::env::var(CASE) {
        let root = std::path::PathBuf::from(std::env::var_os("CHIRON_QUAL_MERGE_ROOT").unwrap());
        let live = root.join("live");
        let write = phase == "write";
        if std::env::var("CHIRON_QUAL_MERGE_ENCRYPTED").unwrap() == "1" {
            let key = root.join("fixture-key.json");
            if write {
                fs::write(&key, r#"{"version":1,"active_key_id":"fixture","keys":[{"id":"fixture","key_base64":"ERERERERERERERERERERERERERERERERERERERERERE="}]}"#).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
                }
                storage_layout::initialize_empty(&live).unwrap();
            }
            encryption::install_process_keyring(encryption::Keyring::load(&key).unwrap(), true)
                .unwrap();
        }
        let tenant = TenantScope::tenant("fixture", "fleet");
        let access = TemporalAccess::Scoped(&tenant);
        let sample = |time| {
            TemporalSample::new(
                "truck",
                "temperature",
                time,
                SensorValue::Float(time as f64),
            )
        };
        let db = Db::open(&live).unwrap();
        if write {
            db.create_collection(
                serde_json::from_value(serde_json::json!({"name":"docs","vector_dim":2})).unwrap(),
            )
            .unwrap();
            for time in 0..2 {
                db.append_temporal_batch("docs", access, vec![sample(time)])
                    .unwrap();
                db.compact_collection("docs").unwrap();
            }
            panic!("expected to pause at merge publication");
        }
        let check = |db: &Db| {
            let rows = db
                .scan_temporal("docs", access, "truck", "temperature", 0..3, 3)
                .unwrap();
            assert_eq!(rows.len(), 2);
            for (time, row) in rows.iter().enumerate() {
                assert_eq!(row.time, time as i64);
                assert_eq!(row.value, SensorValue::Float(time as f64));
            }
        };
        check(&db);
        db.compact_collection("docs").unwrap();
        let backup = root.join("backup");
        db.snapshot(&backup).unwrap();
        db.append_temporal_batch("docs", access, vec![sample(2)])
            .unwrap();
        db.restore(&backup).unwrap();
        check(&db);
        drop(db);
        check(&Db::open(&live).unwrap());
        return;
    }
    for encrypted in [false, true] {
        for boundary in [
            "temporal.before_merge_publish",
            "temporal.after_merge_publish",
        ] {
            let root = tempfile::tempdir().unwrap();
            let command = |phase: &str| {
                let mut cmd = Command::new(std::env::current_exe().unwrap());
                cmd.args(["--exact", TEST, "--nocapture"])
                    .env(CASE, phase)
                    .env("CHIRON_QUAL_MERGE_ROOT", root.path())
                    .env(
                        "CHIRON_QUAL_MERGE_ENCRYPTED",
                        if encrypted { "1" } else { "0" },
                    )
                    .env_remove("CHIRONDB_FAILPOINT")
                    .env_remove("CHIRONDB_FAILPOINT_MARKER")
                    .env_remove("CHIRONDB_FAILPOINT_RELEASE");
                cmd
            };
            let marker = root.path().join("paused");
            let mut child = command("write")
                .env("CHIRONDB_FAILPOINT", format!("pause:{boundary}"))
                .env("CHIRONDB_FAILPOINT_MARKER", &marker)
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(60);
            while !marker.exists() {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "child exited before {boundary}"
                );
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("merge pause timed out");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            child.kill().unwrap();
            child.wait().unwrap();
            assert!(
                command("verify").status().unwrap().success(),
                "{boundary} encrypted={encrypted}"
            );
        }
    }
}

#[cfg(feature = "fault-injection")]
#[test]
fn audit_failure_degrades_readiness_until_recovery() {
    const CHILD: &str = "CHIRON_QUAL_AUDIT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        for boundary in [
            "audit.before_append",
            "audit.before_registry_prepare",
            "audit.before_rotate",
        ] {
            assert!(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "audit_failure_degrades_readiness_until_recovery",
                        "--nocapture"
                    ])
                    .env(CHILD, boundary)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let db = Db::open(root.path()).unwrap();
    assert!(db.durability_ready());
    // This test runs alone in its own process; no other test can see the fault.
    unsafe {
        std::env::set_var(
            "CHIRONDB_FAILPOINT",
            format!("error:{}", std::env::var(CHILD).unwrap()),
        );
    }
    assert!(
        db.audit_read_operation("read", None, chirondb_core::audit::AuditContext::embedded())
            .is_err()
    );
    unsafe {
        std::env::remove_var("CHIRONDB_FAILPOINT");
    }
    assert!(
        !db.durability_ready(),
        "audit failure was invisible to health"
    );
    let retry =
        db.audit_read_operation("read", None, chirondb_core::audit::AuditContext::embedded());
    if std::env::var(CHILD).unwrap() == "audit.before_registry_prepare" {
        retry.unwrap().success(serde_json::Value::Null).unwrap();
        assert!(db.durability_ready());
    } else {
        assert!(retry.is_err());
    }
    drop(db);
    let db = Db::open(root.path()).unwrap();
    assert!(db.durability_ready());
    db.audit_read_operation("read", None, chirondb_core::audit::AuditContext::embedded())
        .unwrap()
        .success(serde_json::Value::Null)
        .unwrap();
}
