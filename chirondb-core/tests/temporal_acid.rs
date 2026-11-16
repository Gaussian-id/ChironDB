use chirondb_core::{
    Db,
    db::{
        create_offline_protected_backup, create_offline_protected_journal_archive,
        restore_offline_protected_backup,
        temporal::{SensorValue, TemporalAccess, TemporalSample},
    },
    encryption,
    security::{Action, ScopeGrant, onboarding},
};
use std::collections::BTreeSet;

#[test]
fn protected_journal_restore_recovers_temporal_activation_after_backup() {
    let Ok(case) = std::env::var("CHIRON_TEMPORAL_RESTORE_CASE") else {
        for profile in ["legacy", "authority", "common"] {
            for lifecycle in ["activate", "existing", "new", "recreated", "dropped"] {
                let case = format!("{profile}/{lifecycle}");
                assert!(
                    std::process::Command::new(std::env::current_exe().unwrap())
                        .args([
                            "--exact",
                            "protected_journal_restore_recovers_temporal_activation_after_backup",
                            "--nocapture"
                        ])
                        .env("CHIRON_TEMPORAL_RESTORE_CASE", &case)
                        .status()
                        .unwrap()
                        .success(),
                    "{case}"
                );
            }
        }
        return;
    };
    let (profile, lifecycle) = case.split_once('/').unwrap();
    let create = |db: &Db, actor: &chirondb_core::security::AuthenticatedIdentity| {
        db.create_protected_collection_authorized(
            actor,
            db.catalog_revision_authorized(actor).unwrap(),
            serde_json::from_value(serde_json::json!({"name":"trucks","vector_dim":2})).unwrap(),
        )
        .unwrap();
    };
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let live = root.join("live");
    onboarding::initialize(
        &live,
        "fleet",
        "admin",
        &root.join("keyring.json"),
        &root.join("admin.key"),
        false,
    )
    .unwrap();
    let secret = std::fs::read_to_string(root.join("admin.key")).unwrap();
    let keyring = encryption::Keyring::load(root.join("keyring.json")).unwrap();
    {
        let db = Db::open(&live).unwrap();
        let authority = db.identity_authority().unwrap();
        let actor = authority.authenticate(secret.trim()).unwrap();
        if lifecycle != "new" {
            create(&db, &actor);
        }
        let mut principal = actor.principal().clone();
        principal.grants.push(ScopeGrant {
            tenants: BTreeSet::from(["fleet".into()]),
            collections: BTreeSet::from(["trucks".into()]),
            actions: BTreeSet::from([Action::TemporalAppend, Action::TemporalRead]),
        });
        authority
            .put_principal(&actor, actor.revision(), principal)
            .unwrap();
        if matches!(lifecycle, "existing" | "recreated" | "dropped") {
            let actor = authority.authenticate(secret.trim()).unwrap();
            let ctx = db
                .bind_access(&actor, "trucks", "fleet", Action::TemporalAppend)
                .unwrap();
            db.append_temporal_batch(
                "trucks",
                TemporalAccess::Authorized(&ctx),
                vec![TemporalSample::new(
                    "truck-7",
                    "temperature",
                    -1,
                    SensorValue::Float(20.),
                )],
            )
            .unwrap();
        }
    }
    if profile != "legacy" {
        Db::migrate_transaction_authority_offline(&live).unwrap();
    }
    if profile == "common" {
        Db::migrate_common_frontier_offline(&live).unwrap();
    }
    let backup = root.join("backup");
    create_offline_protected_backup(&live, &backup, &keyring).unwrap();
    let samples = vec![
        TemporalSample::new("truck-7", "temperature", i64::MIN, SensorValue::Float(24.5)),
        TemporalSample::new("truck-7", "temperature", 1, SensorValue::Float(25.0)),
    ];
    {
        let db = Db::open(&live).unwrap();
        let actor = db
            .identity_authority()
            .unwrap()
            .authenticate(secret.trim())
            .unwrap();
        if lifecycle == "recreated" {
            db.delete_protected_collection_authorized(&actor, "trucks")
                .unwrap();
        }
        if matches!(lifecycle, "new" | "recreated") {
            create(&db, &actor);
        }
        let ctx = db
            .bind_access(&actor, "trucks", "fleet", Action::TemporalAppend)
            .unwrap();
        assert_eq!(
            db.append_temporal_batch("trucks", TemporalAccess::Authorized(&ctx), samples.clone())
                .unwrap(),
            2
        );
        if lifecycle == "dropped" {
            db.delete_protected_collection_authorized(&actor, "trucks")
                .unwrap();
        }
    }
    let archive = root.join("archive");
    create_offline_protected_journal_archive(&live, &archive, &keyring).unwrap();
    // The restore must use the backup plus journal, never consult live segments.
    std::fs::rename(&live, root.join("parked")).unwrap();
    let restored = root.join("restored");
    restore_offline_protected_backup(&backup, &archive, &restored, &keyring).unwrap();
    for _ in 0..2 {
        let db = Db::open(&restored).unwrap();
        let actor = db
            .identity_authority()
            .unwrap()
            .authenticate(secret.trim())
            .unwrap();
        if lifecycle == "dropped" {
            assert!(
                db.bind_access(&actor, "trucks", "fleet", Action::TemporalRead)
                    .is_err()
            );
            continue;
        }
        let read = db
            .bind_access(&actor, "trucks", "fleet", Action::TemporalRead)
            .unwrap();
        let rows = db
            .scan_temporal(
                "trucks",
                TemporalAccess::Authorized(&read),
                "truck-7",
                "temperature",
                i64::MIN..2,
                10,
            )
            .unwrap();
        let mut expected = vec![(i64::MIN, SensorValue::Float(24.5))];
        if lifecycle == "existing" {
            expected.push((-1, SensorValue::Float(20.)));
        }
        expected.push((1, SensorValue::Float(25.)));
        assert_eq!(
            rows.iter().map(|p| (p.time, p.value)).collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            db.latest_temporal(
                "trucks",
                TemporalAccess::Authorized(&read),
                "truck-7",
                "temperature"
            )
            .unwrap(),
            rows.last().copied()
        );
        let append = db
            .bind_access(&actor, "trucks", "fleet", Action::TemporalAppend)
            .unwrap();
        assert_eq!(
            db.append_temporal_batch(
                "trucks",
                TemporalAccess::Authorized(&append),
                samples.clone()
            )
            .unwrap(),
            0
        );
    }
}

#[cfg(all(unix, feature = "fault-injection"))]
#[test]
fn temporal_decision_boundaries_recover_whole_batches() {
    use chirondb_core::{storage_layout, tenant::TenantScope};
    use std::{
        fs,
        os::unix::process::ExitStatusExt,
        path::Path,
        process::Command,
        time::{Duration, Instant},
    };
    const TEST: &str = "temporal_decision_boundaries_recover_whole_batches";
    if let Some(root) = std::env::var_os("CHIRON_TEMPORAL_ACID_ROOT") {
        let root = std::path::PathBuf::from(root);
        let phase = std::env::var("CHIRON_TEMPORAL_ACID_PHASE").unwrap();
        let seeded = std::env::var("CHIRON_TEMPORAL_ACID_SEEDED").unwrap() == "true";
        let live = root.join("live");
        if std::env::var("CHIRON_TEMPORAL_ACID_ENCRYPTED").unwrap() == "true" {
            let key = root.join("keyring.json");
            if phase == "init" {
                fs::write(&key, r#"{"version":1,"active_key_id":"test","keys":[{"id":"test","key_base64":"ERERERERERERERERERERERERERERERERERERERERERE="}]}"#).unwrap();
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
                storage_layout::initialize_empty(&live).unwrap();
            }
            encryption::install_process_keyring(encryption::Keyring::load(key).unwrap(), true)
                .unwrap();
        }
        let db = Db::open(&live).unwrap();
        let tenant = TenantScope::tenant("writer", "fleet");
        let access = TemporalAccess::Scoped(&tenant);
        let sample = |time| {
            TemporalSample::new(
                "truck",
                "temperature",
                time,
                SensorValue::Float(time as f64),
            )
        };
        match phase.as_str() {
            "init" => {
                db.create_collection(
                    serde_json::from_value(serde_json::json!({"name":"trucks","vector_dim":2}))
                        .unwrap(),
                )
                .unwrap();
                if seeded {
                    db.append_temporal_batch("trucks", access, vec![sample(-10)])
                        .unwrap();
                    db.compact_collection("trucks").unwrap();
                }
            }
            "write" => {
                // Install the fault only after startup; the boundary belongs to this batch.
                unsafe {
                    std::env::set_var(
                        "CHIRONDB_FAILPOINT",
                        std::env::var("CHIRON_TEMPORAL_ACID_FAULT").unwrap(),
                    );
                }
                let result =
                    db.append_temporal_batch("trucks", access, (0..32).map(sample).collect());
                fs::write(root.join("response"), format!("{result:?}")).unwrap();
            }
            "verify" => {
                let rows = db
                    .scan_temporal("trucks", access, "truck", "temperature", -10..32, 100)
                    .unwrap();
                let count: usize = std::env::var("CHIRON_TEMPORAL_ACID_EXPECTED")
                    .unwrap()
                    .parse()
                    .unwrap();
                let expected = (if seeded { vec![-10] } else { vec![] })
                    .into_iter()
                    .chain(0..count as i64)
                    .collect::<Vec<_>>();
                assert_eq!(rows.iter().map(|p| p.time).collect::<Vec<_>>(), expected);
                for row in &rows {
                    assert_eq!(row.value, SensorValue::Float(row.time as f64));
                }
                assert_eq!(
                    db.latest_temporal("trucks", access, "truck", "temperature")
                        .unwrap(),
                    rows.last().copied()
                );
                if count == 32 {
                    assert_eq!(
                        db.append_temporal_batch("trucks", access, (0..32).map(sample).collect())
                            .unwrap(),
                        0
                    );
                }
            }
            _ => panic!("unknown phase"),
        }
        return;
    }
    fn child(root: &Path, phase: &str, encrypted: bool, seeded: bool) -> Command {
        let mut c = Command::new(std::env::current_exe().unwrap());
        c.args(["--exact", TEST, "--nocapture"])
            .env("CHIRON_TEMPORAL_ACID_ROOT", root)
            .env("CHIRON_TEMPORAL_ACID_PHASE", phase)
            .env("CHIRON_TEMPORAL_ACID_ENCRYPTED", encrypted.to_string())
            .env("CHIRON_TEMPORAL_ACID_SEEDED", seeded.to_string())
            .env_remove("CHIRONDB_FAILPOINT")
            .env_remove("CHIRONDB_FAILPOINT_MARKER")
            .env_remove("CHIRONDB_FAILPOINT_RELEASE");
        c
    }
    for encrypted in [false, true] {
        for seeded in [false, true] {
            for (boundary, count) in [
                ("transaction.before_prepare", 0),
                ("transaction.after_prepare", 0),
                ("transaction.before_commit", 0),
                ("transaction.after_commit", 32),
                ("transaction.before_storage_projection", 32),
                ("transaction.before_audit_projection", 32),
            ] {
                for action in ["pause", "error"] {
                    let temp = tempfile::tempdir().unwrap();
                    let root = temp.path();
                    assert!(
                        child(root, "init", encrypted, seeded)
                            .status()
                            .unwrap()
                            .success()
                    );
                    let marker = root.join("paused");
                    let mut process = child(root, "write", encrypted, seeded)
                        .env("CHIRON_TEMPORAL_ACID_FAULT", format!("{action}:{boundary}"))
                        .env("CHIRONDB_FAILPOINT_MARKER", &marker)
                        .spawn()
                        .unwrap();
                    if action == "pause" {
                        let deadline = Instant::now() + Duration::from_secs(45);
                        while !marker.exists() {
                            assert!(
                                process.try_wait().unwrap().is_none(),
                                "writer exited before {boundary}"
                            );
                            if Instant::now() > deadline {
                                process.kill().unwrap();
                                process.wait().unwrap();
                                panic!("boundary not reached: {boundary}");
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        process.kill().unwrap();
                        assert_eq!(process.wait().unwrap().signal(), Some(9));
                    } else {
                        assert!(process.wait().unwrap().success());
                        let response = fs::read_to_string(root.join("response")).unwrap();
                        if count == 32 {
                            assert_eq!(response, "Ok(32)");
                        } else {
                            assert!(response.starts_with("Err("), "{response}");
                        }
                    }
                    for _ in 0..2 {
                        assert!(
                            child(root, "verify", encrypted, seeded)
                                .env("CHIRON_TEMPORAL_ACID_EXPECTED", count.to_string())
                                .status()
                                .unwrap()
                                .success(),
                            "{action}:{boundary}, encrypted={encrypted}, seeded={seeded}"
                        );
                    }
                }
            }
        }
    }
}
