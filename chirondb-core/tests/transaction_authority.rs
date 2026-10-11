use chirondb_core::{
    Db, GaussError, SqlExecutionRequest, SqlResult,
    db::{
        create_offline_protected_backup, create_offline_protected_journal_archive,
        restore_offline_protected_backup,
    },
    encryption,
    security::{Action, ScopeGrant, SecurityError, onboarding},
};
use std::{collections::BTreeSet, path::Path};

fn request(sql: &str, key: Option<&str>) -> SqlExecutionRequest {
    serde_json::from_value(serde_json::json!({"statements":[{"sql":sql}], "idempotency_key":key}))
        .unwrap()
}
fn prepare(root: &Path) {
    let data = root.join("live");
    onboarding::initialize(
        &data,
        "acme",
        "admin",
        &root.join("storage.json"),
        &root.join("admin.key"),
        false,
    )
    .unwrap();
    let db = Db::open(&data).unwrap();
    let authority = db.identity_authority().unwrap();
    let secret = std::fs::read_to_string(root.join("admin.key")).unwrap();
    let actor = authority.authenticate(secret.trim()).unwrap();
    db.execute_sql_authorized(
        &actor,
        request(
            "CREATE TABLE knowledge (id BIGINT PRIMARY KEY, title TEXT)",
            None,
        ),
        "authority-test",
    )
    .unwrap();
    let mut principal = actor.principal().clone();
    principal.grants.push(ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: BTreeSet::from(["knowledge".into()]),
        actions: BTreeSet::from([Action::Create, Action::Read]),
    });
    authority
        .put_principal(&actor, actor.revision(), principal)
        .unwrap();
    let actor = authority.authenticate(secret.trim()).unwrap();
    db.execute_sql_authorized(
        &actor,
        request("INSERT INTO knowledge VALUES (1, 'ack')", Some("one")),
        "authority-test",
    )
    .unwrap();
}
fn install(root: &Path) {
    if !encryption::encryption_enforced() {
        encryption::install_process_keyring(
            encryption::Keyring::load(root.join("storage.json")).unwrap(),
            true,
        )
        .unwrap();
    }
}
fn verify(root: &Path) {
    install(root);
    let data = root.join("live");
    {
        let db = Db::open(&data).unwrap();
        let secret = std::fs::read_to_string(root.join("admin.key")).unwrap();
        let actor = db
            .identity_authority()
            .unwrap()
            .authenticate(secret.trim())
            .unwrap();
        let rows = db
            .execute_sql_authorized(
                &actor,
                request("SELECT id, title FROM knowledge", None),
                "authority-test",
            )
            .unwrap();
        assert!(matches!(&rows.results[0], SqlResult::Rows { rows, .. } if rows.len() == 1));
        db.execute_sql_authorized(
            &actor,
            request("INSERT INTO knowledge VALUES (1, 'ack')", Some("one")),
            "authority-test",
        )
        .unwrap();
    }
    Db::migrate_transaction_authority_offline(&data).unwrap();
    assert!(!Db::migrate_transaction_authority_offline(&data).unwrap());
    let db = Db::open(&data).unwrap();
    let secret = std::fs::read_to_string(root.join("admin.key")).unwrap();
    let actor = db
        .identity_authority()
        .unwrap()
        .authenticate(secret.trim())
        .unwrap();
    db.execute_sql_authorized(
        &actor,
        request("INSERT INTO knowledge VALUES (1, 'ack')", Some("one")),
        "authority-test",
    )
    .unwrap();
    assert!(
        encryption::read_persistent(&data.join("transactions/FORMAT"))
            .unwrap()
            .starts_with(b"CHIRONTXN3\n")
    );
    assert!(
        std::fs::read(data.join(onboarding::MARKER))
            .unwrap()
            .starts_with(b"CHRNINSTALL6\n")
    );
}
#[test]
fn protected_authority_migration_backup_archive_replay_preserves_current_revocation() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    prepare(&root);
    assert!(Db::migrate_transaction_authority_offline(root.join("live")).unwrap());
    verify(&root);
    let data = root.join("live");
    let keyring = encryption::Keyring::load(root.join("storage.json")).unwrap();
    let backup = root.join("backup");
    create_offline_protected_backup(&data, &backup, &keyring).unwrap();
    assert!(
        backup
            .join("data/transactions/authority/.chiron-decision-checkpoint/CURRENT")
            .is_file()
    );
    {
        let db = Db::open(&data).unwrap();
        let authority = db.identity_authority().unwrap();
        let secret = std::fs::read_to_string(root.join("admin.key")).unwrap();
        let actor = authority.authenticate(secret.trim()).unwrap();
        db.execute_sql_authorized(
            &actor,
            request("INSERT INTO knowledge VALUES (2, 'suffix')", Some("two")),
            "authority-test",
        )
        .unwrap();
        let mut principal = actor.principal().clone();
        for grant in &mut principal.grants {
            grant.actions.remove(&Action::Create);
        }
        authority
            .put_principal(&actor, actor.revision(), principal)
            .unwrap();
    }
    let archive = root.join("archive");
    create_offline_protected_journal_archive(&data, &archive, &keyring).unwrap();
    assert!(
        archive
            .join("data/transactions/authority/.chiron-decision-checkpoint/CURRENT")
            .is_file()
    );
    std::fs::rename(&data, root.join("parked")).unwrap();
    let restored = root.join("restored");
    restore_offline_protected_backup(&backup, &archive, &restored, &keyring).unwrap();
    assert!(
        encryption::read_persistent(&restored.join("transactions/FORMAT"))
            .unwrap()
            .starts_with(b"CHIRONTXN3\n")
    );
    assert!(
        std::fs::read(restored.join(onboarding::MARKER))
            .unwrap()
            .starts_with(b"CHRNINSTALL6\n")
    );
    let db = Db::open(&restored).unwrap();
    let secret = std::fs::read_to_string(root.join("admin.key")).unwrap();
    let actor = db
        .identity_authority()
        .unwrap()
        .authenticate(secret.trim())
        .unwrap();
    let selected = db
        .execute_sql_authorized(
            &actor,
            request("SELECT id, title FROM knowledge ORDER BY id", None),
            "authority-test",
        )
        .unwrap();
    assert!(matches!(&selected.results[0], SqlResult::Rows { rows, .. } if rows.len() == 2));
    assert!(matches!(
        db.execute_sql_authorized(
            &actor,
            request("INSERT INTO knowledge VALUES (1, 'ack')", Some("one")),
            "authority-test"
        ),
        Err(GaussError::Security(SecurityError::Forbidden))
    ));
}

#[cfg(all(unix, feature = "fault-injection"))]
#[test]
fn protected_authority_migration_sigkill_boundaries_keep_complete_recoverable_generation() {
    use std::{
        os::unix::process::ExitStatusExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    if let Some(root) = std::env::var_os("CHIRON_AUTHORITY_TEST_ROOT") {
        let root = std::path::PathBuf::from(root);
        match std::env::var("CHIRON_AUTHORITY_TEST_STAGE")
            .unwrap()
            .as_str()
        {
            "prepare" => prepare(&root),
            "migrate" => {
                install(&root);
                Db::migrate_transaction_authority_offline(root.join("live")).unwrap();
            }
            "verify" => verify(&root),
            _ => panic!("unknown child stage"),
        }
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    fn copy(source: &Path, destination: &Path) {
        std::fs::create_dir(destination).unwrap();
        std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o700)).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let path = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy(&entry.path(), &path);
            } else {
                std::fs::copy(entry.path(), path).unwrap();
            }
        }
    }
    fn child(root: &Path, stage: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "protected_authority_migration_sigkill_boundaries_keep_complete_recoverable_generation", "--nocapture", "--test-threads=1"])
            .env("CHIRON_AUTHORITY_TEST_ROOT", root).env("CHIRON_AUTHORITY_TEST_STAGE", stage)
            .env_remove("CHIRONDB_FAILPOINT").env_remove("CHIRONDB_FAILPOINT_MARKER").env_remove("CHIRONDB_FAILPOINT_RELEASE");
        command
    }
    let seed = root.join("seed");
    std::fs::create_dir(&seed).unwrap();
    std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(child(&seed, "prepare").status().unwrap().success());
    for (index, point) in [
        "transaction_authority.before_fence",
        "transaction_authority.after_fence",
        "transaction_checkpoint.before_link",
        "transaction_checkpoint.before_publish",
        "transaction_checkpoint.after_manifest",
        "transaction_authority.before_parent_sync",
        "transaction_authority.after_parent_sync",
        "transaction_authority.before_activation",
        "transaction_authority.after_activation",
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = root.join(format!("case-{index}"));
        copy(&seed, &fixture);
        let marker = fixture.join("paused");
        let log = std::fs::File::create(fixture.join("child.log")).unwrap();
        let mut process = child(&fixture, "migrate")
            .env("CHIRONDB_FAILPOINT", format!("pause:{point}"))
            .env("CHIRONDB_FAILPOINT_MARKER", &marker)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !marker.exists() {
            assert!(
                process.try_wait().unwrap().is_none(),
                "child exited before {point}"
            );
            assert!(Instant::now() < deadline, "boundary {point} not reached");
            std::thread::sleep(Duration::from_millis(20));
        }
        process.kill().unwrap();
        let status = process.wait().unwrap();
        assert_eq!(status.signal(), Some(9));
        assert!(
            child(&fixture, "verify").status().unwrap().success(),
            "recovery after {point}"
        );
    }
}
