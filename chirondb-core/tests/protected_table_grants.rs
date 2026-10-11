use std::{collections::BTreeSet, sync::Arc};

use chirondb_core::{
    Db, GaussError, RelationalValue, SqlExecutionRequest, SqlResult,
    db::{
        create_offline_protected_backup, restore_offline_protected_backup,
        verify_offline_protected_backup,
    },
    encryption,
    security::{Action, Classification, SecurityError, SubjectAttributes, onboarding},
};

fn sql(text: &str) -> SqlExecutionRequest {
    serde_json::from_value(serde_json::json!({"statements": [{"sql": text}]})).unwrap()
}

#[cfg(all(feature = "fault-injection", unix))]
#[test]
fn installed_table_migration_survives_sigkill_on_both_sides_of_manifest() {
    use std::{
        os::unix::process::ExitStatusExt,
        process::Command,
        time::{Duration, Instant},
    };
    for point in [
        "table_authority.before_manifest",
        "table_authority.after_manifest",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let child = |role: &str| {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", "table_migration_crash_child", "--nocapture"])
                .env("CHIRONDB_TABLE_MIGRATION_ROOT", &root)
                .env("CHIRONDB_TABLE_MIGRATION_ROLE", role)
                .env_remove("CHIRONDB_FAILPOINT");
            command
        };
        let setup = child("setup").output().unwrap();
        assert!(
            setup.status.success(),
            "{}",
            String::from_utf8_lossy(&setup.stderr)
        );
        let marker = root.join("pause.marker");
        let mut migration = child("migrate")
            .env("CHIRONDB_FAILPOINT", format!("pause:{point}"))
            .env("CHIRONDB_FAILPOINT_MARKER", &marker)
            .env("CHIRONDB_FAILPOINT_RELEASE", root.join("never.release"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        while !marker.exists() {
            assert!(
                migration.try_wait().unwrap().is_none(),
                "migration exited before {point}"
            );
            if start.elapsed() >= Duration::from_secs(30) {
                migration.kill().unwrap();
                migration.wait().unwrap();
                panic!("migration did not reach {point}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        migration.kill().unwrap();
        assert_eq!(migration.wait().unwrap().signal(), Some(9));
        let verified = child("verify")
            .env(
                "CHIRONDB_TABLE_MIGRATION_PUBLISHED",
                if point.ends_with("after_manifest") {
                    "1"
                } else {
                    "0"
                },
            )
            .output()
            .unwrap();
        assert!(
            verified.status.success(),
            "{}",
            String::from_utf8_lossy(&verified.stderr)
        );
    }
}

#[cfg(all(feature = "fault-injection", unix))]
#[test]
fn failed_table_migration_requires_reopen_before_writing() {
    for point in [
        "table_authority.before_manifest",
        "table_authority.after_manifest",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        for role in ["setup", "error", "verify"] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", "table_migration_crash_child", "--nocapture"])
                .env("CHIRONDB_TABLE_MIGRATION_ROOT", &root)
                .env("CHIRONDB_TABLE_MIGRATION_ROLE", role)
                .env_remove("CHIRONDB_FAILPOINT");
            if role == "error" {
                command.env("CHIRONDB_FAILPOINT", format!("error:{point}"));
            }
            command.env(
                "CHIRONDB_TABLE_MIGRATION_PUBLISHED",
                if point.ends_with("after_manifest") {
                    "1"
                } else {
                    "0"
                },
            );
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[cfg(all(feature = "fault-injection", unix))]
#[test]
fn table_migration_crash_child() {
    use chirondb_core::{encryption, security::ScopeGrant};
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};
    let Ok(role) = std::env::var("CHIRONDB_TABLE_MIGRATION_ROLE") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("CHIRONDB_TABLE_MIGRATION_ROOT").unwrap());
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let data = root.join("data");
    let keyring = root.join("storage.json");
    let key_path = root.join("admin.key");
    if role == "setup" {
        onboarding::initialize(&data, "acme", "admin", &keyring, &key_path, false).unwrap();
    } else {
        encryption::install_process_keyring(encryption::Keyring::load(&keyring).unwrap(), false)
            .unwrap();
    }
    let secret = std::fs::read_to_string(&key_path).unwrap();
    let mut db = Db::open(&data).unwrap();
    if role == "migrate" {
        db.migrate_table_authority_offline().unwrap();
        return;
    }
    if role == "error" {
        assert!(db.migrate_table_authority_offline().is_err());
        let actor = db
            .identity_authority()
            .unwrap()
            .authenticate(secret.trim())
            .unwrap();
        assert!(matches!(
            db.execute_sql_authorized(
                &actor,
                sql("INSERT INTO first VALUES (2, 'rejected')"),
                "test"
            ),
            Err(GaussError::WalUnavailable(_))
        ));
        return;
    }
    let authority = Arc::clone(db.identity_authority().unwrap());
    let actor = authority.authenticate(secret.trim()).unwrap();
    if role == "setup" {
        let mut principal = actor.principal().clone();
        principal.grants.push(ScopeGrant {
            tenants: BTreeSet::from(["acme".into()]),
            collections: BTreeSet::from(["first".into(), "second".into()]),
            actions: BTreeSet::from([Action::Read, Action::Create]),
        });
        authority
            .put_principal(&actor, actor.revision(), principal)
            .unwrap();
        let actor = authority.authenticate(secret.trim()).unwrap();
        for name in ["first", "second"] {
            db.execute_sql_authorized(
                &actor,
                sql(&format!(
                    "CREATE TABLE {name} (id BIGINT PRIMARY KEY, title TEXT)"
                )),
                "test",
            )
            .unwrap();
            db.execute_sql_authorized(
                &actor,
                sql(&format!("INSERT INTO {name} VALUES (1, 'retained')")),
                "test",
            )
            .unwrap();
        }
    } else {
        assert_eq!(role, "verify");
        let published = std::env::var("CHIRONDB_TABLE_MIGRATION_PUBLISHED").unwrap() == "1";
        assert_eq!(
            db.relational_tables()
                .iter()
                .filter(|table| table.security_incarnation.is_some())
                .count(),
            if published { 2 } else { 0 }
        );
        for name in ["first", "second"] {
            let rows = db
                .execute_sql_authorized(
                    &actor,
                    sql(&format!("SELECT title FROM {name} WHERE id=1")),
                    "test",
                )
                .unwrap();
            assert!(matches!(&rows.results[0], SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Text("retained".into())]]));
        }
        assert_eq!(
            db.migrate_table_authority_offline().unwrap(),
            if published { 0 } else { 2 }
        );
        assert!(
            db.relational_tables()
                .iter()
                .all(|table| table.security_incarnation.is_some())
        );
    }
}

#[test]
fn sql_only_table_grants_follow_incarnation_across_rename_revoke_and_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let data = root.join("data");
    let keyring = root.join("storage.json");
    let key_path = root.join("admin.key");
    onboarding::initialize(&data, "acme", "admin", &keyring, &key_path, false).unwrap();
    let secret = std::fs::read_to_string(&key_path).unwrap();
    let mut db = Db::open(&data).unwrap();
    let authority = Arc::clone(db.identity_authority().unwrap());
    let admin = || authority.authenticate(secret.trim()).unwrap();
    db.execute_sql_authorized(
        &admin(),
        sql("CREATE TABLE documents (id BIGINT PRIMARY KEY, title TEXT)"),
        "test",
    )
    .unwrap();
    assert!(db.relational_tables()[0].security_incarnation.is_none());
    let transaction = db
        .begin_sql_transaction_authorized(&admin(), "test")
        .unwrap();
    let revision = authority.revision();
    assert!(db.migrate_table_authority_offline().is_err());
    assert_eq!(authority.revision(), revision);
    assert!(db.relational_tables()[0].security_incarnation.is_none());
    db.rollback_sql_transaction_authorized(&admin(), &transaction.handle, "test")
        .unwrap();
    assert!(db.clone().migrate_table_authority_offline().is_err());
    assert_eq!(authority.revision(), revision);
    assert_eq!(db.migrate_table_authority_offline().unwrap(), 1);
    let original = db.relational_tables()[0].clone();
    assert!(original.security_incarnation.is_some());
    let revision = authority.revision();
    assert_eq!(db.migrate_table_authority_offline().unwrap(), 0);
    assert_eq!(authority.revision(), revision);
    assert!(
        std::fs::read_to_string(data.join(onboarding::MARKER))
            .unwrap()
            .starts_with("CHRNINSTALL4\n")
    );
    authority
        .create_role(&admin(), authority.revision(), "editor")
        .unwrap();
    authority
        .create_user(
            &admin(),
            authority.revision(),
            "ana",
            SubjectAttributes {
                department: "Finance".into(),
                clearance: Classification::Confidential,
            },
        )
        .unwrap();
    db.change_role_table_privileges_authorized(
        &admin(),
        authority.revision(),
        "editor",
        "documents",
        BTreeSet::from([Action::Read, Action::Create, Action::Update, Action::Delete]),
        true,
    )
    .unwrap();
    authority
        .assign_role(&admin(), authority.revision(), "editor", "ana", true)
        .unwrap();
    let principal = authority.resolve_user(&admin(), "ana").unwrap();
    let key = authority
        .issue_credential(&admin(), authority.revision(), &principal)
        .unwrap();
    let reader = || authority.authenticate(&key.secret).unwrap();
    let mut insertion = sql("INSERT INTO documents VALUES (1, 'visible')");
    insertion.idempotency_key = Some("table-identity-insert".into());
    let receipt = db
        .execute_sql_authorized(&reader(), insertion.clone(), "test")
        .unwrap();
    db.execute_sql_authorized(
        &admin(),
        sql("ALTER TABLE documents RENAME TO renamed"),
        "test",
    )
    .unwrap();
    assert_eq!(
        db.execute_sql_authorized(&reader(), insertion.clone(), "test")
            .unwrap(),
        receipt
    );
    let result = db
        .execute_sql_authorized(
            &reader(),
            sql("SELECT title FROM renamed WHERE id = 1"),
            "test",
        )
        .unwrap();
    assert!(matches!(&result.results[0], SqlResult::Rows { rows, .. }
        if rows == &vec![vec![RelationalValue::Text("visible".into())]]));
    assert!(
        db.sql_table_privileges_authorized(&reader())
            .unwrap()
            .contains(&("renamed".into(), Action::Read))
    );
    let committed = db
        .begin_sql_transaction_authorized(&reader(), "test")
        .unwrap();
    db.execute_sql_transaction_authorized(
        &reader(),
        &committed.handle,
        sql("UPDATE renamed SET title='visible' WHERE id=1"),
        "test",
    )
    .unwrap();
    let committed_receipt = db
        .commit_sql_transaction_authorized(&reader(), &committed.handle, "test")
        .unwrap();
    db.change_role_table_privileges_authorized(
        &admin(),
        authority.revision(),
        "editor",
        "renamed",
        BTreeSet::from([Action::Update]),
        false,
    )
    .unwrap();
    assert!(matches!(
        db.commit_sql_transaction_authorized(&reader(), &committed.handle, "test"),
        Err(GaussError::Security(SecurityError::Forbidden))
    ));
    db.change_role_table_privileges_authorized(
        &admin(),
        authority.revision(),
        "editor",
        "renamed",
        BTreeSet::from([Action::Update]),
        true,
    )
    .unwrap();
    assert_eq!(
        db.commit_sql_transaction_authorized(&reader(), &committed.handle, "test")
            .unwrap(),
        committed_receipt
    );
    let transaction = db
        .begin_sql_transaction_authorized(&reader(), "test")
        .unwrap();
    db.execute_sql_transaction_authorized(
        &reader(),
        &transaction.handle,
        sql("INSERT INTO renamed VALUES (2, 'must-not-commit')"),
        "test",
    )
    .unwrap();
    db.change_role_table_privileges_authorized(
        &admin(),
        authority.revision(),
        "editor",
        "renamed",
        BTreeSet::from([Action::Create]),
        false,
    )
    .unwrap();
    assert!(matches!(
        db.commit_sql_transaction_authorized(&reader(), &transaction.handle, "test"),
        Err(GaussError::Security(SecurityError::Forbidden))
    ));
    assert!(matches!(
        db.execute_sql_authorized(&reader(), insertion.clone(), "test"),
        Err(GaussError::Security(SecurityError::Forbidden))
    ));
    db.rollback_sql_transaction_authorized(&reader(), &transaction.handle, "test")
        .unwrap();
    let absent = db
        .execute_sql_authorized(
            &reader(),
            sql("SELECT title FROM renamed WHERE id=2"),
            "test",
        )
        .unwrap();
    assert!(matches!(&absent.results[0], SqlResult::Rows { rows, .. } if rows.is_empty()));
    db.change_role_table_privileges_authorized(
        &admin(),
        authority.revision(),
        "editor",
        "renamed",
        BTreeSet::from([Action::Create]),
        true,
    )
    .unwrap();
    let stale = reader();
    db.change_role_table_privileges_authorized(
        &admin(),
        authority.revision(),
        "editor",
        "renamed",
        BTreeSet::from([Action::Read]),
        false,
    )
    .unwrap();
    assert!(
        db.execute_sql_authorized(&stale, sql("SELECT title FROM renamed"), "test")
            .is_err()
    );
    assert!(matches!(
        db.execute_sql_authorized(&reader(), sql("SELECT title FROM renamed"), "test"),
        Err(GaussError::Security(SecurityError::Forbidden))
    ));
    db.change_role_table_privileges_authorized(
        &admin(),
        authority.revision(),
        "editor",
        "renamed",
        BTreeSet::from([Action::Read]),
        true,
    )
    .unwrap();
    // Issuing a SQL credential must not downgrade the authority envelope.
    authority
        .issue_sql_credential(&admin(), authority.revision(), &principal)
        .unwrap();
    drop(authority);
    drop(db);
    let db = Db::open(&data).unwrap();
    let authority = db.identity_authority().unwrap();
    let admin = || authority.authenticate(secret.trim()).unwrap();
    let reader = || authority.authenticate(&key.secret).unwrap();
    assert_eq!(
        db.relational_tables()[0].security_incarnation,
        original.security_incarnation
    );
    db.execute_sql_authorized(&reader(), sql("SELECT title FROM renamed"), "test")
        .unwrap();
    assert_eq!(
        db.execute_sql_authorized(&reader(), insertion, "test")
            .unwrap(),
        receipt
    );
    db.execute_sql_authorized(&admin(), sql("DROP TABLE renamed"), "test")
        .unwrap();
    db.execute_sql_authorized(
        &admin(),
        sql("CREATE TABLE renamed (id BIGINT PRIMARY KEY, title TEXT)"),
        "test",
    )
    .unwrap();
    let replacement = db.relational_tables()[0].clone();
    assert_ne!(
        replacement.security_incarnation,
        original.security_incarnation
    );
    assert!(replacement.security_incarnation.is_some());
    assert!(matches!(
        db.execute_sql_authorized(&reader(), sql("SELECT title FROM renamed"), "test"),
        Err(GaussError::Security(SecurityError::Forbidden))
    ));
    assert!(matches!(
        db.execute_sql_authorized(
            &reader(),
            sql("INSERT INTO renamed VALUES (2, 'forbidden')"),
            "test"
        ),
        Err(GaussError::Security(SecurityError::Forbidden))
    ));
    db.change_role_table_privileges_authorized(
        &admin(),
        authority.revision(),
        "editor",
        "renamed",
        BTreeSet::from([Action::Read, Action::Create]),
        true,
    )
    .unwrap();
    db.execute_sql_authorized(
        &reader(),
        sql("INSERT INTO renamed VALUES (2, 'restored')"),
        "test",
    )
    .unwrap();
    drop(db);
    let keyring = encryption::Keyring::load(&keyring).unwrap();
    let backup = root.join("backup");
    create_offline_protected_backup(&data, &backup, &keyring).unwrap();
    assert!(
        Db::open(backup.join("data")).is_err(),
        "a backup capsule must never become runnable"
    );
    verify_offline_protected_backup(&backup, &keyring).unwrap();
    let db = Db::open(&data).unwrap();
    let authority = db.identity_authority().unwrap();
    let admin = authority.authenticate(secret.trim()).unwrap();
    db.change_role_table_privileges_authorized(
        &admin,
        authority.revision(),
        "editor",
        "renamed",
        BTreeSet::from([Action::Read]),
        false,
    )
    .unwrap();
    drop(db);
    let restored_path = root.join("restored");
    restore_offline_protected_backup(&backup, &data, &restored_path, &keyring).unwrap();
    let restored = Db::open(&restored_path).unwrap();
    assert!(
        std::fs::read_to_string(restored_path.join(onboarding::MARKER))
            .unwrap()
            .starts_with("CHRNINSTALL4\n")
    );
    assert_eq!(
        restored.relational_tables()[0].security_incarnation,
        replacement.security_incarnation
    );
    let authority = restored.identity_authority().unwrap();
    let reader = authority.authenticate(&key.secret).unwrap();
    assert!(matches!(
        restored.execute_sql_authorized(&reader, sql("SELECT title FROM renamed"), "test"),
        Err(GaussError::Security(SecurityError::Forbidden))
    ));
    let admin = authority.authenticate(secret.trim()).unwrap();
    restored
        .change_role_table_privileges_authorized(
            &admin,
            authority.revision(),
            "editor",
            "renamed",
            BTreeSet::from([Action::Read]),
            true,
        )
        .unwrap();
    let reader = authority.authenticate(&key.secret).unwrap();
    let rows = restored
        .execute_sql_authorized(&reader, sql("SELECT title FROM renamed WHERE id=2"), "test")
        .unwrap();
    assert!(matches!(&rows.results[0], SqlResult::Rows { rows, .. }
        if rows == &vec![vec![RelationalValue::Text("restored".into())]]));
}
