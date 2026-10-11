use chirondb_core::{
    Db, GaussError, SqlExecutionRequest,
    security::{Action, Classification, ScopeGrant, SecurityError, SubjectAttributes, onboarding},
};
use std::{collections::BTreeSet, sync::Arc};

fn sql(text: &str) -> SqlExecutionRequest {
    serde_json::from_value(serde_json::json!({"statements": text.split(';').map(|sql| serde_json::json!({"sql":sql})).collect::<Vec<_>>()})).unwrap()
}

fn grant(names: &[&str]) -> ScopeGrant {
    ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: names.iter().map(|name| (*name).into()).collect(),
        actions: BTreeSet::from([Action::Read, Action::Create, Action::Update, Action::Delete]),
    }
}

#[test]
fn protected_request_cancellation_never_commits_or_cancels_the_next_request() {
    use std::sync::atomic::{AtomicBool, Ordering};
    // Each installation owns a process-global, write-once encryption keyring.
    // The other scope fixture must be free to install its independent keyring.
    const CHILD: &str = "CHIRONDB_SQL_CANCELLATION_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "protected_request_cancellation_never_commits_or_cancels_the_next_request",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let data = root.join("data");
    let key = root.join("admin.key");
    onboarding::initialize(&data, "acme", "admin", &root.join("keys.json"), &key, false).unwrap();
    let mut db = Db::open(&data).unwrap();
    db.migrate_table_authority_offline().unwrap();
    db.migrate_sql_scopes_offline().unwrap();
    let actor = db
        .identity_authority()
        .unwrap()
        .authenticate(std::fs::read_to_string(key).unwrap().trim())
        .unwrap();
    db.execute_sql_authorized(
        &actor,
        sql("CREATE TABLE cancelled (id BIGINT PRIMARY KEY)"),
        "test",
    )
    .unwrap();
    let cancel = Arc::new(AtomicBool::new(true));
    let result = db.execute_sql_authorized_cancellable(
        &actor,
        sql("INSERT INTO cancelled VALUES (1)"),
        "test",
        cancel.clone(),
    );
    assert!(
        matches!(result, Err(GaussError::InvalidRequest(message)) if message == "query canceled")
    );
    let transaction = db.begin_sql_transaction_authorized(&actor, "test").unwrap();
    let result = db.execute_sql_transaction_authorized_cancellable(
        &actor,
        &transaction.handle,
        sql("INSERT INTO cancelled VALUES (2)"),
        "test",
        cancel.clone(),
    );
    assert!(
        matches!(result, Err(GaussError::InvalidRequest(message)) if message == "query canceled")
    );
    cancel.store(false, Ordering::Release);
    db.execute_sql_transaction_authorized_cancellable(
        &actor,
        &transaction.handle,
        sql("INSERT INTO cancelled VALUES (3)"),
        "test",
        cancel.clone(),
    )
    .unwrap();
    cancel.store(true, Ordering::Release);
    let result = db.commit_sql_transaction_authorized_cancellable(
        &actor,
        &transaction.handle,
        "test",
        cancel.clone(),
    );
    assert!(
        matches!(result, Err(GaussError::InvalidRequest(message)) if message == "query canceled")
    );
    let before = db
        .execute_sql_authorized(&actor, sql("SELECT id FROM cancelled"), "test")
        .unwrap();
    assert!(
        matches!(&before.results[0], chirondb_core::SqlResult::Rows { rows, .. } if rows.is_empty())
    );
    cancel.store(false, Ordering::Release);
    db.commit_sql_transaction_authorized_cancellable(&actor, &transaction.handle, "test", cancel)
        .unwrap();
    let after = db
        .execute_sql_authorized(&actor, sql("SELECT id FROM cancelled"), "test")
        .unwrap();
    assert!(
        matches!(&after.results[0], chirondb_core::SqlResult::Rows { rows, .. } if rows == &vec![vec![chirondb_core::RelationalValue::Integer(3)]])
    );
}

#[test]
fn migrated_names_bind_existing_tables_and_creator_transactions_are_atomic() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let data = root.join("data");
    let keyring = root.join("keyring.json");
    let admin_path = root.join("admin.key");
    onboarding::initialize(&data, "acme", "admin", &keyring, &admin_path, false).unwrap();
    let secret = std::fs::read_to_string(&admin_path).unwrap();
    let mut db = Db::open(&data).unwrap();
    assert!(db.migrate_sql_scopes_offline().is_err());
    drop(db); // invalid migration fails closed; reopen preserves original authority
    let mut db = Db::open(&data).unwrap();
    let authority = Arc::clone(db.identity_authority().unwrap());
    let admin = || authority.authenticate(secret.trim()).unwrap();
    for name in ["docs", "ungranted"] {
        db.execute_sql_authorized(
            &admin(),
            sql(&format!("CREATE TABLE {name} (id BIGINT PRIMARY KEY)")),
            "test",
        )
        .unwrap();
    }
    authority
        .create_user(
            &admin(),
            authority.revision(),
            "reader",
            SubjectAttributes {
                department: "Engineering".into(),
                clearance: Classification::Internal,
            },
        )
        .unwrap();
    let reader_id = authority.resolve_user(&admin(), "reader").unwrap();
    let key = authority
        .issue_credential(&admin(), authority.revision(), &reader_id)
        .unwrap();
    let reader = || authority.authenticate(&key.secret).unwrap();
    let mut principal = reader().principal().clone();
    principal.grants.push(grant(&["docs", "future_name"]));
    authority
        .put_principal(&admin(), authority.revision(), principal)
        .unwrap();
    let mut old_insert = sql("INSERT INTO docs VALUES (1)");
    old_insert.idempotency_key = Some("legacy-receipt".into());
    db.execute_sql_authorized(&reader(), old_insert.clone(), "test")
        .unwrap();
    db.migrate_table_authority_offline().unwrap();
    let before = db.relational_tables();
    let mut bound_insert = sql("INSERT INTO docs VALUES (2)");
    bound_insert.idempotency_key = Some("bound-receipt".into());
    let receipt = db
        .execute_sql_authorized(&reader(), bound_insert.clone(), "test")
        .unwrap();
    let active = db
        .begin_sql_transaction_authorized(&reader(), "test")
        .unwrap();
    let revision = authority.revision();
    assert!(db.migrate_sql_scopes_offline().is_err());
    assert_eq!(authority.revision(), revision);
    db.rollback_sql_transaction_authorized(&reader(), &active.handle, "test")
        .unwrap();
    assert!(db.clone().migrate_sql_scopes_offline().is_err());
    assert!(db.migrate_sql_scopes_offline().unwrap());
    assert_eq!(
        db.relational_tables(),
        before,
        "scope conversion must not change catalog or creators"
    );
    assert!(reader().has_strict_sql_scopes());
    assert!(!db.migrate_sql_scopes_offline().unwrap());
    assert_eq!(authority.revision(), revision + 1);
    assert!(
        std::fs::read_to_string(data.join(onboarding::MARKER))
            .unwrap()
            .starts_with("CHRNINSTALL5\n")
    );
    assert!(matches!(
        db.execute_sql_authorized(&reader(), old_insert, "test"),
        Err(GaussError::Security(SecurityError::Forbidden))
    ));
    assert_eq!(
        db.execute_sql_authorized(&reader(), bound_insert.clone(), "test")
            .unwrap(),
        receipt
    );
    // Collection capabilities remain, but do not grant data on future SQL names.
    assert!(reader().allows("acme", "future_name", Action::Read));
    db.execute_sql_authorized(
        &admin(),
        sql(
            "CREATE TABLE future_name (id BIGINT PRIMARY KEY); INSERT INTO future_name VALUES (10)",
        ),
        "test",
    )
    .unwrap();
    assert!(
        db.execute_sql_authorized(&reader(), sql("SELECT * FROM future_name"), "test")
            .is_err()
    );
    assert!(
        db.execute_sql_authorized(&admin(), sql("SELECT * FROM ungranted"), "test")
            .is_err(),
        "admin does not inherit pre-migration data rights"
    );
    assert!(
        db.sql_table_privileges_authorized(&admin())
            .unwrap()
            .contains(&("future_name".into(), Action::Read))
    );
    // ORM-style private CREATE + DML survives commit and stable commit replay.
    let transaction = db
        .begin_sql_transaction_authorized(&admin(), "test")
        .unwrap();
    for statement in [
        "CREATE TABLE private_table (id BIGINT PRIMARY KEY)",
        "INSERT INTO private_table VALUES (1)",
        "UPDATE private_table SET id=2 WHERE id=1",
    ] {
        db.execute_sql_transaction_authorized(
            &admin(),
            &transaction.handle,
            sql(statement),
            "test",
        )
        .unwrap();
    }
    let committed = db
        .commit_sql_transaction_authorized(&admin(), &transaction.handle, "test")
        .unwrap();
    assert_eq!(
        db.commit_sql_transaction_authorized(&admin(), &transaction.handle, "test")
            .unwrap(),
        committed
    );
    let transaction = db
        .begin_sql_transaction_authorized(&admin(), "test")
        .unwrap();
    db.execute_sql_transaction_authorized(
        &admin(),
        &transaction.handle,
        sql("CREATE TABLE rolled_back (id BIGINT PRIMARY KEY); INSERT INTO rolled_back VALUES (1)"),
        "test",
    )
    .unwrap();
    db.rollback_sql_transaction_authorized(&admin(), &transaction.handle, "test")
        .unwrap();
    assert!(
        !db.relational_tables()
            .iter()
            .any(|table| table.name == "rolled_back")
    );
    db.execute_sql_authorized(&admin(), sql("ALTER TABLE docs RENAME TO renamed"), "test")
        .unwrap();
    assert_eq!(
        db.execute_sql_authorized(&reader(), bound_insert.clone(), "test")
            .unwrap(),
        receipt
    );
    db.execute_sql_authorized(
        &admin(),
        sql("CREATE TABLE docs (id BIGINT PRIMARY KEY); INSERT INTO docs VALUES (99)"),
        "test",
    )
    .unwrap();
    assert!(
        db.execute_sql_authorized(&reader(), sql("SELECT * FROM docs"), "test")
            .is_err()
    );
    db.execute_sql_authorized(&reader(), sql("SELECT * FROM renamed"), "test")
        .unwrap();
    let migrated_role = reader()
        .roles()
        .iter()
        .find(|role| role.name.starts_with("sql_migrated_"))
        .unwrap()
        .name
        .clone();
    let transaction = db
        .begin_sql_transaction_authorized(&reader(), "test")
        .unwrap();
    db.execute_sql_transaction_authorized(
        &reader(),
        &transaction.handle,
        sql("INSERT INTO renamed VALUES (3)"),
        "test",
    )
    .unwrap();
    db.change_role_table_privileges_authorized(
        &admin(),
        authority.revision(),
        &migrated_role,
        "renamed",
        BTreeSet::from([Action::Create]),
        false,
    )
    .unwrap();
    assert!(
        db.commit_sql_transaction_authorized(&reader(), &transaction.handle, "test")
            .is_err()
    );
    assert!(
        db.execute_sql_authorized(&reader(), bound_insert.clone(), "test")
            .is_err()
    );
    db.rollback_sql_transaction_authorized(&reader(), &transaction.handle, "test")
        .unwrap();
    let mut principal = reader().principal().clone();
    principal.grants.push(grant(&["ungranted"]));
    authority
        .put_principal(&admin(), authority.revision(), principal)
        .unwrap();
    assert!(
        db.execute_sql_authorized(&reader(), sql("SELECT * FROM ungranted"), "test")
            .is_err()
    );
    drop(db);
    drop(authority);
    let db = Db::open(&data).unwrap();
    let authority = db.identity_authority().unwrap();
    let admin = authority.authenticate(secret.trim()).unwrap();
    assert!(admin.has_strict_sql_scopes());
    db.execute_sql_authorized(
        &admin,
        sql("SELECT * FROM private_table WHERE id=2"),
        "test",
    )
    .unwrap();
    assert!(
        db.execute_sql_authorized(
            &authority.authenticate(&key.secret).unwrap(),
            bound_insert,
            "test"
        )
        .is_err()
    );
    chirondb_core::audit::verify_hash_chain(&data).unwrap();
    drop(db);
    let keyring = chirondb_core::encryption::Keyring::load(&keyring).unwrap();
    let backup = root.join("backup");
    chirondb_core::db::create_offline_protected_backup(&data, &backup, &keyring).unwrap();
    assert!(Db::open(backup.join("data")).is_err());
    let db = Db::open(&data).unwrap();
    let authority = db.identity_authority().unwrap();
    let admin = authority.authenticate(secret.trim()).unwrap();
    db.change_role_table_privileges_authorized(
        &admin,
        authority.revision(),
        &migrated_role,
        "renamed",
        BTreeSet::from([Action::Read]),
        false,
    )
    .unwrap();
    drop(db);
    let restored_path = root.join("restored");
    chirondb_core::db::restore_offline_protected_backup(&backup, &data, &restored_path, &keyring)
        .unwrap();
    let restored = Db::open(&restored_path).unwrap();
    assert!(
        std::fs::read_to_string(restored_path.join(onboarding::MARKER))
            .unwrap()
            .starts_with("CHRNINSTALL5\n")
    );
    let authority = restored.identity_authority().unwrap();
    assert!(
        restored
            .execute_sql_authorized(
                &authority.authenticate(&key.secret).unwrap(),
                sql("SELECT * FROM renamed"),
                "test"
            )
            .is_err()
    );
    let admin = authority.authenticate(secret.trim()).unwrap();
    restored
        .execute_sql_authorized(
            &admin,
            sql("SELECT * FROM private_table WHERE id=2"),
            "test",
        )
        .unwrap();
}

#[cfg(all(feature = "fault-injection", unix))]
#[test]
fn sql_scope_migration_survives_sigkill_and_io_errors() {
    use std::{
        os::unix::process::ExitStatusExt,
        process::Command,
        time::{Duration, Instant},
    };
    for point in [
        "sql_scopes.before_authority",
        "identity.after_reader_fence",
        "sql_scopes.after_authority",
    ] {
        for error in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            let child = |mode: &str| {
                let mut command = Command::new(std::env::current_exe().unwrap());
                command
                    .args(["--exact", "sql_scope_crash_child", "--nocapture"])
                    .env("CHIRONDB_SQL_SCOPE_ROOT", &root)
                    .env("CHIRONDB_SQL_SCOPE_MODE", mode)
                    .env_remove("CHIRONDB_FAILPOINT");
                command
            };
            let setup = child("setup").output().unwrap();
            assert!(
                setup.status.success(),
                "{}",
                String::from_utf8_lossy(&setup.stderr)
            );
            let marker = root.join("marker");
            let mut migration = child(if error { "error" } else { "migrate" })
                .env(
                    "CHIRONDB_FAILPOINT",
                    format!("{}:{point}", if error { "error" } else { "pause" }),
                )
                .env("CHIRONDB_FAILPOINT_MARKER", &marker)
                .env("CHIRONDB_FAILPOINT_RELEASE", root.join("never"))
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            if error {
                let output = migration.wait_with_output().unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            } else {
                let deadline = Instant::now() + Duration::from_secs(30);
                while !marker.exists() {
                    assert!(
                        migration.try_wait().unwrap().is_none(),
                        "exit before {point}"
                    );
                    if Instant::now() >= deadline {
                        migration.kill().unwrap();
                        migration.wait().unwrap();
                        panic!("timeout at {point}");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                migration.kill().unwrap();
                assert_eq!(migration.wait().unwrap().signal(), Some(9));
            }
            let verify = child("verify")
                .env(
                    "CHIRONDB_SQL_SCOPE_PUBLISHED",
                    if point == "sql_scopes.after_authority" {
                        "1"
                    } else {
                        "0"
                    },
                )
                .output()
                .unwrap();
            assert!(
                verify.status.success(),
                "{}",
                String::from_utf8_lossy(&verify.stderr)
            );
        }
    }
}

#[cfg(all(feature = "fault-injection", unix))]
#[test]
fn sql_scope_crash_child() {
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};
    let Ok(mode) = std::env::var("CHIRONDB_SQL_SCOPE_MODE") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("CHIRONDB_SQL_SCOPE_ROOT").unwrap());
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let data = root.join("data");
    let keyring = root.join("storage.json");
    let admin_path = root.join("admin.key");
    if mode == "setup" {
        onboarding::initialize(&data, "acme", "admin", &keyring, &admin_path, false).unwrap();
    } else {
        chirondb_core::encryption::install_process_keyring(
            chirondb_core::encryption::Keyring::load(&keyring).unwrap(),
            false,
        )
        .unwrap();
    }
    let secret = std::fs::read_to_string(&admin_path).unwrap();
    let mut db = Db::open(&data).unwrap();
    let authority = Arc::clone(db.identity_authority().unwrap());
    let actor = || authority.authenticate(secret.trim()).unwrap();
    match mode.as_str() {
        "setup" => {
            let mut principal = actor().principal().clone();
            principal.grants.push(grant(&["first", "second"]));
            authority
                .put_principal(&actor(), authority.revision(), principal)
                .unwrap();
            for name in ["first", "second"] {
                db.execute_sql_authorized(
                    &actor(),
                    sql(&format!(
                        "CREATE TABLE {name} (id BIGINT PRIMARY KEY); INSERT INTO {name} VALUES (7)"
                    )),
                    "test",
                )
                .unwrap();
            }
            db.migrate_table_authority_offline().unwrap();
        }
        "migrate" => {
            db.migrate_sql_scopes_offline().unwrap();
        }
        "error" => {
            assert!(db.migrate_sql_scopes_offline().is_err());
            assert!(
                authority.authenticate(secret.trim()).is_err(),
                "uncertain authority closes the old epoch"
            );
        }
        "verify" => {
            let published = std::env::var("CHIRONDB_SQL_SCOPE_PUBLISHED").unwrap() == "1";
            assert_eq!(actor().has_strict_sql_scopes(), published);
            assert_eq!(actor().roles().len(), usize::from(published));
            if published {
                assert_eq!(actor().roles()[0].table_grants.len(), 2);
            }
            for name in ["first", "second"] {
                let rows = db
                    .execute_sql_authorized(
                        &actor(),
                        sql(&format!("SELECT id FROM {name}")),
                        "test",
                    )
                    .unwrap();
                assert!(
                    matches!(&rows.results[0], chirondb_core::SqlResult::Rows { rows, .. } if rows == &vec![vec![chirondb_core::RelationalValue::Integer(7)]])
                );
            }
            assert_eq!(db.migrate_sql_scopes_offline().unwrap(), !published);
            assert!(!db.migrate_sql_scopes_offline().unwrap());
            assert_eq!(actor().roles().len(), 1);
            assert_eq!(actor().roles()[0].table_grants.len(), 2);
            assert!(
                std::fs::read_to_string(data.join(onboarding::MARKER))
                    .unwrap()
                    .starts_with("CHRNINSTALL5\n")
            );
            chirondb_core::audit::verify_hash_chain(&data).unwrap();
        }
        _ => panic!("unknown child mode"),
    }
}
