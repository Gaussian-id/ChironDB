use chirondb::{
    Db, GaussError, audit, encryption,
    security::{IdentityAuthority, SecurityError, onboarding},
};

#[test]
fn encrypted_sql_guard_migration_and_admin_recovery_preserve_reader_fence() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let data = root.join("data");
    let keyring = root.join("storage.json");
    let admin_key = root.join("admin.key");
    let report =
        onboarding::initialize(&data, "acme", "admin", &keyring, &admin_key, false).unwrap();
    let secret = std::fs::read_to_string(&admin_key).unwrap();
    let db = Db::open(&data).unwrap();
    let authority = db.identity_authority().unwrap().clone();
    let actor = authority.authenticate(secret.trim()).unwrap();
    let issued = authority
        .issue_sql_credential(&actor, actor.revision(), &actor.principal().id)
        .unwrap();
    let current_actor = authority.authenticate(secret.trim()).unwrap();
    let request: chirondb::SqlExecutionRequest = serde_json::from_value(serde_json::json!({
        "statements": [{"sql": "CREATE TABLE guarded_receipts (id BIGINT PRIMARY KEY)"}],
        "idempotency_key": "guarded-create"
    }))
    .unwrap();
    let receipt = db
        .execute_sql_authorized(&current_actor, request.clone(), "test-http")
        .unwrap();
    assert_eq!(
        db.execute_sql_authorized(&current_actor, request, "test-grpc")
            .unwrap(),
        receipt
    );
    let interactive = db
        .begin_sql_transaction_authorized(&current_actor, "test-http")
        .unwrap();
    let ddl: chirondb::SqlExecutionRequest = serde_json::from_value(serde_json::json!({
        "statements": [{"sql": "CREATE TABLE guarded_interactive (id BIGINT PRIMARY KEY)"}]
    }))
    .unwrap();
    db.execute_sql_transaction_authorized(&current_actor, &interactive.handle, ddl, "test-http")
        .unwrap();
    let interactive_receipt = db
        .commit_sql_transaction_authorized(&current_actor, &interactive.handle, "test-http")
        .unwrap();
    assert!(
        matches!(
            db.snapshot(root.join("sql-only-protected-snapshot")),
            Err(GaussError::Security(SecurityError::Forbidden))
        ),
        "a content-only snapshot must not claim a restorable protected backup"
    );
    let unprotected_source = root.join("unprotected-source");
    let unprotected_snapshot = root.join("unprotected-snapshot");
    let unprotected = Db::open(&unprotected_source).unwrap();
    unprotected.snapshot(&unprotected_snapshot).unwrap();
    let protected_content = root.join("protected-content-only");
    std::fs::create_dir(&protected_content).unwrap();
    let active = std::fs::read_to_string(data.join("CURRENT")).unwrap();
    std::fs::copy(
        data.join("generations")
            .join(active.trim())
            .join("catalog.json"),
        protected_content.join("catalog.json"),
    )
    .unwrap();
    assert!(matches!(
        unprotected.restore(&protected_content),
        Err(GaussError::Security(SecurityError::Forbidden))
    ));
    drop(unprotected);
    assert!(
        matches!(
            db.restore(&unprotected_snapshot),
            Err(GaussError::Security(SecurityError::Forbidden))
        ),
        "legacy restore must not replace a SQL-only protected installation"
    );
    assert_eq!(
        interactive_receipt.transaction_id,
        interactive.transaction_id
    );
    assert_eq!(
        encryption::read_persistent(&data.join("transactions/FORMAT")).unwrap(),
        format!("CHIRONTXN2\n{}\n", report.installation_id).as_bytes()
    );
    let identity_path = data.join("security/identity.v1");
    let before = encryption::read_persistent(&identity_path).unwrap();
    // Offline migration cannot race a live DB (even in this process).
    assert!(!migrate(&data, &keyring).status.success());
    drop(actor);
    drop(authority);
    drop(db);
    // Reproduce the pre-fence preview fixture without changing its v4 data.
    std::fs::write(
        data.join(onboarding::MARKER),
        format!("CHRNINSTALL1\n{}\n", report.installation_id),
    )
    .unwrap();
    assert!(Db::open(&data).is_err());
    #[cfg(feature = "fault-injection")]
    for (point, expected_version, changed_on_resume) in [
        ("security_sql_guard.before_marker", 1, true),
        ("security_sql_guard.after_marker", 2, false),
    ] {
        let interrupted = std::process::Command::new(env!("CARGO_BIN_EXE_chironctl"))
            .args(["security", "migrate-sql-guard", "--data-dir"])
            .arg(&data)
            .arg("--keyring")
            .arg(&keyring)
            .env("CHIRONDB_FAILPOINT", format!("exit:{point}"))
            .output()
            .unwrap();
        assert_eq!(interrupted.status.code(), Some(86), "{point}");
        assert_eq!(
            std::fs::read_to_string(data.join(onboarding::MARKER)).unwrap(),
            format!(
                "CHRNINSTALL{expected_version}\n{}\n",
                report.installation_id
            ),
            "{point}"
        );
        assert_eq!(encryption::read_persistent(&identity_path).unwrap(), before);
        audit::verify_hash_chain(&data).unwrap();
        if expected_version == 1 {
            assert!(Db::open(&data).is_err());
        } else {
            drop(Db::open(&data).unwrap());
        }
        let resumed = migrate(&data, &keyring);
        assert!(
            resumed.status.success(),
            "{point}: {}",
            String::from_utf8_lossy(&resumed.stderr)
        );
        let receipt: serde_json::Value = serde_json::from_slice(&resumed.stdout).unwrap();
        assert_eq!(receipt["migrated"], changed_on_resume, "{point}");
        std::fs::write(
            data.join(onboarding::MARKER),
            format!("CHRNINSTALL1\n{}\n", report.installation_id),
        )
        .unwrap();
    }
    for expected in [true, false] {
        let output = migrate(&data, &keyring);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["migrated"], expected);
        assert_eq!(report["installation_format"], 2);
    }
    assert_eq!(encryption::read_persistent(&identity_path).unwrap(), before);
    let authority = IdentityAuthority::open(&data).unwrap().unwrap();
    assert_eq!(authority.revision(), issued.revision);
    assert_eq!(
        authority.sql_verifier_for_user("admin").unwrap().id,
        issued.id
    );
    assert!(authority.authenticate(secret.trim()).is_ok());
    drop(authority);
    {
        let reopened = Db::open(&data).unwrap();
        let actor = reopened
            .identity_authority()
            .unwrap()
            .authenticate(secret.trim())
            .unwrap();
        assert_eq!(
            reopened
                .commit_sql_transaction_authorized(
                    &actor,
                    &interactive.handle,
                    "test-wire-reconnect"
                )
                .unwrap(),
            interactive_receipt
        );
    }
    let recovered_key = root.join("recovered.key");
    let mut recovery = std::process::Command::new(env!("CARGO_BIN_EXE_chironctl"));
    recovery
        .args(["security", "recover-admin", "--data-dir"])
        .arg(&data)
        .arg("--keyring")
        .arg(&keyring)
        .arg("--admin-key-out")
        .arg(&recovered_key)
        .arg("--yes");
    #[cfg(feature = "fault-injection")]
    {
        let interrupted = recovery
            .env("CHIRONDB_FAILPOINT", "exit:security_recover.prepared")
            .output()
            .unwrap();
        assert_eq!(interrupted.status.code(), Some(86));
        assert!(Db::open(&data).is_err());
        recovery.env_remove("CHIRONDB_FAILPOINT").arg("--resume");
    }
    let output = recovery.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(data.join(onboarding::MARKER)).unwrap(),
        format!("CHRNINSTALL2\n{}\n", report.installation_id)
    );
    let db = Db::open(&data).unwrap();
    let authority = db.identity_authority().unwrap().clone();
    assert!(authority.authenticate(secret.trim()).is_err());
    assert!(authority.sql_verifier_for_user("admin").is_none());
    assert!(
        authority
            .authenticate(std::fs::read_to_string(&recovered_key).unwrap().trim())
            .is_ok()
    );
    audit::verify_hash_chain(&data).unwrap();
    drop(authority);
    drop(db);
    let migrated = std::process::Command::new(env!("CARGO_BIN_EXE_chironctl"))
        .args(["security", "migrate-table-authority", "--data-dir"])
        .arg(&data)
        .arg("--keyring")
        .arg(&keyring)
        .output()
        .unwrap();
    assert!(
        migrated.status.success(),
        "{}",
        String::from_utf8_lossy(&migrated.stderr)
    );
    let table_recovered_key = root.join("table-recovered.key");
    let recovered = std::process::Command::new(env!("CARGO_BIN_EXE_chironctl"))
        .args(["security", "recover-admin", "--data-dir"])
        .arg(&data)
        .arg("--keyring")
        .arg(&keyring)
        .arg("--admin-key-out")
        .arg(&table_recovered_key)
        .arg("--yes")
        .output()
        .unwrap();
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(data.join(onboarding::MARKER)).unwrap(),
        format!("CHRNINSTALL4\n{}\n", report.installation_id)
    );
    assert!(
        encryption::read_persistent(&identity_path)
            .unwrap()
            .starts_with(b"CHRNID05")
    );
    let db = Db::open(&data).unwrap();
    let authority = db.identity_authority().unwrap();
    assert!(
        authority
            .authenticate(std::fs::read_to_string(recovered_key).unwrap().trim())
            .is_err()
    );
    assert!(
        authority
            .authenticate(std::fs::read_to_string(table_recovered_key).unwrap().trim())
            .is_ok()
    );
    assert!(
        db.relational_tables()
            .iter()
            .all(|table| table.security_incarnation.is_some())
    );
    audit::verify_hash_chain(&data).unwrap();
    drop(db);
    let migrated = std::process::Command::new(env!("CARGO_BIN_EXE_chironctl"))
        .args(["security", "migrate-sql-scopes", "--data-dir"])
        .arg(&data)
        .arg("--keyring")
        .arg(&keyring)
        .output()
        .unwrap();
    assert!(
        migrated.status.success(),
        "{}",
        String::from_utf8_lossy(&migrated.stderr)
    );
    let strict_recovered_key = root.join("strict-recovered.key");
    let recovered = std::process::Command::new(env!("CARGO_BIN_EXE_chironctl"))
        .args(["security", "recover-admin", "--data-dir"])
        .arg(&data)
        .arg("--keyring")
        .arg(&keyring)
        .arg("--admin-key-out")
        .arg(&strict_recovered_key)
        .arg("--yes")
        .output()
        .unwrap();
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(data.join(onboarding::MARKER)).unwrap(),
        format!("CHRNINSTALL5\n{}\n", report.installation_id)
    );
    assert!(
        encryption::read_persistent(&identity_path)
            .unwrap()
            .starts_with(b"CHRNID06")
    );
    let db = Db::open(&data).unwrap();
    let actor = db
        .identity_authority()
        .unwrap()
        .authenticate(
            std::fs::read_to_string(strict_recovered_key)
                .unwrap()
                .trim(),
        )
        .unwrap();
    assert!(actor.has_strict_sql_scopes());
    audit::verify_hash_chain(&data).unwrap();
}

fn migrate(data: &std::path::Path, keyring: &std::path::Path) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_chironctl"))
        .args(["security", "migrate-sql-guard", "--data-dir"])
        .arg(data)
        .arg("--keyring")
        .arg(keyring)
        .output()
        .unwrap()
}
