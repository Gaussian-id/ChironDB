use std::process::Command;

use chirondb::{Db, security::onboarding};

#[test]
fn offline_transaction_authority_cli_activates_and_is_repeatable() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let data = root.join("live");
    let keyring = root.join("storage.json");
    let key = root.join("admin.key");
    let output = Command::new(env!("CARGO_BIN_EXE_chironctl"))
        .args(["security", "init", "--data-dir"])
        .arg(&data)
        .args(["--tenant", "acme", "--admin", "admin", "--keyring-out"])
        .arg(&keyring)
        .arg("--admin-key-out")
        .arg(&key)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for changed in [true, false] {
        let output = Command::new(env!("CARGO_BIN_EXE_chironctl"))
            .args(["security", "migrate-transaction-authority", "--data-dir"])
            .arg(&data)
            .arg("--keyring")
            .arg(&keyring)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["transaction_format"], 3);
        assert_eq!(report["installation_format"], 6);
        assert_eq!(report["migrated"], changed);
    }
    assert!(
        data.join("transactions/authority/.chiron-decision-checkpoint/CURRENT")
            .is_file()
    );
}

#[test]
fn offline_security_cli_exports_verifies_and_restores() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let data = root.join("live");
    let keyring = root.join("storage.json");
    let admin_key = root.join("admin.key");
    let installation =
        onboarding::initialize(&data, "acme", "admin", &keyring, &admin_key, false).unwrap();
    let busy = Db::open(&data).unwrap();
    let busy_destination = root.join("busy-backup");
    let output = Command::new(env!("CARGO_BIN_EXE_chironctl"))
        .args(["security", "backup", "--data-dir"])
        .arg(&data)
        .arg("--destination")
        .arg(&busy_destination)
        .arg("--keyring")
        .arg(&keyring)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!busy_destination.exists());
    drop(busy);
    let backup = root.join("backup");
    let mut export = Command::new(env!("CARGO_BIN_EXE_chironctl"));
    let output = export
        .args(["security", "backup", "--data-dir"])
        .arg(&data)
        .arg("--destination")
        .arg(&backup)
        .arg("--keyring")
        .arg(&keyring)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        manifest["installation"],
        installation.installation_id.to_string()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_chironctl"))
        .args(["security", "verify-backup", "--backup"])
        .arg(&backup)
        .arg("--keyring")
        .arg(&keyring)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        manifest
    );

    let archive = root.join("archive");
    let output = Command::new(env!("CARGO_BIN_EXE_chironctl"))
        .args(["security", "journal-archive", "--data-dir"])
        .arg(&data)
        .arg("--destination")
        .arg(&archive)
        .arg("--keyring")
        .arg(&keyring)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let journal_manifest: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chironctl"))
        .args(["security", "verify-journal-archive", "--archive"])
        .arg(&archive)
        .arg("--keyring")
        .arg(&keyring)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        journal_manifest
    );
    let parked = root.join("parked-live");
    std::fs::rename(&data, parked).unwrap();
    let restored = root.join("restored");
    let output = Command::new(env!("CARGO_BIN_EXE_chironctl"))
        .args(["security", "restore-backup", "--backup"])
        .arg(&backup)
        .arg("--authority-source")
        .arg(&archive)
        .arg("--destination")
        .arg(&restored)
        .arg("--keyring")
        .arg(&keyring)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        receipt["installation"],
        installation.installation_id.to_string()
    );
    let db = Db::open(&restored).unwrap();
    assert_eq!(
        db.identity_authority().unwrap().installation_id(),
        Some(installation.installation_id)
    );
    drop(db);

    let refused = root.join("self-authority");
    let output = Command::new(env!("CARGO_BIN_EXE_chironctl"))
        .args(["security", "restore-backup", "--backup"])
        .arg(&backup)
        .arg("--authority-source")
        .arg(&backup)
        .arg("--destination")
        .arg(&refused)
        .arg("--keyring")
        .arg(&keyring)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!refused.exists());
}
