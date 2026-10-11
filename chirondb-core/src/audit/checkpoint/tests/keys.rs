use super::*;

#[test]
fn encrypted_checkpoint_key_rotation_revalidates_history_and_cannot_hide_missing_old_key() {
    const CHILD: &str = "CHIRON_AUDIT_CHECKPOINT_KEYS";
    const MODE: &str = "CHIRON_AUDIT_CHECKPOINT_KEY_MODE";
    if let Some(root) = std::env::var_os(CHILD) {
        let root = PathBuf::from(root);
        let mode = std::env::var(MODE).unwrap();
        // The empty legacy journal is deliberately opened before installation
        // of this process's keyring so the test isolates encrypted audit/cache.
        let journal = open_journal(&root.join("data"));
        let old = serde_json::json!({"id": "old", "key_base64": STANDARD.encode([17; 32])});
        let new = serde_json::json!({"id": "new", "key_base64": STANDARD.encode([29; 32])});
        let keys = match mode.as_str() {
            "create" => vec![old],
            "rotate" => vec![old, new],
            "verify" => vec![new, old],
            "missing" => vec![new],
            _ => panic!("unknown key test mode"),
        };
        let keyring = root.join("external-keyring.json");
        fs::write(
            &keyring,
            serde_json::to_vec(&serde_json::json!({"version": 1,
            "active_key_id": if mode == "create" { "old" } else { "new" }, "keys": keys}))
            .unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
        }
        encryption::install_process_keyring(encryption::Keyring::load(&keyring).unwrap(), false)
            .unwrap();
        let data = root.join("data");
        if mode == "missing" {
            let before = fs::read(audit_log_path(&data)).unwrap();
            assert!(AuditWriter::open_with_journal(&data, journal).is_err());
            assert_eq!(fs::read(audit_log_path(&data)).unwrap(), before);
            return;
        }
        let writer = AuditWriter::open_with_journal(&data, journal).unwrap();
        match mode.as_str() {
            "create" => append(&writer, 1, 3),
            "rotate" => {
                assert_eq!(
                    suffix(&writer),
                    2,
                    "keyring change requires source revalidation"
                );
                append(&writer, 3, 4);
            }
            "verify" => {
                assert_eq!(
                    suffix(&writer),
                    0,
                    "key order must not change the context fingerprint"
                );
                append(&writer, 1, 4);
                assert_eq!(records_for_test(&data).unwrap().len(), 3);
            }
            _ => unreachable!(),
        }
        writer.checkpoint_recovery().unwrap();
        assert!(
            fs::read(current(&data))
                .unwrap()
                .starts_with(encryption::MAGIC)
        );
        return;
    }
    let root = tempfile::tempdir().unwrap();
    for mode in ["create", "rotate", "verify", "missing"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "audit::checkpoint::tests::keys::encrypted_checkpoint_key_rotation_revalidates_history_and_cannot_hide_missing_old_key", "--nocapture", "--test-threads=1"])
            .env(CHILD, root.path()).env(MODE, mode).output().unwrap();
        assert!(
            output.status.success(),
            "key mode {mode}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
