use super::*;

#[test]
fn optional_checkpoint_failure_during_shutdown_preserves_durable_acknowledgements() {
    for boundary in [
        "audit_checkpoint.before_publish",
        "audit_checkpoint.after_publish",
    ] {
        let root = tempfile::tempdir().unwrap();
        let journal = open_journal(root.path());
        let writer = AuditWriter::open_with_journal(root.path(), Arc::clone(&journal)).unwrap();
        append(&writer, 1, 4);
        {
            let _fault =
                crate::failpoint::test_env(&format!("error:{boundary}"), root.path(), root.path());
            writer.flush_and_shutdown().unwrap();
        }
        drop(writer);
        let writer = AuditWriter::open_with_journal(root.path(), journal).unwrap();
        assert_eq!(writer.state.lock().unwrap().sequence, 3);
        append(&writer, 1, 4);
        assert_eq!(records_for_test(root.path()).unwrap().len(), 3);
    }
}

#[cfg(unix)]
#[test]
fn sigkill_checkpoint_publication_recovers_old_or_new_complete_registry() {
    const CHILD: &str = "CHIRON_AUDIT_CHECKPOINT_CHILD";
    if let Some(root) = std::env::var_os(CHILD) {
        let root = PathBuf::from(root);
        let journal = open_journal(&root);
        let writer = AuditWriter::open_with_journal(&root, journal).unwrap();
        writer.checkpoint_recovery().unwrap();
        panic!("checkpoint did not pause");
    }
    for boundary in [
        "audit_checkpoint.before_publish",
        "transaction_checkpoint.before_link",
        "transaction_checkpoint.before_publish",
        "transaction_checkpoint.after_manifest",
        "audit_checkpoint.after_publish",
    ] {
        let root = tempfile::tempdir().unwrap();
        {
            let journal = open_journal(root.path());
            let writer = AuditWriter::open_with_journal(root.path(), journal).unwrap();
            append(&writer, 1, 3);
            writer.checkpoint_recovery().unwrap();
            append(&writer, 3, 5);
        }
        let before = fs::read(audit_log_path(root.path())).unwrap();
        let marker = root.path().join("marker");
        let release = root.path().join("release");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "audit::checkpoint::tests::faults::sigkill_checkpoint_publication_recovers_old_or_new_complete_registry", "--nocapture", "--test-threads=1"])
            .env(CHILD, root.path())
            .env("CHIRONDB_FAILPOINT", format!("pause:{boundary}"))
            .env("CHIRONDB_FAILPOINT_MARKER", &marker)
            .env("CHIRONDB_FAILPOINT_RELEASE", &release)
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !marker.exists() && Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let paused = marker.exists();
        if child.try_wait().unwrap().is_none() {
            child.kill().unwrap();
        }
        let status = child.wait().unwrap();
        assert!(paused, "child did not reach {boundary}");
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
        let journal = open_journal(root.path());
        let writer = AuditWriter::open_with_journal(root.path(), journal).unwrap();
        assert!(
            [0, 2].contains(&suffix(&writer)),
            "incomplete registry at {boundary}"
        );
        append(&writer, 1, 5);
        assert_eq!(fs::read(audit_log_path(root.path())).unwrap(), before);
        append(&writer, 5, 6);
        writer.checkpoint_recovery().unwrap();
        verify_hash_chain(root.path()).unwrap();
        assert_eq!(records_for_test(root.path()).unwrap().len(), 5);
        println!("SIGKILL {boundary}: acknowledged history and retry preserved");
    }
}
