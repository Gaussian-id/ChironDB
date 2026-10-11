use super::*;
#[cfg(feature = "fault-injection")]
use crate::transaction_journal::{ProjectionKind, TransactionJournal, TransactionTarget};
use crate::transaction_journal::{TransactionAudit, TransactionId};
#[cfg(feature = "fault-injection")]
use crate::wal::{Wal, WalEntry};

fn projection() -> TransactionAudit {
    TransactionAudit::mutation(
        "delete",
        Some("docs"),
        &AuditContext::embedded(),
        serde_json::json!({"fixture": "durable-projection"}),
    )
}

#[test]
fn duplicate_projection_after_reopen_preserves_original_principal_and_details() {
    let root = tempfile::tempdir().unwrap();
    let id = TransactionId::new();
    let writer = AuditWriter::open(root.path()).unwrap();
    writer
        .project_committed_transaction(id, &projection())
        .unwrap();
    drop(writer);
    let writer = AuditWriter::open(root.path()).unwrap();
    for principal in ["foreign", ""] {
        let mut changed = projection();
        changed.principal_id = principal.into();
        assert!(writer.project_committed_transaction(id, &changed).is_err());
    }
    let mut changed = projection();
    changed.details = serde_json::json!({"fixture": "changed"});
    assert!(writer.project_committed_transaction(id, &changed).is_err());
    writer
        .project_committed_transaction(id, &projection())
        .unwrap();
    assert_eq!(records_for_test(root.path()).unwrap().len(), 1);
}

#[test]
fn restore_copies_all_rotated_audit_files_without_derived_cache_or_full_file_hydration() {
    let root = tempfile::tempdir().unwrap();
    let staged = tempfile::tempdir().unwrap();
    let writer = AuditWriter::open(root.path()).unwrap();
    writer
        .project_committed_transaction(TransactionId::new(), &projection())
        .unwrap();
    rotate_if_needed_at(&mut writer.state.lock().unwrap(), 1).unwrap();
    writer
        .project_committed_transaction(TransactionId::new(), &projection())
        .unwrap();
    crate::relational::wal_decode::with_test_storage_pool(512 * 1024, |used| {
        preserve_durable_log(root.path(), staged.path()).unwrap();
        assert_eq!(used(), 0);
    });
    verify_hash_chain(staged.path()).unwrap();
    assert_eq!(records_for_test(staged.path()).unwrap().len(), 2);
    assert_eq!(
        fs::read_dir(staged.path().join("audit")).unwrap().count(),
        2
    );
}

#[test]
fn complete_malformed_or_unreadable_active_tail_is_never_trimmed() {
    for bytes in [b"{bad}".as_slice(), b"CHIRENC1:AQIDBA==", b"\xff"] {
        let root = tempfile::tempdir().unwrap();
        let path = audit_log_path(root.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        assert!(AuditWriter::open(root.path()).is_err());
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}

#[test]
fn verified_chain_with_changed_committed_audit_semantics_refuses_startup_before_append() {
    use crate::transaction_journal::{TransactionJournal, TransactionTarget};
    let root = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(root.path()).unwrap();
    let transaction = journal
        .commit(
            TransactionTarget::Collection {
                name: "docs".into(),
            },
            crate::wal::WalEntry::Delete { id: "one".into() },
            projection(),
        )
        .unwrap();
    crate::transaction_journal::activate_test_authority(&journal);
    let writer = AuditWriter::open(root.path()).unwrap();
    writer
        .project_committed_transaction(transaction.prepare.transaction_id, &projection())
        .unwrap();
    drop(writer);
    let path = audit_log_path(root.path());
    let mut value = records_for_test(root.path()).unwrap().remove(0);
    value["principal_id"] = Value::String("foreign".into());
    value.as_object_mut().unwrap().remove("record_hash");
    value["record_hash"] = Value::String(hash_json_value(&value).unwrap());
    let mut file = File::create(&path).unwrap();
    write_audit_value(&mut file, &value).unwrap();
    file.sync_all().unwrap();
    verify_hash_chain(root.path()).unwrap();
    let before = fs::read(&path).unwrap();
    assert!(AuditWriter::open_with_journal(root.path(), journal).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
}

#[test]
fn tail_admission_failure_preserves_complete_unterminated_acknowledged_record() {
    let root = tempfile::tempdir().unwrap();
    append_success(root.path(), "one", None, Value::Null).unwrap();
    let path = audit_log_path(root.path());
    let mut bytes = fs::read(&path).unwrap();
    bytes.pop();
    fs::write(&path, &bytes).unwrap();
    crate::relational::wal_decode::with_test_storage_pool(1, |used| {
        assert!(AuditWriter::open(root.path()).is_err());
        assert_eq!(used(), 0);
    });
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[cfg(unix)]
#[test]
fn exclusive_cache_cleanup_refuses_audit_directory_symlink_without_touching_target() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let cache = outside.path().join(".chiron-decisions-another-live-owner");
    fs::create_dir(&cache).unwrap();
    fs::write(cache.join("owned"), b"retain").unwrap();
    let journal = crate::transaction_journal::TransactionJournal::open(root.path()).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("audit")).unwrap();
    assert!(AuditWriter::open_with_journal(root.path(), journal).is_err());
    assert_eq!(fs::read(cache.join("owned")).unwrap(), b"retain");
}

#[test]
fn concurrent_transaction_projection_writes_one_durable_record_per_identity() {
    let root = tempfile::tempdir().unwrap();
    let writer = AuditWriter::open(root.path()).unwrap();
    let ids = Arc::new((0..24).map(|_| TransactionId::new()).collect::<Vec<_>>());
    let barrier = Arc::new(std::sync::Barrier::new(8));
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let writer = Arc::clone(&writer);
            let ids = Arc::clone(&ids);
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                for id in ids.iter() {
                    barrier.wait();
                    writer
                        .project_committed_transaction(*id, &projection())
                        .unwrap();
                }
            });
        }
    });
    writer.flush_and_shutdown().unwrap();
    drop(writer);
    verify_hash_chain(root.path()).unwrap();
    let rows = records_for_test(root.path()).unwrap();
    assert_eq!(rows.len(), ids.len());
    for id in ids.iter() {
        assert_eq!(
            rows.iter()
                .filter(|row| row["operation_id"] == id.to_string())
                .count(),
            1
        );
    }
    let reopened = AuditWriter::open(root.path()).unwrap();
    for id in ids.iter() {
        reopened
            .project_committed_transaction(*id, &projection())
            .unwrap();
    }
    reopened.flush_and_shutdown().unwrap();
    assert_eq!(records_for_test(root.path()).unwrap().len(), ids.len());
}

#[test]
#[cfg(feature = "fault-injection")]
fn failed_audit_sync_retry_cannot_ack_or_advance_completed_commit_frontier() {
    let root = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(root.path()).unwrap();
    let committed = journal
        .commit(
            TransactionTarget::Collection {
                name: "docs".into(),
            },
            WalEntry::Delete { id: "one".into() },
            projection(),
        )
        .unwrap();
    let id = committed.prepare.transaction_id;
    let mut storage = Wal::open(&root.path().join("collections/docs/wal")).unwrap();
    storage
        .append(&WalEntry::TransactionApply {
            transaction_id: id,
            entry: committed.prepare.mutation.clone(),
        })
        .unwrap();
    journal.mark_projected(id, ProjectionKind::Storage).unwrap();
    let writer = AuditWriter::open(root.path()).unwrap();
    {
        let _fault =
            crate::failpoint::test_env("error:audit.before_sync", root.path(), root.path());
        assert!(matches!(
            writer.project_committed_transaction(id, &committed.prepare.audit),
            Err(GaussError::AuditUnavailable(_))
        ));
    }
    // A complete visible frame is not proof that its fsync succeeded.
    assert_eq!(records_for_test(root.path()).unwrap().len(), 1);
    let retry = writer.project_committed_transaction(id, &committed.prepare.audit);
    if retry.is_ok() {
        journal.mark_projected(id, ProjectionKind::Audit).unwrap();
    }
    let frontier = journal.completed_commit_frontier().unwrap();
    let shutdown = writer.flush_and_shutdown();
    drop(writer);
    assert!(matches!(retry, Err(GaussError::AuditUnavailable(_))));
    assert_eq!(frontier, None);
    assert!(shutdown.is_err());
    let recovered = AuditWriter::open(root.path()).unwrap();
    recovered
        .project_committed_transaction(id, &committed.prepare.audit)
        .unwrap();
    journal.mark_projected(id, ProjectionKind::Audit).unwrap();
    assert_eq!(journal.completed_commit_frontier().unwrap(), Some(1));
    recovered.flush_and_shutdown().unwrap();
    verify_hash_chain(root.path()).unwrap();
    assert_eq!(records_for_test(root.path()).unwrap().len(), 1);
}

#[test]
#[cfg(feature = "fault-injection")]
fn recovered_audit_requires_sync_barrier_before_existing_record_can_ack() {
    let root = tempfile::tempdir().unwrap();
    let id = TransactionId::new();
    let writer = AuditWriter::open(root.path()).unwrap();
    writer
        .project_committed_transaction(id, &projection())
        .unwrap();
    writer.flush_and_shutdown().unwrap();
    drop(writer);
    let before = fs::read(audit_log_path(root.path())).unwrap();
    {
        let _fault = crate::failpoint::test_env(
            "error:audit.before_recovery_sync",
            root.path(),
            root.path(),
        );
        assert!(matches!(
            AuditWriter::open(root.path()),
            Err(GaussError::AuditUnavailable(_))
        ));
    }
    assert_eq!(fs::read(audit_log_path(root.path())).unwrap(), before);
    let writer = AuditWriter::open(root.path()).unwrap();
    writer
        .project_committed_transaction(id, &projection())
        .unwrap();
    writer.flush_and_shutdown().unwrap();
    assert_eq!(fs::read(audit_log_path(root.path())).unwrap(), before);
}

#[test]
fn duplicate_projection_waits_for_pending_group_durability() {
    let root = tempfile::tempdir().unwrap();
    let writer = AuditWriter::open(root.path()).unwrap();
    // Gate the worker to hold a real group-commit record before its fsync.
    writer.stop_group_committer();
    let id = TransactionId::new();
    let original = Arc::clone(&writer);
    let append = std::thread::spawn(move || {
        original.append(
            "mutation",
            "delete",
            &id.to_string(),
            "success",
            Some("docs"),
            &AuditContext::embedded(),
            None,
            projection().details,
            false,
        )
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    while writer.state.lock().unwrap().group_pending == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    let pending = writer.state.lock().unwrap().group_pending;
    let (send, receive) = std::sync::mpsc::channel();
    let duplicate = Arc::clone(&writer);
    let retry = std::thread::spawn(move || {
        send.send(duplicate.project_committed_transaction(id, &projection()))
            .unwrap()
    });
    let early = receive.recv_timeout(Duration::from_millis(100)).ok();
    let acknowledged_early = early.is_some();
    {
        let mut state = writer.state.lock().unwrap();
        state.file.sync_all().unwrap();
        state.durable_sequence = state.sequence;
        state.group_pending = 0;
        state.group_started = None;
        writer.commit.notify_all();
    }
    append.join().unwrap().unwrap();
    let completed = if early.is_some() {
        early
    } else {
        receive.recv_timeout(Duration::from_secs(2)).ok()
    };
    retry.join().unwrap();
    writer.flush_and_shutdown().unwrap();
    assert_eq!(pending, 1);
    assert!(completed.unwrap().is_ok());
    assert!(!acknowledged_early, "duplicate acknowledged before fsync");
    verify_hash_chain(root.path()).unwrap();
    assert_eq!(records_for_test(root.path()).unwrap().len(), 1);
}

#[test]
#[cfg(feature = "fault-injection")]
fn root_swap_sync_failure_keeps_old_audit_binding_until_retry() {
    let old = tempfile::tempdir().unwrap();
    let new = tempfile::tempdir().unwrap();
    let old_id = TransactionId::new();
    let new_id = TransactionId::new();
    let writer = AuditWriter::open(old.path()).unwrap();
    writer
        .project_committed_transaction(old_id, &projection())
        .unwrap();
    let replacement = AuditWriter::open(new.path()).unwrap();
    replacement
        .project_committed_transaction(new_id, &projection())
        .unwrap();
    replacement.flush_and_shutdown().unwrap();
    drop(replacement);
    let old_bytes = fs::read(audit_log_path(old.path())).unwrap();
    let new_bytes = fs::read(audit_log_path(new.path())).unwrap();
    {
        let _fault =
            crate::failpoint::test_env("error:audit.before_recovery_sync", old.path(), old.path());
        assert!(matches!(
            writer.reload_after_root_swap(new.path()),
            Err(GaussError::AuditUnavailable(_))
        ));
    }
    writer
        .project_committed_transaction(old_id, &projection())
        .unwrap();
    assert_eq!(fs::read(audit_log_path(old.path())).unwrap(), old_bytes);
    assert_eq!(fs::read(audit_log_path(new.path())).unwrap(), new_bytes);
    writer.reload_after_root_swap(new.path()).unwrap();
    writer
        .project_committed_transaction(new_id, &projection())
        .unwrap();
    writer
        .project_committed_transaction(old_id, &projection())
        .unwrap();
    writer.flush_and_shutdown().unwrap();
    verify_hash_chain(new.path()).unwrap();
    assert_eq!(records_for_test(new.path()).unwrap().len(), 2);
    assert_eq!(fs::read(audit_log_path(old.path())).unwrap(), old_bytes);
}

#[test]
#[cfg(all(unix, feature = "fault-injection"))]
fn sigkill_before_audit_sync_recovers_one_record_and_complete_frontier() {
    const CHILD: &str = "CHIRONDB_AUDIT_PROJECTION_KILL_CHILD";
    const ID: &str = "CHIRONDB_AUDIT_PROJECTION_KILL_ID";
    if let Some(path) = std::env::var_os(CHILD) {
        let writer = AuditWriter::open(Path::new(&path)).unwrap();
        let id = std::env::var(ID).unwrap().parse::<TransactionId>().unwrap();
        writer
            .project_committed_transaction(id, &projection())
            .unwrap();
        fs::write(Path::new(&path).join("acknowledged"), b"returned").unwrap();
        panic!("child should pause before audit fsync");
    }
    let root = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(root.path()).unwrap();
    let transaction = journal
        .commit(
            TransactionTarget::Collection {
                name: "docs".into(),
            },
            WalEntry::Delete { id: "one".into() },
            projection(),
        )
        .unwrap();
    let id = transaction.prepare.transaction_id;
    let mut storage = Wal::open(&root.path().join("collections/docs/wal")).unwrap();
    storage
        .append(&WalEntry::TransactionApply {
            transaction_id: id,
            entry: transaction.prepare.mutation.clone(),
        })
        .unwrap();
    journal.mark_projected(id, ProjectionKind::Storage).unwrap();
    drop(storage);
    drop(transaction);
    drop(journal);
    let marker = root.path().join("audit-kill-marker");
    let release = root.path().join("audit-kill-release");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "audit::projection_tests::sigkill_before_audit_sync_recovers_one_record_and_complete_frontier", "--nocapture", "--test-threads=1"])
        .env(CHILD, root.path())
        .env(ID, id.to_string())
        .env("CHIRONDB_FAILPOINT", "pause:audit.before_sync")
        .env("CHIRONDB_FAILPOINT_MARKER", &marker)
        .env("CHIRONDB_FAILPOINT_RELEASE", &release)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !marker.exists() && Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let paused = marker.exists();
    child.kill().unwrap();
    let status = child.wait().unwrap();
    assert!(paused, "child did not reach pre-fsync boundary");
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(9));
    assert!(!root.path().join("acknowledged").exists());
    let journal = TransactionJournal::open(root.path()).unwrap();
    assert_eq!(journal.completed_commit_frontier().unwrap(), None);
    let writer = AuditWriter::open(root.path()).unwrap();
    writer
        .project_committed_transaction(id, &projection())
        .unwrap();
    journal.mark_projected(id, ProjectionKind::Audit).unwrap();
    assert_eq!(journal.completed_commit_frontier().unwrap(), Some(1));
    writer
        .project_committed_transaction(id, &projection())
        .unwrap();
    writer.flush_and_shutdown().unwrap();
    verify_hash_chain(root.path()).unwrap();
    assert_eq!(records_for_test(root.path()).unwrap().len(), 1);
}
