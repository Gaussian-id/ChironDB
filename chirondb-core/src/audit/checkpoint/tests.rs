use super::*;
use crate::transaction_journal::{TransactionAudit, TransactionId, TransactionJournal};

fn projection() -> TransactionAudit {
    TransactionAudit::mutation(
        "delete",
        Some("docs"),
        &AuditContext::embedded(),
        Value::Null,
    )
}
fn open_journal(root: &Path) -> Arc<TransactionJournal> {
    let marker = root.join(crate::transaction_journal::TRANSACTION_FORMAT_MARKER);
    if !marker.exists() {
        fs::create_dir_all(marker.parent().unwrap()).unwrap();
        fs::write(&marker, format!("CHIRONTXN2\n{}\n", uuid::Uuid::new_v4())).unwrap();
        File::open(&marker).unwrap().sync_all().unwrap();
        sync_directory(marker.parent().unwrap()).unwrap();
    }
    TransactionJournal::open(root).unwrap()
}
fn id(number: u64) -> TransactionId {
    format!("00000000-0000-0000-0000-{number:012x}")
        .parse()
        .unwrap()
}
fn append(writer: &AuditWriter, start: u64, end: u64) {
    for number in start..end {
        writer
            .project_committed_transaction(id(number), &projection())
            .unwrap();
    }
}
fn suffix(writer: &AuditWriter) -> u64 {
    writer
        .state
        .lock()
        .unwrap()
        .registry
        .recovery_decoded_records
}
fn current(root: &Path) -> PathBuf {
    root.join("audit/.chiron-decision-checkpoint/CURRENT")
}
fn change_checkpoint(writer: &AuditWriter, change: impl FnOnce(&mut Checkpoint)) {
    let mut state = writer.state.lock().unwrap();
    let checkpoint = state
        .registry
        .disk
        .load_checkpoint::<Checkpoint>()
        .unwrap()
        .unwrap();
    checkpoint
        .consume(|mut checkpoint| {
            change(&mut checkpoint);
            state.registry.disk.publish_checkpoint(&checkpoint)
        })
        .unwrap();
}

#[test]
fn reuses_durable_registry_and_decodes_only_new_suffix_without_duplicate_projection() {
    let root = tempfile::tempdir().unwrap();
    let journal = open_journal(root.path());
    let writer = AuditWriter::open_with_journal(root.path(), Arc::clone(&journal)).unwrap();
    append(&writer, 1, 11);
    writer.checkpoint_recovery().unwrap();
    append(&writer, 11, 14);
    drop(writer);
    let writer = AuditWriter::open_with_journal(root.path(), journal).unwrap();
    assert_eq!(suffix(&writer), 3);
    assert_eq!(writer.state.lock().unwrap().sequence, 13);
    append(&writer, 1, 14);
    assert_eq!(records_for_test(root.path()).unwrap().len(), 13);
    verify_hash_chain(root.path()).unwrap();
}

#[test]
fn resumes_across_rotation_before_and_after_checkpoint_including_empty_active_file() {
    for empty_active in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let journal = open_journal(root.path());
        let writer = AuditWriter::open_with_journal(root.path(), Arc::clone(&journal)).unwrap();
        append(&writer, 1, 3);
        rotate_if_needed_at(&mut writer.state.lock().unwrap(), 1).unwrap();
        if !empty_active {
            append(&writer, 3, 4);
        }
        writer.checkpoint_recovery().unwrap();
        append(&writer, 4, 6);
        rotate_if_needed_at(&mut writer.state.lock().unwrap(), 1).unwrap();
        append(&writer, 6, 8);
        drop(writer);
        let writer = AuditWriter::open_with_journal(root.path(), journal).unwrap();
        assert_eq!(suffix(&writer), 4);
        assert_eq!(
            writer.state.lock().unwrap().sequence,
            if empty_active { 6 } else { 7 }
        );
        verify_hash_chain(root.path()).unwrap();
    }
}

#[test]
fn invalid_resume_metadata_falls_back_to_original_verified_log() {
    for case in 0..5 {
        let root = tempfile::tempdir().unwrap();
        let journal = open_journal(root.path());
        let writer = AuditWriter::open_with_journal(root.path(), Arc::clone(&journal)).unwrap();
        append(&writer, 1, 4);
        writer.checkpoint_recovery().unwrap();
        change_checkpoint(&writer, |checkpoint| match case {
            0 => checkpoint.sequence += 1,
            1 => checkpoint.previous_hash = "0".repeat(64),
            2 => checkpoint.installation = uuid::Uuid::new_v4(),
            3 => checkpoint.key_context[0] ^= 1,
            _ => checkpoint.version += 1,
        });
        let before = fs::read(audit_log_path(root.path())).unwrap();
        drop(writer);
        let writer = AuditWriter::open_with_journal(root.path(), journal).unwrap();
        assert_eq!(suffix(&writer), 3, "invalid cache case {case}");
        assert_eq!(writer.state.lock().unwrap().sequence, 3);
        assert_eq!(fs::read(audit_log_path(root.path())).unwrap(), before);
        append(&writer, 1, 4);
        assert_eq!(records_for_test(root.path()).unwrap().len(), 3);
    }
}

#[test]
fn missing_or_corrupt_cache_keeps_acknowledged_audit_and_full_recovery() {
    for missing in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let journal = open_journal(root.path());
        let writer = AuditWriter::open_with_journal(root.path(), Arc::clone(&journal)).unwrap();
        append(&writer, 1, 4);
        writer.checkpoint_recovery().unwrap();
        drop(writer);
        if missing {
            fs::remove_file(current(root.path())).unwrap();
        } else {
            fs::write(current(root.path()), b"invalid cache").unwrap();
        }
        let before = fs::read(audit_log_path(root.path())).unwrap();
        let writer = AuditWriter::open_with_journal(root.path(), journal).unwrap();
        assert_eq!(suffix(&writer), 3);
        append(&writer, 1, 4);
        assert_eq!(fs::read(audit_log_path(root.path())).unwrap(), before);
    }
}

#[test]
fn cached_prefix_never_hides_changed_audit_history() {
    let root = tempfile::tempdir().unwrap();
    let journal = open_journal(root.path());
    let writer = AuditWriter::open_with_journal(root.path(), Arc::clone(&journal)).unwrap();
    append(&writer, 1, 4);
    writer.checkpoint_recovery().unwrap();
    drop(writer);
    let path = audit_log_path(root.path());
    let mut bytes = fs::read(&path).unwrap();
    let offset = bytes
        .windows(b"embedded-system".len())
        .position(|value| value == b"embedded-system")
        .unwrap();
    bytes[offset] = b'X';
    fs::write(&path, &bytes).unwrap();
    assert!(AuditWriter::open_with_journal(root.path(), journal).is_err());
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn cached_terminal_is_rechecked_against_current_authoritative_commit() {
    use crate::transaction_journal::TransactionTarget;
    let root = tempfile::tempdir().unwrap();
    let journal = open_journal(root.path());
    let committed = journal
        .commit(
            TransactionTarget::Collection {
                name: "docs".into(),
            },
            crate::wal::WalEntry::Delete { id: "one".into() },
            projection(),
        )
        .unwrap();
    crate::transaction_journal::activate_test_authority(&journal);
    let writer = AuditWriter::open_with_journal(root.path(), Arc::clone(&journal)).unwrap();
    writer
        .project_committed_transaction(committed.prepare.transaction_id, &projection())
        .unwrap();
    writer.checkpoint_recovery().unwrap();
    // Publish a well-framed cache with the wrong semantic digest. Recovery
    // must reject that cache and derive the real receipt from its source.
    let mut state = writer.state.lock().unwrap();
    let checkpoint = state
        .registry
        .disk
        .load_checkpoint::<Checkpoint>()
        .unwrap()
        .unwrap();
    state.registry.disk =
        crate::relational::disk_map::DiskMap::new(&root.path().join("audit")).unwrap();
    let entry = registry::Entry::Terminal(registry::Terminal {
        operation_id: committed.prepare.transaction_id.to_string(),
        sequence: 1,
        digest: [0; 32],
    });
    state
        .registry
        .disk
        .insert_batch(|batch| batch.insert(&entry.key(), &entry))
        .unwrap();
    state
        .registry
        .disk
        .publish_checkpoint(&*checkpoint)
        .unwrap();
    drop(state);
    drop(writer);
    let writer = AuditWriter::open_with_journal(root.path(), journal).unwrap();
    assert_eq!(suffix(&writer), 1);
    writer
        .project_committed_transaction(committed.prepare.transaction_id, &projection())
        .unwrap();
    assert_eq!(records_for_test(root.path()).unwrap().len(), 1);
}

#[test]
fn two_thousand_fifty_receipts_checkpoint_and_reopen_with_bounded_owner_and_no_leak() {
    let root = tempfile::tempdir().unwrap();
    let journal = open_journal(root.path());
    crate::relational::wal_decode::with_test_storage_pool(2 * 1024 * 1024, |used| {
        let writer = AuditWriter::open_with_journal(root.path(), Arc::clone(&journal)).unwrap();
        append(&writer, 1, 2051);
        writer.checkpoint_recovery().unwrap();
        append(&writer, 2051, 2054);
        drop(writer);
        assert_eq!(used(), 0);
        let writer = AuditWriter::open_with_journal(root.path(), journal).unwrap();
        assert_eq!(suffix(&writer), 3);
        append(&writer, 1, 2054);
        drop(writer);
        assert_eq!(used(), 0);
    });
    assert_eq!(records_for_test(root.path()).unwrap().len(), 2053);
    verify_hash_chain(root.path()).unwrap();
}

#[test]
fn checkpoint_admission_failure_leaves_source_and_last_valid_frontier_intact() {
    let root = tempfile::tempdir().unwrap();
    let journal = open_journal(root.path());
    let writer = AuditWriter::open_with_journal(root.path(), Arc::clone(&journal)).unwrap();
    append(&writer, 1, 3);
    writer.checkpoint_recovery().unwrap();
    append(&writer, 3, 4);
    let before = fs::read(current(root.path())).unwrap();
    crate::relational::wal_decode::with_test_storage_pool(1, |used| {
        assert!(matches!(
            writer.checkpoint_recovery(),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(used(), 0);
    });
    assert_eq!(fs::read(current(root.path())).unwrap(), before);
    drop(writer);
    let writer = AuditWriter::open_with_journal(root.path(), journal).unwrap();
    assert_eq!(suffix(&writer), 1);
    append(&writer, 1, 4);
    assert_eq!(records_for_test(root.path()).unwrap().len(), 3);
}

#[cfg(feature = "fault-injection")]
mod faults;
mod keys;

#[test]
fn empty_frontier_can_reopen_then_publish_its_first_record() {
    let root = tempfile::tempdir().unwrap();
    let journal = open_journal(root.path());
    let writer = AuditWriter::open_with_journal(root.path(), Arc::clone(&journal)).unwrap();
    writer.checkpoint_recovery().unwrap();
    drop(writer);
    let writer = AuditWriter::open_with_journal(root.path(), journal).unwrap();
    assert_eq!(suffix(&writer), 0);
    append(&writer, 1, 2);
    verify_hash_chain(root.path()).unwrap();
}

#[test]
fn legacy_identity_never_changes_format_to_enable_optional_audit_cache() {
    let root = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(root.path()).unwrap();
    let marker = root
        .path()
        .join(crate::transaction_journal::TRANSACTION_FORMAT_MARKER);
    let before = fs::read(&marker).unwrap();
    let writer = AuditWriter::open_with_journal(root.path(), journal).unwrap();
    append(&writer, 1, 3);
    writer.flush_and_shutdown().unwrap();
    drop(writer);
    assert_eq!(fs::read(&marker).unwrap(), before);
    assert!(!current(root.path()).exists());
    let journal = TransactionJournal::open(root.path()).unwrap();
    let writer = AuditWriter::open_with_journal(root.path(), journal).unwrap();
    assert_eq!(suffix(&writer), 2);
    append(&writer, 1, 3);
    assert_eq!(records_for_test(root.path()).unwrap().len(), 2);
}

#[test]
fn cached_orphan_intent_is_closed_once_and_keeps_original_context() {
    let root = tempfile::tempdir().unwrap();
    let journal = open_journal(root.path());
    let writer = AuditWriter::open_with_journal(root.path(), Arc::clone(&journal)).unwrap();
    writer
        .append(
            "mutation",
            "delete",
            "orphan",
            "intent",
            Some("docs"),
            &AuditContext::embedded(),
            None,
            Value::Null,
            true,
        )
        .unwrap();
    writer.checkpoint_recovery().unwrap();
    drop(writer);
    let writer = AuditWriter::open_with_journal(root.path(), Arc::clone(&journal)).unwrap();
    assert_eq!(suffix(&writer), 0);
    let rows = records_for_test(root.path()).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1]["outcome"], "interrupted");
    assert_eq!(rows[1]["principal_id"], "embedded-system");
    writer.checkpoint_recovery().unwrap();
    drop(writer);
    let writer = AuditWriter::open_with_journal(root.path(), journal).unwrap();
    assert_eq!(suffix(&writer), 0);
    assert_eq!(records_for_test(root.path()).unwrap().len(), 2);
    verify_hash_chain(root.path()).unwrap();
}

#[test]
fn rehashed_foreign_principal_in_cached_prefix_refuses_before_audit_append() {
    use crate::transaction_journal::TransactionTarget;
    let root = tempfile::tempdir().unwrap();
    let journal = open_journal(root.path());
    let committed = journal
        .commit(
            TransactionTarget::Collection {
                name: "docs".into(),
            },
            crate::wal::WalEntry::Delete { id: "one".into() },
            projection(),
        )
        .unwrap();
    crate::transaction_journal::activate_test_authority(&journal);
    let writer = AuditWriter::open_with_journal(root.path(), Arc::clone(&journal)).unwrap();
    writer
        .project_committed_transaction(committed.prepare.transaction_id, &projection())
        .unwrap();
    writer.checkpoint_recovery().unwrap();
    drop(writer);
    let mut value = records_for_test(root.path()).unwrap().remove(0);
    value["principal_id"] = Value::String("foreign".into());
    value.as_object_mut().unwrap().remove("record_hash");
    value["record_hash"] = Value::String(hash_json_value(&value).unwrap());
    let path = audit_log_path(root.path());
    let mut file = File::create(&path).unwrap();
    write_audit_value(&mut file, &value).unwrap();
    file.sync_all().unwrap();
    verify_hash_chain(root.path()).unwrap();
    let before = fs::read(&path).unwrap();
    assert!(AuditWriter::open_with_journal(root.path(), journal).is_err());
    assert_eq!(fs::read(path).unwrap(), before);
}
