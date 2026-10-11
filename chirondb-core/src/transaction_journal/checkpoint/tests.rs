use super::*;

fn context() -> AuditContext {
    AuditContext {
        principal_id: "writer".into(),
        tenant_id: Some("tenant".into()),
        transport: "test".into(),
        request_id: None,
    }
}

fn execute(journal: &Arc<TransactionJournal>, index: u64) -> CommittedTransaction {
    let IdempotencyAdmission::Execute(guard) = journal
        .begin_idempotent(
            &format!("checkpoint-{index}"),
            &context(),
            "delete",
            &index,
            || Ok(()),
        )
        .unwrap()
    else {
        panic!("duplicate executed")
    };
    guard
        .commit(
            TransactionTarget::Collection {
                name: "docs".into(),
            },
            WalEntry::DeleteBatch {
                ids: vec![format!("row-{index}")],
            },
            TransactionAudit::mutation("delete", Some("docs"), &context(), Value::Null),
            serde_json::json!({"index":index}),
        )
        .unwrap()
}

fn complete(journal: &TransactionJournal, transaction: &CommittedTransaction) {
    for kind in [ProjectionKind::Storage, ProjectionKind::Audit] {
        journal
            .mark_projected(transaction.prepare.transaction_id, kind)
            .unwrap();
    }
}

fn seed(parent: &Path) -> Vec<TransactionId> {
    let journal = TransactionJournal::open(parent).unwrap();
    let mut ids = Vec::new();
    for index in 0..512 {
        let transaction = execute(&journal, index);
        ids.push(transaction.prepare.transaction_id);
        complete(&journal, &transaction);
    }
    drop(journal);
    // First reopen validates authoritative records and publishes the cache.
    let journal = TransactionJournal::open(parent).unwrap();
    assert_eq!(
        journal.inner.lock().unwrap().state.recovery_decoded_records,
        2048
    );
    drop(journal);
    ids
}

fn assert_replay(journal: &Arc<TransactionJournal>, ids: &[TransactionId]) {
    for index in [0_u64, 255, 511] {
        let IdempotencyAdmission::Replay(receipt) = journal
            .begin_idempotent(
                &format!("checkpoint-{index}"),
                &context(),
                "delete",
                &index,
                || Ok(()),
            )
            .unwrap()
        else {
            panic!("checkpoint lost consumed key")
        };
        assert_eq!(receipt.status.transaction_id, ids[index as usize]);
        assert_eq!(receipt.response.unwrap()["index"], index);
        assert!(
            journal
                .status_for_owner(ids[index as usize], "other", "tenant")
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn checkpoint_skips_old_decoding_and_recovers_pending_suffix_then_repairs() {
    let parent = tempfile::tempdir().unwrap();
    let ids = seed(parent.path());
    let journal = TransactionJournal::open(parent.path()).unwrap();
    assert_eq!(
        journal.inner.lock().unwrap().state.recovery_decoded_records,
        0
    );
    assert_replay(&journal, &ids);
    let pending = execute(&journal, 512);
    drop(journal);
    let journal = TransactionJournal::open(parent.path()).unwrap();
    {
        let inner = journal.inner.lock().unwrap();
        assert_eq!(inner.state.recovery_decoded_records, 2);
        assert_eq!(inner.state.committed_count, 513);
        assert_eq!(inner.state.pending_storage, 1);
        assert_eq!(inner.state.pending_audit, 1);
        assert_eq!(inner.state.prepares.len(), 1);
    }
    let mut seen = Vec::new();
    journal
        .for_each_committed(|transaction| {
            seen.push(transaction.prepare.transaction_id);
            if transaction.prepare.transaction_id == pending.prepare.transaction_id {
                complete(&journal, &transaction);
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(&seen[..512], &ids);
    assert_eq!(seen[512], pending.prepare.transaction_id);
    drop(journal);
    let journal = TransactionJournal::open(parent.path()).unwrap();
    assert_eq!(
        journal.inner.lock().unwrap().state.recovery_decoded_records,
        4
    );
    assert_replay(&journal, &ids);
    drop(journal);
    let journal = TransactionJournal::open(parent.path()).unwrap();
    assert_eq!(
        journal.inner.lock().unwrap().state.recovery_decoded_records,
        0
    );
    assert_eq!(journal.completed_commit_frontier().unwrap(), Some(513));
}

#[test]
fn broken_cache_rebuilds_without_releasing_consumed_keys() {
    for damage in [
        "manifest",
        "run",
        "missing",
        "prefix-length",
        "metadata-bit",
    ] {
        let parent = tempfile::tempdir().unwrap();
        let ids = seed(parent.path());
        let root = parent
            .path()
            .join(TRANSACTION_JOURNAL_DIR)
            .join(".chiron-decision-checkpoint");
        let current = root.join("CURRENT");
        std::fs::write(root.join(".CURRENT.interrupted.tmp"), b"unpublished").unwrap();
        let bytes = std::fs::read(&current).unwrap();
        let mut manifest: Value = serde_json::from_slice(
            crate::security::storage::decode_metadata(b"CHIRDEC1", &bytes).unwrap(),
        )
        .unwrap();
        let generation = root.join(manifest["generation"].as_str().unwrap());
        let level = manifest["runs"][0]["level"].as_u64().unwrap();
        let run = generation.join(format!("level-{level}.rseg"));
        match damage {
            "manifest" => std::fs::write(&current, b"invalid cache").unwrap(),
            "run" => std::fs::write(&run, b"invalid run").unwrap(),
            "missing" => std::fs::remove_file(&run).unwrap(),
            "metadata-bit" => {
                let mut bytes = bytes;
                *bytes.last_mut().unwrap() ^= 1;
                std::fs::write(&current, bytes).unwrap();
            }
            _ => {
                manifest["metadata"]["prefix"]["end_lsn"] = Value::from(u64::MAX);
                let bytes = crate::security::storage::encode_metadata(
                    b"CHIRDEC1",
                    &serde_json::to_vec(&manifest).unwrap(),
                );
                std::fs::write(&current, bytes).unwrap();
            }
        }
        let journal = TransactionJournal::open(parent.path()).unwrap();
        assert!(!root.join(".CURRENT.interrupted.tmp").exists());
        assert_eq!(
            journal.inner.lock().unwrap().state.recovery_decoded_records,
            2048,
            "{damage}"
        );
        assert_replay(&journal, &ids);
        assert_eq!(
            std::fs::read_dir(&root)
                .unwrap()
                .filter(|entry| entry.as_ref().unwrap().file_type().unwrap().is_dir())
                .count(),
            1
        );
        drop(journal);
        let journal = TransactionJournal::open(parent.path()).unwrap();
        assert_eq!(
            journal.inner.lock().unwrap().state.recovery_decoded_records,
            0
        );
    }
}

#[test]
fn legacy_unordered_cache_rebuilds_from_unchanged_authoritative_wal() {
    let parent = tempfile::tempdir().unwrap();
    let ids = seed(parent.path());
    let dir = parent.path().join(TRANSACTION_JOURNAL_DIR);
    let wal_path = dir.join("000000.gdwal");
    let wal_before = std::fs::read(&wal_path).unwrap();
    let current = dir.join(".chiron-decision-checkpoint/CURRENT");
    let bytes = std::fs::read(&current).unwrap();
    let mut manifest: Value = serde_json::from_slice(
        crate::security::storage::decode_metadata(b"CHIRDEC1", &bytes).unwrap(),
    )
    .unwrap();
    manifest["metadata"]
        .as_object_mut()
        .unwrap()
        .remove("decision_index_version");
    std::fs::write(
        &current,
        crate::security::storage::encode_metadata(
            b"CHIRDEC1",
            &serde_json::to_vec(&manifest).unwrap(),
        ),
    )
    .unwrap();
    let journal = TransactionJournal::open(parent.path()).unwrap();
    assert_eq!(
        journal.inner.lock().unwrap().state.recovery_decoded_records,
        2048
    );
    assert_replay(&journal, &ids);
    let mut seen = Vec::new();
    journal
        .for_each_committed(|transaction| {
            seen.push(transaction.prepare.transaction_id);
            Ok(())
        })
        .unwrap();
    assert_eq!(seen, ids);
    assert_eq!(std::fs::read(&wal_path).unwrap(), wal_before);
    drop(journal);
    let journal = TransactionJournal::open(parent.path()).unwrap();
    assert_eq!(
        journal.inner.lock().unwrap().state.recovery_decoded_records,
        0
    );
}

#[test]
fn changed_authoritative_prefix_fails_closed_and_historical_duplicate_tail_rejects() {
    let parent = tempfile::tempdir().unwrap();
    let ids = seed(parent.path());
    let dir = parent.path().join(TRANSACTION_JOURNAL_DIR);
    let mut wal = Wal::open_control_journal(&dir).unwrap();
    wal.append(&WalEntry::TransactionCommit {
        commit: TransactionCommit {
            version: 2,
            transaction_id: ids[0],
            commit_sequence: 1,
        },
    })
    .unwrap();
    drop(wal);
    assert!(TransactionJournal::open(parent.path()).is_err());
    let parent = tempfile::tempdir().unwrap();
    seed(parent.path());
    let dir = parent.path().join(TRANSACTION_JOURNAL_DIR);
    let path = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "gdwal")
        })
        .unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[12] ^= 1;
    std::fs::write(path, bytes).unwrap();
    assert!(TransactionJournal::open(parent.path()).is_err());
}

#[test]
#[cfg(feature = "fault-injection")]
fn interrupted_cache_publication_keeps_old_or_new_complete_generation() {
    for point in [
        "transaction_checkpoint.before_publish",
        "transaction_checkpoint.after_manifest",
    ] {
        let parent = tempfile::tempdir().unwrap();
        let ids = seed(parent.path());
        let journal = TransactionJournal::open(parent.path()).unwrap();
        let extra = execute(&journal, 512);
        complete(&journal, &extra);
        {
            let mut inner = journal.inner.lock().unwrap();
            let fault =
                crate::failpoint::test_env(&format!("error:{point}"), parent.path(), parent.path());
            let length = inner.wal.len().unwrap();
            let result = publish(journal.dir(), &mut inner.state, length);
            drop(fault);
            assert!(result.is_err());
        }
        assert_replay(&journal, &ids);
        drop(journal);
        let journal = TransactionJournal::open(parent.path()).unwrap();
        let expected = if point.ends_with("before_publish") {
            4
        } else {
            0
        };
        assert_eq!(
            journal.inner.lock().unwrap().state.recovery_decoded_records,
            expected
        );
        assert_eq!(journal.completed_commit_frontier().unwrap(), Some(513));
        assert_replay(&journal, &ids);
    }
}

#[test]
#[cfg(all(unix, feature = "fault-injection"))]
fn sigkill_during_cache_publication_preserves_every_acknowledged_decision() {
    const CHILD: &str = "CHIRONDB_CHECKPOINT_KILL_CHILD";
    if let Some(directory) = std::env::var_os(CHILD) {
        let journal = TransactionJournal::open(Path::new(&directory)).unwrap();
        let transaction = execute(&journal, 512);
        complete(&journal, &transaction);
        let mut inner = journal.inner.lock().unwrap();
        let length = inner.wal.len().unwrap();
        publish(journal.dir(), &mut inner.state, length).unwrap();
        panic!("child was expected to pause at checkpoint publication");
    }
    for point in [
        "transaction_checkpoint.before_publish",
        "transaction_checkpoint.after_manifest",
    ] {
        let parent = tempfile::tempdir().unwrap();
        let ids = seed(parent.path());
        let marker = parent.path().join("kill-marker");
        let release = parent.path().join("kill-release");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "transaction_journal::checkpoint::tests::sigkill_during_cache_publication_preserves_every_acknowledged_decision", "--nocapture"])
            .env(CHILD, parent.path())
            .env("CHIRONDB_FAILPOINT", format!("pause:{point}"))
            .env("CHIRONDB_FAILPOINT_MARKER", &marker)
            .env("CHIRONDB_FAILPOINT_RELEASE", &release)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn().unwrap();
        let started = std::time::Instant::now();
        while !marker.exists() && started.elapsed() < std::time::Duration::from_secs(30) {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("checkpoint child exited before pause: {status}");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let paused = marker.exists();
        child.kill().unwrap();
        let status = child.wait().unwrap();
        assert!(paused, "child never reached {point}");
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
        let journal = TransactionJournal::open(parent.path()).unwrap();
        assert_eq!(journal.completed_commit_frontier().unwrap(), Some(513));
        assert_replay(&journal, &ids);
        let IdempotencyAdmission::Replay(receipt) = journal
            .begin_idempotent("checkpoint-512", &context(), "delete", &512_u64, || Ok(()))
            .unwrap()
        else {
            panic!("SIGKILL lost acknowledged consumed key");
        };
        assert_eq!(receipt.response.unwrap()["index"], 512);
    }
}
