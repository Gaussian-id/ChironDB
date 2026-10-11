use super::*;

fn pin_paths(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(PREFIX)
        })
        .collect()
}

#[test]
fn archived_file_pins_survive_prefix_retirement() {
    let dir = tempfile::tempdir().unwrap();
    let archives = tempfile::tempdir().unwrap();
    let mut wal = Wal::open_with_segment_bytes(dir.path(), 400).unwrap();
    for index in 0..17 {
        wal.append(&WalEntry::Delete {
            id: format!("row-{index:02}"),
        })
        .unwrap();
    }
    let end = wal.len().unwrap();
    let frozen = wal.freeze_archive_cut(end).unwrap().unwrap();
    wal.drop_prefix(end).unwrap();
    assert_eq!(Wal::retained_base_lsn(dir.path()).unwrap(), end);
    let archive = frozen
        .publish(archives.path())
        .expect("frozen archive must retain every captured file");
    let records = Wal::load(&archive.path).unwrap();
    assert_eq!(records.len(), 17);
    for (index, record) in records.iter().enumerate() {
        assert!(
            matches!(&record.entry, WalEntry::Delete { id } if id == &format!("row-{index:02}"))
        );
    }
    assert_eq!(pin_paths(dir.path()).len(), 1);
    drop(frozen);
    assert!(pin_paths(dir.path()).is_empty());
}

#[test]
fn inode_pins_release_on_reader_error_and_archive_retry() {
    let dir = tempfile::tempdir().unwrap();
    let mut wal = Wal::open(dir.path()).unwrap();
    wal.append(&WalEntry::Delete { id: "one".into() }).unwrap();
    let end = wal.len().unwrap();
    let original = wal.path().to_path_buf();
    let bytes = fs::read(&original).unwrap();
    crate::relational::wal_decode::with_test_storage_pool(4 * 1024 * 1024, |used| {
        let mut reader = OrderedJournalReader::open(dir.path(), end).unwrap();
        let pins = pin_paths(dir.path());
        assert_eq!(pins.len(), 1);
        let retained = pins[0].join(original.file_name().unwrap());
        assert_eq!(fs::read(&retained).unwrap(), bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                fs::metadata(&original).unwrap().ino(),
                fs::metadata(&retained).unwrap().ino()
            );
            assert_eq!(fs::metadata(&original).unwrap().nlink(), 2);
        }
        assert!(reader.read(end).is_err());
        drop(reader);
        assert_eq!(used(), 0);
        assert!(pin_paths(dir.path()).is_empty());
    });
    let archives = tempfile::tempdir().unwrap();
    let blocked = archives.path().join("not-a-directory");
    fs::write(&blocked, b"blocked").unwrap();
    let frozen = wal.freeze_archive_cut(end).unwrap().unwrap();
    assert!(frozen.publish(&blocked).is_err());
    wal.drop_prefix(end).unwrap();
    let archive = frozen.publish(archives.path()).unwrap();
    assert_eq!(Wal::load(&archive.path).unwrap().len(), 1);
    drop(frozen);
    assert!(pin_paths(dir.path()).is_empty());
}

#[test]
fn pin_admission_refuses_before_creating_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    crate::relational::wal_decode::with_test_storage_pool(1, |used| {
        assert!(matches!(
            DirectoryPin::new(dir.path()),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(used(), 0);
        assert!(pin_paths(dir.path()).is_empty());
    });
}

#[test]
fn cancelled_capture_creates_no_file_pin() {
    let dir = tempfile::tempdir().unwrap();
    let mut wal = Wal::open(dir.path()).unwrap();
    wal.append(&WalEntry::Delete { id: "one".into() }).unwrap();
    let end = wal.len().unwrap();
    let cancel = std::sync::Arc::new(AtomicBool::new(false));
    crate::relational::wal_decode::with_test_storage_pool(4 * 1024 * 1024, |used| {
        crate::relational::with_sql_cancellation(cancel.clone(), || {
            cancel.store(true, Ordering::Release);
            assert!(OrderedJournalReader::open(dir.path(), end).is_err());
            assert!(pin_paths(dir.path()).is_empty());
            assert_eq!(used(), 0);
            Ok(())
        })
        .unwrap();
    });
}

#[test]
#[cfg(feature = "fault-injection")]
fn cancellation_during_capture_releases_partial_links_and_keeps_source() {
    let dir = tempfile::tempdir().unwrap();
    let mut wal = Wal::open(dir.path()).unwrap();
    wal.append(&WalEntry::Delete { id: "one".into() }).unwrap();
    let end = wal.len().unwrap();
    let bytes = fs::read(wal.path()).unwrap();
    let marker = dir.path().join("marker");
    let release = dir.path().join("release");
    let fault = crate::failpoint::test_env("pause:wal_pin.after_link", &marker, &release);
    let cancel = std::sync::Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();
    let worker_dir = dir.path().to_path_buf();
    let worker = std::thread::spawn(move || {
        crate::relational::wal_decode::with_test_storage_pool(4 * 1024 * 1024, |used| {
            let result = crate::relational::with_sql_cancellation(worker_cancel, || {
                OrderedJournalReader::open(&worker_dir, end)
            });
            assert!(result.is_err());
            assert!(pin_paths(&worker_dir).is_empty());
            assert_eq!(used(), 0);
        });
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !marker.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let reached = marker.exists();
    let partial = !pin_paths(dir.path()).is_empty();
    cancel.store(true, Ordering::Release);
    fs::write(&release, b"continue").unwrap();
    worker.join().unwrap();
    drop(fault);
    assert!(
        reached && partial,
        "capture did not retain the first linked file"
    );
    assert_eq!(fs::read(wal.path()).unwrap(), bytes);
    assert_eq!(wal.len().unwrap(), end);
}

#[test]
#[cfg(unix)]
fn backup_copy_refuses_pin_named_symlinks() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("untouched"), b"outside source").unwrap();
    let wal = root.path().join("wal");
    fs::create_dir(&wal).unwrap();
    std::os::unix::fs::symlink(outside.path(), wal.join(".chiron-wal-pins-link")).unwrap();
    assert!(crate::fs_util::copy_dir_contents(root.path(), destination.path()).is_err());
    assert_eq!(
        fs::read(outside.path().join("untouched")).unwrap(),
        b"outside source"
    );
}

#[test]
#[cfg(feature = "fault-injection")]
fn failed_link_releases_partial_pins_without_changing_source() {
    let dir = tempfile::tempdir().unwrap();
    let mut wal = Wal::open(dir.path()).unwrap();
    wal.append(&WalEntry::Delete { id: "one".into() }).unwrap();
    let end = wal.len().unwrap();
    let bytes = fs::read(wal.path()).unwrap();
    for point in ["wal_pin.before_link", "wal_pin.after_link"] {
        let fault = crate::failpoint::test_env(
            &format!("error:{point}"),
            &dir.path().join("marker"),
            &dir.path().join("release"),
        );
        crate::relational::wal_decode::with_test_storage_pool(4 * 1024 * 1024, |used| {
            assert!(OrderedJournalReader::open(dir.path(), end).is_err());
            assert_eq!(used(), 0);
            assert!(pin_paths(dir.path()).is_empty());
        });
        drop(fault);
        assert_eq!(fs::read(wal.path()).unwrap(), bytes);
        assert_eq!(wal.len().unwrap(), end);
        let mut reader = OrderedJournalReader::open(dir.path(), end).unwrap();
        assert!(reader.read(0).is_ok());
        drop(reader);
        assert!(pin_paths(dir.path()).is_empty());
    }
}

#[test]
fn backup_copy_excludes_live_pins_and_wal_open_preserves_them() {
    let root = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let dir = root.path().join("collections/docs/wal");
    let mut wal = Wal::open(&dir).unwrap();
    wal.append(&WalEntry::Delete { id: "one".into() }).unwrap();
    let mut reader = OrderedJournalReader::open(&dir, wal.len().unwrap()).unwrap();
    assert_eq!(pin_paths(&dir).len(), 1);
    drop(Wal::open(&dir).unwrap());
    assert_eq!(
        pin_paths(&dir).len(),
        1,
        "live open cannot clean another reader's pins"
    );
    crate::fs_util::copy_dir_contents(root.path(), destination.path()).unwrap();
    let copied = destination.path().join("collections/docs/wal");
    assert!(pin_paths(&copied).is_empty());
    assert_eq!(Wal::load(&copied).unwrap().len(), 1);
    assert!(reader.read(0).is_ok());
    drop(reader);
    assert!(pin_paths(&dir).is_empty());
    assert!(!Wal::is_snapshot_scratch(
        &root.path().join("collections/.chiron-wal-pins-customer")
    ));
}

#[test]
fn encrypted_pins_retain_ciphertext_and_replay_after_retirement() {
    const CHILD: &str = "CHIRONDB_ENCRYPTED_PIN_CHILD";
    let Some(root) = std::env::var_os(CHILD) else {
        let temp = tempfile::tempdir().unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "wal::pinned::tests::encrypted_pins_retain_ciphertext_and_replay_after_retirement",
                "--nocapture",
            ])
            .env(CHILD, temp.path())
            .env("RUST_TEST_THREADS", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    };
    use base64::Engine;
    let root = PathBuf::from(root);
    let keyring = root.join("keyring.json");
    fs::write(&keyring, serde_json::json!({"version":1,"active_key_id":"pin-test","keys":[{"id":"pin-test","key_base64":base64::engine::general_purpose::STANDARD.encode([47_u8;32])}]}).to_string()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
    }
    encryption::install_process_keyring(encryption::Keyring::load(&keyring).unwrap(), true)
        .unwrap();
    let dir = root.join("wal");
    let mut wal = Wal::open(&dir).unwrap();
    wal.append(&WalEntry::Delete {
        id: "private-payload".into(),
    })
    .unwrap();
    let bytes = fs::read(wal.path()).unwrap();
    let end = wal.len().unwrap();
    let mut reader = OrderedJournalReader::open(&dir, end).unwrap();
    let frozen = wal.freeze_archive_cut(end).unwrap().unwrap();
    for pins in pin_paths(&dir) {
        let path = pins.join(segment_name(0));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(
            !bytes
                .windows(b"private-payload".len())
                .any(|part| part == b"private-payload")
        );
    }
    wal.drop_prefix(end).unwrap();
    assert!(
        matches!(&reader.read(0).unwrap().entry, WalEntry::Delete { id } if id == "private-payload")
    );
    let archive = frozen.publish(&root.join("archive")).unwrap();
    assert_eq!(Wal::load(&archive.path).unwrap().len(), 1);
    drop(reader);
    assert_eq!(pin_paths(&dir).len(), 1);
    drop(frozen);
    assert!(pin_paths(&dir).is_empty());
}

#[test]
#[cfg(unix)]
fn exclusive_startup_reclaims_sigkill_pins_without_losing_acknowledged_data() {
    const CHILD: &str = "CHIRONDB_PIN_KILL_ROOT";
    if let Some(data) = std::env::var_os(CHILD) {
        let data = PathBuf::from(data);
        let dirs = [
            data.join(crate::transaction_journal::TRANSACTION_JOURNAL_DIR),
            data.join("catalog_wal"),
            data.join("relational/wal"),
            data.join("collections/docs/wal"),
        ];
        let readers: Vec<_> = dirs
            .iter()
            .map(|dir| {
                let wal = Wal::open(dir).unwrap();
                OrderedJournalReader::open(dir, wal.len().unwrap()).unwrap()
            })
            .collect();
        fs::write(data.parent().unwrap().join("pin-ready"), b"ready").unwrap();
        std::hint::black_box(&readers);
        loop {
            std::thread::park_timeout(Duration::from_millis(20));
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    let db = crate::Db::open(&data).unwrap();
    db.create_collection(
        serde_json::from_value(serde_json::json!({"name":"docs","vector_dim":2})).unwrap(),
    )
    .unwrap();
    db.upsert(
        "docs",
        vec![serde_json::from_value(serde_json::json!({"id":"ack","vector":[1.0,0.0]})).unwrap()],
    )
    .unwrap();
    drop(db);
    let dirs = [
        data.join(crate::transaction_journal::TRANSACTION_JOURNAL_DIR),
        data.join("catalog_wal"),
        data.join("relational/wal"),
        data.join("collections/docs/wal"),
    ];
    let journal = serde_json::to_value(Wal::load(&dirs[0]).unwrap()).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "wal::pinned::tests::exclusive_startup_reclaims_sigkill_pins_without_losing_acknowledged_data", "--nocapture"])
        .env(CHILD, &data).env("RUST_TEST_THREADS", "1").spawn().unwrap();
    let marker = temp.path().join("pin-ready");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !marker.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let ready = marker.exists();
    child.kill().unwrap();
    let status = child.wait().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert!(ready, "child did not capture the file pins");
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert!(dirs.iter().all(|dir| pin_paths(dir).len() == 1));
    let reopened = crate::Db::open(&data).unwrap();
    assert_eq!(
        reopened.get_points("docs", &["ack".into()]).unwrap().len(),
        1
    );
    assert!(dirs.iter().all(|dir| pin_paths(dir).is_empty()));
    assert_eq!(
        serde_json::to_value(Wal::load(&dirs[0]).unwrap()).unwrap(),
        journal
    );
    drop(reopened);
}
