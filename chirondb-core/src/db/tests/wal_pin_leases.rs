use super::*;

#[test]
fn native_snapshot_excludes_live_wal_pins_and_keeps_the_reader_valid() {
    let temp = TempDir::new().unwrap();
    let output = TempDir::new().unwrap();
    let db = Db::open(temp.path()).unwrap();
    db.create_collection(ls_vec_config("docs")).unwrap();
    db.upsert("docs", vec![ls_vec_point("ack", 1.0, "retained")])
        .unwrap();
    let wal_dir = temp.path().join("collections/docs/wal");
    let wal = Wal::open(&wal_dir).unwrap();
    let mut reader = crate::wal::OrderedJournalReader::open(&wal_dir, wal.len().unwrap()).unwrap();
    drop(wal);
    db.snapshot(output.path()).unwrap();
    let copied = output.path().join("collections/docs/wal");
    assert!(
        fs::read_dir(&copied)
            .unwrap()
            .all(|entry| !Wal::is_snapshot_scratch(&entry.unwrap().path()))
    );
    assert!(reader.read(0).is_ok());
    assert_eq!(db.get_points("docs", &["ack".into()]).unwrap().len(), 1);
}

#[test]
fn retained_journal_keeps_the_root_lease_until_its_last_drop() {
    let temp = TempDir::new().unwrap();
    let db = Db::open(temp.path()).unwrap();
    let journal = Arc::clone(&db.transaction_journal);
    drop(db);
    assert!(matches!(
        Db::open(temp.path()),
        Err(GaussError::DataDirLocked { .. })
    ));
    journal.for_each_committed(|_| Ok(())).unwrap();
    drop(journal);
    let reopened = Db::open(temp.path()).unwrap();
    drop(reopened);
}

#[test]
fn unsupported_format_refuses_before_cleaning_orphaned_wal_pins() {
    let temp = TempDir::new().unwrap();
    drop(Db::open(temp.path()).unwrap());
    let marker = temp
        .path()
        .join(crate::transaction_journal::TRANSACTION_FORMAT_MARKER);
    let original = fs::read(&marker).unwrap();
    let pin = temp
        .path()
        .join(crate::transaction_journal::TRANSACTION_JOURNAL_DIR)
        .join(".chiron-wal-pins-orphan");
    fs::create_dir(&pin).unwrap();
    fs::write(pin.join("held"), b"retain until format accepted").unwrap();
    fs::write(&marker, b"CHIRONTXN99\n").unwrap();
    assert!(Db::open(temp.path()).is_err());
    assert_eq!(
        fs::read(pin.join("held")).unwrap(),
        b"retain until format accepted"
    );
    assert_eq!(fs::read(&marker).unwrap(), b"CHIRONTXN99\n");
    fs::write(&marker, original).unwrap();
    let db = Db::open(temp.path()).unwrap();
    assert!(!pin.exists());
    drop(db);
}
