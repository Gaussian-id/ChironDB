use super::*;

#[test]
fn ordered_file_pins_survive_prefix_retirement() {
    let dir = tempfile::tempdir().unwrap();
    let mut wal = Wal::open_with_segment_bytes(dir.path(), 800).unwrap();
    let mut offsets = Vec::new();
    for index in 0..31 {
        offsets.push(wal.len().unwrap());
        wal.append(&WalEntry::Delete {
            id: format!("row-{index:02}"),
        })
        .unwrap();
    }
    let end = wal.len().unwrap();
    let mut reader = OrderedJournalReader::open(dir.path(), end).unwrap();
    wal.drop_prefix(end).unwrap();
    assert_eq!(Wal::retained_base_lsn(dir.path()).unwrap(), end);
    for (index, lsn) in offsets.into_iter().enumerate() {
        let record = reader
            .read(lsn)
            .expect("captured files must outlive prefix retirement");
        assert!(
            matches!(&record.entry, WalEntry::Delete { id } if id == &format!("row-{index:02}"))
        );
    }
    assert!(reader.read(end).is_err());
}

#[test]
fn ordered_reads_cross_rotated_segments_once_and_exclude_later_appends() {
    let dir = tempfile::tempdir().unwrap();
    let mut wal = Wal::open_with_segment_bytes(dir.path(), 800).unwrap();
    let mut offsets = Vec::new();
    for index in 0..31 {
        let lsn = wal.len().unwrap();
        wal.append(&WalEntry::Delete {
            id: format!("row-{index:02}"),
        })
        .unwrap();
        offsets.push(lsn);
    }
    let end = wal.len().unwrap();
    let segment_count = wal_segments(dir.path()).unwrap().len();
    let mut reader = OrderedJournalReader::open(dir.path(), end).unwrap();
    for index in 31..60 {
        wal.append(&WalEntry::Delete {
            id: format!("row-{index:02}"),
        })
        .unwrap();
    }
    for (index, lsn) in offsets
        .iter()
        .enumerate()
        .filter(|(index, _)| index % 3 == 0)
    {
        let record = reader.read(*lsn).unwrap();
        assert_eq!(record.lsn, *lsn);
        assert!(
            matches!(&record.entry, WalEntry::Delete { id } if id == &format!("row-{index:02}"))
        );
    }
    assert_eq!(reader.opened_segments, segment_count);
    assert!(reader.read(0).is_err());
    assert!(reader.read(end).is_err());
}

#[test]
fn ordered_reader_admission_refuses_without_mutation_and_releases_on_error() {
    let dir = tempfile::tempdir().unwrap();
    let mut wal = Wal::open(dir.path()).unwrap();
    wal.append(&WalEntry::Delete { id: "one".into() }).unwrap();
    let end = wal.len().unwrap();
    let bytes = fs::read(wal.path()).unwrap();
    crate::relational::wal_decode::with_test_storage_pool(1, |used| {
        assert!(matches!(
            OrderedJournalReader::open(dir.path(), end),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(used(), 0);
    });
    assert_eq!(fs::read(wal.path()).unwrap(), bytes);
    crate::relational::wal_decode::with_test_storage_pool(2 * 1024 * 1024, |used| {
        let mut reader = OrderedJournalReader::open(dir.path(), end).unwrap();
        let record = reader.read(0).unwrap();
        drop(reader);
        assert!(used() > 0);
        drop(record);
        assert_eq!(used(), 0);
    });
}

#[test]
fn ordered_reader_refuses_crc_and_snapshot_cut_through_a_frame() {
    for damage in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut wal = Wal::open(dir.path()).unwrap();
        wal.append(&WalEntry::Delete { id: "one".into() }).unwrap();
        let end = wal.len().unwrap();
        if damage {
            let mut bytes = fs::read(wal.path()).unwrap();
            bytes[HEADER_LEN] ^= 1;
            fs::write(wal.path(), bytes).unwrap();
        }
        let mut reader =
            OrderedJournalReader::open(dir.path(), if damage { end } else { end - 1 }).unwrap();
        assert!(matches!(
            reader.read(0),
            Err(GaussError::WalCorruption { .. })
        ));
    }
}
