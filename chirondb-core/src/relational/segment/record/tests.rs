use super::*;
use crate::relational::{
    checkpoint::sort::Sorter,
    memory::{self, with_storage_pool},
    runs, segment_reference,
};
use tempfile::tempdir;

fn fixture(path: &Path, count: u8, bytes: usize) -> Vec<SegmentRecord> {
    let records = (1..=count)
        .map(|id| SegmentRecord {
            key: vec![id].into(),
            value: vec![id; bytes].into(),
        })
        .collect::<Vec<_>>();
    write_segment(path, SegmentKind::Row, 1, &records).unwrap();
    records
}

#[test]
fn returned_frame_bytes_outlive_reader_and_share_one_reservation_across_clones() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("rows.rseg");
    fixture(&path, 1, 8192);
    with_storage_pool(64 * 1024, |pool| {
        let reader = SegmentReader::open(&path).unwrap();
        let metadata = pool.used();
        let record = reader
            .read_record(reader.layout.body_start, 12 + 1 + 8192)
            .unwrap();
        let retained = pool.used();
        assert!(retained >= metadata + 8192 + 1 + 2 * OWNER_BYTES);
        let clone = record.clone();
        assert_eq!(pool.used(), retained);
        assert!(Arc::ptr_eq(&record.key.0, &clone.key.0));
        assert!(Arc::ptr_eq(&record.value.0, &clone.value.0));
        drop(reader);
        assert_eq!(pool.used(), retained - metadata);
        drop(record);
        assert_eq!(pool.used(), retained - metadata);
        let key = clone.key;
        let value = clone.value;
        drop(key);
        assert_eq!(
            pool.used(),
            value.capacity() as u64 + OWNER_BYTES + memory::LEASE_ROOT_BYTES
        );
        assert_eq!(value.as_slice(), vec![1; 8192]);
        drop(value);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn held_frame_refuses_the_next_payload_until_its_owner_releases() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("rows.rseg");
    fixture(&path, 2, 16 * 1024);
    let before = fs::read(&path).unwrap();
    with_storage_pool(32 * 1024, |pool| {
        let reader = SegmentReader::open(&path).unwrap();
        let mut cursor = reader.cursor();
        let first = cursor.next().unwrap().unwrap();
        let next_offset = cursor.next_offset();
        let held = pool.used();
        assert!(matches!(
            cursor.next().unwrap(),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert!(cursor.next().is_none(), "failed cursor is terminal");
        assert_eq!(
            pool.used(),
            held,
            "partial next-frame allocations are released"
        );
        assert_eq!(first.value.as_slice(), vec![1; 16 * 1024]);
        drop(first);
        let second = reader.read_record(next_offset, 12 + 1 + 16 * 1024).unwrap();
        assert_eq!(second.value.as_slice(), vec![2; 16 * 1024]);
        assert!(pool.used() <= 32 * 1024);
        drop(second);
        drop(cursor);
        drop(reader);
        assert_eq!(pool.used(), 0);
    });
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn json_value_growth_refuses_before_exhaustion_and_retains_successful_output() {
    let large = "x".repeat(8192);
    with_storage_pool(1024, |pool| {
        assert!(matches!(
            SegmentRecord::json(vec![1], &large),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
        let record = SegmentRecord::json(vec![2], &"ok").unwrap();
        let retained = pool.used();
        assert_eq!(
            retained,
            (record.key.capacity() + record.value.capacity()) as u64
                + 2 * (OWNER_BYTES + memory::LEASE_ROOT_BYTES)
        );
        assert_eq!(record.value.as_slice(), b"\"ok\"");
        let second = record.clone();
        assert_eq!(pool.used(), retained);
        drop(record);
        assert_eq!(pool.used(), retained);
        drop(second);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn prefix_bytes_are_admitted_and_payload_corruption_releases_temporary_owners() {
    use std::io::{Seek, SeekFrom, Write};
    let directory = tempdir().unwrap();
    let path = directory.path().join("rows.rseg");
    fixture(&path, 1, 4096);
    with_storage_pool(16 * 1024, |pool| {
        let reader = SegmentReader::open(&path).unwrap();
        let baseline = pool.used();
        assert!(matches!(
            reader.prefix_cursor(&vec![1; 16 * 1024]),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), baseline);
        let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&[7]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(matches!(
            reader.read_record(reader.layout.body_start, 12 + 1 + 4096),
            Err(GaussError::SegmentCorruption { .. })
        ));
        assert_eq!(pool.used(), baseline);
        drop(reader);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn cancellation_before_frame_copy_leaves_metadata_and_reservations_unchanged() {
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
    let directory = tempdir().unwrap();
    let path = directory.path().join("rows.rseg");
    fixture(&path, 1, 8192);
    with_storage_pool(64 * 1024, |pool| {
        let reader = SegmentReader::open(&path).unwrap();
        let baseline = pool.used();
        let flag = Arc::new(AtomicBool::new(false));
        let error = crate::relational::with_sql_cancellation(Arc::clone(&flag), || {
            flag.store(true, AtomicOrdering::Release);
            reader.read_record(reader.layout.body_start, 12 + 1 + 8192)
        })
        .unwrap_err();
        assert!(error.to_string().contains("query canceled"));
        assert_eq!(pool.used(), baseline);
        let record = reader
            .read_record(reader.layout.body_start, 12 + 1 + 8192)
            .unwrap();
        assert_eq!(record.value.len(), 8192);
        drop(record);
        drop(reader);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn merge_heads_and_sort_handoff_preserve_one_payload_lease() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("rows.rseg");
    let records = fixture(&path, 2, 8192);
    let metadata = write_segment(&path, SegmentKind::Row, 1, &records).unwrap();
    let reference = segment_reference("rows.rseg".into(), &metadata);
    drop(metadata);
    drop(records);
    with_storage_pool(128 * 1024, |pool| {
        let mut merge =
            runs::RunMerge::open(directory.path(), SegmentKind::Row, &[reference]).unwrap();
        let first = merge.next().unwrap().unwrap();
        drop(merge);
        let payload = pool.used();
        assert_eq!(
            payload,
            (first.key.capacity() + first.value.capacity()) as u64
                + 2 * (OWNER_BYTES + memory::LEASE_ROOT_BYTES)
        );
        let mut sorter = Sorter::locator(directory.path(), 1).unwrap();
        let slots = pool.used() - payload;
        sorter.push(first).unwrap();
        assert_eq!(
            pool.used(),
            payload + slots,
            "handoff does not charge payload twice"
        );
        let sorted = sorter.finish().unwrap();
        assert_eq!(pool.used(), 0);
        let reader = sorted.into_reader().unwrap();
        let frame = reader.cursor().next().unwrap().unwrap();
        drop(reader);
        assert_eq!(
            pool.used(),
            (frame.key.capacity() + frame.value.capacity()) as u64
                + 2 * (OWNER_BYTES + memory::LEASE_ROOT_BYTES)
        );
        assert_eq!(frame.value.as_slice(), vec![1; 8192]);
        drop(frame);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn encrypted_multi_chunk_frame_reserves_before_copy_and_survives_shared_clones() {
    const CHILD: &str = "CHIRONDB_RECORD_ADMISSION_ENCRYPTED_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "relational::segment::record::tests::encrypted_multi_chunk_frame_reserves_before_copy_and_survives_shared_clones", "--nocapture"])
            .env(CHILD,"1").output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    use base64::Engine as _;
    let mut key = tempfile::NamedTempFile::new().unwrap();
    serde_json::to_writer(&mut key,&serde_json::json!({"version":1,"active_key_id":"test","keys":[{"id":"test","key_base64":base64::engine::general_purpose::STANDARD.encode([19u8;32])}]})).unwrap();
    crate::encryption::install_process_keyring(
        crate::encryption::Keyring::load(key.path()).unwrap(),
        true,
    )
    .unwrap();
    let directory = tempdir().unwrap();
    let path = directory.path().join("rows.rseg");
    fixture(&path, 1, 150_000);
    let before = fs::read(&path).unwrap();
    assert!(before.starts_with(b"CHIRENC1"));
    with_storage_pool(64 * 1024, |pool| {
        assert!(matches!(
            SegmentReader::open(&path),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    let reader = SegmentReader::open(&path).unwrap();
    with_storage_pool(64 * 1024, |pool| {
        let baseline = pool.used();
        assert!(matches!(
            reader.read_record(reader.layout.body_start, 12 + 1 + 150_000),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), baseline);
        assert_eq!(pool.used(), 0);
    });
    drop(reader);
    with_storage_pool(256 * 1024, |pool| {
        let reader = SegmentReader::open(&path).unwrap();
        let record = reader
            .read_record(reader.layout.body_start, 12 + 1 + 150_000)
            .unwrap();
        drop(reader);
        let held = pool.used();
        let clones = vec![record.clone(); 16];
        drop(record);
        assert_eq!(pool.used(), held);
        assert!(
            clones
                .iter()
                .all(|record| record.value.as_slice() == vec![1; 150_000])
        );
        drop(clones);
        assert_eq!(pool.used(), 0);
    });
    assert_eq!(fs::read(path).unwrap(), before);
}
