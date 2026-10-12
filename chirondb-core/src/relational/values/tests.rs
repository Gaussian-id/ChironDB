use super::*;
use crate::relational::memory::with_storage_pool;

fn encoded(value: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "row_id": 7,
        "version": {"begin": 2, "end": null, "values": [{"type": "json", "value": value}]}
    }))
    .unwrap()
}

#[test]
fn disk_payload_admission_precedes_parse_and_decoded_expansion() {
    let malformed = vec![b'!'; 8192];
    with_storage_pool((malformed.len() * 6 + 4095) as u64, |pool| {
        assert!(matches!(
            persisted_row(&malformed),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    let bytes = encoded(serde_json::json!(vec![0; 10_000]));
    with_storage_pool(200 * 1024, |pool| {
        assert!(matches!(
            persisted_row(&bytes),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    with_storage_pool(2 * 1024 * 1024, |pool| {
        let row = persisted_row(&bytes).unwrap();
        assert_eq!(row.row_id, 7);
        assert_eq!(row.version.begin, 2);
        assert!(pool.used() > 300 * 1024);
        let held = pool.used();
        let clone = row.version.clone();
        assert_eq!(clone.values.as_ptr(), row.version.values.as_ptr());
        assert_eq!(
            pool.used(),
            held,
            "cloning shares the existing value allocation"
        );
        drop(row);
        assert_eq!(
            pool.used(),
            held,
            "reservation outlives the decoded envelope"
        );
        drop(clone);
        assert_eq!(pool.used(), 0);
    });
    with_storage_pool(2 * 1024 * 1024, |pool| {
        let cancellation = Arc::new(AtomicBool::new(false));
        let error = with_sql_cancellation(cancellation.clone(), || {
            cancellation.store(true, AtomicOrdering::Release);
            persisted_row(&bytes)
        })
        .unwrap_err();
        assert!(error.to_string().contains("query canceled"), "{error}");
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn overlay_read_owners_keep_payload_reservations_after_the_table_drops() {
    with_storage_pool(1024 * 1024, |pool| {
        let mut rows = RowStore::default();
        rows.insert(
            1,
            VersionChain::single(RowVersion {
                begin: 1,
                end: None,
                values: RowValues::adopt(vec![RelationalValue::Text("x".repeat(64 * 1024))])
                    .unwrap(),
            })
            .unwrap(),
        )
        .unwrap();
        let used = pool.used();
        let visible = rows.visible(1, 1).unwrap().unwrap();
        let second = rows.visible_rows(1).next().unwrap().unwrap().1;
        let payload = second.0._charge.bytes() + memory::LEASE_ROOT_BYTES;
        assert!(used > payload, "the table also retains version metadata");
        assert_eq!(visible.values.as_ptr(), second.as_ptr());
        assert_eq!(pool.used(), used);
        drop(rows);
        assert_eq!(pool.used(), payload);
        drop(visible);
        assert_eq!(pool.used(), payload);
        drop(second);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn canonical_validation_streams_the_unchanged_row_encoding() {
    let bytes = encoded(serde_json::json!({"text": "雪\n\\\"", "nested": [null, 7]}));
    let row = persisted_row(&bytes).unwrap();
    let canonical = serde_json::to_vec(&row).unwrap();
    assert_eq!(canonical, bytes);
    assert!(canonical_matches(&row, &canonical).unwrap());
    assert!(!canonical_matches(&row, &canonical[..canonical.len() - 1]).unwrap());
    let mut trailing = canonical.clone();
    trailing.push(b' ');
    assert!(!canonical_matches(&row, &trailing).unwrap());
    assert_eq!(
        serde_json::from_slice::<PersistedRowVersion>(&canonical)
            .unwrap()
            .version
            .values,
        row.version.values
    );
    let source = vec![RelationalValue::Text("long".repeat(4096))];
    with_storage_pool(1024, |pool| {
        assert!(matches!(
            RowValues::copy(&source),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
}
