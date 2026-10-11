use super::*;
use crate::relational::memory::with_storage_pool;
use std::{cell::Cell, io::Cursor, rc::Rc};

fn fixture(values: &str) -> Vec<u8> {
    format!(
        r#"{{"version":2,"sequence":2,"next_catalog_id":2,"wal_watermark":0,
    "tables":[{{"definition":{{"table_id":1,"name":"items","columns":[
    {{"name":"ref","data_type":{{"namespace":"docs","kind":"record_ref"}},
    "nullable":true,"default":{{"value":{{"x":[null,7]}},"type":"json"}}}}]}},
    "rows":{{"1":[{{"begin":2,"end":null,"values":[{values}]}}]}},"next_row_id":2}}],
    "applied_transactions":[]}}"#
    )
    .into_bytes()
}

struct Counted {
    input: Cursor<Vec<u8>>,
    read: Rc<Cell<usize>>,
    cancel: Option<Arc<AtomicBool>>,
}
impl Read for Counted {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = self.input.read(out)?;
        self.read.set(self.read.get() + n);
        if let Some(cancel) = &self.cancel {
            cancel.store(true, AtomicOrdering::Release);
        }
        Ok(n)
    }
}

#[test]
fn checkpoint_guard_preserves_all_value_encodings_and_reversed_tags() {
    let values = [
        RelationalValue::Null,
        RelationalValue::Boolean(true),
        RelationalValue::Integer(-7),
        RelationalValue::Float(2.5),
        RelationalValue::Decimal("123.450".into()),
        RelationalValue::Text("雪\n\\\"".into()),
        RelationalValue::Bytes(vec![0, 255]),
        RelationalValue::Date("2026-10-03".into()),
        RelationalValue::TimestampUtc("2026-10-03T00:00:00Z".into()),
        RelationalValue::Uuid(uuid::Uuid::nil()),
        RelationalValue::Json(serde_json::json!({"a":[null,7,"雪"]})),
        RelationalValue::Vector(vec![0.25, -0.5]),
        RelationalValue::RecordRef(chirondb_types::RecordRef {
            namespace: "docs".into(),
            id: "7".into(),
        }),
    ];
    for reversed in [false, true] {
        let encoded = values
            .iter()
            .map(|value| {
                let object = serde_json::to_value(value).unwrap();
                if reversed && object.get("value").is_some() {
                    format!(
                        r#"{{"value":{},"type":{}}}"#,
                        object["value"], object["type"]
                    )
                } else {
                    serde_json::to_string(value).unwrap()
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        let payload = fixture(&encoded);
        let ordinary: RelationalCheckpoint = serde_json::from_slice(&payload).unwrap();
        with_storage_pool(16 * 1024 * 1024, |pool| {
            let guarded = read(payload.as_slice(), payload.len()).unwrap();
            assert_eq!(
                serde_json::to_value(&guarded).unwrap(),
                serde_json::to_value(&ordinary).unwrap()
            );
            assert!(guarded.owned_memory.bytes() > 0);
            assert!(
                !serde_json::to_string(&guarded)
                    .unwrap()
                    .contains("owned_memory")
            );
            drop(guarded);
            assert_eq!(pool.used(), 0);
        });
    }
}

#[test]
fn scratch_admission_precedes_io_and_typed_expansion_stops_mid_stream() {
    let values = serde_json::json!({"value":vec![0;200_000],"type":"json"});
    let payload = fixture(&values.to_string());
    let read_count = Rc::new(Cell::new(0));
    with_storage_pool(1, |pool| {
        assert!(matches!(
            read(
                Counted {
                    input: Cursor::new(payload.clone()),
                    read: read_count.clone(),
                    cancel: None
                },
                payload.len()
            ),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(read_count.get(), 0);
        assert_eq!(pool.used(), 0);
    });
    let scratch = (payload.len() * 3 + 2 * BUFFER_BYTES + 4096) as u64;
    with_storage_pool(scratch + 64 * 1024, |pool| {
        assert!(matches!(
            read(
                Counted {
                    input: Cursor::new(payload.clone()),
                    read: read_count.clone(),
                    cancel: None
                },
                payload.len()
            ),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert!(read_count.get() > 0);
        assert!(
            read_count.get() < payload.len(),
            "refuse before reading or building the complete JSON array"
        );
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn decoded_checkpoint_keeps_its_admission_after_the_reader_returns() {
    let payload = fixture(r#"{"type":"text","value":"retained"}"#);
    let (pool, checkpoint) = with_storage_pool(1024 * 1024, |pool| {
        let checkpoint = read(payload.as_slice(), payload.len()).unwrap();
        assert!(pool.used() >= checkpoint.owned_memory.bytes());
        (pool, checkpoint)
    });
    assert!(pool.used() > 0);
    drop(checkpoint);
    assert_eq!(pool.used(), 0);
}

#[test]
fn nested_payload_admission_failure_remains_a_resource_error() {
    let value = serde_json::json!({"type":"json","value":vec![0;10_000]});
    let payload = fixture(&value.to_string());
    let (decoded, owned_payload) = with_storage_pool(16 * 1024 * 1024, |pool| {
        let checkpoint = read(payload.as_slice(), payload.len()).unwrap();
        let decoded = checkpoint.owned_memory.bytes();
        let owned_payload = pool.used() - decoded;
        assert!(owned_payload > 64 * 1024);
        drop(checkpoint);
        assert_eq!(pool.used(), 0);
        (decoded, owned_payload)
    });
    let scratch = (payload.len() * 3 + 2 * BUFFER_BYTES + 4096) as u64;
    // The generic decode budget fits. Its nested RowValues owner cannot acquire
    // a complete independent payload lease; serde must not disguise that as
    // malformed JSON or leave a failure marker on the next decode.
    with_storage_pool(scratch + decoded + owned_payload / 2, |pool| {
        assert!(matches!(
            read(payload.as_slice(), payload.len()),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
        let small = fixture(r#"{"type":"integer","value":7}"#);
        drop(read(small.as_slice(), small.len()).unwrap());
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn cancelled_and_invalid_decodes_release_partial_owners() {
    let payload = fixture(r#"{"type":"text","value":"value"}"#);
    with_storage_pool(1024 * 1024, |pool| {
        let cancel = Arc::new(AtomicBool::new(false));
        let read_count = Rc::new(Cell::new(0));
        let error = with_sql_cancellation(cancel.clone(), || {
            read(
                Counted {
                    input: Cursor::new(payload.clone()),
                    read: read_count.clone(),
                    cancel: Some(cancel),
                },
                payload.len(),
            )
        })
        .unwrap_err();
        assert!(read_count.get() > 0);
        assert!(error.to_string().contains("query canceled"), "{error}");
        assert_eq!(pool.used(), 0);
        for invalid in [
            String::from_utf8(payload.clone()).unwrap() + " trailing",
            String::from_utf8(payload.clone())
                .unwrap()
                .replace("\"sequence\":2", "\"sequence\":2,\"sequence\":3"),
            String::from_utf8(payload.clone())
                .unwrap()
                .replace("\"version\":2", "\"unknown\":2"),
            String::from_utf8(payload.clone())
                .unwrap()
                .replace("\"type\":\"text\"", "\"type\":\"unknown\""),
        ] {
            let ordinary =
                serde_json::from_reader::<_, RelationalCheckpoint>(invalid.as_bytes()).unwrap_err();
            let guarded = read(invalid.as_bytes(), invalid.len()).unwrap_err();
            assert!(
                guarded.to_string().contains(&ordinary.to_string()),
                "{guarded} != {ordinary}"
            );
            assert_eq!(pool.used(), 0);
        }
    });
}

#[test]
fn reopen_refusal_preserves_the_checkpoint_and_retry_recovers_rows() {
    fn request(sql: &str) -> SqlExecutionRequest {
        SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql: sql.into(),
                parameters: vec![],
            }],
            idempotency_key: None,
            retry_id: None,
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let open = || {
        RelationalEngine::open(
            directory.path(),
            TransactionJournal::open(directory.path())?,
        )
    };
    let engine = open().unwrap();
    engine
        .execute(request(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT)",
        ))
        .unwrap();
    engine
        .execute(request("INSERT INTO items VALUES (1, 'acknowledged')"))
        .unwrap();
    engine.checkpoint().unwrap();
    let before = fs::read(&engine.checkpoint_path).unwrap();
    let expected = engine
        .execute(request("SELECT * FROM items WHERE id = 1"))
        .unwrap()
        .response
        .results;
    drop(engine);
    with_storage_pool(1, |pool| {
        assert!(matches!(open(), Err(GaussError::ResourceExhausted(_))));
        assert_eq!(
            fs::read(directory.path().join(RELATIONAL_CHECKPOINT_FILE)).unwrap(),
            before
        );
        assert_eq!(pool.used(), 0);
    });
    let engine = open().unwrap();
    assert_eq!(
        engine
            .execute(request("SELECT * FROM items WHERE id = 1"))
            .unwrap()
            .response
            .results,
        expected
    );
}

#[test]
fn ignored_fields_do_not_reserve_retained_map_nodes() {
    #[derive(serde::Deserialize)]
    struct Tiny {
        value: u64,
    }
    let input = serde_json::to_vec(&serde_json::json!({
        "value": 7,
        "ignored": (0..1000).map(|i| serde_json::json!({"i":i,"nested":{"skip":[1,2,3]}})).collect::<Vec<_>>()
    })).unwrap();
    memory::with_storage_pool(input.len() as u64 * 3 + 8192, |pool| {
        let value = crate::relational::wal_decode::decode::<Tiny>(&input).unwrap();
        assert_eq!(value.value, 7);
        assert!(
            pool.used() < 4096,
            "discarded values own no retained map nodes"
        );
        drop(value);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn slice_scratch_tracks_tokens_and_ignored_depth_instead_of_array_length() {
    #[derive(Deserialize)]
    struct Tiny {
        value: u64,
    }
    let input = format!(
        "{{\"value\":7,\"ignored\":[{}]}}",
        vec!["0"; 100_000].join(",")
    );
    assert!(scratch::slice_bound(input.as_bytes()).unwrap() < 8192);
    memory::with_storage_pool(8192, |pool| {
        let value = crate::relational::wal_decode::decode::<Tiny>(input.as_bytes()).unwrap();
        assert_eq!(value.value, 7);
        drop(value);
        assert_eq!(pool.used(), 0);
    });
    let deep = format!(
        "{{\"value\":7,\"ignored\":{}0{}}}",
        "[".repeat(10_000),
        "]".repeat(10_000)
    );
    let bound = scratch::slice_bound(deep.as_bytes()).unwrap();
    assert!(bound >= 3 * 10_001 + 4096);
    memory::with_storage_pool(bound + 4096, |pool| {
        let value = crate::relational::wal_decode::decode::<Tiny>(deep.as_bytes()).unwrap();
        assert_eq!(value.value, 7);
        drop(value);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn slice_scratch_covers_escaped_and_unterminated_tokens() {
    let input = format!("\"{}\"", "\\u96ea\\n\\\\\\\"".repeat(10_000));
    let bound = scratch::slice_bound(input.as_bytes()).unwrap();
    assert!(bound >= input.len() as u64 * 3 + 4096);
    memory::with_storage_pool(bound + input.len() as u64 * 2 + 8192, |pool| {
        let value = crate::relational::wal_decode::decode::<String>(input.as_bytes()).unwrap();
        assert_eq!(**value, serde_json::from_str::<String>(&input).unwrap());
        drop(value);
        assert_eq!(pool.used(), 0);
    });
    for input in [
        "\"".to_owned() + &"\\u96ea".repeat(1000),
        "9".repeat(10_000),
    ] {
        assert!(scratch::slice_bound(input.as_bytes()).unwrap() >= input.len() as u64 * 3 + 4096);
        memory::with_storage_pool(input.len() as u64 * 6 + 8192, |pool| {
            assert!(
                crate::relational::wal_decode::decode::<serde_json::Value>(input.as_bytes())
                    .is_err()
            );
            assert_eq!(pool.used(), 0);
        });
    }
}

#[test]
fn sequence_capacity_and_map_nodes_cover_supported_container_layouts() {
    for count in [0, 1, 4, 8, 9, 64, 65, 1024, 1025] {
        let floats = vec![0.25_f32; count];
        let input = serde_json::to_vec(&floats).unwrap();
        memory::with_storage_pool(1024 * 1024, |pool| {
            let (decoded, charge) = slice_owned::<Vec<f32>>(&input).unwrap();
            assert_eq!(decoded, floats);
            assert!(charge.bytes() >= (decoded.capacity() * size_of::<f32>() * 3) as u64);
            drop(decoded);
            drop(charge);
            assert_eq!(pool.used(), 0);
        });
        let map = (0..count)
            .map(|i| (i.to_string(), i as u64))
            .collect::<BTreeMap<_, _>>();
        let input = serde_json::to_vec(&map).unwrap();
        memory::with_storage_pool(4 * 1024 * 1024, |pool| {
            let (decoded, charge) = slice_owned::<BTreeMap<String, u64>>(&input).unwrap();
            assert_eq!(decoded, map);
            // One root plus at most one node per entry is a deliberately loose
            // independent upper bound for these 11-pair std BTreeMap nodes.
            let nodes = if count == 0 { 0 } else { count.div_ceil(5) + 1 };
            let bytes = nodes * (11 * (size_of::<String>() + size_of::<u64>()) + 128);
            assert!(charge.bytes() >= bytes as u64);
            drop(decoded);
            drop(charge);
            assert_eq!(pool.used(), 0);
        });
    }
}

#[test]
fn transparent_boxed_wal_enum_retains_concrete_allocation_admission() {
    #[derive(Deserialize)]
    struct Envelope {
        entry: Box<crate::wal::WalEntry>,
    }
    let input = br#"{"entry":{"Delete":{"id":"retained"}}}"#;
    memory::with_storage_pool(64 * 1024, |pool| {
        let (value, charge) = slice_owned::<Envelope>(input).unwrap();
        assert!(
            matches!(*value.entry, crate::wal::WalEntry::Delete { ref id } if id == "retained")
        );
        assert!(charge.bytes() >= 2 * size_of::<crate::wal::WalEntry>() as u64);
        drop(value);
        drop(charge);
        assert_eq!(pool.used(), 0);
    });
}
