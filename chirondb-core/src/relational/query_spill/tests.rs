use super::*;
use std::{cell::Cell, io::Cursor, rc::Rc};

fn encoded(values: &[RelationalValue]) -> Vec<u8> {
    serde_json::to_vec(&SpillRecordRef {
        position: 17,
        values,
    })
    .unwrap()
}

#[test]
fn bounded_spill_decode_roundtrips_every_value_and_expanded_json() {
    let values = vec![
        RelationalValue::Null,
        RelationalValue::Boolean(true),
        RelationalValue::Integer(i64::MIN),
        RelationalValue::Float(-12.5),
        RelationalValue::Decimal("123.450".into()),
        RelationalValue::Text("雪\n\"escaped\\text".into()),
        RelationalValue::Bytes(vec![0, 255, 17]),
        RelationalValue::Date("2026-10-03".into()),
        RelationalValue::TimestampUtc("2026-10-03T01:02:03Z".into()),
        RelationalValue::Uuid(uuid::Uuid::nil()),
        RelationalValue::Json(serde_json::json!({"雪": [null, true, -7, 1.5, {"q": "\n\\\""}]})),
        RelationalValue::Json(serde_json::Value::Null),
        RelationalValue::Vector(vec![0.0, 1.5, -10.25]),
        RelationalValue::RecordRef(chirondb_types::RecordRef {
            namespace: "文書".into(),
            id: "id\n1".into(),
        }),
    ];
    let payload = encoded(&values);
    let row = decode::record(&payload, 1024 * 1024).unwrap();
    assert_eq!(row.position, 17);
    assert_eq!(row.values, values);
    assert!(row.charge < 1024 * 1024);
    let expanded = encoded(&[RelationalValue::Json(serde_json::json!(vec![0; 10_000]))]);
    assert!(expanded.len() < 32 * 1024);
    assert!(matches!(
        decode::record(&expanded, 32 * 1024),
        Err(GaussError::ResourceExhausted(_))
    ));
    let row = decode::record(&expanded, 1024 * 1024).unwrap();
    assert!(row.charge > expanded.len() * 8);
    assert_eq!(
        row.values,
        vec![RelationalValue::Json(serde_json::json!(vec![0; 10_000]))]
    );
    let reordered = br#"{"values":[{"value":[0,1,2],"type":"json"}],"position":17}"#;
    assert_eq!(
        decode::record(reordered, 4096).unwrap().values,
        vec![RelationalValue::Json(serde_json::json!([0, 1, 2]))]
    );
    let mut reversed = serde_json::from_slice::<serde_json::Value>(&expanded).unwrap();
    // serde_json's sorted object keys serialize type before value; construct
    // the reversed content explicitly to exercise borrowed envelope decoding.
    reversed["position"] = 17.into();
    let array = format!(
        r#"{{"values":[{{"value":{},"type":"json"}}],"position":17}}"#,
        reversed["values"][0]["value"]
    );
    assert!(matches!(
        decode::record(array.as_bytes(), 4096),
        Err(GaussError::ResourceExhausted(_))
    ));
}

#[test]
fn malformed_and_cancelled_spill_heads_never_become_current() {
    for payload in [
        br#"{"position":0,"values":[{"type":"text","value":7}]}"#.as_slice(),
        br#"{"position":0,"values":[{"type":"bytes","value":[256]}]}"#,
        br#"{"position":0,"values":[]} trailing"#,
        br#"{"position":0,"values":[{"type":"unknown"}]}"#,
    ] {
        assert!(decode::record(payload, 1024 * 1024).is_err());
    }
    let payload = encoded(&[RelationalValue::Integer(7)]);
    let cancellation = Arc::new(AtomicBool::new(false));
    let error = with_sql_cancellation(cancellation.clone(), || {
        cancellation.store(true, AtomicOrdering::Release);
        decode::record(&payload, 1024 * 1024)
    })
    .unwrap_err();
    assert!(error.to_string().contains("query canceled"), "{error}");
}

#[test]
fn spill_frame_admission_precedes_payload_read_and_old_head_releases_before_advance() {
    struct Counted {
        input: Cursor<Vec<u8>>,
        read: Rc<Cell<usize>>,
    }
    impl Read for Counted {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let n = self.input.read(out)?;
            self.read.set(self.read.get() + n);
            Ok(n)
        }
    }
    let payload = encoded(&[RelationalValue::Text("x".repeat(64 * 1024))]);
    let frame = || {
        let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&payload);
        frame
    };
    let read = Rc::new(Cell::new(0));
    let mut reader = RunReader {
        reader: Box::new(Counted {
            input: Cursor::new(frame()),
            read: read.clone(),
        }),
        remaining: 1,
        current: None,
    };
    assert!(matches!(
        reader.advance(0, 1024 * 1024),
        Err(GaussError::ResourceExhausted(_))
    ));
    assert_eq!(read.get(), 4, "refuse before reading or allocating payload");
    assert!(reader.current.is_none());
    let read = Rc::new(Cell::new(0));
    let mut reader = RunReader {
        reader: Box::new(Counted {
            input: Cursor::new(frame()),
            read: read.clone(),
        }),
        remaining: 1,
        current: None,
    };
    assert!(matches!(
        reader.advance(1024 * 1024, 128 * 1024),
        Err(GaussError::ResourceExhausted(_))
    ));
    assert_eq!(read.get(), 4, "scratch is admitted before payload");

    let mut both = frame();
    both.extend(frame());
    let mut reader = RunReader {
        reader: Box::new(Cursor::new(both)),
        remaining: 2,
        current: None,
    };
    reader.advance(100 * 1024, 1024 * 1024).unwrap();
    let first = reader.current.take().unwrap();
    assert!(first.charge < 100 * 1024);
    drop(first);
    reader.advance(100 * 1024, 1024 * 1024).unwrap();
    assert_eq!(
        reader.current.take().unwrap().values[0],
        RelationalValue::Text("x".repeat(64 * 1024))
    );
    reader.advance(100 * 1024, 1024 * 1024).unwrap();
    assert!(reader.current.is_none());
}

#[test]
fn aggregate_spill_admission_stops_before_opening_another_run_and_cleans_up() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().to_owned();
    let values = [
        RelationalValue::Json(serde_json::json!(vec![0; 10_000])),
        RelationalValue::Text("x".repeat(150 * 1024)),
    ];
    let payload = encoded(&values);
    let first = path.join("first.run");
    let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&payload);
    fs::write(&first, frame).unwrap();
    let spill = QuerySpill {
        directory: Some(directory),
        runs: vec![
            SpillRun {
                path: first,
                count: 1,
            },
            SpillRun {
                path: path.join("must-not-open"),
                count: 1,
            },
        ],
        disk_bytes: 0,
        disk_limit: 1_000_000,
        memory_limit: 768 * 1024,
    };
    let error = spill
        .for_each_window(Vec::new(), &[], 0, 1, |_| {
            panic!("must not publish a partial merge")
        })
        .unwrap_err();
    assert!(
        matches!(error, GaussError::ResourceExhausted(_)),
        "must refuse quota before opening the missing run: {error}"
    );
    assert!(!path.exists(), "quota refusal removes temporary files");
}
