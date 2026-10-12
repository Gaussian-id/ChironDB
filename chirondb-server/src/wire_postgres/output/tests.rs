use super::*;
use serde_json::json;
use tokio::io::AsyncReadExt;

fn specs(types: &[PgType]) -> Vec<ColumnSpec> {
    types
        .iter()
        .enumerate()
        .map(|(i, t)| ColumnSpec {
            name: format!("c{i}"),
            pg_type: *t,
        })
        .collect()
}
fn oracle(cells: &[Option<Vec<u8>>]) -> Vec<u8> {
    let mut body = (cells.len() as u16).to_be_bytes().to_vec();
    for cell in cells {
        match cell {
            Some(value) => {
                body.extend_from_slice(&(value.len() as i32).to_be_bytes());
                body.extend_from_slice(value);
            }
            None => body.extend_from_slice(&(-1_i32).to_be_bytes()),
        }
    }
    let mut out = vec![b'D'];
    out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    out.extend(body);
    out
}
#[test]
fn sql_text_binary_rows_match_independent_wire_bytes() {
    let rows = vec![
        V::Boolean(true),
        V::Integer(i64::MAX),
        V::Float(-0.0),
        V::Decimal("-12.3400".into()),
        V::Text("日本語\n".into()),
        V::Bytes(vec![0, 15, 255]),
        V::Date("2000-01-02".into()),
        V::TimestampUtc("2000-01-01T00:00:00Z".into()),
        V::Uuid(uuid::Uuid::nil()),
        V::Json(json!({"integer":i64::MAX,"escape":"日本語\n"})),
        V::Vector(vec![0.1, -0.0]),
        V::RecordRef(chirondb_types::RecordRef {
            namespace: "docs".into(),
            id: "chunk-1".into(),
        }),
        V::Null,
    ];
    let columns = specs(&[
        PgType::Bool,
        PgType::Int8,
        PgType::Float8,
        PgType::Numeric,
        PgType::Text,
        PgType::Bytea,
        PgType::Date,
        PgType::TimestampTz,
        PgType::Uuid,
        PgType::Jsonb,
        PgType::Text,
        PgType::Jsonb,
        PgType::Text,
    ]);
    let texts = [
        "t",
        "9223372036854775807",
        "-0",
        "-12.3400",
        "日本語\n",
        "\\x000fff",
        "2000-01-02",
        "2000-01-01T00:00:00Z",
        "00000000-0000-0000-0000-000000000000",
        r#"{"escape":"日本語\n","integer":9223372036854775807}"#,
        "[0.1,-0.0]",
        r#"{"namespace":"docs","id":"chunk-1"}"#,
    ];
    let mut expected = texts
        .iter()
        .map(|s| Some(s.as_bytes().to_vec()))
        .collect::<Vec<_>>();
    expected.push(None);
    assert_eq!(
        sql_row(&rows, &columns, &[0; 13]).unwrap().as_ref(),
        oracle(&expected)
    );
    let mut binaries = vec![
        Some(vec![1]),
        Some(i64::MAX.to_be_bytes().to_vec()),
        Some((-0.0_f64).to_bits().to_be_bytes().to_vec()),
        Some(vec![0, 2, 0, 0, 0x40, 0, 0, 4, 0, 12, 0x0d, 0x48]),
        Some("日本語\n".as_bytes().to_vec()),
        Some(vec![0, 15, 255]),
        Some(1_i32.to_be_bytes().to_vec()),
        Some(0_i64.to_be_bytes().to_vec()),
        Some(vec![0; 16]),
    ];
    binaries.push(Some([vec![1], texts[9].as_bytes().to_vec()].concat()));
    binaries.push(Some(texts[10].as_bytes().to_vec()));
    binaries.push(Some([vec![1], texts[11].as_bytes().to_vec()].concat()));
    binaries.push(None);
    assert_eq!(
        sql_row(&rows, &columns, &[1; 13]).unwrap().as_ref(),
        oracle(&binaries)
    );
    let formats = [0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0];
    let mixed = expected
        .into_iter()
        .zip(binaries)
        .zip(formats)
        .map(|((text, binary), format)| if format == 0 { text } else { binary })
        .collect::<Vec<_>>();
    assert_eq!(
        sql_row(&rows, &columns, &formats).unwrap().as_ref(),
        oracle(&mixed)
    );
}
#[test]
fn row_description_and_explain_keep_protocol_metadata_without_row_copy() {
    let names = vec!["日本語列".into(), "integer".into()];
    let columns = Columns::sql(&names, &[RelationalType::Text, RelationalType::BigInt]).unwrap();
    let formats = Formats::new(&[1, 0], 2).unwrap();
    let frame = description(&columns, &formats).unwrap();
    let mut payload = vec![0, 2];
    for (name, oid, len, format) in [("日本語列", 25_u32, -1_i16, 1_i16), ("integer", 20, 8, 0)]
    {
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&[0; 6]);
        payload.extend_from_slice(&oid.to_be_bytes());
        payload.extend_from_slice(&len.to_be_bytes());
        payload.extend_from_slice(&(-1_i32).to_be_bytes());
        payload.extend_from_slice(&format.to_be_bytes());
    }
    let mut expected = vec![b'T'];
    expected.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    expected.extend(payload);
    assert_eq!(frame.as_ref(), expected);
    assert_eq!(
        explain_row("plan 日本語", 1).unwrap().as_ref(),
        oracle(&[Some("plan 日本語".as_bytes().to_vec())])
    );
    assert!(Formats::new(&[2], 1).is_err());
    assert!(Columns::sql(&names, &[RelationalType::Text]).is_err());
    assert!(description(&specs(&[PgType::Text]), &[]).is_err());
}
#[test]
fn json_validation_matches_value_acceptance_without_duplicate_value() {
    let cases = [
        r#"{"a":[null,true,"\u0000",1,-0.0,18446744073709551615],"b":"日本語"}"#,
        "1e400",
        "[NaN]",
        "{\"a\":1} trailing",
        "\"\\ud800\"",
        "{\"a\":}",
        "[1,2]",
        "-0.0",
        r#"{"\ud800":1}"#,
        r#"{"\u0000":1}"#,
        r#"{"\ud800":1}"#,
        r#"{"\u0000":1}"#,
        "1.2345678901234567",
        "18446744073709551616",
    ];
    for value in cases {
        assert_eq!(
            validate_json(value).is_ok(),
            serde_json::from_str::<serde_json::Value>(value).is_ok(),
            "{value}"
        );
    }
    let deep = "[".repeat(129) + "0" + &"]".repeat(129);
    assert!(validate_json(&deep).is_err());
    let columns = specs(&[PgType::Jsonb]);
    let row = vec![Some("{\"a\":1e400}".into())];
    assert!(text_row(&row, &columns, &[1]).is_err());
}
#[test]
fn pg_message_and_shape_limits_reject_before_frame_publication() {
    let value = "x".repeat(MAX_MESSAGE_LEN - 10);
    let row = vec![Some(value)];
    let owner = simple_row(&row).unwrap();
    assert_eq!(owner.as_ref().len(), MAX_MESSAGE_LEN + 1);
    drop(owner);
    let row = vec![Some("x".repeat(MAX_MESSAGE_LEN - 9))];
    assert!(simple_row(&row).is_err());
    assert!(sql_row(&[V::Integer(1)], &specs(&[PgType::Int8]), &[]).is_err());
    assert!(sql_row(&[V::Text("bad".into())], &specs(&[PgType::Int8]), &[1]).is_err());
    assert!(sql_row(&[V::Integer(i64::MAX)], &specs(&[PgType::Int2]), &[1]).is_err());
    assert!(
        description(
            &[ColumnSpec {
                name: "bad\0name".into(),
                pg_type: PgType::Text
            }],
            &[0]
        )
        .is_err()
    );
}
#[tokio::test]
async fn pg_receiving_quota_covers_pending_write_refusal_and_final_byte() {
    const CHILD: &str = "CHIRON_PG_OUTPUT_QUOTA_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","wire_postgres::output::tests::pg_receiving_quota_covers_pending_write_refusal_and_final_byte","--nocapture"]).env(CHILD,"1").status().unwrap().success());
        return;
    }
    let mut profile = crate::resource_profile::ResourceProfile::from_limits(1 << 30, 1);
    profile.sql_pool_bytes = 256 * 1024;
    crate::resource_profile::install(profile);
    let row = vec![Some("x".repeat(90 * 1024))];
    let owner = simple_row(&row).unwrap();
    assert!(ResponseReservation::new(64 * 1024).is_err());
    let long_name = vec!["n".repeat(64 * 1024)];
    assert!(Columns::sql(&long_name, &[RelationalType::Text]).is_err());
    let mut error_frame = tokio::io::BufWriter::new(Vec::new());
    let error = send(&mut error_frame, simple_row(&row))
        .await
        .err()
        .unwrap();
    assert!(error.get_ref().unwrap().downcast_ref::<Refusal>().is_some());
    assert_eq!(error_frame.get_ref()[0], b'E');
    assert!(error_frame.get_ref().windows(6).any(|v| v == b"53200\0"));
    let (mut writer, mut reader) = tokio::io::duplex(1);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(15),
            send(&mut writer, Ok(owner))
        )
        .await
        .is_err()
    );
    let mut byte = [0];
    reader.read_exact(&mut byte).await.unwrap();
    assert_eq!(byte, [b'D']);
    assert!(ResponseReservation::new(120 * 1024).is_ok());
    let bytes = axum::body::Bytes::from_owner(simple_row(&row).unwrap());
    let last = bytes.slice(..1);
    drop(bytes);
    assert!(ResponseReservation::new(64 * 1024).is_err());
    drop(last);
    assert!(ResponseReservation::new(120 * 1024).is_ok());
    let bad_json = vec![Some(" ".repeat(20 * 1024) + "null")];
    assert!(text_row(&bad_json, &specs(&[PgType::Jsonb]), &[1]).is_err());
    assert!(ResponseReservation::new(120 * 1024).is_ok());
}

#[tokio::test]
async fn connection_transaction_owner_rolls_back_on_abort_and_unwind() {
    use super::super::{ConnectionTransaction, PgRelationalTransaction};
    let directory = tempfile::tempdir().unwrap();
    let db = crate::Db::open(directory.path()).unwrap();
    let audit = chirondb_core::audit::AuditContext {
        principal_id: "client".into(),
        tenant_id: None,
        transport: "pgwire".into(),
        request_id: None,
    };
    let handle = db.begin_sql_transaction(&audit).unwrap().handle;
    let mut guard = ConnectionTransaction::new(&db, "client", None, "pgwire").unwrap();
    guard.value = Some(PgRelationalTransaction {
        handle: handle.clone(),
        failed: false,
    });
    let (ready, wait) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _guard = guard;
        ready.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    wait.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(db.rollback_sql_transaction(&handle, &audit).is_err());
    let handle = db.begin_sql_transaction(&audit).unwrap().handle;
    let mut guard = ConnectionTransaction::new(&db, "client", None, "pgwire").unwrap();
    guard.value = Some(PgRelationalTransaction {
        handle: handle.clone(),
        failed: false,
    });
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = guard;
            panic!("handler unwind");
        }))
        .is_err()
    );
    assert!(db.rollback_sql_transaction(&handle, &audit).is_err());
    for _ in 0..70 {
        let mut guard = ConnectionTransaction::new(&db, "client", None, "pgwire").unwrap();
        let handle = db.begin_sql_transaction(&audit).unwrap().handle;
        guard.value = Some(PgRelationalTransaction {
            handle,
            failed: false,
        });
        drop(guard);
    }
    let final_handle = db.begin_sql_transaction(&audit).unwrap().handle;
    db.rollback_sql_transaction(&final_handle, &audit).unwrap();
}

#[test]
fn catalog_binary_arrays_preserve_null_header_and_element_bytes() {
    let cases = [
        (
            PgType::TextArray,
            r#"{"hello",NULL,"日本語"}"#,
            25_u32,
            vec![
                Some(b"hello".to_vec()),
                None,
                Some("日本語".as_bytes().to_vec()),
            ],
        ),
        (
            PgType::BoolArray,
            "{t,f,NULL}",
            16,
            vec![Some(vec![1]), Some(vec![0]), None],
        ),
        (
            PgType::Int2Array,
            "{-32768,32767,NULL}",
            21,
            vec![
                Some((-32768_i16).to_be_bytes().to_vec()),
                Some(32767_i16.to_be_bytes().to_vec()),
                None,
            ],
        ),
    ];
    for (data_type, value, oid, elements) in cases {
        let mut binary = Vec::new();
        for field in [1_i32, 1, oid as i32, elements.len() as i32, 1] {
            binary.extend_from_slice(&field.to_be_bytes());
        }
        for element in elements {
            match element {
                Some(bytes) => {
                    binary.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                    binary.extend(bytes);
                }
                None => binary.extend_from_slice(&(-1_i32).to_be_bytes()),
            }
        }
        assert_eq!(
            text_row(&[Some(value.into())], &specs(&[data_type]), &[1])
                .unwrap()
                .as_ref(),
            oracle(&[Some(binary)])
        );
        let mut empty = vec![0; 8];
        empty.extend_from_slice(&oid.to_be_bytes());
        assert_eq!(
            text_row(&[Some("{}".into())], &specs(&[data_type]), &[1])
                .unwrap()
                .as_ref(),
            oracle(&[Some(empty)])
        );
    }
}
