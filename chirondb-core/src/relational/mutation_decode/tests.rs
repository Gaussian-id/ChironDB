use super::*;
use crate::relational::{memory, wal_decode};
use serde_json::json;

#[test]
fn mutation_fields_keep_wire_format_and_accept_tag_in_any_position() {
    let definition = json!({"name":"result", "columns":[]});
    let rows = json!([{"row_id":7, "values":[
        {"type":"integer","value":-7}, {"value":2.5,"type":"float"},
        {"type":"text","value":"雪\n"}, {"type":"null"},
        {"type":"json","value":{"nested":[null,7,"x"]}},
        {"type":"vector","value":[0.1,-0.5]}]}]);
    for body in [
        json!({"kind":"row_security", "delta":{"table":"result", "incarnation":"00000000-0000-0000-0000-000000000001", "expected_revision":0, "policy":{"revision":1, "default_template":"default", "policy":{"department_actions":[], "owner_actions":[], "templates":{}}}, "records":[]}}),
        json!({"kind":"create_table", "definition":definition}),
        json!({"kind":"alter_table", "definition":definition}),
        json!({"kind":"drop_table", "name":"result"}),
        json!({"kind":"rename_table", "old_name":"old", "definition":definition}),
        json!({"kind":"rewrite_table", "definition":definition, "rows":rows}),
        json!({"kind":"insert", "table":"result", "rows":rows}),
        json!({"kind":"update", "table":"result", "rows":rows}),
        json!({"kind":"delete", "table":"result", "row_ids":[7]}),
    ] {
        let fields = body
            .as_object()
            .unwrap()
            .iter()
            .filter(|(k, _)| *k != "kind")
            .map(|(k, v)| format!("{k:?}:{v}"))
            .collect::<Vec<_>>();
        let mut expected = None;
        for position in 0..=fields.len() {
            let mut fields = fields.clone();
            fields.insert(position, format!("\"kind\":{}", body["kind"]));
            fields.push("\"future_ignored_field\":{\"nested\":[1,2]}".into());
            let input = format!("{{{}}}", fields.join(","));
            memory::with_storage_pool(1024 * 1024, |pool| {
                let decoded = wal_decode::decode::<RelationalMutation>(input.as_bytes()).unwrap();
                let encoded = serde_json::to_vec(&*decoded).unwrap();
                if let Some(expected) = &expected {
                    assert_eq!(&encoded, expected);
                } else {
                    expected = Some(encoded.clone());
                }
                assert!(
                    String::from_utf8(encoded)
                        .unwrap()
                        .starts_with("{\"kind\":")
                );
                drop(decoded);
                assert_eq!(pool.used(), 0);
            });
        }
        let borrowed: RelationalMutation = serde_json::from_value(body).unwrap();
        assert_eq!(serde_json::to_vec(&borrowed).unwrap(), expected.unwrap());
    }
}

#[test]
fn malformed_mutations_reject_and_release_decode_reservations() {
    for input in [
        r#"{"table":"x","rows":[]}"#,
        r#"{"kind":"insert","table":"x"}"#,
        r#"{"kind":"unknown","table":"x","rows":[]}"#,
        r#"{"kind":"insert","kind":"delete","table":"x","rows":[]}"#,
        r#"{"table":"x","kind":"insert","table":"y","rows":[]}"#,
        r#"{"rows":[],"rows":[],"kind":"insert","table":"x"}"#,
        r#"{"rows":[{"row_id":1,"row_id":2,"values":[]}],"kind":"insert","table":"x"}"#,
        r#"{"rows":[{"row_id":1,"values":[{"type":"integer","type":"float","value":7}]}],"kind":"insert","table":"x"}"#,
        r#"{"kind":"insert","table":"x","rows":[{"row_id":1,"values":[],"unknown":1}]}"#,
        r#"{"kind":"delete","table":"x","row_ids":[-1]}"#,
        r#"{"kind":"insert","table":"x","rows":[]} trailing"#,
    ] {
        memory::with_storage_pool(1024 * 1024, |pool| {
            assert!(
                wal_decode::decode::<RelationalMutation>(input.as_bytes()).is_err(),
                "{input}"
            );
            assert_eq!(pool.used(), 0);
        });
    }
}

#[test]
fn prefix_and_typed_rows_are_still_admitted_before_allocation() {
    for input in [
        json!({"rows":[{"row_id":1,"values":[{"type":"json","value":vec![0;10000]}]}],"kind":"insert","table":"x"}),
        json!({"kind":"insert","table":"x","rows":[{"row_id":1,"values":[{"type":"text","value":"x".repeat(10000)}]}]}),
    ] {
        // Force canonical and reversed field order instead of Value's key order.
        let rows = &input["rows"];
        for encoded in [
            format!(r#"{{"kind":"insert","table":"x","rows":{rows}}}"#),
            format!(r#"{{"rows":{rows},"kind":"insert","table":"x"}}"#),
        ] {
            memory::with_storage_pool(8192, |pool| {
                assert!(matches!(
                    wal_decode::decode::<RelationalMutation>(encoded.as_bytes()),
                    Err(crate::GaussError::ResourceExhausted(_))
                ));
                assert_eq!(pool.used(), 0);
            });
        }
    }
}
