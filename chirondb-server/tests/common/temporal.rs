// Shared transport oracle. Timestamp strings differ by exactly one nanosecond.
pub fn statements(collection: &str) -> [String; 3] {
    [
        format!(
            "APPEND INTO {collection} [{{asset:'truk-7',property:'suhu',time_ns:'1700000000000000000',value:24.5}},{{asset:'truk-7',property:'suhu',time_ns:'1700000000000000001',value:25.0}}];"
        ),
        format!(
            "HISTORY {collection} ASSET 'truk-7' PROPERTY 'suhu' FROM '1700000000000000000' TO '1700000000000000002' LIMIT 100;"
        ),
        format!("LATEST {collection} ASSET 'truk-7' PROPERTY 'suhu';"),
    ]
}
pub fn rows(collection: &str, idx: usize) -> Vec<serde_json::Value> {
    let point = |t: &str, v: f64| serde_json::json!({"asset_ref":{"namespace":collection,"id":"truk-7"},"property":"suhu","time_ns":t,"value":v});
    let first = point("1700000000000000000", 24.5);
    let last = point("1700000000000000001", 25.);
    match idx {
        0 => vec![],
        1 => vec![first, last],
        2 => vec![last],
        _ => unreachable!(),
    }
}
