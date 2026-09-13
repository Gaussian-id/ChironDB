#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = chirondb::chironql_parser::parse(text);
        let _ = chirondb::pgvector_parser::parse(text);
    }
    // HTTP request conversion starts with bounded JSON decoding.
    let _ = serde_json::from_slice::<chirondb_core::SearchRequest>(data);
    let _ = serde_json::from_slice::<chirondb_core::MultiSearchRequest>(data);
    let _ = serde_json::from_slice::<chirondb_core::Point>(data);
});
