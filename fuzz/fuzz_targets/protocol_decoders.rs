#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    // Covers protobuf/gRPC compatibility messages and ChironWire envelopes.
    let _ = chirondb::grpc::pb::WireRequest::decode(data);
    let _ = chirondb::grpc::pb::SearchRequest::decode(data);
    if let Ok(text) = std::str::from_utf8(data) {
        // PostgreSQL startup/message SQL eventually reaches this parser.
        let _ = chirondb::pgvector_parser::parse(text);
    }
});
