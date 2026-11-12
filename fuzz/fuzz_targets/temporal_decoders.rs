#![no_main]

use std::io::Cursor;

use chirondb_temporal::{Point, Segment, Series, Value, encode_segment};
use libfuzzer_sys::fuzz_target;

fn exact(point: Point) -> (i64, u8, u64) {
    match point.value {
        Value::Float(value) => (point.time, 0, value.to_bits()),
        Value::Boolean(value) => (point.time, 1, u64::from(value)),
    }
}

fn inspect(bytes: &[u8]) {
    if let Ok(mut segment) = Segment::open(Cursor::new(bytes)) {
        for tenant in ["fuzz-a", "fuzz-b"] {
            let series = Series::new(tenant, "asset", "value");
            let _ = segment.scan_limit(&series, i64::MIN, i64::MAX, 32);
            let _ = segment.latest(&series);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    inspect(data);

    // Construct valid envelopes so mutations can reach block/index decoders,
    // rather than exercising only the magic/version rejection path.
    let mut input = Vec::new();
    for chunk in data.chunks_exact(17).take(128) {
        let series = Series::new(
            if chunk[0] & 1 == 0 {
                "fuzz-a"
            } else {
                "fuzz-b"
            },
            "asset",
            "value",
        );
        let time = i64::from_le_bytes(chunk[1..9].try_into().unwrap());
        let bits = u64::from_le_bytes(chunk[9..17].try_into().unwrap());
        // One value type per tenant; invalid float patterns are explicit rejects.
        let value = if chunk[0] & 1 == 0 {
            Value::from_bits(0, bits)
        } else {
            Value::from_bits(2, bits & 1)
        };
        if let Ok(value) = value {
            input.push((series, Point { time, value }));
        }
    }
    let Ok(mut encoded) = encode_segment(input.clone()) else {
        return; // Conflicting duplicate timestamps are not publishable input.
    };
    let mut segment = Segment::open(Cursor::new(&encoded)).unwrap();
    for tenant in ["fuzz-a", "fuzz-b"] {
        let series = Series::new(tenant, "asset", "value");
        let mut expected: Vec<_> = input
            .iter()
            .filter(|(key, _)| key == &series)
            .map(|(_, point)| *point)
            .collect();
        expected.sort_by_key(|point| point.time);
        expected.dedup_by_key(|point| point.time);
        assert_eq!(
            segment.latest(&series).unwrap().map(exact),
            expected.last().copied().map(exact)
        );
        expected.retain(|point| point.time < i64::MAX);
        expected.truncate(32);
        assert_eq!(
            segment
                .scan_limit(&series, i64::MIN, i64::MAX, 32)
                .unwrap()
                .into_iter()
                .map(exact)
                .collect::<Vec<_>>(),
            expected.into_iter().map(exact).collect::<Vec<_>>()
        );
    }
    drop(segment);
    if let Some(&byte) = data.first() {
        let position = usize::from(byte) % encoded.len();
        encoded[position] ^= data.last().copied().unwrap_or(1) | 1;
        inspect(&encoded);
    }
});
