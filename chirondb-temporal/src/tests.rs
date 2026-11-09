use super::*;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::ops::Range;
use std::path::Path;

fn fixture(input: &str) -> Vec<(Series, Point)> {
    input
        .lines()
        .map(|line| {
            let c: Vec<_> = line.split('\t').collect();
            let value = Value::from_bits(
                c[4].parse().unwrap(),
                u64::from_str_radix(c[5], 16).unwrap(),
            )
            .unwrap();
            (
                Series::new(c[0], c[1], c[2]),
                Point {
                    time: c[3].parse().unwrap(),
                    value,
                },
            )
        })
        .collect()
}

fn check_against_input(input: &[(Series, Point)], encoded: &[u8]) {
    let mut want = BTreeMap::<Series, Vec<Point>>::new();
    for (k, p) in input {
        want.entry(k.clone()).or_default().push(*p);
    }
    let mut r = Segment::open(Cursor::new(encoded)).unwrap();
    for (k, mut ps) in want {
        ps.sort_by_key(|p| p.time);
        ps.dedup_by_key(|p| p.time);
        let latest = r.latest(&k).unwrap().unwrap();
        assert_eq!(
            (latest.time, latest.value.bits()),
            (ps.last().unwrap().time, ps.last().unwrap().value.bits())
        );
        for (lo, hi) in [
            (i64::MIN, i64::MAX),
            (ps[0].time, ps[ps.len() / 2].time),
            (-10, 10),
            (0, 0),
        ] {
            let got = r.scan(&k, lo, hi).unwrap();
            let bits = |p: &Point| (p.time, p.value.tag(), p.value.bits());
            assert_eq!(
                got.iter().map(bits).collect::<Vec<_>>(),
                ps.iter()
                    .filter(|p| p.time >= lo && p.time < hi)
                    .map(bits)
                    .collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn offline_go_files_and_full_history() {
    for (input, golden) in [
        (
            include_str!("../verification/fixtures/new-edge.tsv"),
            include_bytes!("../verification/fixtures/new-edge.tsm").as_slice(),
        ),
        (
            include_str!("../verification/fixtures/new-keylen.tsv"),
            include_bytes!("../verification/fixtures/new-keylen.tsm").as_slice(),
        ),
    ] {
        let samples = fixture(input);
        assert_eq!(segment::encode(samples.clone(), true).unwrap(), golden);
        let bytes = encode_segment(samples.clone()).unwrap();
        check_against_input(&samples, &bytes);
    }
}

#[test]
fn packed_timestamp_and_multiblock_go_parity() {
    let key = Series::new("main", "motor", "speed");
    let input: Vec<_> = (0..2113)
        .map(|i| {
            (
                key.clone(),
                Point {
                    time: i * 1000 + (i / 12) * 100,
                    value: Value::Float(i as f64 / 3.0),
                },
            )
        })
        .collect();
    assert_eq!(
        segment::encode(input.clone(), true).unwrap(),
        include_bytes!("../verification/fixtures/new-main.tsm").as_slice()
    );
    check_against_input(&input, &encode_segment(input.clone()).unwrap());
}

#[test]
#[ignore = "run through verification/verify.py with the pinned Go writer and reader"]
fn live_upstream_files() {
    let dir = std::env::var_os("TEMPORAL_CASES").expect("verify.py supplies input");
    let mut count = 0;
    for path in fs::read_dir(Path::new(&dir))
        .unwrap()
        .map(|p| p.unwrap().path())
    {
        if path.extension().and_then(|e| e.to_str()) != Some("tsv") {
            continue;
        }
        let samples = fixture(&fs::read_to_string(&path).unwrap());
        let reference = segment::encode(samples.clone(), true).unwrap();
        let upstream = fs::read(path.with_extension("go.tsm")).unwrap();
        fs::write(path.with_extension("rust.tsm"), &reference).unwrap();
        assert_eq!(reference.len(), upstream.len(), "{}", path.display());
        assert_eq!(
            reference.iter().zip(upstream).position(|(a, b)| *a != b),
            None,
            "{}",
            path.display()
        );
        check_against_input(&samples, &encode_segment(samples.clone()).unwrap());
        count += 1;
    }
    assert_eq!(count, 12);
}

#[test]
fn java_filter_and_last_partial_results() {
    for line in include_str!("../verification/fixtures/java.tsv").lines() {
        let f: Vec<_> = line.split(' ').collect();
        if f[0] == "range" {
            let ts = |i: usize| f[i].parse().unwrap();
            assert_eq!(format!("{:?}", coverage(ts(1), ts(2), ts(3), ts(4))), f[5]);
        } else {
            let mut latest = None;
            if f[2] != "empty" {
                for (i, t) in f[2].split(',').enumerate() {
                    let value = if f[1] == "DOUBLE" {
                        Value::Float((i + 1) as f64)
                    } else {
                        Value::Boolean(i % 2 == 0)
                    };
                    merge_latest(
                        &mut latest,
                        Point {
                            time: t.parse().unwrap(),
                            value,
                        },
                    )
                    .unwrap();
                }
            }
            if f[2] == "-9223372036854775808" {
                // Java initializes maxTime to MIN and leaves the default typed value.
                assert_eq!(f[4], "0");
                assert_eq!(latest.unwrap().time, i64::MIN);
                assert_ne!(latest.unwrap().value.bits(), 0);
            } else if f[4] == "empty" {
                assert!(latest.is_none())
            } else {
                let p = latest.unwrap();
                assert_eq!(p.time, f[3].parse().unwrap());
                assert_eq!(p.value.bits(), u64::from_str_radix(f[4], 16).unwrap());
            }
        }
    }
}

#[test]
fn identity_order_duplicates_and_types() {
    let k = Series::new("t", "asset", "speed");
    let other = Series::new("t\0asset", "", "speed");
    let same_asset = Series::new("t2", "asset", "speed");
    let p = |t, v| Point {
        time: t,
        value: Value::Float(v),
    };
    let input = vec![
        (k.clone(), p(8, 3.)),
        (k.clone(), p(-1, 2.)),
        (k.clone(), p(8, 3.)),
        (other, p(8, 0.)),
        (same_asset, p(8, 6.)),
    ];
    check_against_input(&input, &encode_segment(input.clone()).unwrap());
    for invalid in [
        p(8, 4.),
        p(12, f64::NAN),
        Point {
            time: 12,
            value: Value::Boolean(true),
        },
    ] {
        let mut samples = input.clone();
        samples.push((k.clone(), invalid));
        assert!(encode_segment(samples).is_err());
    }
    assert!(Value::from_bits(1, 0).is_err());
    assert!(Value::from_bits(2, 2).is_err());
    assert!(encode_segment([(k.clone(), p(0, -0.)), (k.clone(), p(0, 0.))]).is_err());
    let mut empty = Segment::open(Cursor::new(encode_segment([]).unwrap())).unwrap();
    assert_eq!(empty.latest(&k).unwrap(), None);
    assert_eq!(empty.scan(&k, 0, 1).unwrap(), []);
    assert!(empty.scan(&k, 2, 1).is_err());
}

struct Observed {
    cursor: Cursor<Vec<u8>>,
    reads: Vec<Range<u64>>,
}
impl Read for Observed {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let start = self.cursor.position();
        let n = self.cursor.read(b)?;
        self.reads.push(start..start + n as u64);
        Ok(n)
    }
}
impl Seek for Observed {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.cursor.seek(pos)
    }
}
#[test]
fn selective_reads_touch_only_overlapping_blocks() {
    let s = Series::new("t", "a", "x");
    let samples: Vec<_> = (0..3001)
        .rev()
        .map(|i| {
            (
                s.clone(),
                Point {
                    time: i,
                    value: Value::Boolean(i % 2 == 0),
                },
            )
        })
        .collect();
    let bytes = encode_segment(samples).unwrap();
    let len = bytes.len();
    let mut source = Observed {
        cursor: Cursor::new(bytes),
        reads: vec![],
    };
    let mut r = Segment::open(&mut source).unwrap();
    assert_eq!(
        r.scan(&s, 1000, 1001).unwrap(),
        [Point {
            time: 1000,
            value: Value::Boolean(true)
        }]
    );
    assert_eq!(r.latest(&s).unwrap().unwrap().time, 3000);
    // Header, footer, index, second block, fourth block. No payload on open.
    assert_eq!(source.reads.len(), 5);
    assert_eq!(source.reads[0], 0..5);
    assert_eq!(source.reads[1], (len - 16) as u64..len as u64);
    assert!(source.reads[3].start > 5 && source.reads[3].end < source.reads[4].start);
    assert_eq!(source.reads[4].end, source.reads[2].start);
}

#[test]
fn every_single_bit_flip_and_every_truncation_is_detected_by_full_read() {
    for text in [
        include_str!("../verification/fixtures/new-keylen.tsv"),
        include_str!("../verification/fixtures/new-edge.tsv"),
    ] {
        let input = fixture(text);
        let keys: std::collections::BTreeSet<_> = input.iter().map(|(key, _)| key).collect();
        let bytes = encode_segment(input.clone()).unwrap();
        let check = |data: &[u8]| -> Result<()> {
            let mut s = Segment::open(Cursor::new(data))?;
            for k in &keys {
                s.scan(k, i64::MIN, i64::MAX)?;
            }
            Ok(())
        };
        check(&bytes).unwrap();
        let mut altered = bytes.clone();
        for i in 0..bytes.len() {
            for bit in 0..8 {
                altered[i] ^= 1 << bit;
                assert!(check(&altered).is_err(), "byte {i} bit {bit}");
                altered[i] ^= 1 << bit;
            }
        }
        for len in 0..bytes.len() {
            assert!(check(&bytes[..len]).is_err(), "length {len}");
        }
        eprintln!(
            "{} flips; {} truncations; 0 silent wrong",
            8 * bytes.len(),
            bytes.len()
        );
    }
}

#[test]
fn malformed_checked_metadata_and_payload_return_errors() {
    let input = fixture(include_str!("../verification/fixtures/new-keylen.tsv"));
    let original = encode_segment(input.clone()).unwrap();
    let tail = original.len() - 16;
    let index = u64::from_be_bytes(original[tail..tail + 8].try_into().unwrap()) as usize;
    let keylen = u16::from_be_bytes(original[index..index + 2].try_into().unwrap()) as usize;
    let offset = index + 2 + keylen + 3 + 16;
    // Recompute both metadata CRCs, so rejection must come from extent validation.
    let mut forged = original.clone();
    forged[offset..offset + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    let crc = crc32fast::hash(&forged[index..tail]);
    forged[tail + 8..tail + 12].copy_from_slice(&crc.to_be_bytes());
    let crc = crc32fast::hash(&forged[tail..tail + 12]);
    forged[tail + 12..].copy_from_slice(&crc.to_be_bytes());
    assert!(Segment::open(Cursor::new(forged)).is_err());
    // A valid outer CRC still cannot make an invalid inner timestamp length readable.
    let mut bad_block = original;
    let size = u32::from_be_bytes(bad_block[offset + 8..offset + 12].try_into().unwrap()) as usize;
    bad_block[10] = 127;
    let crc = crc32fast::hash(&bad_block[9..5 + size]);
    bad_block[5..9].copy_from_slice(&crc.to_be_bytes());
    let mut s = Segment::open(Cursor::new(bad_block)).unwrap();
    assert!(s.latest(&input[0].0).is_err());
}
