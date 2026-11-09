//! Offline fixture measurement. Run the release binary under an OS RSS sampler.
use chirondb_temporal::{Point, Segment, Series, Value, encode_segment};
use std::collections::BTreeMap;
use std::error::Error;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::time::Instant;

struct Meter<'a> {
    inner: Cursor<&'a [u8]>,
    calls: usize,
    bytes: usize,
}
impl Read for Meter<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.calls += 1;
        self.bytes += n;
        Ok(n)
    }
}
impl Seek for Meter<'_> {
    fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(p)
    }
}
fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("expected one six-column fixture path")?;
    let input = std::fs::read_to_string(path)?;
    let mut samples = Vec::new();
    let mut oracle = BTreeMap::<Series, Vec<Point>>::new();
    for line in input.lines() {
        let c: Vec<_> = line.split('\t').collect();
        if c.len() != 6 {
            return Err("bad fixture row".into());
        }
        let k = Series::new(c[0], c[1], c[2]);
        let time = c[3].parse()?;
        let value = Value::from_bits(c[4].parse()?, u64::from_str_radix(c[5], 16)?)?;
        let p = Point { time, value };
        oracle.entry(k.clone()).or_default().push(p);
        samples.push((k, p));
    }
    let count = samples.len();
    for ps in oracle.values_mut() {
        ps.sort_by_key(|p| p.time);
    }
    let start = Instant::now();
    let bytes = encode_segment(samples)?;
    let encode = start.elapsed();
    let measure = |query_one: bool| -> std::io::Result<(usize, usize, usize, u128)> {
        let mut m = Meter {
            inner: Cursor::new(bytes.as_slice()),
            calls: 0,
            bytes: 0,
        };
        let mut r = Segment::open(&mut m)?;
        let mut elapsed = 0;
        for (k, ps) in &oracle {
            let window = if query_one {
                &ps[ps.len() / 2..=ps.len() / 2]
            } else {
                ps.as_slice()
            };
            let start = Instant::now();
            let got = r.scan(
                k,
                window[0].time,
                window
                    .last()
                    .unwrap()
                    .time
                    .checked_add(1)
                    .expect("bounded benchmark fixture"),
            )?;
            elapsed += start.elapsed().as_nanos();
            assert_eq!(got, window);
            if query_one {
                break;
            }
        }
        // The open reads header/footer/index; every later read consumes one whole block.
        Ok((m.calls - 3, m.bytes, bytes.len(), elapsed))
    };
    let (blocks, full_bytes, size, decode_ns) = measure(false)?;
    let (select_blocks, select_bytes, _, select_ns) = measure(true)?;
    println!(
        "values={count} series={} size={size} bytes_per_value={:.3} encode_ns={} scan_ns={decode_ns} full_blocks={blocks} full_bytes={full_bytes} selective_ns={select_ns} selective_blocks={select_blocks} selective_bytes={select_bytes}",
        oracle.len(),
        size as f64 / count as f64,
        encode.as_nanos()
    );
    Ok(())
}
