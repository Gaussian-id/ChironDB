//! InfluxDB tsm1 scalar wire encoding. See THIRD_PARTY.md for source pins.
use super::{BLOCK_POINTS, Point, Value, bad};
use std::io::Result;

const FLOAT: u8 = 0;
const BOOL: u8 = 2;
const NAN_END: u64 = 0x7ff8_0000_0000_0001;

pub(super) fn varint(mut n: u64, out: &mut Vec<u8>) {
    while n >= 128 {
        out.push(n as u8 | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

pub(super) fn take<'a>(src: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    src.split_off(..n)
        .ok_or_else(|| bad("truncated temporal data"))
}
pub(super) fn bytes<const N: usize>(src: &mut &[u8]) -> Result<[u8; N]> {
    Ok(take(src, N)?.try_into().expect("fixed width"))
}
fn read_varint(src: &mut &[u8]) -> Result<u64> {
    let mut n = 0;
    for shift in (0..64).step_by(7) {
        let b = bytes::<1>(src)?[0];
        if shift == 63 && b > 1 {
            break;
        }
        n |= u64::from(b & 127) << shift;
        if b < 128 {
            return Ok(n);
        }
    }
    Err(bad("overflowing varint"))
}

// jwilder/encoding/simple8b: selector (number of deltas, bits per delta).
const SELECTORS: [(usize, u32); 16] = [
    (240, 0),
    (120, 0),
    (60, 1),
    (30, 2),
    (20, 3),
    (15, 4),
    (12, 5),
    (10, 6),
    (8, 7),
    (7, 8),
    (6, 10),
    (5, 12),
    (4, 15),
    (3, 20),
    (2, 30),
    (1, 60),
];

fn times(points: &[Point]) -> Vec<u8> {
    let first = points[0].time as u64;
    let mut deltas: Vec<_> = points
        .windows(2)
        .map(|w| (w[1].time as u64).wrapping_sub(w[0].time as u64))
        .collect();
    let mut exponent = 12;
    while exponent > 0
        && deltas
            .iter()
            .any(|d| !d.is_multiple_of(10u64.pow(exponent)))
    {
        exponent -= 1;
    }
    let divisor = 10u64.pow(exponent);
    let mut out = vec![0];
    out.extend(first.to_be_bytes());
    if !deltas.is_empty() && deltas.iter().all(|d| *d == deltas[0]) {
        out[0] = 0x20 | exponent as u8;
        varint(deltas[0] / divisor, &mut out);
        varint(points.len() as u64, &mut out);
    } else if deltas.iter().any(|d| *d >= 1 << 60) {
        for d in deltas {
            out.extend(d.to_be_bytes());
        }
    } else {
        out[0] = 0x10 | exponent as u8;
        for d in &mut deltas {
            *d /= divisor;
        }
        let mut remaining = deltas.as_slice();
        while !remaining.is_empty() {
            // Upstream streams through a 240-element buffer. Its zero-bit selectors
            // test all buffered values for ones, including those beyond the selector.
            let window = &remaining[..remaining.len().min(240)];
            let (sel, &(n, bits)) = SELECTORS
                .iter()
                .enumerate()
                .find(|(_, (n, bits))| {
                    window.len() >= *n
                        && if *bits == 0 {
                            window.iter().all(|d| *d == 1)
                        } else {
                            window[..*n].iter().all(|d| *d < 1u64 << bits)
                        }
                })
                .expect("last selector fits every scaled delta");
            let mut word = (sel as u64) << 60;
            if bits > 0 {
                for (i, d) in remaining[..n].iter().enumerate() {
                    word |= *d << (i as u32 * bits);
                }
            }
            out.extend(word.to_be_bytes());
            remaining = &remaining[n..];
        }
    }
    out
}

fn read_times(mut src: &[u8]) -> Result<Vec<i64>> {
    let tag = bytes::<1>(&mut src)?[0];
    let mut current = u64::from_be_bytes(bytes(&mut src)?);
    let mut out = vec![current as i64];
    let exp = tag & 15;
    if exp > 12 {
        return Err(bad("invalid timestamp scaling"));
    }
    let scale = 10u64.pow(exp.into());
    let mut push = |delta: u64| -> Result<()> {
        if out.len() >= BLOCK_POINTS {
            return Err(bad("oversized block"));
        }
        current = current.wrapping_add(
            delta
                .checked_mul(scale)
                .ok_or_else(|| bad("timestamp delta overflow"))?,
        );
        out.push(current as i64);
        Ok(())
    };
    match tag >> 4 {
        0 if exp == 0 => {
            while !src.is_empty() {
                push(u64::from_be_bytes(bytes(&mut src)?))?;
            }
        }
        1 => {
            while !src.is_empty() {
                let mut word = u64::from_be_bytes(bytes(&mut src)?);
                let (n, bits) = SELECTORS[(word >> 60) as usize];
                let mask = (1u64 << bits) - 1;
                for _ in 0..n {
                    push(if bits == 0 { 1 } else { word & mask })?;
                    word >>= bits;
                }
            }
        }
        2 => {
            let delta = read_varint(&mut src)?;
            let n = read_varint(&mut src)?;
            if !(2..=BLOCK_POINTS as u64).contains(&n) || !src.is_empty() {
                return Err(bad("invalid timestamp run"));
            }
            for _ in 1..n {
                push(delta)?;
            }
        }
        _ => return Err(bad("unsupported timestamp encoding")),
    }
    if !out.windows(2).all(|w| w[0] < w[1]) {
        return Err(bad("unordered timestamps"));
    }
    Ok(out)
}

struct BitWriter {
    buf: Vec<u8>,
    used: usize,
}
impl BitWriter {
    fn put(&mut self, value: u64, width: u32) {
        for i in (0..width).rev() {
            if self.used == 0 {
                self.buf.push(0);
            }
            let b = self.buf.last_mut().unwrap();
            *b |= (((value >> i) & 1) as u8) << (7 - self.used);
            self.used = (self.used + 1) % 8;
        }
    }
}
struct BitReader<'a> {
    buf: &'a [u8],
    pos: usize,
}
impl BitReader<'_> {
    fn get(&mut self, width: u32) -> Result<u64> {
        if self.pos + width as usize > self.buf.len() * 8 {
            return Err(bad("truncated bit stream"));
        }
        let mut v = 0;
        for _ in 0..width {
            v = (v << 1) | u64::from((self.buf[self.pos / 8] >> (7 - self.pos % 8)) & 1);
            self.pos += 1;
        }
        Ok(v)
    }
    fn finish(mut self) -> Result<()> {
        let left = self.buf.len() * 8 - self.pos;
        if left >= 8 || self.get(left as u32)? != 0 {
            return Err(bad("invalid bit padding"));
        }
        Ok(())
    }
}

fn float_values(points: &[Point]) -> Vec<u8> {
    let mut bits = BitWriter {
        buf: vec![0x10],
        used: 0,
    };
    let mut prev = points[0].value.bits();
    bits.put(prev, 64);
    let mut window = None;
    for v in points[1..].iter().map(|p| p.value.bits()).chain([NAN_END]) {
        let d = v ^ prev;
        prev = v;
        bits.put(u64::from(d != 0), 1);
        if d == 0 {
            continue;
        }
        // Preserve the donor's five-bit mask (not saturation at 31).
        let lead = d.leading_zeros() & 31;
        let trail = d.trailing_zeros();
        let (l, t) = match window {
            Some((l, t)) if lead >= l && trail >= t => {
                bits.put(0, 1);
                (l, t)
            }
            _ => {
                bits.put(1, 1);
                bits.put(lead.into(), 5);
                bits.put((64 - lead - trail).into(), 6);
                window = Some((lead, trail));
                (lead, trail)
            }
        };
        bits.put(d >> t, 64 - l - t);
    }
    bits.buf
}

fn decode_floats(src: &[u8], count: usize) -> Result<Vec<Value>> {
    let mut bits = BitReader { buf: src, pos: 0 };
    let mut prev = bits.get(64)?;
    let mut window = None;
    let mut values = Vec::with_capacity(count);
    loop {
        if prev == NAN_END {
            break;
        }
        let v = f64::from_bits(prev);
        if v.is_nan() || values.len() >= count {
            return Err(bad("invalid float stream"));
        }
        values.push(Value::Float(v));
        if bits.get(1)? != 0 {
            if bits.get(1)? != 0 {
                let l = bits.get(5)? as u32;
                let width = bits.get(6)? as u32;
                let width = if width == 0 { 64 } else { width };
                let t = 64u32
                    .checked_sub(l + width)
                    .ok_or_else(|| bad("invalid float window"))?;
                window = Some((width, t));
            }
            let (width, t) = window.ok_or_else(|| bad("missing float window"))?;
            prev ^= bits.get(width)? << t;
        }
    }
    bits.finish()?;
    if values.len() != count {
        return Err(bad("timestamp/value count mismatch"));
    }
    Ok(values)
}

pub(super) fn encode(points: &[Point]) -> Vec<u8> {
    let tag = points[0].value.tag();
    let mut out = vec![tag];
    let ts = times(points);
    varint(ts.len() as u64, &mut out);
    out.extend(ts);
    if tag == BOOL {
        out.push(0x10);
        varint(points.len() as u64, &mut out);
        for chunk in points.chunks(8) {
            out.push(
                chunk
                    .iter()
                    .enumerate()
                    .fold(0, |acc, (i, p)| acc | ((p.value.bits() as u8) << (7 - i))),
            );
        }
    } else {
        out.extend(float_values(points));
    }
    out
}

pub(super) fn decode(mut src: &[u8], tag: u8) -> Result<Vec<Point>> {
    if bytes::<1>(&mut src)?[0] != tag {
        return Err(bad("block type mismatch"));
    }
    let len =
        usize::try_from(read_varint(&mut src)?).map_err(|_| bad("timestamp size overflow"))?;
    let ts = read_times(take(&mut src, len)?)?;
    if bytes::<1>(&mut src)?[0] != 0x10 {
        return Err(bad("unsupported value encoding"));
    }
    let values = match tag {
        FLOAT => decode_floats(src, ts.len())?,
        BOOL => {
            if read_varint(&mut src)? != ts.len() as u64 || src.len() != ts.len().div_ceil(8) {
                return Err(bad("boolean count mismatch"));
            }
            (0..ts.len())
                .map(|i| Value::Boolean(src[i / 8] & (128 >> (i % 8)) != 0))
                .collect()
        }
        _ => return Err(bad("unsupported value type")),
    };
    Ok(ts
        .into_iter()
        .zip(values)
        .map(|(time, value)| Point { time, value })
        .collect())
}
