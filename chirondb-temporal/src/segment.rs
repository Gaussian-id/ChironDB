use super::{BLOCK_POINTS, Coverage, Point, Series, Value, bad, codec, coverage, merge_latest};
use std::collections::BTreeMap;
use std::io::{Read, Result, Seek, SeekFrom};

const HEADER: &[u8; 5] = b"CTSG\x01";
const TSM_HEADER: &[u8; 5] = b"\x16\xd1\x16\xd1\x01";
const FOOTER: usize = 16;
const MAX_INDEX: usize = 64 << 20;
const MAX_BLOCK: usize = 32 << 10;

/// Build a complete segment in memory. An error yields no publishable bytes.
pub fn encode_segment(samples: impl IntoIterator<Item = (Series, Point)>) -> Result<Vec<u8>> {
    encode(samples, false)
}

// The reference lane changes only the envelope. Both lanes encode identical TSM blocks.
pub(super) fn encode(
    samples: impl IntoIterator<Item = (Series, Point)>,
    reference: bool,
) -> Result<Vec<u8>> {
    let mut groups: BTreeMap<Vec<u8>, Vec<Point>> = BTreeMap::new();
    for (series, p) in samples {
        Value::from_bits(p.value.tag(), p.value.bits())?;
        groups.entry(series.key()?).or_default().push(p);
    }
    let mut out = if reference { TSM_HEADER } else { HEADER }.to_vec();
    let mut index = Vec::new();
    for (key, mut ps) in groups {
        ps.sort_unstable_by_key(|p| p.time);
        let tag = ps[0].value.tag();
        if ps.iter().any(|p| p.value.tag() != tag) {
            return Err(bad("mixed types in series"));
        }
        if ps
            .windows(2)
            .any(|w| w[0].time == w[1].time && w[0].value.bits() != w[1].value.bits())
        {
            return Err(bad("conflicting event"));
        }
        ps.dedup_by_key(|p| p.time);
        let n = u16::try_from(ps.len().div_ceil(BLOCK_POINTS))
            .map_err(|_| bad("too many blocks in series"))?;
        index.extend((key.len() as u16).to_be_bytes());
        index.extend(key);
        index.push(tag);
        index.extend(n.to_be_bytes());
        for chunk in ps.chunks(BLOCK_POINTS) {
            let block = codec::encode(chunk);
            index.extend(chunk[0].time.to_be_bytes());
            index.extend(chunk.last().unwrap().time.to_be_bytes());
            index.extend((out.len() as u64).to_be_bytes());
            index.extend(((block.len() + 4) as u32).to_be_bytes());
            out.extend(crc32fast::hash(&block).to_be_bytes());
            out.extend(block);
        }
        if index.len() > MAX_INDEX {
            return Err(bad("oversized index"));
        }
    }
    let pos = out.len() as u64;
    let index_crc = crc32fast::hash(&index);
    out.extend(index);
    out.extend(pos.to_be_bytes());
    if !reference {
        out.extend(index_crc.to_be_bytes());
        let footer_crc = crc32fast::hash(&out[out.len() - 12..]);
        out.extend(footer_crc.to_be_bytes());
    }
    Ok(out)
}

#[derive(Clone, Copy)]
struct Block {
    min: i64,
    max: i64,
    pos: u64,
    size: u32,
}
struct Entry {
    tag: u8,
    blocks: Vec<Block>,
}

/// Range reads use the caller's seekable, immutable source (e.g. a File or Cursor).
pub struct Segment<R> {
    source: R,
    entries: BTreeMap<Vec<u8>, Entry>,
}
impl<R: Read + Seek> Segment<R> {
    pub fn open(mut source: R) -> Result<Self> {
        let size = source.seek(SeekFrom::End(0))?;
        if size < (HEADER.len() + FOOTER) as u64 {
            return Err(bad("short segment"));
        }
        source.rewind()?;
        let mut header = [0; 5];
        source.read_exact(&mut header)?;
        if &header != HEADER {
            return Err(bad("unknown temporal magic/version"));
        }
        let footer_pos = size - FOOTER as u64;
        source.seek(SeekFrom::Start(footer_pos))?;
        let mut tail = [0; FOOTER];
        source.read_exact(&mut tail)?;
        let mut footer = tail.as_slice();
        let pos = u64::from_be_bytes(codec::bytes(&mut footer)?);
        let index_crc = u32::from_be_bytes(codec::bytes(&mut footer)?);
        if u32::from_be_bytes(codec::bytes(&mut footer)?) != crc32fast::hash(&tail[..12]) {
            return Err(bad("footer checksum"));
        }
        if pos < HEADER.len() as u64 || pos > footer_pos || footer_pos - pos > MAX_INDEX as u64 {
            return Err(bad("invalid index extent"));
        }
        source.seek(SeekFrom::Start(pos))?;
        let mut index = vec![0; (footer_pos - pos) as usize];
        source.read_exact(&mut index)?;
        if crc32fast::hash(&index) != index_crc {
            return Err(bad("index checksum"));
        }
        let mut rest = index.as_slice();
        let mut entries = BTreeMap::new();
        let mut next_pos = HEADER.len() as u64;
        while !rest.is_empty() {
            let len = u16::from_be_bytes(codec::bytes(&mut rest)?) as usize;
            let key = codec::take(&mut rest, len)?;
            let mut parts = key;
            for _ in 0..3 {
                let len = u16::from_be_bytes(codec::bytes(&mut parts)?) as usize;
                std::str::from_utf8(codec::take(&mut parts, len)?)
                    .map_err(|_| bad("invalid series key"))?;
            }
            if !parts.is_empty() {
                return Err(bad("invalid series key length"));
            }
            let tag = codec::bytes::<1>(&mut rest)?[0];
            let n = u16::from_be_bytes(codec::bytes(&mut rest)?) as usize;
            if !matches!(tag, 0 | 2) || n == 0 || n > rest.len() / 28 {
                return Err(bad("invalid index entry"));
            }
            let mut blocks: Vec<Block> = Vec::with_capacity(n);
            for _ in 0..n {
                let b = Block {
                    min: i64::from_be_bytes(codec::bytes(&mut rest)?),
                    max: i64::from_be_bytes(codec::bytes(&mut rest)?),
                    pos: u64::from_be_bytes(codec::bytes(&mut rest)?),
                    size: u32::from_be_bytes(codec::bytes(&mut rest)?),
                };
                if b.min > b.max
                    || blocks.last().is_some_and(|prev| prev.max >= b.min)
                    || b.pos != next_pos
                    || !(5..=MAX_BLOCK).contains(&(b.size as usize))
                    || u64::from(b.size) > pos - next_pos
                {
                    return Err(bad("invalid block extent/order"));
                }
                next_pos += u64::from(b.size);
                blocks.push(b);
            }
            if entries
                .insert(key.to_vec(), Entry { tag, blocks })
                .is_some()
            {
                return Err(bad("duplicate series"));
            }
        }
        if next_pos != pos {
            return Err(bad("unindexed block data"));
        }
        Ok(Self { source, entries })
    }
    fn read_block(source: &mut R, tag: u8, b: Block) -> Result<Vec<Point>> {
        source.seek(SeekFrom::Start(b.pos))?;
        let mut buf = vec![0; b.size as usize];
        source.read_exact(&mut buf)?;
        let mut payload = buf.as_slice();
        let crc = u32::from_be_bytes(codec::bytes(&mut payload)?);
        if crc != crc32fast::hash(payload) {
            return Err(bad("block checksum"));
        }
        let ps = codec::decode(payload, tag)?;
        if ps.first().map(|p| p.time) != Some(b.min) || ps.last().map(|p| p.time) != Some(b.max) {
            return Err(bad("block time bounds mismatch"));
        }
        Ok(ps)
    }
    /// Sorted history in [start,end). A reversed interval is an input error.
    pub fn scan(&mut self, series: &Series, start: i64, end: i64) -> Result<Vec<Point>> {
        self.scan_limit(series, start, end, usize::MAX)
    }
    /// At most `limit` earliest matching observations; avoid reading later blocks.
    pub fn scan_limit(
        &mut self,
        series: &Series,
        start: i64,
        end: i64,
        limit: usize,
    ) -> Result<Vec<Point>> {
        if start > end {
            return Err(bad("reversed query interval"));
        }
        let mut result = Vec::new();
        if let Some(entry) = self.entries.get(&series.key()?) {
            let first = entry.blocks.partition_point(|b| b.max < start);
            for b in &entry.blocks[first..] {
                if result.len() == limit || b.min >= end {
                    break;
                }
                let mode = coverage(start, end, b.min, b.max);
                if mode == Coverage::Skip {
                    continue;
                }
                let mut ps = Self::read_block(&mut self.source, entry.tag, *b)?;
                if mode == Coverage::Partial {
                    ps.retain(|p| p.time >= start && p.time < end);
                }
                result.extend(ps.into_iter().take(limit - result.len()));
            }
        }
        Ok(result)
    }
    /// Last observed value by event time, including events at i64::MAX.
    pub fn latest(&mut self, series: &Series) -> Result<Option<Point>> {
        let mut last = None;
        if let Some(entry) = self.entries.get(&series.key()?) {
            // Nonoverlapping ordered blocks: the final block contains the global maximum.
            if let Some(&b) = entry.blocks.last() {
                for p in Self::read_block(&mut self.source, entry.tag, b)? {
                    merge_latest(&mut last, p)?;
                }
            }
        }
        Ok(last)
    }
}
