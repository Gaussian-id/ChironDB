//! An admitted ordered snapshot: at most one framed record per immutable run.
//! Shared layouts pin scratch/checkpoint generations across concurrent merges.
use super::*;

pub(crate) struct Cursor {
    streams: [Option<Stream>; 64],
    heads: [Option<segment::SegmentRecord>; 64],
    finished: bool,
    _memory: wal_decode::MetadataCharge,
}
enum Stream {
    Prefix(segment::SegmentPrefixCursor),
    Full(segment::SegmentCursor),
}
impl Stream {
    fn next(&mut self) -> Option<Result<segment::SegmentRecord>> {
        match self {
            Self::Prefix(cursor) => cursor.next(),
            Self::Full(cursor) => cursor.next(),
        }
    }
}

pub(crate) struct Record(segment::SegmentRecord);
impl Record {
    pub(super) fn into_inner(self) -> segment::SegmentRecord {
        self.0
    }
    pub(crate) fn key(&self) -> &[u8] {
        &self.0.key
    }
    pub(crate) fn decode<V: DeserializeOwned>(&self) -> Result<wal_decode::Owned<V>> {
        wal_decode::decode(&self.0.value)
    }
}

impl DiskMap {
    pub(crate) fn prefix_cursor(&self, prefix: &[u8]) -> Result<Cursor> {
        self.cursor_inner(Some(prefix))
    }
    pub(crate) fn cursor(&self) -> Result<Cursor> {
        self.cursor_inner(None)
    }
    fn cursor_inner(&self, prefix: Option<&[u8]>) -> Result<Cursor> {
        let mut memory = wal_decode::MetadataCharge::default();
        memory.prepare(std::mem::size_of::<Cursor>() as u64 + 1024)?;
        let mut cursor = Cursor {
            streams: std::array::from_fn(|_| None),
            heads: std::array::from_fn(|_| None),
            finished: false,
            _memory: memory,
        };
        for (slot, reader) in self.levels.iter().enumerate() {
            if let Some(reader) = reader {
                cursor.streams[slot] = Some(match prefix {
                    Some(prefix) => Stream::Prefix(reader.prefix_cursor(prefix)?),
                    None => Stream::Full(reader.cursor()),
                });
            }
        }
        Ok(cursor)
    }
}

impl Cursor {
    fn read_next(&mut self) -> Result<Option<segment::SegmentRecord>> {
        check_sql_cancelled()?;
        let mut selected: Option<usize> = None;
        for slot in 0..self.streams.len() {
            if self.heads[slot].is_none()
                && let Some(stream) = &mut self.streams[slot]
            {
                self.heads[slot] = stream.next().transpose()?;
                if self.heads[slot].is_none() {
                    self.streams[slot] = None;
                }
            }
            let Some(head) = &self.heads[slot] else {
                continue;
            };
            if let Some(previous) = selected {
                match head
                    .key
                    .cmp(&self.heads[previous].as_ref().expect("selected head").key)
                {
                    std::cmp::Ordering::Equal => {
                        return Err(GaussError::WalCorruption {
                            path: crate::transaction_journal::TRANSACTION_JOURNAL_DIR.into(),
                            message: "duplicate decision key across immutable runs".into(),
                        });
                    }
                    std::cmp::Ordering::Less => selected = Some(slot),
                    std::cmp::Ordering::Greater => {}
                }
            } else {
                selected = Some(slot);
            }
        }
        Ok(selected.and_then(|slot| self.heads[slot].take()))
    }

    fn finish(&mut self) {
        self.finished = true;
        self.heads.fill_with(|| None);
        self.streams.fill_with(|| None);
    }
}

impl Iterator for Cursor {
    type Item = Result<Record>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        match self.read_next() {
            Ok(Some(record)) => Some(Ok(Record(record))),
            Ok(None) => {
                self.finish();
                None
            }
            Err(error) => {
                self.finish();
                Some(Err(error))
            }
        }
    }
}
impl std::iter::FusedIterator for Cursor {}

#[cfg(test)]
mod tests;
