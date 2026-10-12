//! Direct ordered journal reads reuse one admitted directory inventory and one
//! open segment. They do not reopen every preceding file for each PREPARE.
use super::*;

struct Current {
    file: WalRangeReader,
    segment: WalSegment,
}

pub(crate) struct OrderedJournalReader {
    current: Option<Current>,
    remaining: layout::WalSegmentsIter,
    dir: PathBuf,
    segment_start: u64,
    end_lsn: u64,
    minimum_lsn: u64,
    admission: crate::relational::wal_decode::FrameAdmission,
    #[cfg(test)]
    opened_segments: usize,
    // Files/reader inventory drop before the private directory links.
    _pin: super::pinned::DirectoryPin,
    _memory: crate::relational::wal_decode::MetadataCharge,
}

impl OrderedJournalReader {
    pub(crate) fn open(dir: &Path, end_lsn: u64) -> Result<Self> {
        let memory = layout::root(dir, std::mem::size_of::<Self>())?;
        let base = read_wal_base(dir)?.lsn;
        if end_lsn < base {
            return Err(wal_corruption(
                dir,
                "journal snapshot precedes retained WAL",
            ));
        }
        let mut segments = wal_segments(dir)?;
        let pin = super::pinned::DirectoryPin::new(dir)?;
        segments.pin_files(&pin)?;
        Ok(Self {
            current: None,
            remaining: segments.into_iter(),
            dir: dir.to_path_buf(),
            segment_start: base,
            end_lsn,
            minimum_lsn: base,
            admission: crate::relational::wal_decode::FrameAdmission::new()?,
            #[cfg(test)]
            opened_segments: 0,
            _pin: pin,
            _memory: memory,
        })
    }

    pub(crate) fn read(
        &mut self,
        lsn: u64,
    ) -> Result<crate::relational::wal_decode::Owned<WalRecord>> {
        if lsn < self.minimum_lsn || lsn >= self.end_lsn {
            return Err(wal_corruption(
                &self.dir,
                "ordered journal LSN is outside snapshot or precedes the previous frame",
            ));
        }
        loop {
            if self.current.is_none() {
                let segment = self.remaining.next().ok_or_else(|| {
                    wal_corruption(&self.dir, "record LSN is past the journal snapshot end")
                })?;
                let file = WalRangeReader::open(&segment.path).map_err(|error| match error {
                    error @ GaussError::ResourceExhausted(_) => error,
                    error => wal_corruption(&segment.path, &error.to_string()),
                })?;
                self.current = Some(Current { file, segment });
                #[cfg(test)]
                {
                    self.opened_segments += 1;
                }
            }
            let current = self.current.as_mut().expect("opened segment");
            let segment_end = self
                .segment_start
                .checked_add(current.file.len() as u64)
                .ok_or_else(|| wal_corruption(&current.segment.path, "WAL length overflow"))?;
            if lsn >= segment_end {
                self.current = None;
                self.segment_start = segment_end;
                continue;
            }
            let offset = usize::try_from(lsn - self.segment_start)
                .map_err(|_| wal_corruption(&current.segment.path, "WAL offset exceeds usize"))?;
            let header_end = offset.checked_add(HEADER_LEN).ok_or_else(|| {
                wal_corruption(&current.segment.path, "WAL header offset overflow")
            })?;
            if header_end > current.file.len() {
                return Err(wal_corruption(
                    &current.segment.path,
                    "partial WAL record header",
                ));
            }
            let encrypted = matches!(current.file, WalRangeReader::Encrypted(_));
            let file_len = current.file.len();
            self.admission.prepare(HEADER_LEN, encrypted)?;
            let header = current.file.read_range_admitted(offset..header_end)?;
            let payload_len =
                u32::from_le_bytes(header[..4].try_into().expect("length header")) as usize;
            validate_payload_len(&current.segment.path, payload_len)?;
            let payload_end = header_end.checked_add(payload_len).ok_or_else(|| {
                wal_corruption(&current.segment.path, "WAL payload offset overflow")
            })?;
            let frame_end = self
                .segment_start
                .checked_add(payload_end as u64)
                .ok_or_else(|| wal_corruption(&current.segment.path, "WAL frame end overflow"))?;
            if payload_end > file_len || frame_end > self.end_lsn {
                return Err(wal_corruption(
                    &current.segment.path,
                    "torn WAL record or frame exceeds journal snapshot",
                ));
            }
            let crc = u32::from_le_bytes(header[4..8].try_into().expect("crc header"));
            drop(header);
            self.admission.prepare(payload_len, encrypted)?;
            let payload = current.file.read_range_admitted(header_end..payload_end)?;
            if checksum(&payload) != crc {
                return Err(wal_corruption(&current.segment.path, "crc mismatch"));
            }
            let record = decode_record_owned(&current.segment.path, lsn, &payload)?;
            self.minimum_lsn = frame_end;
            return Ok(record);
        }
    }
}

#[cfg(test)]
mod tests;
