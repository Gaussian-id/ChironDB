//! A checkpoint can skip decoding only bytes previously validated and unchanged.
//! This is a derived-cache binding, not permission to reclaim the WAL prefix.
use super::*;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WalPrefix {
    base_lsn: u64,
    pub(crate) end_lsn: u64,
    digest: [u8; 32],
}

impl Wal {
    /// A trusted authority generation supplies the frame boundary. Require the
    /// retained files to contain that frontier before skipping historical bytes.
    pub(crate) fn validate_authority_frontier(dir: &Path, end_lsn: u64) -> Result<()> {
        let base = read_wal_base(dir)?.lsn;
        if base > end_lsn {
            return Err(wal_corruption(
                dir,
                "retained WAL starts after transaction authority",
            ));
        }
        let mut end = base;
        for segment in wal_segments(dir)? {
            end = end
                .checked_add(WalRangeReader::open(&segment.path)?.len() as u64)
                .ok_or_else(|| wal_corruption(dir, "authority WAL length overflow"))?;
        }
        if end < end_lsn {
            return Err(wal_corruption(dir, "WAL ends before transaction authority"));
        }
        Ok(())
    }

    pub(crate) fn recover_journal_authority_suffix(
        dir: &Path,
        end_lsn: u64,
        mut visitor: impl FnMut(crate::relational::wal_decode::Owned<WalRecord>) -> Result<()>,
    ) -> Result<WalScanStats> {
        Self::validate_authority_frontier(dir, end_lsn)?;
        scan_frames_decoded(
            dir,
            end_lsn,
            TailPolicy::RepairFinalActive,
            true,
            true,
            decode_record_owned,
            |record, payload| {
                drop(payload);
                visitor(record)
            },
        )
    }

    /// The caller supplies an end boundary from a completed scan or live WAL.
    pub(crate) fn checkpoint_prefix(dir: &Path, end_lsn: u64) -> Result<WalPrefix> {
        // Fixed range output and reader/header roots, before opening files.
        // Persistent ciphertext mappings and shared chunk cache are separate.
        let _memory = layout::root(dir, std::mem::size_of::<WalPrefix>() + 64 * 1024)?;
        let base_lsn = read_wal_base(dir)?.lsn;
        if end_lsn < base_lsn {
            return Err(wal_corruption(dir, "checkpoint precedes retained WAL"));
        }
        let mut hash = Sha256::new();
        hash.update(base_lsn.to_le_bytes());
        hash.update(end_lsn.to_le_bytes());
        let mut offset = base_lsn;
        for segment in wal_segments(dir)? {
            let mut reader = WalRangeReader::open(&segment.path)?;
            let take = end_lsn.saturating_sub(offset).min(reader.len() as u64) as usize;
            for start in (0..take).step_by(64 * 1024) {
                hash.update(reader.read_range_admitted(start..(start + 64 * 1024).min(take))?);
            }
            offset += take as u64;
            if offset == end_lsn {
                break;
            }
        }
        if offset != end_lsn {
            return Err(wal_corruption(dir, "checkpoint exceeds retained WAL"));
        }
        Ok(WalPrefix {
            base_lsn,
            end_lsn,
            digest: hash.finalize().into(),
        })
    }

    pub(crate) fn matches_checkpoint_prefix(dir: &Path, prefix: &WalPrefix) -> Result<bool> {
        Ok(Self::checkpoint_prefix(dir, prefix.end_lsn)? == *prefix)
    }

    #[cfg(test)]
    pub(crate) fn recover_checkpoint_suffix(
        dir: &Path,
        prefix: &WalPrefix,
        mut visitor: impl FnMut(WalRecord) -> Result<()>,
    ) -> Result<WalScanStats> {
        if !Self::matches_checkpoint_prefix(dir, prefix)? {
            return Err(wal_corruption(dir, "checkpoint WAL prefix changed"));
        }
        scan_frames_inner(
            dir,
            prefix.end_lsn,
            TailPolicy::RepairFinalActive,
            true,
            |record, payload| {
                drop(payload);
                visitor(record)
            },
        )
    }
    pub(crate) fn recover_journal_checkpoint_suffix(
        dir: &Path,
        prefix: &WalPrefix,
        mut visitor: impl FnMut(crate::relational::wal_decode::Owned<WalRecord>) -> Result<()>,
    ) -> Result<WalScanStats> {
        if !Self::matches_checkpoint_prefix(dir, prefix)? {
            return Err(wal_corruption(dir, "checkpoint WAL prefix changed"));
        }
        scan_frames_decoded(
            dir,
            prefix.end_lsn,
            TailPolicy::RepairFinalActive,
            true,
            true,
            decode_record_owned,
            |record, payload| {
                drop(payload);
                visitor(record)
            },
        )
    }
}

struct AdmittedReader {
    file: WalRangeReader,
    position: usize,
    _memory: crate::relational::wal_decode::MetadataCharge,
}

impl Read for AdmittedReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.file {
            WalRangeReader::Raw { file, .. } => file.read(output),
            WalRangeReader::Encrypted(file) => {
                let count = output.len().min(64 * 1024).min(file.len() - self.position);
                let bytes = file
                    .read_range_admitted(self.position..self.position + count)
                    .map_err(std::io::Error::other)?;
                output[..count].copy_from_slice(&bytes);
                self.position += count;
                Ok(count)
            }
        }
    }
}

pub(super) fn open_reader_at(path: &Path, offset: u64) -> Result<Box<dyn Read>> {
    let memory = layout::root(path, std::mem::size_of::<AdmittedReader>() + 64 * 1024)?;
    let mut file = WalRangeReader::open(path)?;
    let position = match &mut file {
        WalRangeReader::Raw { file, .. } => {
            file.seek(std::io::SeekFrom::Start(offset))?;
            0
        }
        WalRangeReader::Encrypted(_) => usize::try_from(offset)
            .map_err(|_| wal_corruption(path, "checkpoint offset overflow"))?,
    };
    Ok(Box::new(AdmittedReader {
        file,
        position,
        _memory: memory,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_workspace_refusal_preserves_bytes_and_releases_on_retry() {
        let root = tempfile::tempdir().unwrap();
        let capacity = 1024 * 1024;
        crate::relational::wal_decode::with_test_storage_pool(capacity, |used| {
            let mut wal = Wal::open(root.path()).unwrap();
            wal.append(&WalEntry::Delete { id: "one".into() }).unwrap();
            let end = wal.len().unwrap();
            let bytes = fs::read(wal.path()).unwrap();
            let baseline = used();
            let mut pressure = crate::relational::wal_decode::MetadataCharge::default();
            pressure
                .prepare(
                    capacity
                        - baseline
                        - 64 * 1024
                        - crate::relational::wal_decode::lease_root_bytes(),
                )
                .unwrap();
            let before = used();
            assert!(matches!(
                Wal::checkpoint_prefix(root.path(), end),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), before);
            assert_eq!(fs::read(wal.path()).unwrap(), bytes);
            drop(pressure);
            let prefix = Wal::checkpoint_prefix(root.path(), end).unwrap();
            assert!(Wal::matches_checkpoint_prefix(root.path(), &prefix).unwrap());
            assert_eq!(used(), baseline);
            drop(wal);
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn positioned_reader_keeps_reservation_until_drop() {
        let root = tempfile::tempdir().unwrap();
        crate::relational::wal_decode::with_test_storage_pool(1024 * 1024, |used| {
            let mut wal = Wal::open(root.path()).unwrap();
            wal.append(&WalEntry::Delete { id: "one".into() }).unwrap();
            let mut reader = open_reader_at(wal.path(), 0).unwrap();
            drop(wal);
            assert!(used() > 0);
            let mut header = [0; HEADER_LEN];
            reader.read_exact(&mut header).unwrap();
            assert!(u32::from_le_bytes(header[..4].try_into().unwrap()) > 0);
            drop(reader);
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn suffix_crosses_segments_and_repairs_only_final_torn_bytes() {
        let root = tempfile::tempdir().unwrap();
        let mut wal = Wal::open_with_segment_bytes(root.path(), 600).unwrap();
        let entry = WalEntry::DeleteBatch {
            ids: vec!["x".repeat(100)],
        };
        for _ in 0..5 {
            wal.append(&entry).unwrap();
        }
        let boundary = wal.len().unwrap();
        let prefix = Wal::checkpoint_prefix(root.path(), boundary).unwrap();
        for _ in 0..7 {
            wal.append(&entry).unwrap();
        }
        let complete = wal.len().unwrap();
        let active = wal.path.clone();
        drop(wal);
        OpenOptions::new()
            .append(true)
            .open(&active)
            .unwrap()
            .write_all(&[1, 2, 3])
            .unwrap();
        let mut lsns = Vec::new();
        let stats = Wal::recover_checkpoint_suffix(root.path(), &prefix, |record| {
            lsns.push(record.lsn);
            Ok(())
        })
        .unwrap();
        assert_eq!(stats.records, 7);
        assert_eq!(lsns[0], boundary);
        assert_eq!(stats.end_lsn, complete);
        assert_eq!(stats.repaired_tail_bytes, 3);
        assert_eq!(
            Wal::scan_from(root.path(), 0, |_| Ok(())).unwrap().records,
            12
        );
        // Truncating even a valid authoritative generation invalidates the cache.
        Wal::truncate_to_lsn(root.path(), 0).unwrap();
        assert!(Wal::recover_checkpoint_suffix(root.path(), &prefix, |_| Ok(())).is_err());
    }

    #[test]
    fn cached_prefix_does_not_hide_suffix_crc_or_sealed_torn_frames() {
        for sealed in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let mut wal = Wal::open_with_segment_bytes(root.path(), 200).unwrap();
            let entry = WalEntry::DeleteBatch {
                ids: vec!["x".repeat(100)],
            };
            wal.append(&entry).unwrap();
            let prefix = Wal::checkpoint_prefix(root.path(), wal.len().unwrap()).unwrap();
            wal.append(&entry).unwrap();
            let suffix = wal.path.clone();
            if sealed {
                wal.append(&entry).unwrap();
            }
            drop(wal);
            let mut bytes = fs::read(&suffix).unwrap();
            if sealed {
                bytes.pop();
            } else {
                bytes[HEADER_LEN] ^= 1;
            }
            fs::write(suffix, bytes).unwrap();
            assert!(Wal::recover_checkpoint_suffix(root.path(), &prefix, |_| Ok(())).is_err());
        }
    }
}
