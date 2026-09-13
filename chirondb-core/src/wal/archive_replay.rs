//! Source-preserving replay, exclusively into an uninstalled restore WAL.

use super::*;

impl Wal {
    pub(crate) fn archive_fingerprint(dir: &Path) -> Result<[u8; 32]> {
        let mut digest = Sha256::new();
        digest.update(Self::retained_base_lsn(dir)?.to_le_bytes());
        let stats = scan_frames(dir, 0, TailPolicy::Strict, |record, payload| {
            digest.update(record.lsn.to_le_bytes());
            digest.update((payload.len() as u64).to_le_bytes());
            digest.update(encryption::decode_persistent(&payload)?.as_ref());
            Ok(())
        })?;
        digest.update(stats.end_lsn.to_le_bytes());
        Ok(digest.finalize().into())
    }

    /// Check retained overlap and append only a contiguous new suffix. Frame
    /// bytes, timestamps and absolute LSNs survive encryption and segment rotation.
    /// The caller owns staging: any failure must discard it, not install a prefix.
    pub(crate) fn replay_archive<F>(&mut self, archive: &Path, mut appended: F) -> Result<()>
    where
        F: FnMut(WalRecord) -> Result<()>,
    {
        self.ensure_available()?;
        let existing_end = self.len()?;
        let retained = Self::retained_base_lsn(&self.dir)?;
        let archive_base = Self::retained_base_lsn(archive)?;
        if archive_base > existing_end {
            return Err(wal_corruption(
                archive,
                "gap between snapshot WAL and archive suffix",
            ));
        }
        let overlap_start = archive_base.max(retained);
        if overlap_start < existing_end {
            // The first compared frame must also begin on a real target frame,
            // not merely on bytes that happen to resemble a nested frame header.
            Self::scan_from(&self.dir, overlap_start, |_| Ok(()))?;
        }
        let mut prefix = PrefixReader::new(&self.dir)?;
        scan_frames(archive, 0, TailPolicy::Strict, |record, payload| {
            match &record.entry {
                WalEntry::CreateCollection { .. } | WalEntry::DropCollection { .. } => {
                    return Err(wal_corruption(
                        archive,
                        "catalog entry found in collection WAL archive",
                    ));
                }
                WalEntry::GraphBatch { batch } => batch.validate()?,
                _ => {}
            }
            let end = record
                .lsn
                .checked_add(HEADER_LEN as u64 + payload.len() as u64)
                .ok_or_else(|| wal_corruption(archive, "archive WAL LSN overflow"))?;
            if record.lsn < existing_end {
                if end > existing_end || (record.lsn < retained && end > retained) {
                    return Err(wal_corruption(
                        archive,
                        "archive overlaps a partial snapshot WAL frame",
                    ));
                }
                // A selected checkpoint already covers the pruned prefix. The
                // retained overlap still has to prove it is the same history.
                if record.lsn >= retained && !prefix.matches(record.lsn, &payload)? {
                    return Err(wal_corruption(
                        archive,
                        "archive diverges from retained snapshot WAL",
                    ));
                }
                return Ok(());
            }
            if record.lsn != self.len()? {
                return Err(wal_corruption(
                    archive,
                    "gap between snapshot WAL and archive suffix",
                ));
            }
            if encryption::encryption_enabled() && !encryption::is_encrypted(&payload) {
                return Err(wal_corruption(
                    archive,
                    "plaintext archive frames require an explicit encryption migration; WAL offsets cannot be rewritten",
                ));
            }
            self.append_payload(record.lsn, &payload, false)?;
            appended(record)
        })?;
        self.sync()
    }
}

/// One forward reader for retained overlap, independent of archive segmentation.
/// Only a single bounded frame is held, never a map of all historical records.
struct PrefixReader {
    segments: std::vec::IntoIter<WalSegment>,
    reader: Option<Box<dyn Read>>,
    position: u64,
    segment_end: u64,
    path: PathBuf,
}

impl PrefixReader {
    fn new(dir: &Path) -> Result<Self> {
        let base = Wal::retained_base_lsn(dir)?;
        Ok(Self {
            segments: wal_segments(dir)?.into_iter(),
            reader: None,
            position: base,
            segment_end: base,
            path: dir.to_path_buf(),
        })
    }

    fn matches(&mut self, lsn: u64, payload: &[u8]) -> Result<bool> {
        if lsn < self.position {
            return Err(wal_corruption(&self.path, "non-monotonic archive overlap"));
        }
        while lsn >= self.segment_end {
            let segment = self
                .segments
                .next()
                .ok_or_else(|| wal_corruption(&self.path, "missing snapshot WAL overlap"))?;
            self.position = self.segment_end;
            let (reader, len) = open_wal_reader(&segment.path)?;
            self.segment_end = self
                .position
                .checked_add(len)
                .ok_or_else(|| wal_corruption(&segment.path, "WAL segment range overflow"))?;
            self.reader = Some(reader);
            self.path = segment.path;
        }
        let reader = self.reader.as_mut().expect("selected overlap segment");
        let skip = lsn - self.position;
        if std::io::copy(&mut reader.by_ref().take(skip), &mut std::io::sink())? != skip {
            return Err(wal_corruption(&self.path, "short snapshot WAL overlap"));
        }
        let mut header = [0; HEADER_LEN];
        reader.read_exact(&mut header)?;
        let len = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
        let frame_end = lsn
            .checked_add(HEADER_LEN as u64 + len as u64)
            .ok_or_else(|| wal_corruption(&self.path, "overlap frame LSN overflow"))?;
        if len != payload.len() || frame_end > self.segment_end {
            return Ok(false);
        }
        let mut existing = vec![0; len];
        reader.read_exact(&mut existing)?;
        self.position = frame_end;
        if checksum(&existing) != u32::from_le_bytes(header[4..].try_into().unwrap()) {
            return Err(wal_corruption(&self.path, "snapshot overlap CRC mismatch"));
        }
        // Key rotation changes authenticated envelope bytes but must preserve
        // original record bytes and encoded length to preserve absolute LSNs.
        Ok(existing == payload
            || encryption::decode_persistent(&existing)? == encryption::decode_persistent(payload)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn replay_preserves_offsets_time_and_overlap_across_segment_boundaries() {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        let mut wal = Wal::open_with_segment_bytes(&source, 100).unwrap();
        wal.append(&WalEntry::Delete { id: "first".into() })
            .unwrap();
        crate::fs_util::copy_dir_contents(&source, &target).unwrap();
        let cut = wal.len().unwrap();
        wal.append(&WalEntry::Delete {
            id: "second".into(),
        })
        .unwrap();
        wal.append(&WalEntry::Delete { id: "third".into() })
            .unwrap();
        let expected = serde_json::to_value(Wal::load(&source).unwrap()).unwrap();
        let end = wal.len().unwrap();
        let archive = wal
            .archive_current(&temp.path().join("archives"))
            .unwrap()
            .unwrap();
        assert_eq!(wal.len().unwrap(), end);
        assert_eq!(Wal::retained_base_lsn(&source).unwrap(), 0);
        let mut restored = Wal::open(&target).unwrap();
        let mut appended = Vec::new();
        restored
            .replay_archive(&archive.path, |record| {
                appended.push(record.lsn);
                Ok(())
            })
            .unwrap();
        assert_eq!(appended.len(), 2);
        assert_eq!(appended[0], cut);
        assert_eq!(restored.len().unwrap(), end);
        assert_eq!(
            serde_json::to_value(Wal::load(&target).unwrap()).unwrap(),
            expected
        );
        restored
            .replay_archive(&archive.path, |_| panic!("duplicate replay"))
            .unwrap();
        assert_eq!(restored.len().unwrap(), end);
        assert_eq!(
            Wal::archive_fingerprint(&source).unwrap(),
            Wal::archive_fingerprint(&target).unwrap()
        );
    }

    #[test]
    fn replay_refuses_gaps_divergent_overlap_and_catalog_frames() {
        let temp = TempDir::new().unwrap();
        let mut target = Wal::open(&temp.path().join("target")).unwrap();
        target
            .append(&WalEntry::Delete { id: "aaa".into() })
            .unwrap();
        let original = target.len().unwrap();
        let mut divergent = Wal::open(&temp.path().join("different")).unwrap();
        divergent
            .append(&WalEntry::Delete { id: "bbb".into() })
            .unwrap();
        let error = target
            .replay_archive(&divergent.dir, |_| Ok(()))
            .unwrap_err();
        assert!(error.to_string().contains("diverges"), "{error}");
        assert_eq!(target.len().unwrap(), original);

        let mut gap = Wal::open(&temp.path().join("gap")).unwrap();
        gap.append(&WalEntry::Delete {
            id: "longer-prefix-than-target".into(),
        })
        .unwrap();
        gap.reset().unwrap();
        gap.append(&WalEntry::Delete {
            id: "after-gap".into(),
        })
        .unwrap();
        let error = target.replay_archive(&gap.dir, |_| Ok(())).unwrap_err();
        assert!(error.to_string().contains("gap between"), "{error}");
        assert_eq!(target.len().unwrap(), original);

        let mut catalog = Wal::open(&temp.path().join("catalog")).unwrap();
        catalog
            .append(&WalEntry::DropCollection {
                name: "docs".into(),
            })
            .unwrap();
        let error = target.replay_archive(&catalog.dir, |_| Ok(())).unwrap_err();
        assert!(error.to_string().contains("catalog entry"), "{error}");
        assert_eq!(target.len().unwrap(), original);
    }
}
