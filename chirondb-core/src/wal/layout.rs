//! WAL path and directory inventory ownership.
use super::*;
use crate::relational::wal_decode::MetadataCharge;
use std::mem::size_of;

mod directory;
use directory::DirectoryReader;

#[derive(Debug)]
pub(super) struct WalSegment {
    pub(super) index: u64,
    pub(super) path: PathBuf,
    // Last: a moved path keeps its own reservation after inventory/iterator drop.
    pub(super) memory: MetadataCharge,
}

#[derive(Debug, Default)]
pub(super) struct WalSegments {
    segments: Vec<WalSegment>,
    memory: MetadataCharge,
}

fn exhausted() -> GaussError {
    GaussError::ResourceExhausted("WAL directory metadata memory is full".into())
}

pub(crate) fn root(path: &Path, bytes: usize) -> Result<MetadataCharge> {
    let mut memory = MetadataCharge::default();
    memory.prepare(
        (path.as_os_str().len() as u64)
            .checked_mul(8)
            .and_then(|n| n.checked_add((bytes as u64).checked_mul(2)?))
            .and_then(|n| n.checked_add(8192))
            .ok_or_else(exhausted)?,
    )?;
    Ok(memory)
}

impl WalSegments {
    pub(super) fn pin_files(&mut self, pin: &super::pinned::DirectoryPin) -> Result<()> {
        for segment in &mut self.segments {
            pin.link(segment)?;
        }
        Ok(())
    }

    fn prepare_slot(&mut self) -> Result<()> {
        if self.segments.len() < self.segments.capacity() {
            return Ok(());
        }
        let next = self
            .segments
            .len()
            .checked_add(1)
            .and_then(usize::checked_next_power_of_two)
            .map(|n| n.max(8))
            .ok_or_else(exhausted)?;
        let bytes = (next as u64)
            .checked_add(self.segments.capacity() as u64)
            .and_then(|n| n.checked_mul(size_of::<WalSegment>() as u64))
            .and_then(|n| n.checked_add(4096))
            .ok_or_else(exhausted)?;
        self.memory.prepare(bytes)?;
        self.segments
            .try_reserve_exact(next - self.segments.len())
            .map_err(|_| exhausted())?;
        self.memory
            .reduce(4096 + self.segments.capacity() as u64 * size_of::<WalSegment>() as u64);
        Ok(())
    }

    pub(super) fn retain(&mut self, mut predicate: impl FnMut(&WalSegment) -> bool) {
        self.segments.retain(|segment| predicate(segment));
        // Capacity survives filtering; do not release its reservation.
    }
}

impl std::ops::Deref for WalSegments {
    type Target = [WalSegment];
    fn deref(&self) -> &Self::Target {
        &self.segments
    }
}

pub(super) struct WalSegmentsIter {
    segments: std::vec::IntoIter<WalSegment>,
    _memory: MetadataCharge,
}
impl Iterator for WalSegmentsIter {
    type Item = WalSegment;
    fn next(&mut self) -> Option<Self::Item> {
        self.segments.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.segments.size_hint()
    }
}
impl DoubleEndedIterator for WalSegmentsIter {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.segments.next_back()
    }
}
impl ExactSizeIterator for WalSegmentsIter {}
impl std::iter::FusedIterator for WalSegmentsIter {}
impl IntoIterator for WalSegments {
    type Item = WalSegment;
    type IntoIter = WalSegmentsIter;
    fn into_iter(self) -> Self::IntoIter {
        WalSegmentsIter {
            segments: self.segments.into_iter(),
            _memory: self.memory,
        }
    }
}
impl<'a> IntoIterator for &'a WalSegments {
    type Item = &'a WalSegment;
    type IntoIter = std::slice::Iter<'a, WalSegment>;
    fn into_iter(self) -> Self::IntoIter {
        self.segments.iter()
    }
}

pub(super) fn all_wal_segments(dir: &Path) -> Result<WalSegments> {
    let mut segments = WalSegments::default();
    segments.memory.prepare(4096)?;
    if dir.exists() {
        let mut reader = DirectoryReader::open(dir)?;
        while let Some(entry) = reader.next_entry()? {
            let name = entry.name;
            if Path::new(&name)
                .extension()
                .is_none_or(|extension| extension != "gdwal")
            {
                continue;
            }
            let mut memory = MetadataCharge::default();
            memory.prepare(
                (dir.as_os_str().len() as u64)
                    .checked_add(name.len() as u64)
                    .and_then(|n| n.checked_mul(4))
                    .and_then(|n| n.checked_add(size_of::<WalSegment>() as u64 + 256))
                    .ok_or_else(exhausted)?,
            )?;
            let path = dir.join(&name);
            if !fs::symlink_metadata(&path)?.is_file() {
                continue;
            }
            segments.prepare_slot()?;
            let index = name
                .to_str()
                .ok_or_else(|| wal_corruption(&path, "WAL segment name is not valid UTF-8"))?
                .strip_suffix(".gdwal")
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| wal_corruption(&path, "invalid WAL segment index"))?;
            segments.segments.push(WalSegment {
                index,
                path,
                memory,
            });
        }
    }
    // In-place unstable sorting allocates no merge scratch.
    segments
        .segments
        .sort_unstable_by_key(|segment| segment.index);
    segments
        .memory
        .reduce(4096 + segments.segments.capacity() as u64 * size_of::<WalSegment>() as u64);
    Ok(segments)
}

pub(super) fn wal_segments(dir: &Path) -> Result<WalSegments> {
    let wal_base = read_wal_base(dir)?;
    let mut segments = all_wal_segments(dir)?;
    segments.retain(|segment| segment.index >= wal_base.first_segment);
    for (position, segment) in segments.iter().enumerate() {
        let expected = wal_base
            .first_segment
            .checked_add(position as u64)
            .ok_or_else(|| wal_corruption(&segment.path, "wal segment index overflow"))?;
        if segment.index != expected {
            let message = if position > 0 && segment.index == segments[position - 1].index {
                format!("duplicate wal segment index {}", segment.index)
            } else {
                format!(
                    "wal segment gap: expected index {expected}, found {}",
                    segment.index
                )
            };
            return Err(wal_corruption(&segment.path, &message));
        }
    }
    Ok(segments)
}

pub(super) fn cleanup_snapshot_pins(dir: &Path) -> Result<()> {
    let mut memory = root(dir, 256)?;
    let metadata = match fs::symlink_metadata(dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(wal_corruption(
            dir,
            "WAL pin cleanup requires a regular directory",
        ));
    }
    let mut reader = DirectoryReader::open(dir)?;
    let mut removed = false;
    while let Some(entry) = reader.next_entry()? {
        if !entry
            .name
            .to_str()
            .is_some_and(|name| name.starts_with(super::pinned::PREFIX))
        {
            continue;
        }
        memory.prepare((dir.as_os_str().len() as u64 + entry.name.len() as u64) * 4 + 8192)?;
        let path = dir.join(&entry.name);
        // remove_dir_all does not follow a symlink. A cached entry may already
        // be absent, but permission/type/fsync errors must still propagate.
        match fs::remove_dir_all(&path) {
            Ok(()) => removed = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if removed {
        sync_directory(dir)?;
    }
    Ok(())
}

pub(super) fn cleanup_child_snapshot_pins(collections: &Path) -> Result<()> {
    let mut memory = root(collections, 256)?;
    if !collections.try_exists()? {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(collections)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(wal_corruption(
            collections,
            "collection pin cleanup requires a regular directory",
        ));
    }
    let mut reader = DirectoryReader::open(collections)?;
    while let Some(entry) = reader.next_entry()? {
        if entry
            .name
            .to_str()
            .is_some_and(|name| name == "." || name == "..")
        {
            continue;
        }
        memory
            .prepare((collections.as_os_str().len() as u64 + entry.name.len() as u64) * 8 + 8192)?;
        let path = collections.join(&entry.name);
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            cleanup_snapshot_pins(&path.join("wal"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relational::wal_decode::with_test_storage_pool;

    #[test]
    fn root_refusal_precedes_directory_and_active_file_creation() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("not-created");
        with_test_storage_pool(1, |used| {
            assert!(matches!(
                Wal::open(&dir),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert!(!dir.exists());
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn inventory_and_moved_path_keep_admission_until_last_drop() {
        let temp = tempfile::tempdir().unwrap();
        for index in 0..9 {
            fs::write(segment_path(temp.path(), index), []).unwrap();
        }
        with_test_storage_pool(1024 * 1024, |used| {
            let segments = all_wal_segments(temp.path()).unwrap();
            assert_eq!(segments.len(), 9);
            assert!(used() > 0);
            let mut iter = segments.into_iter();
            let first = iter.next().unwrap();
            assert_eq!(first.index, 0);
            drop(iter);
            assert!(used() > 0, "moved path keeps its own reservation");
            assert!(first.path.exists());
            drop(first);
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn inventory_refusal_preserves_all_files_and_releases_its_workspace() {
        let temp = tempfile::tempdir().unwrap();
        let path = segment_path(temp.path(), 0);
        fs::write(&path, b"unchanged").unwrap();
        with_test_storage_pool(1, |used| {
            assert!(matches!(
                all_wal_segments(temp.path()),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(fs::read(&path).unwrap(), b"unchanged");
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn inventory_growth_refusal_cleans_partial_owners_and_retries() {
        let temp = tempfile::tempdir().unwrap();
        for index in 0..64 {
            fs::write(segment_path(temp.path(), index), [index as u8]).unwrap();
        }
        with_test_storage_pool(directory::BUFFER_BYTES + 32 * 1024, |used| {
            let reader = DirectoryReader::open(temp.path()).unwrap();
            drop(reader);
            assert_eq!(used(), 0);
            assert!(matches!(
                all_wal_segments(temp.path()),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
            for index in 0..64 {
                assert_eq!(
                    fs::read(segment_path(temp.path(), index)).unwrap(),
                    [index as u8]
                );
            }
        });
        with_test_storage_pool(1024 * 1024, |used| {
            let segments = all_wal_segments(temp.path()).unwrap();
            assert_eq!(segments.len(), 64);
            assert!(
                segments
                    .iter()
                    .enumerate()
                    .all(|(index, segment)| index as u64 == segment.index)
            );
            drop(segments);
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn frozen_archive_keeps_descriptor_and_path_owners_after_wal_drop() {
        let temp = tempfile::tempdir().unwrap();
        with_test_storage_pool(1024 * 1024, |used| {
            let mut wal = Wal::open_with_segment_bytes(temp.path(), 100).unwrap();
            for index in 0..3 {
                wal.append(&WalEntry::Delete {
                    id: index.to_string(),
                })
                .unwrap();
            }
            let end = wal.len().unwrap();
            let frozen = wal.freeze_archive_cut(end).unwrap().unwrap();
            let with_wal = used();
            assert!(with_wal > 0);
            drop(wal);
            assert!(used() > 0 && used() < with_wal);
            assert!(frozen.segments.iter().all(|segment| segment.path.exists()));
            assert_eq!(frozen.end_lsn, end);
            drop(frozen);
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn sidecar_write_refusal_preserves_old_frontier_without_temp_file() {
        let temp = tempfile::tempdir().unwrap();
        let capacity = 1024 * 1024;
        with_test_storage_pool(capacity, |used| {
            let before = WalBase {
                lsn: 19,
                first_segment: 3,
            };
            write_wal_base(temp.path(), before).unwrap();
            let path = temp.path().join(WAL_BASE_FILE);
            let bytes = fs::read(&path).unwrap();
            let mut pressure = MetadataCharge::default();
            pressure
                .prepare(capacity - crate::relational::wal_decode::lease_root_bytes())
                .unwrap();
            assert!(matches!(
                write_wal_base(
                    temp.path(),
                    WalBase {
                        lsn: 99,
                        first_segment: 9
                    }
                ),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert!(!temp.path().join("wal.base.tmp").exists());
            drop(pressure);
            assert_eq!(read_wal_base(temp.path()).unwrap(), before);
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn reset_inventory_refusal_does_not_poison_writer_or_change_frontier() {
        let temp = tempfile::tempdir().unwrap();
        let capacity = 1024 * 1024;
        with_test_storage_pool(capacity, |used| {
            let mut wal = Wal::open(temp.path()).unwrap();
            let end = wal.append(&WalEntry::Delete { id: "one".into() }).unwrap();
            let path = wal.path().to_path_buf();
            let bytes = fs::read(&path).unwrap();
            let mut pressure = MetadataCharge::default();
            pressure
                .prepare(capacity - used() - crate::relational::wal_decode::lease_root_bytes())
                .unwrap();
            assert!(matches!(wal.reset(), Err(GaussError::ResourceExhausted(_))));
            assert_eq!(wal.len().unwrap(), end);
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert!(!temp.path().join(WAL_BASE_FILE).exists());
            drop(pressure);
            assert!(wal.append(&WalEntry::Delete { id: "two".into() }).unwrap() > end);
            wal.reset().unwrap();
            assert!(Wal::load(temp.path()).unwrap().is_empty());
            drop(wal);
            assert_eq!(used(), 0);
        });
    }
}
