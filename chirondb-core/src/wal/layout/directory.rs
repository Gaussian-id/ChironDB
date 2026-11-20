//! Caller-owned directory buffers on the four required Unix targets.
use super::*;
use std::borrow::Cow;
use std::ffi::OsStr;

pub(super) const BUFFER_BYTES: u64 = 64 * 1024;

pub(super) struct Entry<'a> {
    pub(super) name: Cow<'a, OsStr>,
    error: Option<std::io::Error>,
}

impl<'a> Entry<'a> {
    pub(super) fn into_wal_name(self) -> Result<Option<Cow<'a, OsStr>>> {
        if Path::new(&self.name)
            .extension()
            .is_none_or(|extension| extension != "gdwal")
        {
            return Ok(None);
        }
        if let Some(error) = self.error {
            return Err(error.into());
        }
        Ok(Some(self.name))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod native {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    pub(in crate::wal::layout) struct DirectoryReader {
        file: File,
        // u64 storage also satisfies getattrlistbulk's eight-byte alignment.
        buffer: Vec<u64>,
        position: usize,
        available: usize,
        remaining: usize,
        budget: u64,
        _memory: MetadataCharge,
    }

    fn invalid() -> GaussError {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid native directory record",
        )
        .into()
    }

    #[cfg(target_os = "linux")]
    fn parse(bytes: &[u8]) -> Result<(usize, &[u8], Option<std::io::Error>)> {
        let length_offset = std::mem::offset_of!(libc::dirent64, d_reclen);
        let name_offset = std::mem::offset_of!(libc::dirent64, d_name);
        let length = bytes
            .get(length_offset..length_offset + 2)
            .ok_or_else(invalid)?;
        let length = u16::from_ne_bytes(length.try_into().unwrap()) as usize;
        let record = bytes
            .get(..length)
            .filter(|r| r.len() > name_offset)
            .ok_or_else(invalid)?;
        let names = &record[name_offset..];
        let end = names
            .iter()
            .position(|b| *b == 0)
            .filter(|end| *end > 0)
            .ok_or_else(invalid)?;
        Ok((length, &names[..end], None))
    }

    #[cfg(target_os = "macos")]
    const ATTR_CMN_ERROR: u32 = 0x2000_0000;

    #[cfg(target_os = "macos")]
    fn parse(bytes: &[u8]) -> Result<(usize, &[u8], Option<std::io::Error>)> {
        fn word(bytes: &[u8], offset: usize) -> Result<u32> {
            Ok(u32::from_ne_bytes(
                bytes
                    .get(offset..offset + 4)
                    .ok_or_else(invalid)?
                    .try_into()
                    .unwrap(),
            ))
        }
        let length = word(bytes, 0)? as usize;
        let record = bytes
            .get(..length)
            .filter(|r| r.len() >= 24)
            .ok_or_else(invalid)?;
        let attributes = word(record, 4)?;
        let mut reference = 4 + size_of::<libc::attribute_set_t>();
        // Preserve the per-entry error until the caller selects WAL names.
        // Unrelated pins/atomic temps can disappear during getattrlistbulk;
        // an error on an actual WAL entry must still fail closed.
        let error = if attributes & ATTR_CMN_ERROR != 0 {
            let code = word(record, reference)?;
            reference += 4;
            (code != 0).then(|| std::io::Error::from_raw_os_error(code as i32))
        } else {
            None
        };
        if attributes & libc::ATTR_CMN_NAME == 0 {
            return Err(error.map_or_else(invalid, GaussError::from));
        }
        let offset = word(record, reference)? as i32;
        let count = word(record, reference + 4)? as usize;
        let start = reference
            .checked_add_signed(offset as isize)
            .ok_or_else(invalid)?;
        let end = start.checked_add(count).ok_or_else(invalid)?;
        let name = record
            .get(start..end)
            .filter(|n| n.len() > 1 && n.last() == Some(&0))
            .ok_or_else(invalid)?;
        if start < reference + 8 || name[..name.len() - 1].contains(&0) {
            return Err(invalid());
        }
        Ok((length, &name[..name.len() - 1], error))
    }

    impl DirectoryReader {
        pub(in crate::wal::layout) fn open(path: &Path) -> Result<Self> {
            let mut memory = root(path, size_of::<Self>())?;
            let budget = (path.as_os_str().len() as u64)
                .checked_mul(8)
                .and_then(|n| n.checked_add(BUFFER_BYTES + 8192 + 2 * size_of::<Self>() as u64))
                .ok_or_else(exhausted)?;
            memory.prepare(budget)?;
            let mut buffer = Vec::new();
            buffer
                .try_reserve_exact(BUFFER_BYTES as usize / 8)
                .map_err(|_| exhausted())?;
            buffer.resize(BUFFER_BYTES as usize / 8, 0);
            Ok(Self {
                file: File::open(path)?,
                buffer,
                position: 0,
                available: 0,
                remaining: 0,
                budget,
                _memory: memory,
            })
        }

        fn refill(&mut self) -> Result<bool> {
            loop {
                self._memory.prepare(self.budget)?;
                #[cfg(target_os = "linux")]
                // SAFETY: the open fd is owned; the initialized, exclusively borrowed
                // buffer has exactly BUFFER_BYTES writable bytes for the syscall.
                let count = unsafe {
                    libc::syscall(
                        libc::SYS_getdents64,
                        self.file.as_raw_fd(),
                        self.buffer.as_mut_ptr(),
                        BUFFER_BYTES as usize,
                    )
                };
                #[cfg(target_os = "macos")]
                let count = {
                    let mut attributes = libc::attrlist {
                        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
                        reserved: 0,
                        commonattr: libc::ATTR_CMN_RETURNED_ATTRS
                            | libc::ATTR_CMN_NAME
                            | ATTR_CMN_ERROR,
                        volattr: 0,
                        dirattr: 0,
                        fileattr: 0,
                        forkattr: 0,
                    };
                    // SAFETY: valid stack attrlist, owned fd, exclusive eight-byte
                    // aligned initialized buffer and its actual byte length.
                    unsafe {
                        libc::getattrlistbulk(
                            self.file.as_raw_fd(),
                            (&mut attributes as *mut libc::attrlist).cast(),
                            self.buffer.as_mut_ptr().cast(),
                            BUFFER_BYTES as usize,
                            0,
                        )
                    }
                };
                if count < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error.into());
                }
                self.position = 0;
                #[cfg(target_os = "linux")]
                {
                    self.available = usize::try_from(count).map_err(|_| invalid())?;
                    self.remaining = usize::MAX;
                }
                #[cfg(target_os = "macos")]
                {
                    self.available = BUFFER_BYTES as usize;
                    self.remaining = count as usize;
                }
                if self.available > BUFFER_BYTES as usize {
                    return Err(invalid());
                }
                return Ok(count != 0);
            }
        }

        pub(in crate::wal::layout) fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
            if (self.position == self.available || self.remaining == 0) && !self.refill()? {
                return Ok(None);
            }
            // SAFETY: initialized u64 storage stays alive and immutably borrowed;
            // byte slices permit any alignment and cover only its allocated length.
            let bytes = unsafe {
                std::slice::from_raw_parts(self.buffer.as_ptr().cast::<u8>(), self.buffer.len() * 8)
            };
            let (length, name, error) = parse(&bytes[self.position..self.available])?;
            self.position += length;
            self.remaining -= 1;
            Ok(Some(Entry {
                name: Cow::Borrowed(OsStr::from_bytes(name)),
                error,
            }))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::relational::wal_decode::with_test_storage_pool;

        #[test]
        fn malformed_records_reject_without_advancing_or_reading_outside_buffer() {
            for length in 0..48 {
                assert!(parse(&vec![0; length]).is_err());
            }
            assert!(parse(&[255; 64]).is_err());
            #[cfg(target_os = "linux")]
            let (mut record, name_start) = {
                let mut record = vec![0; 24];
                let offset = std::mem::offset_of!(libc::dirent64, d_reclen);
                record[offset..offset + 2].copy_from_slice(&24u16.to_ne_bytes());
                (record, std::mem::offset_of!(libc::dirent64, d_name))
            };
            #[cfg(target_os = "macos")]
            let (mut record, name_start) = {
                let mut record = vec![0; 40];
                record[..4].copy_from_slice(&40u32.to_ne_bytes());
                record[4..8].copy_from_slice(&libc::ATTR_CMN_NAME.to_ne_bytes());
                record[24..28].copy_from_slice(&8i32.to_ne_bytes());
                record[28..32].copy_from_slice(&4u32.to_ne_bytes());
                (record, 32)
            };
            record[name_start..name_start + 4].copy_from_slice(b"a\xffb\0");
            assert_eq!(parse(&record).unwrap().1, b"a\xffb");
            record[name_start..].fill(b'x');
            assert!(parse(&record).is_err(), "missing name terminator");
        }

        #[test]
        fn wal_name_selection_preserves_errors_on_actual_segments() {
            for code in [libc::ENOENT, libc::EACCES] {
                let auxiliary = Entry {
                    name: Cow::Borrowed(OsStr::new(".released-pin")),
                    error: Some(std::io::Error::from_raw_os_error(code)),
                };
                assert!(auxiliary.into_wal_name().unwrap().is_none());
                let segment = Entry {
                    name: Cow::Borrowed(OsStr::new("00000000000000000000.gdwal")),
                    error: Some(std::io::Error::from_raw_os_error(code)),
                };
                assert!(matches!(
                    segment.into_wal_name(),
                    Err(GaussError::Io(error)) if error.raw_os_error() == Some(code)
                ));
            }
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn attribute_error_records_retain_their_validated_name_and_errno() {
            let mut record = vec![0; 48];
            record[..4].copy_from_slice(&48u32.to_ne_bytes());
            record[4..8].copy_from_slice(&(libc::ATTR_CMN_NAME | ATTR_CMN_ERROR).to_ne_bytes());
            record[24..28].copy_from_slice(&(libc::ENOENT as u32).to_ne_bytes());
            record[28..32].copy_from_slice(&8i32.to_ne_bytes());
            record[32..36].copy_from_slice(&8u32.to_ne_bytes());
            record[36..44].copy_from_slice(b"0.gdwal\0");
            let (length, name, error) = parse(&record).unwrap();
            assert_eq!(length, 48);
            assert_eq!(name, b"0.gdwal");
            assert_eq!(error.unwrap().raw_os_error(), Some(libc::ENOENT));
            record[28..32].copy_from_slice(&i32::MAX.to_ne_bytes());
            assert!(
                parse(&record).is_err(),
                "error records still require a bounded name"
            );
            record[4..8].copy_from_slice(&ATTR_CMN_ERROR.to_ne_bytes());
            assert!(
                parse(&record).is_err(),
                "nameless errors must not be discarded"
            );
        }

        #[test]
        fn native_names_match_independent_filesystem_iterator_and_release_lease() {
            let temp = tempfile::tempdir().unwrap();
            for name in [OsStr::new("unicode-λ"), OsStr::new("plain")] {
                fs::write(temp.path().join(name), []).unwrap();
            }
            // APFS rejects invalid UTF-8 on creation; Linux filesystems retain it.
            #[cfg(target_os = "linux")]
            fs::write(temp.path().join(OsStr::from_bytes(b"non-utf8-\xff")), []).unwrap();
            fs::create_dir(temp.path().join("subdir")).unwrap();
            std::os::unix::fs::symlink("plain", temp.path().join("link")).unwrap();
            let expected: std::collections::BTreeSet<_> = fs::read_dir(temp.path())
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            with_test_storage_pool(1024 * 1024, |used| {
                let mut reader = DirectoryReader::open(temp.path()).unwrap();
                assert!(used() >= BUFFER_BYTES);
                let mut actual = std::collections::BTreeSet::new();
                while let Some(entry) = reader.next_entry().unwrap() {
                    if &*entry.name != OsStr::new(".") && &*entry.name != OsStr::new("..") {
                        assert!(actual.insert(entry.name.into_owned()));
                    }
                }
                assert_eq!(actual, expected);
                assert!(used() >= BUFFER_BYTES);
                drop(reader);
                assert_eq!(used(), 0);
            });
        }

        #[test]
        fn unrelated_entry_cleanup_does_not_abort_wal_inventory() {
            use std::sync::atomic::{AtomicBool, Ordering};

            let temp = tempfile::tempdir().unwrap();
            fs::write(temp.path().join("00000000000000000000.gdwal"), []).unwrap();
            let stop = AtomicBool::new(false);
            let result = std::thread::scope(|scope| {
                let auxiliary = temp.path().join(".released-pin");
                let cleanup_stop = &stop;
                let cleanup = scope.spawn(move || {
                    while !cleanup_stop.load(Ordering::Acquire) {
                        fs::create_dir(&auxiliary).unwrap();
                        fs::remove_dir(&auxiliary).unwrap();
                    }
                });
                let result = (|| -> Result<()> {
                    for _ in 0..1000 {
                        let segments = crate::wal::layout::all_wal_segments(temp.path())?;
                        assert_eq!(segments.len(), 1);
                        assert_eq!(segments.iter().next().unwrap().index, 0);
                    }
                    Ok(())
                })();
                stop.store(true, Ordering::Release);
                cleanup.join().unwrap();
                result
            });
            result.unwrap();
        }

        #[test]
        fn multiple_kernel_batches_keep_constant_workspace_and_no_duplicate_names() {
            let temp = tempfile::tempdir().unwrap();
            for index in 0..1500 {
                fs::write(
                    temp.path().join(format!("{index:020}-{}", "x".repeat(80))),
                    [],
                )
                .unwrap();
            }
            with_test_storage_pool(1024 * 1024, |used| {
                let mut reader = DirectoryReader::open(temp.path()).unwrap();
                let charged = used();
                let mut names = std::collections::HashSet::new();
                while let Some(entry) = reader.next_entry().unwrap() {
                    if &*entry.name != OsStr::new(".") && &*entry.name != OsStr::new("..") {
                        assert!(names.insert(entry.name.into_owned()));
                    }
                    assert_eq!(used(), charged);
                }
                assert_eq!(names.len(), 1500);
                drop(reader);
                assert_eq!(used(), 0);
            });
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) use native::DirectoryReader;

// Other targets are best-effort and do not qualify the four-platform bound.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) struct DirectoryReader {
    entries: fs::ReadDir,
    _memory: MetadataCharge,
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl DirectoryReader {
    pub(in crate::wal::layout) fn open(path: &Path) -> Result<Self> {
        let memory = root(path, BUFFER_BYTES as usize)?;
        Ok(Self {
            entries: fs::read_dir(path)?,
            _memory: memory,
        })
    }
    pub(in crate::wal::layout) fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        self.entries
            .next()
            .map(|e| {
                Ok(Entry {
                    name: Cow::Owned(e?.file_name()),
                    error: None,
                })
            })
            .transpose()
    }
}
