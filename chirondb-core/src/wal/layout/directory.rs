//! Caller-owned directory buffers on the four required Unix targets.
use super::*;
use std::borrow::Cow;
use std::ffi::OsStr;

pub(super) const BUFFER_BYTES: u64 = 64 * 1024;

pub(super) struct Entry<'a> {
    pub(super) name: Cow<'a, OsStr>,
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
    fn parse(bytes: &[u8]) -> Result<(usize, &[u8])> {
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
        Ok((length, &names[..end]))
    }

    #[cfg(target_os = "macos")]
    const ATTR_CMN_ERROR: u32 = 0x2000_0000;

    #[cfg(target_os = "macos")]
    fn parse(bytes: &[u8]) -> Result<(usize, &[u8])> {
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
        // ATTR_CMN_ERROR is packed immediately after returned attributes.
        if attributes & ATTR_CMN_ERROR != 0 {
            let error = word(record, reference)?;
            if error != 0 {
                return Err(std::io::Error::from_raw_os_error(error as i32).into());
            }
            reference += 4;
        }
        if attributes & libc::ATTR_CMN_NAME == 0 {
            return Err(invalid());
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
        Ok((length, &name[..name.len() - 1]))
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
            let (length, name) = parse(&bytes[self.position..self.available])?;
            self.position += length;
            self.remaining -= 1;
            Ok(Some(Entry {
                name: Cow::Borrowed(OsStr::from_bytes(name)),
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
                })
            })
            .transpose()
    }
}
