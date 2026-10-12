//! Private terminal credential I/O, shared by remote and attached consoles.
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub fn read_key(path: &Path) -> std::io::Result<String> {
    let before = std::fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(std::io::Error::other(
            "credential must be a regular private file",
        ));
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.permissions().mode() & 0o077 != 0
        {
            return Err(std::io::Error::other(
                "credential file changed or is accessible to other users",
            ));
        }
    }
    if !opened.is_file() || opened.len() > 4096 {
        return Err(std::io::Error::other("invalid credential file"));
    }
    let mut key = String::new();
    file.take(4097).read_to_string(&mut key)?;
    let key = key.trim();
    if key.is_empty() || key.len() > 4096 || key.chars().any(char::is_whitespace) {
        return Err(std::io::Error::other("invalid credential file"));
    }
    Ok(key.into())
}

pub struct KeyDestination {
    file: File,
    path: PathBuf,
    completed: bool,
}
impl KeyDestination {
    pub fn create(path: &Path) -> std::io::Result<Self> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        Ok(Self {
            file,
            path: path.into(),
            completed: false,
        })
    }
    pub fn save(&mut self, secret: &str) -> std::io::Result<()> {
        self.file.write_all(secret.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.sync_all()?;
        #[cfg(unix)]
        {
            let parent = self
                .path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            File::open(parent)?.sync_all()?;
        }
        self.completed = true;
        Ok(())
    }
}
impl Drop for KeyDestination {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        // Preserve a partial write for diagnosis; only remove our empty file.
        if let (Ok(owned), Ok(current)) =
            (self.file.metadata(), std::fs::symlink_metadata(&self.path))
        {
            #[cfg(unix)]
            let same = {
                use std::os::unix::fs::MetadataExt;
                owned.dev() == current.dev() && owned.ino() == current.ino()
            };
            #[cfg(not(unix))]
            let same = false;
            if same && owned.len() == 0 && current.is_file() {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

/// An omitted revision is fetched separately and sent explicitly. There is no
/// automatic retry after a conflict or uncertain mutation outcome.
pub fn with_revision(query: &str, revision: u64) -> String {
    // The parser accepted exactly one statement; append before its semicolon.
    // Trailing comments require token-aware placement, so put the revision on
    // a fresh line after removing the actual terminator outside strings/comments.
    let mut source = query.to_string();
    if let Some(index) = statement_terminator(query) {
        source.truncate(index);
    }
    format!("{source}\nIF REVISION {revision};")
}

pub fn statement_terminator(source: &str) -> Option<usize> {
    let bytes = source.as_bytes();
    let (mut single, mut double, mut line_comment, mut block_comment, mut depth, mut i) =
        (false, false, false, false, 0_usize, 0_usize);
    while i < bytes.len() {
        if line_comment {
            if bytes[i] == b'\n' {
                line_comment = false;
            }
        } else if block_comment {
            if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                block_comment = false;
                i += 1;
            }
        } else if single {
            if bytes[i] == b'\'' {
                if bytes.get(i + 1) == Some(&b'\'') {
                    i += 1;
                } else {
                    single = false;
                }
            }
        } else if double {
            if bytes[i] == b'"' {
                if bytes.get(i + 1) == Some(&b'"') {
                    i += 1;
                } else {
                    double = false;
                }
            }
        } else if bytes[i] == b'\'' {
            single = true;
        } else if bytes[i] == b'"' {
            double = true;
        } else if bytes[i] == b'-' && bytes.get(i + 1) == Some(&b'-') {
            line_comment = true;
            i += 1;
        } else if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            block_comment = true;
            i += 1;
        } else {
            match bytes[i] {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth = depth.saturating_sub(1),
                b';' if depth == 0 => return Some(i),
                _ => {}
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_output_is_exclusive_and_does_not_overwrite_existing_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let mut output = KeyDestination::create(&path).unwrap();
        assert!(KeyDestination::create(&path).is_err());
        output.save("test-key").unwrap();
        drop(output);
        assert_eq!(read_key(&path).unwrap(), "test-key");
        assert!(KeyDestination::create(&path).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "test-key\n");
    }
    #[test]
    fn terminator_ignores_strings_and_comments() {
        assert_eq!(
            statement_terminator("GET x POINTS 'a;b'; -- comment;"),
            Some(18)
        );
        assert_eq!(
            with_revision("CREATE ROLE r; -- comment;", 12),
            "CREATE ROLE r\nIF REVISION 12;"
        );
        let transaction = "TRANSACTION { SQL INSERT INTO t VALUES ('a;b'); VECTOR UPSERT INTO c {id: 'a', vector: [1]}; GRAPH CONNECT c 'a' -> E -> 'a'; };";
        assert_eq!(
            statement_terminator(transaction),
            Some(transaction.len() - 1)
        );
    }
}
