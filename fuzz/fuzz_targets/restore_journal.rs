#![no_main]

use std::fs;

use chirondb_core::Db;
use libfuzzer_sys::fuzz_target;

mod support;

const ROOT_IDENTITY: &str = "5908acf314e167f47db94f38b0145306fca1c7045f5ef2f65f5f0edee7d3a593";

fuzz_target!(|input: &[u8]| {
    let Ok(directory) = tempfile::tempdir() else {
        return;
    };
    let root = directory.path().join("db-root");
    let control = directory
        .path()
        .join(format!(".chirondb-restore-{ROOT_IDENTITY}"));
    if fs::create_dir_all(&root).is_err()
        || fs::create_dir_all(control.join("stage")).is_err()
        || fs::write(
            control.join(".chirondb-restore.journal"),
            support::restore_journal_bytes(input),
        )
        .is_err()
    {
        return;
    }
    let _ = Db::open(&root);
});
