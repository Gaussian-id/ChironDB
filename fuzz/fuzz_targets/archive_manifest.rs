#![no_main]

use std::fs;

use chirondb_core::wal::Wal;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let Ok(directory) = tempfile::tempdir() else {
        return;
    };
    if fs::write(directory.path().join("000000.gdwal"), []).is_err()
        || fs::write(directory.path().join("wal.manifest.json"), input).is_err()
    {
        return;
    }
    let _ = Wal::scan_from(directory.path(), 0, |_| Ok(()));
});
