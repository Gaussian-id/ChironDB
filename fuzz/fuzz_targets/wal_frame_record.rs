#![no_main]

use chirondb_core::wal::Wal;
use libfuzzer_sys::fuzz_target;

mod support;

fuzz_target!(|input: &[u8]| {
    let Ok(directory) = tempfile::tempdir() else {
        return;
    };
    if support::write_wal_input(directory.path(), input).is_err() {
        return;
    }
    let _ = Wal::scan_from(directory.path(), 0, |_| Ok(()));
});
