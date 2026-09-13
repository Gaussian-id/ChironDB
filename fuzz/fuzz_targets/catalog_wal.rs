#![no_main]

use chirondb_core::{
    GaussError,
    wal::{Wal, WalEntry},
};
use libfuzzer_sys::fuzz_target;

mod support;

fuzz_target!(|input: &[u8]| {
    let Ok(directory) = tempfile::tempdir() else {
        return;
    };
    if support::write_wal_input(directory.path(), input).is_err() {
        return;
    }
    let _ = Wal::scan_from(directory.path(), 0, |record| match record.entry {
        WalEntry::CreateCollection { .. } | WalEntry::DropCollection { .. } => Ok(()),
        _ => Err(GaussError::WalCorruption {
            path: directory.path().display().to_string(),
            message: "collection record found in catalog WAL".to_string(),
        }),
    });
});
