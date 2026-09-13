#![no_main]

use std::{env, sync::Once};

use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 1024 * 1024;
const ENCRYPTED_ENV: &str = "CHIRONDB_GDX_FUZZ_ENCRYPTED";

static ENCRYPTION: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let Ok(temp) = tempfile::tempdir() else {
        return;
    };
    if env::var_os(ENCRYPTED_ENV).is_some() {
        ENCRYPTION.call_once(|| {
            chirondb_core::graph_fuzz::install_fixed_fuzz_keyring(temp.path())
                .expect("fixed graph fuzz keyring must install");
        });
    }
    chirondb_core::graph_fuzz::exercise_graph_loader(temp.path(), data);
});
