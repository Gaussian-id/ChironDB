#![no_main]

use std::fs;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    let Ok(temp) = tempfile::tempdir() else {
        return;
    };
    let root = temp.path();
    let selector = data.first().copied().unwrap_or_default() % 8;
    match selector {
        0 => {
            let wal = root.join("000000.gdwal");
            let _ = fs::write(wal, data);
            let _ = chirondb_core::wal::Wal::load(root);
        }
        1 => {
            let _ = fs::write(root.join(chirondb_core::checkpoint::CHECKPOINT_FILE), data);
            let _ = chirondb_core::checkpoint::read_checkpoint(root);
        }
        2 => {
            let _ = fs::write(root.join(chirondb_core::snapshot::SNAPSHOT_FILE), data);
            let _ = chirondb_core::snapshot::read_snapshot_marker(root);
        }
        3 => {
            let _ = fs::write(root.join(chirondb_core::seal::SEAL_FILE), data);
            let _ = chirondb_core::seal::read_marker(&root.join(chirondb_core::seal::SEAL_FILE));
        }
        4 => {
            let _ = fs::write(root.join("audit.jsonl"), data);
            let _ = chirondb_core::audit::verify_hash_chain(root);
        }
        5 => {
            let _ = fs::write(root.join("envelope.enc"), data);
            let _ = chirondb_core::encryption::inspect_file(&root.join("envelope.enc"));
        }
        6 => {
            let _ = fs::write(root.join("catalog.json"), data);
            let _ = chirondb_core::Db::open(root);
        }
        _ => {
            let collection = root.join("collections/fuzz");
            let _ = fs::create_dir_all(&collection);
            let _ = fs::write(
                collection.join(chirondb_core::checkpoint::SEGMENTS_MANIFEST_FILE),
                data,
            );
            let _ = chirondb_core::checkpoint::read_segments_manifest(&collection);
        }
    }
});
