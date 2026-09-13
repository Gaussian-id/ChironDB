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
    let path = temp.path().join("artifact.gdx");
    let _ = fs::write(&path, data);
    match data.first().copied().unwrap_or_default() % 8 {
        0 => {
            let _ = chirondb_core::h2qg::read_index(&path);
        }
        1 => {
            let _ = chirondb_core::h2qg::read_hnsw_vecs(&path);
        }
        2 => {
            let _ = chirondb_core::index::ivf::IvfArtifact::open(&path);
        }
        3 => {
            let _ = chirondb_core::segment::read_vamana_index(&path);
        }
        4 => {
            let _ = chirondb_core::index::diskann::DiskAnnArtifact::open(&path, 0, 0);
        }
        5 => {
            let _ = chirondb_core::encryption::inspect_file(&path);
        }
        6 => {
            if let Ok(ivf) = chirondb_core::index::ivf::IvfArtifact::open(&path) {
                let _ = chirondb_core::index::rabitq::RabitqArtifact::open(&path, &ivf);
            }
        }
        _ => {
            if let Ok(ivf) = chirondb_core::index::ivf::IvfArtifact::open(&path) {
                let _ = chirondb_core::index::vamana::VamanaArtifact::open(&path, &ivf);
            }
        }
    }
});
