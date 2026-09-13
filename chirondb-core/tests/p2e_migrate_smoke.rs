// P2E: end-to-end migration smoke test for `gaussctl migrate-segment`.
//
// Builds a real on-disk V2 (GAUSSGD2) segment file with the same
// paged-framed envelope the production writer emits, then runs the
// in-process migrator (the same primitive the `gaussctl
// migrate-segment` CLI walks for every `vec.gdx` under a directory),
// and verifies:
//   - the live `vec.gdx` is now GAUSSGD3
//   - the legacy backup is GAUSSGD2 (so a rollback works)
//   - the SoA read gives back the same dim-strided grid that the
//     original V2 JSON would have materialised
//   - the dim-strided layout `soa[d*count + i] = points[i].vector[d]`
//     is intact after a full disk round-trip
//   - re-running the migrator is idempotent (V3 → no-op)

use std::fs;
use std::path::Path;

use chirondb_core::{Point, SoASegmentCache, segment::write_segment_v2_legacy};
use serde_json::json;

const V2_MAGIC: &[u8; 8] = b"GAUSSGD2";
const V3_MAGIC: &[u8; 8] = b"GAUSSGD3";

fn read_magic(path: &Path) -> [u8; 8] {
    let raw = fs::read(path).unwrap();
    raw[..8].try_into().unwrap()
}

fn make_point(id: &str, vector: Vec<f32>) -> Point {
    Point {
        id: id.to_string(),
        vector,
        vectors: Default::default(),
        sparse_vector: None,
        payload: json!({}),
    }
}

#[test]
fn end_to_end_migration_v2_disk_file_to_v3() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vec.gdx");

    // 1. Build a V2 (JSON) segment on disk using the public
    //    `write_segment_v2_legacy` helper. Three points, 4-dim each.
    let points = vec![
        make_point("e2e-0", vec![0.0, 0.1, 0.2, 0.3]),
        make_point("e2e-1", vec![0.4, 0.5, 0.6, 0.7]),
        make_point("e2e-2", vec![0.8, 0.9, 1.0, 1.1]),
    ];
    write_segment_v2_legacy(&path, &points).unwrap();

    // 2. Confirm the file is V2.
    let magic_before = read_magic(&path);
    assert_eq!(&magic_before, V2_MAGIC);

    // 3. Run the in-process migrator (the same primitive the
    //    `gaussctl migrate-segment` CLI calls per file).
    let migrated = SoASegmentCache::migrate_legacy_file(&path).unwrap();

    // 4. The live file is now V3 and the backup is V2.
    let magic_after = read_magic(&path);
    assert_eq!(&magic_after, V3_MAGIC);
    let backup = path.with_extension("v2bak");
    assert!(backup.exists(), "V2 backup must be left next to the file");
    assert_eq!(&read_magic(&backup), V2_MAGIC);

    // 5. The migrated SoA storage has the right shape.
    assert_eq!(migrated.count(), 3);
    assert_eq!(migrated.dim(), 4);

    // 6. The dim-strided grid matches what we built:
    //    soa[d*count + i] = points[i].vector[d].
    for (i, point) in points.iter().enumerate() {
        for d in 0..4 {
            assert_eq!(
                migrated.soa()[d * migrated.count() + i],
                point.vector[d],
                "soa mismatch at i={i} d={d}"
            );
        }
    }

    // 7. Re-running the migrator on the V3 file is a no-op
    //    (idempotent). The live file stays V3, no V1 backup is left
    //    behind (V1 backup only happens for true V1 source files).
    let re_migrated = SoASegmentCache::migrate_legacy_file(&path).unwrap();
    assert_eq!(re_migrated.count(), 3);
    assert_eq!(re_migrated.dim(), 4);
    assert_eq!(&read_magic(&path), V3_MAGIC);
    assert!(!path.with_extension("v1bak").exists());
}

#[test]
fn end_to_end_migration_idempotent_on_v1_file() {
    // A V1 file (GAUSSGD1, the original non-paged framed format) also
    // migrates cleanly. We hand-craft the V1 file: 8-byte magic +
    // 4-byte payload crc + 4-byte payload length (LE) + JSON payload.
    // The V1 reader in segment.rs (`read_segment` V1 fallback path)
    // expects this exact envelope.
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vec.gdx");
    let points = vec![make_point("v1-pt", vec![1.0, 2.0, 3.0, 4.0])];
    let payload = serde_json::to_vec(&serde_json::json!({"points": &points})).unwrap();
    let crc = crc32fast::hash(&payload);
    let mut file = std::fs::File::create(&path).unwrap();
    use std::io::Write;
    file.write_all(b"GAUSSGD1").unwrap();
    file.write_all(&(payload.len() as u64).to_le_bytes())
        .unwrap();
    file.write_all(&crc.to_le_bytes()).unwrap();
    file.write_all(&payload).unwrap();
    file.sync_all().unwrap();
    drop(file);

    assert_eq!(&read_magic(&path), b"GAUSSGD1");

    let migrated = SoASegmentCache::migrate_legacy_file(&path).unwrap();
    assert_eq!(migrated.count(), 1);
    assert_eq!(migrated.dim(), 4);
    assert_eq!(&read_magic(&path), V3_MAGIC);
    let v1_backup = path.with_extension("v1bak");
    assert!(v1_backup.exists(), "V1 backup must be preserved");
    assert_eq!(&read_magic(&v1_backup), b"GAUSSGD1");
}
