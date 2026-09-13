use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};

use chirondb::{
    CollectionConfig, Db, DistanceMetric, Filter, HybridFusion, HybridSearchRequest, Point,
    RecommendRequest, RerankRequest, SearchRequest, SparseVector, wal::Wal,
};
use serde_json::json;
use tempfile::TempDir;

#[derive(Clone, Copy, Debug)]
enum SimStep {
    Upsert { id: u8, x: i16, y: i16 },
    Delete { id: u8 },
    Compact,
    Restart,
}

#[test]
fn deterministic_fail_restart_simulation_replays_every_committed_prefix() {
    let active = TempDir::new().unwrap();
    let mut model = HashMap::<String, Point>::new();
    let mut db = open_seeded_db(active.path());

    drop(db);
    assert_root_matches_model(active.path(), &model);
    assert_crash_image_matches("after-create", active.path(), &model);
    db = Db::open(active.path()).unwrap();

    let schedule = [
        SimStep::Upsert { id: 0, x: 10, y: 1 },
        SimStep::Upsert { id: 1, x: 2, y: 10 },
        SimStep::Restart,
        SimStep::Compact,
        SimStep::Upsert { id: 2, x: 8, y: 3 },
        SimStep::Delete { id: 0 },
        SimStep::Compact,
        SimStep::Upsert { id: 3, x: 9, y: 2 },
        SimStep::Delete { id: 1 },
        SimStep::Restart,
    ];

    for (index, step) in schedule.into_iter().enumerate() {
        apply_step(&mut db, &mut model, step);
        drop(db);

        assert_root_matches_model(active.path(), &model);
        assert_crash_image_matches(&format!("step-{index}-{step:?}"), active.path(), &model);

        db = Db::open(active.path()).unwrap();
    }
}

#[test]
fn deterministic_active_wal_tail_simulation_repairs_partial_headers_and_payloads() {
    let active = TempDir::new().unwrap();
    let db = open_seeded_db(active.path());
    db.upsert("docs", vec![model_point(0, 10, 1)]).unwrap();
    drop(db);
    let wal_path = first_wal_path(active.path());
    let committed_len = fs::metadata(&wal_path).unwrap().len();

    for partial_header_len in 1..8 {
        let crash_image = TempDir::new().unwrap();
        copy_dir_contents(active.path(), crash_image.path()).unwrap();
        let crash_wal = first_wal_path(crash_image.path());
        append_bytes(&crash_wal, &vec![0_u8; partial_header_len]);

        let strict_error = Wal::load(crash_wal.parent().unwrap()).unwrap_err();
        assert!(
            strict_error.to_string().contains("partial wal header"),
            "unexpected strict partial-header error: {strict_error}"
        );

        let recovered = Db::open(crash_image.path()).unwrap();
        assert_eq!(recovered.count("docs", None).unwrap().count, 1);
        drop(recovered);
        assert_eq!(fs::metadata(&crash_wal).unwrap().len(), committed_len);
        assert_eq!(Wal::load(crash_wal.parent().unwrap()).unwrap().len(), 1);
    }

    let partial_payload = TempDir::new().unwrap();
    copy_dir_contents(active.path(), partial_payload.path()).unwrap();
    let partial_payload_wal = first_wal_path(partial_payload.path());
    let mut torn_record = Vec::new();
    torn_record.extend_from_slice(&16_u32.to_le_bytes());
    torn_record.extend_from_slice(&0_u32.to_le_bytes());
    torn_record.extend_from_slice(&[1, 2, 3]);
    append_bytes(&partial_payload_wal, &torn_record);

    let strict_error = Wal::load(partial_payload_wal.parent().unwrap()).unwrap_err();
    assert!(
        strict_error.to_string().contains("torn wal record"),
        "unexpected strict partial-payload error: {strict_error}"
    );
    let stats = Wal::recover_from(partial_payload_wal.parent().unwrap(), 0, |_| Ok(())).unwrap();
    assert_eq!(stats.records, 1);
    assert_eq!(stats.end_lsn, committed_len);
    assert_eq!(stats.repaired_tail_bytes, torn_record.len() as u64);
    let recovered = Db::open(partial_payload.path()).unwrap();
    assert_eq!(recovered.count("docs", None).unwrap().count, 1);
    drop(recovered);
    assert_eq!(
        fs::metadata(&partial_payload_wal).unwrap().len(),
        committed_len
    );
}

#[test]
fn deterministic_wal_corruption_matrix_fails_closed() {
    let active = TempDir::new().unwrap();
    let db = open_seeded_db(active.path());
    db.upsert("docs", vec![model_point(0, 10, 1)]).unwrap();
    drop(db);

    let excessive_length = TempDir::new().unwrap();
    copy_dir_contents(active.path(), excessive_length.path()).unwrap();
    let mut oversized_header = Vec::new();
    oversized_header.extend_from_slice(&u32::MAX.to_le_bytes());
    oversized_header.extend_from_slice(&0_u32.to_le_bytes());
    append_bytes(&first_wal_path(excessive_length.path()), &oversized_header);
    let error = Db::open(excessive_length.path()).unwrap_err();
    assert!(
        error.to_string().contains("maximum"),
        "unexpected excessive WAL length error: {error}"
    );

    let bad_crc = TempDir::new().unwrap();
    copy_dir_contents(active.path(), bad_crc.path()).unwrap();
    corrupt_wal_payload(&first_wal_path(bad_crc.path()));
    let error = Db::open(bad_crc.path()).unwrap_err();
    assert!(
        error.to_string().contains("crc mismatch"),
        "unexpected WAL CRC error: {error}"
    );

    let bad_json = TempDir::new().unwrap();
    copy_dir_contents(active.path(), bad_json.path()).unwrap();
    let payload = b"not-json";
    let mut invalid_record = Vec::new();
    invalid_record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    invalid_record.extend_from_slice(&test_crc32(payload).to_le_bytes());
    invalid_record.extend_from_slice(payload);
    append_bytes(&first_wal_path(bad_json.path()), &invalid_record);
    let error = Db::open(bad_json.path()).unwrap_err();
    assert!(
        error.to_string().contains("expected ident"),
        "unexpected WAL JSON error: {error}"
    );

    let segment_gap = TempDir::new().unwrap();
    copy_dir_contents(active.path(), segment_gap.path()).unwrap();
    let gap_segment = wal_dir(segment_gap.path()).join("000002.gdwal");
    let gap_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(gap_segment)
        .unwrap();
    gap_file.sync_all().unwrap();
    let error = Db::open(segment_gap.path()).unwrap_err();
    assert!(
        error.to_string().contains("gap"),
        "unexpected WAL segment-gap error: {error}"
    );

    let corrupt_base = TempDir::new().unwrap();
    copy_dir_contents(active.path(), corrupt_base.path()).unwrap();
    let base_path = wal_dir(corrupt_base.path()).join("wal.base");
    let mut base_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(base_path)
        .unwrap();
    base_file.write_all(b"invalid-wal-base").unwrap();
    base_file.sync_all().unwrap();
    let error = Db::open(corrupt_base.path()).unwrap_err();
    assert!(
        error.to_string().contains("invalid wal.base header"),
        "unexpected wal.base error: {error}"
    );

    let sealed_tail = TempDir::new().unwrap();
    copy_dir_contents(active.path(), sealed_tail.path()).unwrap();
    append_bytes(&first_wal_path(sealed_tail.path()), &[0, 0, 0]);
    let active_segment = wal_dir(sealed_tail.path()).join("000001.gdwal");
    let active_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(active_segment)
        .unwrap();
    active_file.sync_all().unwrap();
    let error = Db::open(sealed_tail.path()).unwrap_err();
    assert!(
        error.to_string().contains("partial wal header"),
        "unexpected sealed WAL tail error: {error}"
    );
}

#[test]
fn deterministic_disk_fault_simulation_rejects_corrupt_segment_marker() {
    let active = TempDir::new().unwrap();
    let db = open_seeded_db(active.path());
    db.upsert("docs", vec![model_point(0, 10, 1)]).unwrap();
    db.compact_collection("docs").unwrap();
    db.upsert("docs", vec![model_point(1, 7, 4)]).unwrap();
    drop(db);

    let corrupt_marker = TempDir::new().unwrap();
    copy_dir_contents(active.path(), corrupt_marker.path()).unwrap();
    corrupt_byte(&first_segment_marker_path(corrupt_marker.path()));
    let error = Db::open(corrupt_marker.path()).unwrap_err();
    assert!(
        error.to_string().contains("marker crc mismatch"),
        "unexpected corrupt segment marker error: {error}"
    );
}

#[test]
fn concurrent_restore_keeps_hybrid_recommend_and_rerank_consistent() {
    let active = TempDir::new().unwrap();
    let snapshot = TempDir::new().unwrap();
    let db = open_seeded_db(active.path());
    db.upsert(
        "docs",
        vec![
            model_point(0, 10, 1),
            model_point(1, 8, 2),
            model_point(2, 1, 10),
        ],
    )
    .unwrap();
    db.snapshot(snapshot.path()).unwrap();

    let maintenance_observations = Arc::new(AtomicUsize::new(0));
    let mut completed = 0_usize;
    for _ in 0..3 {
        let start = Arc::new(Barrier::new(4));
        let primed = Arc::new(Barrier::new(4));
        let stop = Arc::new(AtomicBool::new(false));
        let workers = [
            LifecycleQuery::Hybrid,
            LifecycleQuery::Recommend,
            LifecycleQuery::Rerank,
        ]
        .map(|kind| {
            let db = db.clone();
            let start = Arc::clone(&start);
            let primed = Arc::clone(&primed);
            let stop = Arc::clone(&stop);
            let maintenance_observations = Arc::clone(&maintenance_observations);
            thread::spawn(move || {
                start.wait();
                let mut completed = 1_usize;
                let mut successful = usize::from(run_lifecycle_query(&db, kind));
                primed.wait();
                while !stop.load(Ordering::Acquire) {
                    let maintenance_before = !db.durability_ready();
                    let succeeded = run_lifecycle_query(&db, kind);
                    let maintenance_after = !db.durability_ready();
                    if maintenance_before || maintenance_after {
                        maintenance_observations.fetch_add(1, Ordering::Relaxed);
                    }
                    completed += 1;
                    successful += usize::from(succeeded);
                    thread::yield_now();
                }
                (completed, successful)
            })
        });

        start.wait();
        primed.wait();
        db.restore(snapshot.path()).unwrap();
        stop.store(true, Ordering::Release);
        for worker in workers {
            let (worker_completed, worker_successful) = worker.join().unwrap();
            completed += worker_completed;
            assert!(worker_successful > 0, "query worker never succeeded");
        }
    }

    assert!(completed > 0, "query workers never started");
    assert!(
        maintenance_observations.load(Ordering::Relaxed) > 0,
        "workers never observed the restore maintenance interval"
    );
}

#[cfg(unix)]
#[test]
fn snapshot_and_restore_reject_symlink_paths_into_live_root() {
    use std::os::unix::fs::symlink;

    let link_root = TempDir::new().unwrap();

    let snapshot_active = TempDir::new().unwrap();
    let snapshot_db = open_seeded_db(snapshot_active.path());
    let live_link = link_root.path().join("live-root");
    symlink(snapshot_active.path(), &live_link).unwrap();
    let error = snapshot_db
        .snapshot(live_link.join("nested-snapshot"))
        .unwrap_err();
    assert!(
        error.to_string().contains("live data directory"),
        "unexpected symlinked snapshot-path error: {error}"
    );

    let restore_active = TempDir::new().unwrap();
    let restore_db = open_seeded_db(restore_active.path());
    restore_db
        .upsert("docs", vec![model_point(0, 10, 1)])
        .unwrap();
    let valid_snapshot = TempDir::new().unwrap();
    restore_db.snapshot(valid_snapshot.path()).unwrap();
    let embedded_snapshot = restore_active.path().join("embedded-snapshot");
    copy_dir_contents(valid_snapshot.path(), &embedded_snapshot).unwrap();
    let embedded_link = link_root.path().join("embedded-snapshot");
    symlink(&embedded_snapshot, &embedded_link).unwrap();
    let error = restore_db.restore(&embedded_link).unwrap_err();
    assert!(
        error.to_string().contains("live data directory"),
        "unexpected symlinked restore-path error: {error}"
    );
}

#[derive(Clone, Copy)]
enum LifecycleQuery {
    Hybrid,
    Recommend,
    Rerank,
}

fn run_lifecycle_query(db: &Db, kind: LifecycleQuery) -> bool {
    match kind {
        LifecycleQuery::Hybrid => db
            .hybrid_search(
                "docs",
                HybridSearchRequest {
                    graph: None,
                    vector: Some(vec![1.0, 0.0]),
                    vector_name: None,
                    sparse_vector: Some(SparseVector {
                        indices: vec![0],
                        values: vec![1.0],
                    }),
                    k: 2,
                    filter: None,
                    budget_ms: None,
                    fusion: HybridFusion::Rrf,
                    dense_weight: 1.0,
                    sparse_weight: 1.0,
                },
            )
            .is_ok(),
        LifecycleQuery::Recommend => db
            .recommend(
                "docs",
                RecommendRequest {
                    positive: vec![point_id(0)],
                    negative: Vec::new(),
                    vector_name: None,
                    k: 2,
                    filter: None,
                    budget_ms: None,
                },
            )
            .is_ok(),
        LifecycleQuery::Rerank => db
            .rerank(
                "docs",
                RerankRequest {
                    vector: vec![1.0, 0.0],
                    vector_name: None,
                    k: 2,
                    prefetch_k: Some(3),
                    filter: None,
                    score_boosts: Vec::new(),
                    budget_ms: None,
                },
            )
            .is_ok(),
    }
}

fn open_seeded_db(path: &Path) -> Db {
    let db = Db::open(path).unwrap();
    db.create_collection(CollectionConfig {
        name: "docs".to_string(),
        vector_dim: 2,
        metric: DistanceMetric::Cosine,
        shards: 1,
        replicas: 1,
        quantization: None,
        payload_schema: Default::default(),
        named_vector_dims: Default::default(),
        hnsw_m: None,
        hnsw_ef_construction: None,
        hnsw_ef_search: None,
        recall_sla: None,
        index_kind: None,
        streamer_max_bytes: 0,
    })
    .unwrap();
    db
}

fn apply_step(db: &mut Db, model: &mut HashMap<String, Point>, step: SimStep) {
    match step {
        SimStep::Upsert { id, x, y } => {
            let point = model_point(id, x, y);
            db.upsert("docs", vec![point.clone()]).unwrap();
            model.insert(point.id.clone(), point);
        }
        SimStep::Delete { id } => {
            let point_id = point_id(id);
            db.delete("docs", std::slice::from_ref(&point_id)).unwrap();
            model.remove(&point_id);
        }
        SimStep::Compact => {
            db.compact_collection("docs").unwrap();
        }
        SimStep::Restart => {}
    }
}

fn assert_crash_image_matches(label: &str, source: &Path, model: &HashMap<String, Point>) {
    let crash_image = TempDir::new().unwrap();
    copy_dir_contents(source, crash_image.path())
        .unwrap_or_else(|error| panic!("failed to copy crash image {label}: {error}"));
    assert_root_matches_model(crash_image.path(), model);
}

fn assert_root_matches_model(path: &Path, model: &HashMap<String, Point>) {
    let db = Db::open(path).unwrap();
    assert_eq!(db.count("docs", None).unwrap().count, model.len());

    let even_filter = Filter(json!({"bucket": "even"}));
    assert_eq!(
        db.count("docs", Some(even_filter.clone())).unwrap().count,
        model
            .values()
            .filter(|point| even_filter.matches(&point.payload))
            .count()
    );

    assert_search_matches(&db, model, None, None);
    assert_search_matches(&db, model, Some("image"), None);
    assert_search_matches(&db, model, None, Some(even_filter));
}

fn assert_search_matches(
    db: &Db,
    model: &HashMap<String, Point>,
    vector_name: Option<&str>,
    filter: Option<Filter>,
) {
    let query = vec![1.0, 0.0];
    let actual = db
        .search(
            "docs",
            SearchRequest {
                graph: None,
                vector: query.clone(),
                vector_name: vector_name.map(ToString::to_string),
                k: 3,
                filter: filter.clone(),
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: None,
            },
        )
        .unwrap()
        .hits
        .into_iter()
        .map(|hit| hit.id)
        .collect::<Vec<_>>();
    let expected = exact_top_ids(model, &query, vector_name, filter.as_ref(), 3);
    assert_eq!(actual, expected);
}

fn exact_top_ids(
    model: &HashMap<String, Point>,
    query: &[f32],
    vector_name: Option<&str>,
    filter: Option<&Filter>,
    k: usize,
) -> Vec<String> {
    let mut scored = model
        .values()
        .filter(|point| filter.is_none_or(|filter| filter.matches(&point.payload)))
        .filter_map(|point| {
            let vector = match vector_name {
                Some(name) => point.vectors.get(name)?,
                None => &point.vector,
            };
            let score = DistanceMetric::Cosine.score(query, vector).unwrap();
            Some((point.id.clone(), score))
        })
        .collect::<Vec<_>>();
    scored.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    scored.into_iter().take(k).map(|(id, _)| id).collect()
}

fn model_point(id: u8, x: i16, y: i16) -> Point {
    let id = point_id(id);
    let slot = id_slot(&id);
    let vector = vec![x as f32 / 10.0, y as f32 / 10.0];
    Point {
        id,
        vector: vector.clone(),
        vectors: HashMap::from([("image".to_string(), vec![vector[1], vector[0]])]),
        sparse_vector: Some(SparseVector {
            indices: vec![(x.unsigned_abs() % 5) as u32],
            values: vec![(y.unsigned_abs() as f32 + 1.0) / 10.0],
        }),
        payload: json!({
            "bucket": if x % 2 == 0 { "even" } else { "odd" },
            "slot": slot,
        }),
    }
}

fn point_id(id: u8) -> String {
    format!("p-{id}")
}

fn id_slot(id: &str) -> u8 {
    id.strip_prefix("p-")
        .and_then(|value| value.parse().ok())
        .unwrap_or_default()
}

fn copy_dir_contents(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_contents(&source_path, &destination_path)?;
        } else {
            fs::copy(&source_path, &destination_path)?;
        }
    }
    Ok(())
}

fn append_bytes(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn corrupt_wal_payload(path: &Path) {
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(8)).unwrap();
    file.write_all(b"x").unwrap();
    file.sync_all().unwrap();
}

fn wal_dir(root: &Path) -> PathBuf {
    root.join("collections/docs/wal")
}

fn first_wal_path(root: &Path) -> PathBuf {
    wal_dir(root).join("000000.gdwal")
}

fn test_crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn corrupt_byte(path: &Path) {
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(20)).unwrap();
    file.write_all(b"x").unwrap();
    file.sync_all().unwrap();
}

fn first_segment_marker_path(root: &Path) -> PathBuf {
    fs::read_dir(root.join("collections/docs/searchers"))
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            ["seal.gdx", "manifest.gdx"]
                .into_iter()
                .map(|name| entry.path().join(name))
                .find(|marker| marker.exists())
        })
        .next()
        .expect("compacted segment commit marker")
}
