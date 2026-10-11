use super::*;
use crate::relational::wal_decode::with_test_storage_pool;

#[test]
fn encrypted_search_candidate_owner_preserves_visibility_faults_and_cold_values() {
    encrypted_process(|| {
        for kind in [
            crate::seal::SealIndexKind::Hnsw,
            crate::seal::SealIndexKind::Algorithm2,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("segment");
            let expected = crate::Point {
                id: "owned".into(),
                vector: vec![1.25; 16],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: serde_json::json!({"text":"z".repeat(8192)}),
            };
            crate::seal::build_segment(
                std::slice::from_ref(&expected),
                &path,
                crate::seal::SealConfig {
                    vector_dim: 16,
                    metric: crate::DistanceMetric::L2,
                    hnsw_m: None,
                    hnsw_ef_construction: None,
                    index_kind: kind,
                    base_lsn: 0,
                    end_lsn: 1,
                },
            )
            .unwrap();
            let store = Arc::new(crate::seal::V4Store::open(&path).unwrap());
            let index = match kind {
                crate::seal::SealIndexKind::Algorithm2 => {
                    crate::searcher::SegmentIndex::Ivf(Box::new(
                        crate::index::ivf_segment::IvfSegmentIndex::open(
                            &path,
                            store.clone(),
                            crate::DistanceMetric::L2,
                        )
                        .unwrap(),
                    ))
                }
                _ => crate::searcher::SegmentIndex::None,
            };
            let searcher = crate::searcher::SegmentSearcher {
                id: "segment".into(),
                dir: path.clone(),
                index,
                named_index: HashMap::new(),
                store: crate::searcher::SegmentStore::V4(store),
                ordinal_payload_index: None,
                tombstones: HashSet::new(),
                tombstone_ordinals: roaring::RoaringBitmap::new(),
            };
            assert_eq!(
                serde_json::to_value(
                    searcher
                        .get_visible("owned", None)
                        .unwrap()
                        .unwrap()
                        .as_ref()
                )
                .unwrap(),
                serde_json::to_value(&expected).unwrap()
            );
            let payload = path.join(crate::seal::PAYLOAD_FILE);
            let before = fs::read(&payload).unwrap();
            let mut bad = before.clone();
            let last = bad.len() - 1;
            bad[last] ^= 1;
            persistent_chunk_cache().write().unwrap().shrink_to(0);
            fs::write(&payload, &bad).unwrap();
            let hidden = roaring::RoaringBitmap::from_iter([0]);
            with_test_storage_pool(1, |used| {
                assert!(
                    searcher
                        .get_visible_admitted("owned", Some(&hidden))
                        .unwrap()
                        .is_none()
                );
                assert_eq!(
                    used(),
                    0,
                    "visibility rejects before allocation or corrupt payload IO"
                );
                assert!(matches!(
                    searcher.get_visible_admitted("owned", None),
                    Err(GaussError::ResourceExhausted(_))
                ));
                assert_eq!(used(), 0);
            });
            with_test_storage_pool(2 * 1024 * 1024, |used| {
                assert!(
                    matches!(searcher.get_visible_admitted("owned",None),Err(GaussError::InvalidRequest(message)) if message.contains("AES-GCM authentication failed"))
                );
                persistent_chunk_cache().write().unwrap().shrink_to(0);
                assert_eq!(
                    used(),
                    0,
                    "late hydration failure releases partial candidate owners"
                );
                fs::write(&payload, &before).unwrap();
                let candidate = searcher
                    .get_visible_admitted("owned", None)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    serde_json::to_value(&*candidate).unwrap(),
                    serde_json::to_value(&expected).unwrap()
                );
                let mut rows = crate::search::AdmittedVec::default();
                rows.push(candidate).unwrap();
                let mut iter = rows.into_iter();
                let crate::search::CandidatePoint::Owned(point) = iter.next().unwrap() else {
                    panic!("sealed candidate must own admitted data")
                };
                drop(iter);
                drop(searcher);
                let retained = used();
                assert!(retained > 8192);
                assert_eq!(
                    serde_json::to_value(&*point).unwrap(),
                    serde_json::to_value(&expected).unwrap()
                );
                drop(point);
                assert_eq!(used(), 0);
            });
            assert_eq!(fs::read(payload).unwrap(), before);
        }
    });
}

#[test]
fn encrypted_paged_decoded_vector_reserves_after_range_and_survives_cache_eviction() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hnsw-vecs.gdx");
        let expected = vec![1.25; 16384];
        crate::h2qg::write_hnsw_vecs(&path, std::slice::from_ref(&expected)).unwrap();
        let plaintext = fs::read(&path).unwrap();
        atomic_write_persistent(&path, FileType::Segment, &plaintext).unwrap();
        let before = fs::read(&path).unwrap();
        let paged = crate::h2qg::read_hnsw_vecs(&path).unwrap();
        assert_eq!(paged.try_get(0).unwrap().as_ref(), expected);
        with_test_storage_pool(expected.len() as u64 * 4 + 4096, |used| {
            assert!(matches!(
                paged.try_get(0),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(
                used(),
                0,
                "decoded refusal frees admitted range without a partial result"
            );
        });
        with_test_storage_pool(1024 * 1024, |used| {
            let row = paged.try_get(0).unwrap().into_owned_read().unwrap();
            persistent_chunk_cache().write().unwrap().shrink_to(0);
            let retained = used();
            assert!(retained > expected.len() as u64 * 4);
            let row = Some(row);
            assert_eq!(used(), retained);
            assert_eq!(row.as_ref().unwrap().as_ref(), expected);
            drop(row);
            assert_eq!(used(), 0);
        });
        assert_eq!(fs::read(path).unwrap(), before);
    });
}

#[test]
fn admitted_range_moves_hold_output_lease_after_cache_eviction() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("range.gdx");
        let plaintext = vec![37_u8; DEFAULT_CHUNK_SIZE * 2 + 73];
        atomic_write_persistent(&path, FileType::Segment, &plaintext).unwrap();
        let file = PersistentFile::open(&path).unwrap();
        with_test_storage_pool(2 * 1024 * 1024, |used| {
            let owner = file.read_range_admitted(13..plaintext.len() - 17).unwrap();
            persistent_chunk_cache().write().unwrap().shrink_to(0);
            let retained = used();
            assert!(retained > owner.len() as u64);
            assert!(owner.borrowed_bytes().is_none());
            let mut moved = Some(owner);
            assert_eq!(used(), retained);
            assert_eq!(
                &**moved.as_ref().unwrap(),
                &plaintext[13..plaintext.len() - 17]
            );
            drop(moved.take());
            assert_eq!(used(), 0);
            assert_eq!(file.read_range_admitted(7..7).unwrap().len(), 0);
            assert!(matches!(file.read_range(7..7).unwrap(), Cow::Owned(_)));
            assert_eq!(used(), 0);
        });
        let canceled = Arc::new(AtomicBool::new(true));
        assert!(matches!(
            crate::relational::with_sql_cancellation(canceled, || file.read_range_admitted(0..1)),
            Err(GaussError::InvalidRequest(message)) if message == "query canceled"
        ));
    });
}

#[test]
fn admitted_range_late_authentication_failure_releases_partial_output_then_reopens() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("range.gdx");
        let plaintext = vec![31_u8; DEFAULT_CHUNK_SIZE * 2 + 73];
        atomic_write_persistent(&path, FileType::Segment, &plaintext).unwrap();
        let original = fs::read(&path).unwrap();
        let mut damaged = original.clone();
        *damaged.last_mut().unwrap() ^= 1;
        fs::write(&path, damaged).unwrap();
        let file = PersistentFile::open(&path).unwrap();
        with_test_storage_pool(2 * 1024 * 1024, |used| {
            let error = file.read_range_admitted(0..plaintext.len()).unwrap_err();
            assert!(
                matches!(error, GaussError::InvalidRequest(ref message) if message.contains("AES-GCM authentication failed")),
                "{error:?}"
            );
            persistent_chunk_cache().write().unwrap().shrink_to(0);
            assert_eq!(
                used(),
                0,
                "partial copied output releases on a late chunk fault"
            );
            assert_eq!(&*file.read_range_admitted(0..17).unwrap(), &plaintext[..17]);
            persistent_chunk_cache().write().unwrap().shrink_to(0);
            assert_eq!(used(), 0);
        });
        drop(file);
        fs::write(&path, original).unwrap();
        let reopened = PersistentFile::open(&path).unwrap();
        assert_eq!(
            &*reopened.read_range_admitted(0..plaintext.len()).unwrap(),
            plaintext
        );
    });
}

#[test]
fn admitted_raw_range_refuses_before_io_and_releases_on_short_read() {
    let mut reader = std::io::Cursor::new(vec![11_u8; 512]);
    with_test_storage_pool(1, |used| {
        assert!(matches!(
            AdmittedRange::read_from(&mut reader, 512),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(reader.position(), 0);
        assert_eq!(used(), 0);
    });
    with_test_storage_pool(16 * 1024, |used| {
        let owner = AdmittedRange::read_from(&mut reader, 512).unwrap();
        assert!(used() > 512);
        assert_eq!(&*owner, &[11; 512]);
        drop(owner);
        assert_eq!(used(), 0);
        reader.set_position(500);
        assert!(AdmittedRange::read_from(&mut reader, 512).is_err());
        assert_eq!(used(), 0);
    });
    let cancel = Arc::new(AtomicBool::new(true));
    reader.set_position(0);
    assert!(
        matches!(crate::relational::with_sql_cancellation(cancel, || AdmittedRange::read_from(&mut reader, 512)), Err(GaussError::InvalidRequest(message)) if message == "query canceled")
    );
    assert_eq!(reader.position(), 0);
}

#[test]
fn admitted_plain_range_preserves_borrowing_and_bounds_without_output_allocation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plain.gdx");
    fs::write(&path, [1_u8, 2, 3, 4]).unwrap();
    let file = PersistentFile::open(&path).unwrap();
    with_test_storage_pool(1, |used| {
        let owner = file.read_range_admitted(1..3).unwrap();
        let pointer = owner.as_ptr();
        assert_eq!(owner.borrowed_bytes().unwrap().as_ptr(), pointer);
        assert_eq!(&*owner, &[2, 3]);
        assert_eq!(used(), 0);
        assert!(file.read_range_admitted(2..5).is_err());
        assert!(
            file.read_range_admitted(Range { start: 3, end: 1 })
                .is_err()
        );
        assert_eq!(file.read_range_admitted(4..4).unwrap().len(), 0);
        assert_eq!(used(), 0);
    });
}

#[test]
fn encrypted_range_output_refuses_even_when_all_chunks_are_cached() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("range.gdx");
        let plaintext = vec![42_u8; DEFAULT_CHUNK_SIZE * 2 + 73];
        atomic_write_persistent(&path, FileType::Segment, &plaintext).unwrap();
        let file = PersistentFile::open(&path).unwrap();
        assert_eq!(&*file.read_range(0..plaintext.len()).unwrap(), plaintext);
        let before = persistent_cache_stats().decrypted_bytes;
        with_test_storage_pool(1, |used| {
            assert!(matches!(
                file.read_range(13..plaintext.len() - 17),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
        });
        assert_eq!(persistent_cache_stats().decrypted_bytes, before);
        assert_eq!(&*file.read_range(13..79).unwrap(), &plaintext[13..79]);
    });
}

#[test]
fn encrypted_diskann_local_and_remote_ranges_refuse_admission_then_retry() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let points = (0..32)
            .map(|i| crate::Point {
                id: format!("p{i}"),
                vector: vec![i as f32 + 0.125; 128],
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            })
            .collect::<Vec<_>>();
        crate::seal::build_segment(
            points.as_slice(),
            dir.path(),
            crate::seal::SealConfig {
                vector_dim: 128,
                metric: crate::DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: crate::seal::SealIndexKind::Algorithm2,
                base_lsn: 0,
                end_lsn: 1,
            },
        )
        .unwrap();
        let path = dir.path().join(crate::index::diskann::DISKANN_FILE);
        let local = crate::index::diskann::DiskAnnArtifact::open(&path, 32, 128).unwrap();
        let store: Arc<dyn object_store::ObjectStore> =
            Arc::new(object_store::local::LocalFileSystem::new_with_prefix(dir.path()).unwrap());
        let remote = crate::index::diskann::DiskAnnArtifact::open_object_store(
            store,
            object_store::path::Path::from(crate::index::diskann::DISKANN_FILE),
            fs::metadata(&path).unwrap().len(),
            32,
            128,
        )
        .unwrap();
        for artifact in [local, remote] {
            with_test_storage_pool(1, |used| {
                assert!(matches!(
                    artifact.try_vectors(&[20, 0, 20]),
                    Err(GaussError::ResourceExhausted(_))
                ));
                assert_eq!(used(), 0);
                assert_eq!(artifact.stats().physical_page_reads, 0);
                assert_eq!(artifact.stats().remote_range_requests, 0);
            });
            with_test_storage_pool(2 * 1024 * 1024, |used| {
                let result = artifact.try_vectors_admitted(&[20, 0, 20]).unwrap();
                assert_eq!(result[0], result[2]);
                assert_eq!(result[0][0], 20.125);
                assert_eq!(result[1][0], 0.125);
                artifact.reset_stats();
                assert!(used() > 0, "rerank vectors retain their output lease");
                drop(result);
                assert_eq!(used(), 0, "page/range reservations released after eviction");
            });
        }
    });
}

#[test]
fn native_sealed_mutations_refuse_resource_pressure_then_retry_and_reopen() {
    encrypted_process(|| {
        for operation in ["upsert", "delete", "filter"] {
            let dir = tempfile::tempdir().unwrap();
            let db = crate::Db::open(dir.path()).unwrap();
            db.create_collection(
                serde_json::from_value(serde_json::json!({
                    "name":"docs", "vector_dim":2, "metric":"l2"
                }))
                .unwrap(),
            )
            .unwrap();
            let old = crate::Point {
                id: "one".into(),
                vector: vec![1.25, -3.5],
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::json!({"kind":"old","blob":"x".repeat(60_000)}),
            };
            db.upsert("docs", vec![old.clone()]).unwrap();
            db.compact_collection("docs").unwrap();
            persistent_chunk_cache().write().unwrap().shrink_to(0);
            reset_persistent_cache_stats();
            let before = db.multimodel_visibility_frontier().unwrap();
            let mut new = old.clone();
            new.payload = serde_json::json!({"kind":"new"});
            let mutate = || match operation {
                "upsert" => db.upsert("docs", vec![new.clone()]),
                "delete" => db.delete("docs", std::slice::from_ref(&old.id)),
                "filter" => {
                    db.delete_by_filter("docs", &crate::Filter(serde_json::json!({"kind":"old"})))
                }
                _ => unreachable!(),
            };
            with_test_storage_pool(1, |used| {
                assert!(matches!(mutate(), Err(GaussError::ResourceExhausted(_))));
                assert_eq!(used(), 0);
                assert_eq!(persistent_cache_stats().decrypted_bytes, 0);
            });
            assert_eq!(db.multimodel_visibility_frontier().unwrap(), before);
            assert_eq!(
                serde_json::to_value(
                    db.get_points("docs", std::slice::from_ref(&old.id))
                        .unwrap()
                )
                .unwrap(),
                serde_json::json!([old])
            );
            assert_eq!(mutate().unwrap(), 1);
            drop(db);
            let reopened = crate::Db::open(dir.path()).unwrap();
            let actual = reopened
                .get_points("docs", std::slice::from_ref(&old.id))
                .unwrap();
            if operation == "upsert" {
                assert_eq!(
                    serde_json::to_value(actual).unwrap(),
                    serde_json::json!([new])
                );
            } else {
                assert!(actual.is_empty());
            }
        }
    });
}

#[test]
fn native_upsert_and_delete_refuse_unreadable_old_rows_before_commit() {
    encrypted_process(|| {
        for operation in ["upsert", "delete", "filter"] {
            let dir = tempfile::tempdir().unwrap();
            let db = crate::Db::open(dir.path()).unwrap();
            db.create_collection(
                serde_json::from_value(serde_json::json!({
                    "name":"docs", "vector_dim":2, "metric":"l2"
                }))
                .unwrap(),
            )
            .unwrap();
            let points = ["a", "z"].map(|id| crate::Point {
                id: id.into(),
                vector: vec![1.0, 2.0],
                vectors: Default::default(),
                sparse_vector: Some(crate::SparseVector {
                    indices: vec![1],
                    values: vec![1.0],
                }),
                payload: serde_json::json!({"kind":"keep", "blob":"x".repeat(60_000)}),
            });
            db.upsert("docs", points.to_vec()).unwrap();
            db.compact_collection("docs").unwrap();
            let mut paths = Vec::new();
            walk_files(dir.path(), &mut |path| {
                if path
                    .file_name()
                    .is_some_and(|name| name == crate::seal::PAYLOAD_FILE)
                {
                    paths.push(path.to_owned());
                }
                Ok(())
            })
            .unwrap();
            assert_eq!(paths.len(), 1);
            let original = fs::read(&paths[0]).unwrap();
            let mut damaged = original.clone();
            let last = damaged.len() - 1;
            damaged[last] ^= 1;
            fs::write(&paths[0], damaged).unwrap();
            persistent_chunk_cache().write().unwrap().shrink_to(0);
            let before = db.multimodel_visibility_frontier().unwrap();
            let mutate = || {
                if operation == "upsert" {
                    let mut replacements = points.to_vec();
                    for point in &mut replacements {
                        point.vector = vec![2.0, 3.0];
                        point.payload = serde_json::json!({"kind":"new"});
                    }
                    db.upsert("docs", replacements)
                } else if operation == "delete" {
                    db.delete("docs", &["a".into(), "z".into()])
                } else {
                    db.delete_by_filter("docs", &crate::Filter(serde_json::json!({"kind":"keep"})))
                }
            };
            let result = with_test_storage_pool(2 * 1024 * 1024, |used| {
                let result = mutate();
                persistent_chunk_cache().write().unwrap().shrink_to(0);
                assert_eq!(used(), 0, "late read failure releases earlier staged rows");
                result
            });
            assert!(
                matches!(result, Err(GaussError::InvalidRequest(message)) if message.contains("AES-GCM authentication failed")),
                "old row failure must precede commit"
            );
            assert_eq!(db.multimodel_visibility_frontier().unwrap(), before);
            fs::write(&paths[0], original).unwrap();
            persistent_chunk_cache().write().unwrap().shrink_to(0);
            let ids = ["a".into(), "z".into()];
            assert_eq!(
                serde_json::to_value(db.get_points("docs", &ids).unwrap()).unwrap(),
                serde_json::to_value(&points).unwrap()
            );
            drop(db);
            assert_eq!(
                serde_json::to_value(
                    crate::Db::open(dir.path())
                        .unwrap()
                        .get_points("docs", &ids)
                        .unwrap()
                )
                .unwrap(),
                serde_json::to_value(&points).unwrap()
            );
        }
    });
}

#[test]
fn cache_miss_refuses_decryption_before_chunk_allocation() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache-budget");
        atomic_write_persistent(&path, FileType::Segment, &[7; DEFAULT_CHUNK_SIZE]).unwrap();
        let file = PersistentFile::open(&path).unwrap();
        persistent_chunk_cache().write().unwrap().shrink_to(0);
        reset_persistent_cache_stats();
        with_test_storage_pool(1, |used| {
            assert!(matches!(
                file.read_range(0..1),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
            assert_eq!(persistent_cache_stats().decrypted_bytes, 0);
        });
        assert_eq!(file.read_range(0..1).unwrap().as_ref(), &[7]);
    });
}

#[test]
fn cache_chunk_lease_survives_eviction_until_the_last_pin() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pinned-cache");
        atomic_write_persistent(&path, FileType::Segment, &[7; DEFAULT_CHUNK_SIZE]).unwrap();
        let file = PersistentFile::open(&path).unwrap();
        let PersistentStorage::Encrypted { ciphertext, layout } = &file.storage else {
            panic!("encrypted fixture")
        };
        persistent_chunk_cache().write().unwrap().shrink_to(0);
        with_test_storage_pool(1024 * 1024, |used| {
            assert_eq!(used(), 0);
            let pin = file.encrypted_chunk(ciphertext, layout, 0).unwrap();
            let resident = used();
            assert!(resident > pin.bytes.capacity() as u64);
            let clone = pin.clone();
            assert_eq!(used(), resident);
            persistent_chunk_cache().write().unwrap().shrink_to(0);
            let pinned = used();
            assert!(pinned > pin.bytes.capacity() as u64 && pinned < resident);
            drop(pin);
            assert_eq!(used(), pinned);
            drop(clone);
            assert_eq!(used(), 0);
        });
    });
}

#[test]
fn cache_pressure_evicts_residency_but_cannot_release_live_pins() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache-pressure");
        atomic_write_persistent(&path, FileType::Segment, &[7; 3 * DEFAULT_CHUNK_SIZE]).unwrap();
        let file = PersistentFile::open(&path).unwrap();
        let PersistentStorage::Encrypted { ciphertext, layout } = &file.storage else {
            panic!("encrypted fixture")
        };
        persistent_chunk_cache().write().unwrap().shrink_to(0);
        reset_persistent_cache_stats();
        with_test_storage_pool(180 * 1024, |used| {
            let first = file.encrypted_chunk(ciphertext, layout, 0).unwrap();
            let second = file.encrypted_chunk(ciphertext, layout, 1).unwrap();
            let decrypted = persistent_cache_stats().decrypted_bytes;
            assert!(matches!(
                file.encrypted_chunk(ciphertext, layout, 2),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(persistent_cache_usage_bytes().0, 0);
            assert_eq!(persistent_cache_stats().decrypted_bytes, decrypted);
            assert!(used() >= (first.bytes.capacity() + second.bytes.capacity()) as u64);
            assert_eq!(first.bytes[0], 7);
            drop(first);
            let third = file.encrypted_chunk(ciphertext, layout, 2).unwrap();
            assert_eq!(third.bytes[0], 7);
            drop(third);
            persistent_chunk_cache().write().unwrap().shrink_to(0);
            drop(second);
            assert_eq!(used(), 0);
        });
    });
}

#[test]
fn cache_authentication_failure_releases_the_prepared_chunk_lease() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad-cache");
        atomic_write_persistent(&path, FileType::Segment, &[7; DEFAULT_CHUNK_SIZE]).unwrap();
        let file = PersistentFile::open(&path).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, bytes).unwrap();
        persistent_chunk_cache().write().unwrap().shrink_to(0);
        with_test_storage_pool(1024 * 1024, |used| {
            assert!(
                matches!(file.read_range(0..1), Err(GaussError::InvalidRequest(message)) if message.contains("AES-GCM authentication failed"))
            );
            assert_eq!(used(), 0);
            assert_eq!(persistent_cache_usage_bytes().0, 0);
        });
    });
}

#[test]
fn cache_duplicate_misses_own_separate_leases_until_their_last_pin() {
    with_test_storage_pool(1024 * 1024, |used| {
        let chunk = || {
            let memory =
                crate::encryption::admission::cached_chunk(DEFAULT_CHUNK_SIZE + TAG_LEN + 4)
                    .unwrap();
            Arc::new(CachedChunk::admitted(vec![7; DEFAULT_CHUNK_SIZE], memory))
        };
        let first = chunk();
        let one = used();
        let second = chunk();
        assert_eq!(used(), one * 2);
        let mut cache = PersistentChunkCache::default();
        cache.try_insert((42, 0), first.clone()).unwrap();
        let before = used();
        cache.try_insert((42, 0), second.clone()).unwrap();
        assert_eq!(used(), before);
        assert_eq!(cache.chunks.len(), 1);
        assert!(Arc::ptr_eq(&cache.get((42, 0)).unwrap(), &first));
        cache.shrink_to(0);
        assert_eq!(used(), one * 2);
        drop(first);
        assert_eq!(used(), one);
        drop(second);
        assert_eq!(used(), 0);
    });
}

#[test]
fn cache_container_growth_is_admitted_before_entry_publication() {
    with_test_storage_pool(64 * 1024, |used| {
        let mut cache = PersistentChunkCache::default();
        let mut refused = false;
        let mut container_refused = false;
        for i in 0..1024 {
            let memory = match crate::encryption::admission::cached_chunk(1 + TAG_LEN + 4) {
                Ok(memory) => memory,
                Err(GaussError::ResourceExhausted(_)) => {
                    refused = true;
                    break;
                }
                Err(error) => panic!("{error}"),
            };
            let chunk = Arc::new(CachedChunk::admitted(vec![7], memory));
            let count = cache.chunks.len();
            match cache.try_insert((7, i), chunk) {
                Ok(()) => assert_eq!(cache.chunks.len(), count + 1),
                Err(GaussError::ResourceExhausted(_)) => {
                    assert_eq!(cache.chunks.len(), count);
                    assert!(!cache.chunks.contains_key(&(7, i)));
                    refused = true;
                    container_refused = true;
                    break;
                }
                Err(error) => panic!("{error}"),
            }
            assert!(used() <= 64 * 1024);
        }
        assert!(refused && container_refused && !cache.chunks.is_empty());
        assert!(used() >= crate::encryption::admission::cache_containers(&cache, false).unwrap());
        drop(cache);
        assert_eq!(used(), 0);
    });
}

#[test]
fn cache_reinsert_after_tombstones_keeps_allocated_buckets_charged() {
    with_test_storage_pool(4 * 1024 * 1024, |used| {
        let mut cache = PersistentChunkCache::default();
        for i in 0..2048 {
            let memory = crate::encryption::admission::cached_chunk(1 + TAG_LEN + 4).unwrap();
            let chunk = Arc::new(CachedChunk::admitted(vec![7], memory));
            cache.try_insert((i, 0), chunk).unwrap();
            if i >= 50 {
                cache.remove_file(i - 50);
            }
            assert!(cache.hash_capacity >= cache.chunks.capacity());
            assert!(
                used() >= crate::encryption::admission::cache_containers(&cache, false).unwrap()
            );
        }
        assert_eq!(cache.chunks.len(), 50);
        drop(cache);
        assert_eq!(used(), 0);
    });
}

#[test]
fn native_query_cache_refusal_is_typed_before_result_publication() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::Db::open(dir.path()).unwrap();
        db.create_collection(
            serde_json::from_value(serde_json::json!({
                "name":"docs", "vector_dim":2, "metric":"l2"
            }))
            .unwrap(),
        )
        .unwrap();
        db.upsert(
            "docs",
            vec![crate::Point {
                id: "a".into(),
                vector: vec![1.0, 2.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            }],
        )
        .unwrap();
        db.compact_collection("docs").unwrap();
        persistent_chunk_cache().write().unwrap().shrink_to(0);
        reset_persistent_cache_stats();
        let query =
            || serde_json::from_value(serde_json::json!({"vector":[1.0,2.0],"k":1})).unwrap();
        with_test_storage_pool(1, |used| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                db.search("docs", query())
            }));
            assert!(matches!(result, Ok(Err(GaussError::ResourceExhausted(_)))));
            let result = db.hybrid_search(
                "docs",
                serde_json::from_value(serde_json::json!({"vector":[1.0,2.0],"k":1})).unwrap(),
            );
            assert!(matches!(result, Err(GaussError::ResourceExhausted(_))));
            assert_eq!(used(), 0);
            assert_eq!(persistent_cache_stats().decrypted_bytes, 0);
        });
        assert_eq!(db.search("docs", query()).unwrap().hits.len(), 1);
        drop(db);
        assert_eq!(
            crate::Db::open(dir.path())
                .unwrap()
                .search("docs", query())
                .unwrap()
                .hits
                .len(),
            1
        );
    });
}

#[test]
fn paged_h2qg_query_retains_read_failure_instead_of_panicking() {
    encrypted_process(|| {
        use crate::index::IndexBackend;
        for metric in [crate::DistanceMetric::L2, crate::DistanceMetric::Cosine] {
            let dir = tempfile::tempdir().unwrap();
            let points = (0..32)
                .map(|i| crate::Point {
                    id: format!("p{i:02}"),
                    vector: vec![i as f32, 1.0],
                    vectors: Default::default(),
                    sparse_vector: None,
                    payload: serde_json::Value::Null,
                })
                .collect::<Vec<_>>();
            crate::h2qg::write_test_paged_graph(dir.path(), &points, metric).unwrap();
            let path = dir.path().join(crate::h2qg::HNSW_VECS_FILE);
            let plain = fs::read(&path).unwrap();
            atomic_write_persistent(&path, FileType::Segment, &plain).unwrap();
            let mut index = crate::h2qg::read_index_paged(dir.path()).unwrap();
            let mut cascade = crate::h2qg::read_index_paged(dir.path()).unwrap();
            let mut prepare = crate::h2qg::read_index_paged(dir.path()).unwrap();
            let paged = crate::h2qg::read_hnsw_vecs(&path).unwrap();
            cascade
                .try_set_cascade(Arc::new(std::sync::atomic::AtomicBool::new(true)))
                .unwrap();
            let query = [0.0, 1.0];
            let expected = index.try_candidate_ids_with_ef(&query, 2, None).unwrap();
            let original = fs::read(&path).unwrap();
            let mut damaged = original.clone();
            let last = damaged.len() - 1;
            damaged[last] ^= 1;
            fs::write(&path, damaged).unwrap();
            persistent_chunk_cache().write().unwrap().shrink_to(0);
            let auth = |result: Result<()>| {
                assert!(
                    matches!(&result,Err(GaussError::InvalidRequest(message)) if message.contains("AES-GCM authentication failed")),
                    "actual result: {result:?}"
                )
            };
            let allow = |_: &str| true;
            let cancel = std::sync::atomic::AtomicBool::new(false);
            for parallel in [false, true] {
                index.set_intra_query_parallel(Arc::new(std::sync::atomic::AtomicBool::new(
                    parallel,
                )));
                let backend: &dyn IndexBackend = &index;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    backend.try_candidate_ids_with_ef(&query, 2, None)
                }));
                assert!(
                    matches!(result,Ok(Err(GaussError::InvalidRequest(ref message))) if message.contains("AES-GCM authentication failed")),
                    "candidate IO failure must return the typed error without a panic"
                );
                for result in [
                    backend.try_candidate_ids_with_ef_filter(&query, 2, None, Some(&allow)),
                    backend.try_candidate_ids_with_recall_target(
                        &query,
                        2,
                        None,
                        0.95,
                        Some(&allow),
                    ),
                    backend.try_candidate_ids_with_recall_target_cancellable(
                        &query,
                        2,
                        None,
                        0.95,
                        Some(&allow),
                        &cancel,
                    ),
                    backend.try_candidate_ids_with_recall_target_ordinal_filter(
                        &query,
                        2,
                        None,
                        0.95,
                        Some(&allow),
                        None,
                    ),
                    backend.try_candidate_ids_with_recall_target_ordinal_filter_cancellable(
                        &query,
                        2,
                        None,
                        0.95,
                        Some(&allow),
                        None,
                        &cancel,
                    ),
                ] {
                    auth(result.map(|_| ()));
                }
                assert!(index.candidate_ids_with_ef(&query, 2, None).is_empty());
            }
            auth(
                cascade
                    .try_candidate_ids_with_ef(&query, 2, None)
                    .map(|_| ()),
            );
            let old_flag = prepare.cascade_flag().unwrap();
            auth(prepare.try_set_cascade(Arc::new(std::sync::atomic::AtomicBool::new(true))));
            assert!(Arc::ptr_eq(&old_flag, &prepare.cascade_flag().unwrap()));
            assert!(!old_flag.load(std::sync::atomic::Ordering::Relaxed));
            let ids = points.iter().map(|p| p.id.clone()).collect::<Vec<_>>();
            auth(crate::h2qg::build_test_paged_graph(&ids, 2, metric, paged).map(|_| ()));
            let mut new_point = points[0].clone();
            new_point.id = "new".into();
            new_point.vector = vec![0.5, 1.0];
            auth(index.insert_point(&new_point, 2));
            assert_eq!(index.indexed_points(), 32);
            assert!(!index.contains("new"));
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            assert!(
                index
                    .try_candidate_ids_with_recall_target_cancellable(
                        &query, 2, None, 0.95, None, &cancel
                    )
                    .unwrap()
                    .is_empty()
            );
            fs::write(&path, original).unwrap();
            persistent_chunk_cache().write().unwrap().shrink_to(0);
            assert_eq!(
                index.try_candidate_ids_with_ef(&query, 2, None).unwrap(),
                expected
            );
            assert_eq!(
                crate::h2qg::read_index_paged(dir.path())
                    .unwrap()
                    .try_candidate_ids_with_ef(&query, 2, None)
                    .unwrap(),
                expected
            );
            prepare
                .try_set_cascade(Arc::new(std::sync::atomic::AtomicBool::new(true)))
                .unwrap();
            index.insert_point(&new_point, 2).unwrap();
            assert_eq!(index.indexed_points(), 33);
            assert!(
                index
                    .try_candidate_ids_with_ef(&new_point.vector, 2, None)
                    .unwrap()
                    .iter()
                    .any(|id| id == "new")
            );
            assert!(matches!(
                index.try_candidate_ids_with_ef(&[1.0], 2, None),
                Err(GaussError::DimensionMismatch { .. })
            ));
            assert!(
                index
                    .try_candidate_ids_with_ef(&[f32::NAN, 1.0], 2, None)
                    .is_err()
            );
        }
    });
}

#[test]
fn compressed_dense_search_aborts_on_each_storage_tier_failure() {
    encrypted_process(|| {
        use crate::index::IndexBackend;
        use crate::index::ivf_segment::{IvfSegmentIndex, rescore_inflation_for_recall_target};
        for metric in [crate::DistanceMetric::L2, crate::DistanceMetric::Cosine] {
            let dir = tempfile::tempdir().unwrap();
            let points = (0..16)
                .map(|i| crate::Point {
                    id: format!("p{i:02}"),
                    vector: vec![1.0 + i as f32, 2.0, 3.0, 4.0],
                    vectors: std::collections::HashMap::from([(
                        "image".into(),
                        vec![1.0 + i as f32, 2.0, 3.0, 4.0],
                    )]),
                    sparse_vector: None,
                    payload: serde_json::Value::Null,
                })
                .collect::<Vec<_>>();
            crate::seal::build_segment(
                points.as_slice(),
                dir.path(),
                crate::seal::SealConfig {
                    vector_dim: 4,
                    metric,
                    hnsw_m: None,
                    hnsw_ef_construction: None,
                    index_kind: crate::seal::SealIndexKind::Algorithm2,
                    base_lsn: 0,
                    end_lsn: 1,
                },
            )
            .unwrap();
            let query = [1.0, 2.0, 3.0, 4.0];
            let mut prepared = query.to_vec();
            if metric == crate::DistanceMetric::Cosine {
                crate::search::normalize(&mut prepared);
            }
            // The stricter supported SLO exercises graph navigation for both
            // metrics; this small fixture otherwise probes every cosine cell
            // and legitimately does not read Vamana.
            let rho = rescore_inflation_for_recall_target(2, 0.999).unwrap();
            let open = || {
                IvfSegmentIndex::open(
                    dir.path(),
                    Arc::new(crate::seal::V4Store::open(dir.path()).unwrap()),
                    metric,
                )
                .unwrap()
            };
            let call = |index: &IvfSegmentIndex| {
                index.try_search_compressed(&query, &prepared, 2, Some(points.len()), rho, None)
            };
            let expected = call(&open()).unwrap().0;
            assert_eq!(expected.len(), 2);
            let purge = || persistent_chunk_cache().write().unwrap().shrink_to(0);
            let damage = |path: &Path, original: &[u8]| {
                let mut bytes = original.to_vec();
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                fs::write(path, bytes).unwrap();
                purge();
            };
            let auth = |result: Result<()>| {
                assert!(
                    matches!(&result,Err(GaussError::InvalidRequest(message)) if message.contains("AES-GCM authentication failed")),
                    "actual result: {result:?}"
                )
            };
            for name in [
                crate::index::ivf::IVF_FILE,
                crate::index::rabitq::RABITQ_FILE,
                crate::index::vamana::VAMANA_SEGMENT_FILE,
                crate::seal::VECTOR_FILE,
            ] {
                let index = open();
                let path = dir.path().join(name);
                let original = fs::read(&path).unwrap();
                damage(&path, &original);
                auth(call(&index).map(|_| ()));
                auth(
                    crate::search_pool::SEARCH_POOL
                        .install(|| call(&index))
                        .map(|_| ()),
                );
                if name == crate::seal::VECTOR_FILE {
                    struct AllOrdinals;
                    impl crate::index::OrdinalFilterPredicate for AllOrdinals {
                        fn matches_ordinal(&self, _segment: &str, _ordinal: u32) -> bool {
                            true
                        }
                    }
                    let backend: &dyn IndexBackend = &index;
                    let allow = |_: &str| true;
                    let cancel = std::sync::atomic::AtomicBool::new(false);
                    for result in [
                        backend.try_candidate_ids_with_ef(&query, 2, None),
                        backend.try_candidate_ids_with_ef_filter(&query, 2, None, Some(&allow)),
                        backend.try_candidate_ids_with_recall_target(&query, 2, None, 1.0, None),
                        backend.try_candidate_ids_with_recall_target_cancellable(
                            &query, 2, None, 1.0, None, &cancel,
                        ),
                        backend.try_candidate_ids_with_recall_target_ordinal_filter(
                            &query,
                            2,
                            None,
                            1.0,
                            None,
                            Some(&AllOrdinals),
                        ),
                        backend.try_candidate_ids_with_recall_target_ordinal_filter_cancellable(
                            &query,
                            2,
                            None,
                            1.0,
                            None,
                            Some(&AllOrdinals),
                            &cancel,
                        ),
                    ] {
                        auth(result.map(|_| ()))
                    }
                    cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                    assert!(
                        backend
                            .try_candidate_ids_with_recall_target_cancellable(
                                &query, 2, None, 1.0, None, &cancel
                            )
                            .unwrap()
                            .is_empty()
                    );
                    let deny = |_: &str| false;
                    assert!(
                        backend
                            .try_candidate_ids_with_ef_filter(&query, 2, None, Some(&deny))
                            .unwrap()
                            .is_empty()
                    );
                }
                fs::write(&path, &original).unwrap();
                purge();
                assert_eq!(call(&index).unwrap().0, expected);
                drop(index);
                assert_eq!(call(&open()).unwrap().0, expected);
            }
            let named = IvfSegmentIndex::open_named(dir.path(), "image", metric).unwrap();
            let named_path = dir.path().join(crate::seal::named_vector_file("image"));
            let original = fs::read(&named_path).unwrap();
            let primary = open();
            damage(&named_path, &original);
            auth(
                named
                    .try_candidate_ids_with_recall_target(&query, 2, None, 1.0, None)
                    .map(|_| ()),
            );
            assert_eq!(
                primary
                    .try_candidate_ids_with_recall_target(&query, 2, None, 1.0, None)
                    .unwrap()
                    .len(),
                2
            );
            fs::write(&named_path, &original).unwrap();
            purge();
            assert_eq!(
                named
                    .try_candidate_ids_with_recall_target(&query, 2, None, 1.0, None)
                    .unwrap()
                    .len(),
                2
            );
            // A newly opened cold artifact has no warm data pages to hide the fault.
            let cold = IvfSegmentIndex::open_cold(
                dir.path(),
                Arc::new(crate::seal::V4Store::open(dir.path()).unwrap()),
                metric,
            )
            .unwrap();
            let path = dir.path().join(crate::index::diskann::DISKANN_FILE);
            let original = fs::read(&path).unwrap();
            damage(&path, &original);
            auth(call(&cold).map(|_| ()));
            auth(
                cold.try_candidate_ids_with_recall_target(&query, 2, None, 1.0, None)
                    .map(|_| ()),
            );
            fs::write(&path, &original).unwrap();
            purge();
            assert_eq!(call(&cold).unwrap().0.len(), 2);
            assert_eq!(
                cold.try_candidate_ids_with_recall_target(&query, 2, None, 1.0, None)
                    .unwrap()
                    .len(),
                2
            );
            assert!(cold.try_candidate_ids_with_ef(&[1.0], 2, None).is_err());
        }
    });
}

#[test]
fn native_dense_search_preserves_late_encrypted_vector_failure() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::Db::open(dir.path()).unwrap();
        db.create_collection(
            serde_json::from_value(serde_json::json!({
                "name":"docs", "vector_dim":2, "metric":"l2"
            }))
            .unwrap(),
        )
        .unwrap();
        let points = ["a", "z"].map(|id| crate::Point {
            id: id.into(),
            vector: vec![1.0, 2.0],
            vectors: Default::default(),
            sparse_vector: None,
            payload: serde_json::json!({"tag":id}),
        });
        db.upsert("docs", points.to_vec()).unwrap();
        db.compact_collection("docs").unwrap();
        fn vectors(dir: &Path) -> Vec<std::path::PathBuf> {
            fs::read_dir(dir)
                .unwrap()
                .flat_map(|entry| {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        vectors(&path)
                    } else if path
                        .file_name()
                        .is_some_and(|name| name == crate::seal::VECTOR_FILE)
                    {
                        vec![path]
                    } else {
                        Vec::new()
                    }
                })
                .collect()
        }
        let paths = vectors(dir.path());
        assert_eq!(paths.len(), 1);
        let path = &paths[0];
        let original = fs::read(path).unwrap();
        let mut damaged = original.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        fs::write(path, damaged).unwrap();
        persistent_chunk_cache().write().unwrap().shrink_to(0);
        let query =
            || serde_json::from_value(serde_json::json!({"vector":[1.0,2.0],"k":2})).unwrap();
        let result = db.search("docs", query());
        assert!(
            matches!(result,Err(GaussError::InvalidRequest(message)) if message.contains("AES-GCM authentication failed")),
            "native dense query must retain candidate vector read error"
        );
        let hybrid = serde_json::from_value(serde_json::json!({"vector":[1.0,2.0],"k":2})).unwrap();
        assert!(
            matches!(db.hybrid_search("docs",hybrid),Err(GaussError::InvalidRequest(message)) if message.contains("AES-GCM authentication failed"))
        );
        let multi = crate::MultiSearchRequest {
            searches: vec![query(), query()],
            fusion: None,
            fused_k: None,
            weights: vec![],
        };
        assert!(
            matches!(db.multi_search("docs",multi),Err(GaussError::InvalidRequest(message)) if message.contains("AES-GCM authentication failed"))
        );
        fs::write(path, original).unwrap();
        persistent_chunk_cache().write().unwrap().shrink_to(0);
        assert_eq!(db.search("docs", query()).unwrap().hits.len(), 2);
        drop(db);
        assert_eq!(
            crate::Db::open(dir.path())
                .unwrap()
                .search("docs", query())
                .unwrap()
                .hits
                .len(),
            2
        );
    });
}

#[test]
fn ann_artifact_readers_preserve_encrypted_failures_and_recover_after_repair() {
    encrypted_process(|| {
        use crate::index::{
            ivf::{IvfArtifact, write_ivf_artifact},
            rabitq::{RabitqArtifact, write_rabitq_artifact_for_metric},
            rotate_for_cascade,
            vamana::{VamanaArtifact, write_vamana_artifact},
        };
        let dir = tempfile::tempdir().unwrap();
        let vectors = [
            vec![0.0, 1.0],
            vec![1.0, 0.0],
            vec![2.0, 1.0],
            vec![3.0, 2.0],
        ];
        let ivf_path = dir.path().join("ivf.gdx");
        write_ivf_artifact(vectors.as_slice(), 2, 1, &ivf_path).unwrap();
        let ivf_plain = fs::read(&ivf_path).unwrap();
        atomic_write_persistent(&ivf_path, FileType::Segment, &ivf_plain).unwrap();
        let ivf = IvfArtifact::open(&ivf_path).unwrap();
        let ivf_cipher = fs::read(&ivf_path).unwrap();
        let purge = || persistent_chunk_cache().write().unwrap().shrink_to(0);
        let damage = |path: &Path, original: &[u8]| {
            let mut damaged = original.to_vec();
            let last = damaged.len() - 1;
            damaged[last] ^= 1;
            // Encrypted readers use range IO rather than plaintext mmap.
            fs::write(path, damaged).unwrap();
            purge();
        };
        let auth = |result: Result<()>| {
            assert!(matches!(result, Err(GaussError::InvalidRequest(message))
                if message.contains("AES-GCM authentication failed")));
        };
        damage(&ivf_path, &ivf_cipher);
        auth(ivf.try_centroids().map(|_| ()));
        auth(ivf.try_cell_radius(0).map(|_| ()));
        auth(ivf.try_posting_range(0).map(|_| ()));
        auth(ivf.try_posting_ordinal(0).map(|_| ()));
        auth(ivf.try_postings(0).map(|_| ()));
        assert!(
            matches!(ivf.try_posting_ordinal(ivf.len()), Err(GaussError::InvalidRequest(message)) if message.contains("out of bounds"))
        );
        let failed_vamana = dir.path().join("failed-vamana.gdx");
        auth(write_vamana_artifact(
            vectors.as_slice(),
            &ivf,
            crate::DistanceMetric::L2,
            &failed_vamana,
        ));
        assert!(!failed_vamana.exists());
        let failed_rabitq = dir.path().join("failed-rabitq.gdx");
        auth(write_rabitq_artifact_for_metric(
            vectors.as_slice(),
            &ivf,
            crate::DistanceMetric::L2,
            &failed_rabitq,
        ));
        assert!(!failed_rabitq.exists());
        fs::write(&ivf_path, &ivf_cipher).unwrap();
        purge();
        assert_eq!(ivf.try_postings(0).unwrap().len(), vectors.len());
        for metric in [crate::DistanceMetric::L2, crate::DistanceMetric::Cosine] {
            let path = dir.path().join("rabitq.gdx");
            write_rabitq_artifact_for_metric(vectors.as_slice(), &ivf, metric, &path).unwrap();
            let plain = fs::read(&path).unwrap();
            atomic_write_persistent(&path, FileType::Segment, &plain).unwrap();
            let artifact = RabitqArtifact::open(&path, &ivf).unwrap();
            let original = fs::read(&path).unwrap();
            let record = artifact.record_for_ordinal_key(0).unwrap();
            let query = rotate_for_cascade(&[0.5, 0.25]);
            let table = if artifact.uses_global_query_table() {
                let global = artifact.prepare_global_query_table(&query).unwrap();
                artifact
                    .prepare_global_cell_distance_table(
                        &query,
                        &rotate_for_cascade(&ivf.try_centroids().unwrap()[0]),
                        &global,
                    )
                    .unwrap()
            } else {
                artifact.prepare_distance_table(&query).unwrap()
            };
            damage(&path, &original);
            auth(artifact.try_cell(0).map(|_| ()));
            auth(artifact.try_record_for_ordinal_in_cell(0, 0).map(|_| ()));
            let mut output = [f32::NAN; 1];
            if artifact.uses_global_query_table() {
                auth(
                    artifact
                        .try_distance_estimate_for_record_with_basis::<true>(
                            RabitqArtifact::record_index(record),
                            &table,
                        )
                        .map(|_| ()),
                );
                auth(
                    artifact
                        .try_estimate_squared_l2_for_record_with_table_for_basis::<true>(
                            record, &table,
                        )
                        .map(|_| ()),
                );
                auth(
                    artifact.try_estimate_squared_l2_for_records_with_table_for_basis::<true>(
                        &[record],
                        &table,
                        &mut output,
                    ),
                );
            } else {
                auth(
                    artifact
                        .try_estimate_squared_l2(0, &[0.5, 0.25])
                        .map(|_| ()),
                );
                auth(
                    artifact
                        .try_distance_estimate_for_record_with_basis::<false>(
                            RabitqArtifact::record_index(record),
                            &table,
                        )
                        .map(|_| ()),
                );
                auth(
                    artifact
                        .try_estimate_squared_l2_for_record_with_table_for_basis::<false>(
                            record, &table,
                        )
                        .map(|_| ()),
                );
                auth(
                    artifact.try_estimate_squared_l2_for_records_with_table_for_basis::<false>(
                        &[record],
                        &table,
                        &mut output,
                    ),
                );
            }
            assert!(output[0].is_nan());
            fs::write(&path, &original).unwrap();
            purge();
            assert_eq!(artifact.try_cell(0).unwrap(), 0);
            assert!(RabitqArtifact::open(&path, &ivf).is_ok());
        }
        let path = dir.path().join("vamana.gdx");
        write_vamana_artifact(vectors.as_slice(), &ivf, crate::DistanceMetric::L2, &path).unwrap();
        let plain = fs::read(&path).unwrap();
        atomic_write_persistent(&path, FileType::Segment, &plain).unwrap();
        let artifact = VamanaArtifact::open(&path, &ivf).unwrap();
        let inverse = artifact.ordinal_to_key(&ivf).unwrap();
        let original = fs::read(&path).unwrap();
        damage(&path, &original);
        auth(artifact.try_entry(0).map(|_| ()));
        auth(artifact.try_neighbors(0).map(|_| ()));
        auth(artifact.ordinal_neighbors(&ivf, &inverse, 0).map(|_| ()));
        auth(artifact.connectivity_profile(vectors.len()).map(|_| ()));
        let mut calls = 0;
        auth(artifact.try_visit_neighbor_keys(0, |_| {
            calls += 1;
            Ok(())
        }));
        assert_eq!(calls, 0);
        let points = vectors
            .iter()
            .enumerate()
            .map(|(id, vector)| crate::Point {
                id: id.to_string(),
                vector: vector.clone(),
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            })
            .collect::<Vec<_>>();
        auth(crate::index::diskann::write_diskann_artifact(
            points.as_slice(),
            &artifact,
            &ivf,
            2,
            &dir.path().join("failed-diskann.gdx"),
        ));
        fs::write(&path, &original).unwrap();
        purge();
        assert!(!artifact.try_neighbors(0).unwrap().is_empty());
        assert!(VamanaArtifact::open(&path, &ivf).is_ok());
        assert_eq!(fs::read(&ivf_path).unwrap(), ivf_cipher);
    });
}

#[test]
fn vamana_result_reader_preserves_late_encrypted_failure() {
    encrypted_process(|| {
        use crate::index::ivf::{IvfArtifact, write_ivf_artifact};
        use crate::index::vamana::{VamanaArtifact, write_vamana_artifact};
        let dir = tempfile::tempdir().unwrap();
        let vectors = [
            vec![0.0, 1.0],
            vec![1.0, 0.0],
            vec![2.0, 1.0],
            vec![3.0, 2.0],
        ];
        let ivf_path = dir.path().join("ivf.gdx");
        write_ivf_artifact(vectors.as_slice(), 2, 1, &ivf_path).unwrap();
        let ivf = IvfArtifact::open(&ivf_path).unwrap();
        let path = dir.path().join("vamana.gdx");
        write_vamana_artifact(vectors.as_slice(), &ivf, crate::DistanceMetric::L2, &path).unwrap();
        let plain = fs::read(&path).unwrap();
        atomic_write_persistent(&path, FileType::Segment, &plain).unwrap();
        let artifact = VamanaArtifact::open(&path, &ivf).unwrap();
        let inverse = artifact.ordinal_to_key(&ivf).unwrap();
        let original = fs::read(&path).unwrap();
        let mut damaged = original.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        fs::write(&path, &damaged).unwrap();
        persistent_chunk_cache().write().unwrap().shrink_to(0);
        let error = artifact.ordinal_neighbors(&ivf, &inverse, 0).unwrap_err();
        assert!(
            matches!(error, GaussError::InvalidRequest(message)
            if message.contains("AES-GCM authentication failed")),
            "Result reader must retain the real encrypted read failure"
        );
        fs::write(&path, &original).unwrap();
        persistent_chunk_cache().write().unwrap().shrink_to(0);
        assert!(
            !artifact
                .ordinal_neighbors(&ivf, &inverse, 0)
                .unwrap()
                .is_empty()
        );
    });
}

#[test]
fn graph_point_failure_aborts_traversal_and_mutation_before_commit() {
    encrypted_process(|| {
        use crate::graph::{
            ConfigureEdgeTypeRequest, GraphDirection, GraphRelationScope,
            GraphTraversalQueryRequest, GraphTraversalReturn, GraphTraverseRequest, RelateRequest,
            TraversalBudget,
        };
        let dir = tempfile::tempdir().unwrap();
        let db = crate::Db::open(dir.path()).unwrap();
        db.create_collection(
            serde_json::from_value(serde_json::json!({
                "name": "docs", "vector_dim": 2, "metric": "l2"
            }))
            .unwrap(),
        )
        .unwrap();
        let scope = crate::TenantScope::system();
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        let points = ["a", "z"].map(|id| crate::Point {
            id: id.into(),
            vector: vec![1.0, 2.0],
            vectors: Default::default(),
            sparse_vector: None,
            payload: serde_json::json!({"tag": id, "body": "x".repeat(128 * 1024)}),
        });
        db.upsert("docs", points.to_vec()).unwrap();
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: "links".into(),
                weight_property: None,
            },
            true,
            &scope,
        )
        .unwrap();
        let relation = RelateRequest {
            source_point_id: "a".into(),
            target_point_id: "z".into(),
            edge_type: "links".into(),
            properties: serde_json::json!({"kind":"allowed"}),
            scope: GraphRelationScope::Local,
            idempotency_key: None,
        };
        db.relate_scoped("docs", relation.clone(), true, &scope)
            .unwrap();
        db.compact_collection("docs").unwrap();
        fn files(dir: &Path) -> Vec<std::path::PathBuf> {
            fs::read_dir(dir)
                .unwrap()
                .flat_map(|entry| {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        files(&path)
                    } else {
                        vec![path]
                    }
                })
                .collect()
        }
        let payloads = files(dir.path())
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name == crate::seal::PAYLOAD_FILE)
            })
            .collect::<Vec<_>>();
        assert_eq!(payloads.len(), 1);
        let path = &payloads[0];
        let original = fs::read(path).unwrap();
        let mut damaged = original.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        fs::write(path, &damaged).unwrap();
        persistent_chunk_cache().write().unwrap().shrink_to(0);
        let request = GraphTraverseRequest {
            anchors: vec!["a".into()],
            edge_types: vec!["links".into()],
            direction: GraphDirection::Outgoing,
            node_filter: None,
            edge_filter: None,
            budget: TraversalBudget {
                max_depth: 2,
                max_memory_bytes: 64 * 1024 * 1024,
                ..Default::default()
            },
        };
        assert!(
            db.traverse_scoped("docs", request.clone(), &scope).is_err(),
            "corrupt graph neighbour must not disappear from a successful traversal"
        );
        let auth_failure = |error: GaussError| {
            assert!(matches!(error, GaussError::InvalidRequest(message)
                if message.contains("AES-GCM authentication failed")));
        };
        for returns in [
            GraphTraversalReturn::Nodes,
            GraphTraversalReturn::Edges,
            GraphTraversalReturn::Paths,
        ] {
            auth_failure(
                db.traverse_query_scoped(
                    "docs",
                    GraphTraversalQueryRequest {
                        traversal: request.clone(),
                        returns,
                        limit: Some(10),
                        with_payload: true,
                    },
                    &scope,
                )
                .unwrap_err(),
            );
        }
        let mut anchor = request.clone();
        anchor.anchors = vec!["z".into()];
        anchor.budget.max_depth = 0;
        auth_failure(db.traverse_scoped("docs", anchor, &scope).unwrap_err());
        let wal_dir = db.collection_wal_dir("docs").unwrap();
        let before = files(&wal_dir)
            .into_iter()
            .map(|p| {
                let bytes = fs::read(&p).unwrap();
                (p, bytes)
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        auth_failure(db.upsert("docs", vec![points[1].clone()]).unwrap_err());
        auth_failure(db.delete_with_edges("docs", &["z".into()]).unwrap_err());
        auth_failure(
            db.relate_scoped("docs", relation, true, &scope)
                .unwrap_err(),
        );
        let after = files(&wal_dir)
            .into_iter()
            .map(|p| {
                let bytes = fs::read(&p).unwrap();
                (p, bytes)
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            after, before,
            "failed graph mutations must not append a WAL decision"
        );
        assert_eq!(fs::read(path).unwrap(), damaged);
        fs::write(path, &original).unwrap();
        persistent_chunk_cache().write().unwrap().shrink_to(0);
        assert_eq!(
            db.traverse_scoped("docs", request.clone(), &scope)
                .unwrap()
                .nodes
                .len(),
            1
        );
        assert_eq!(
            db.get_points("docs", &["z".into()]).unwrap()[0].payload,
            points[1].payload
        );
        drop(db);
        let reopened = crate::Db::open(dir.path()).unwrap();
        assert_eq!(
            reopened
                .traverse_scoped("docs", request, &scope)
                .unwrap()
                .nodes
                .len(),
            1
        );
        assert_eq!(reopened.count("docs", None).unwrap().count, 2);
    });
}

#[test]
fn failed_aux_hydration_aborts_searcher_admission_and_hidden_points_do_not_read() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let points = ["a", "z"].map(|id| crate::Point {
            id: id.into(),
            vector: vec![1.0, 2.0],
            vectors: Default::default(),
            sparse_vector: None,
            payload: serde_json::json!({"tag": id, "body": "x".repeat(128 * 1024)}),
        });
        crate::seal::build_segment(
            points.as_slice(),
            dir.path(),
            crate::seal::SealConfig {
                vector_dim: 2,
                metric: crate::DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: crate::seal::SealIndexKind::Hnsw,
                base_lsn: 0,
                end_lsn: 1,
            },
        )
        .unwrap();
        let store = Arc::new(crate::seal::V4Store::open(dir.path()).unwrap());
        let loaded_store = crate::seal::V4Store::open(dir.path()).unwrap();
        let make = || {
            crate::searcher::SegmentSearcher::new(
                "segment".into(),
                dir.path().into(),
                crate::searcher::SegmentIndex::None,
                Default::default(),
                crate::searcher::SegmentStore::V4(store.clone()),
                Default::default(),
                Default::default(),
            )
        };
        let mut searcher = make().unwrap();
        let payload_path = dir.path().join(crate::seal::PAYLOAD_FILE);
        let mut encoded = fs::read(&payload_path).unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        fs::write(&payload_path, &encoded).unwrap();
        persistent_chunk_cache().write().unwrap().shrink_to(0);
        assert!(
            matches!(make(), Err(GaussError::InvalidRequest(message)) if message.contains("AES-GCM authentication failed"))
        );
        let loaded = crate::segment::LoadedSegment {
            id: "segment".into(),
            dir: dir.path().into(),
            points: Default::default(),
            h2qg: None,
            named_h2qg: Default::default(),
            payload_index: None,
            v4_store: Some(loaded_store),
            tombstones: Default::default(),
            tombstone_ordinals: Default::default(),
        };
        assert!(
            matches!(crate::searcher::SegmentSearcher::from_loaded(loaded, crate::DistanceMetric::L2),
            Err(GaussError::InvalidRequest(message)) if message.contains("AES-GCM authentication failed"))
        );
        assert!(store.try_get("absent").unwrap().is_none());
        assert!(matches!(
            store.try_get_ordinal(usize::MAX),
            Err(GaussError::InvalidRequest(_))
        ));
        assert!(
            matches!(searcher.try_get_live("z"), Err(GaussError::InvalidRequest(message)) if message.contains("AES-GCM authentication failed"))
        );
        assert!(
            searcher
                .try_iter_live()
                .collect::<crate::Result<Vec<_>>>()
                .is_err()
        );
        let mut hidden = roaring::RoaringBitmap::new();
        hidden.insert(store.ordinal("z").unwrap() as u32);
        assert!(
            searcher
                .get_ordinal_visible(1, Some(&hidden))
                .unwrap()
                .is_none()
        );
        assert!(searcher.get_visible("z", Some(&hidden)).unwrap().is_none());
        let visible = searcher
            .iter_visible(Some(&hidden))
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].id, "a");
        drop(visible);
        searcher.tombstone("z");
        assert!(searcher.try_get_live("z").unwrap().is_none());
        assert_eq!(
            searcher
                .try_iter_live()
                .collect::<crate::Result<Vec<_>>>()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(fs::read(payload_path).unwrap(), encoded);
    });
}

#[test]
fn point_read_failure_is_not_absence_partial_response_or_committed_payload_update() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::Db::open(dir.path()).unwrap();
        db.create_collection(
            serde_json::from_value(serde_json::json!({
                "name": "docs", "vector_dim": 2, "metric": "l2"
            }))
            .unwrap(),
        )
        .unwrap();
        let points = ["a", "z"].map(|id| crate::Point {
            id: id.into(),
            vector: vec![1.0, 2.0],
            vectors: Default::default(),
            sparse_vector: Some(crate::SparseVector {
                indices: vec![0],
                values: vec![1.0],
            }),
            payload: serde_json::json!({"tag": id, "body": "x".repeat(128 * 1024)}),
        });
        db.upsert("docs", points.to_vec()).unwrap();
        db.compact_collection("docs").unwrap();
        fn files(dir: &Path) -> Vec<std::path::PathBuf> {
            fs::read_dir(dir)
                .unwrap()
                .flat_map(|entry| {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        files(&path)
                    } else {
                        vec![path]
                    }
                })
                .collect()
        }
        let payloads = files(dir.path())
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name == crate::seal::PAYLOAD_FILE)
            })
            .collect::<Vec<_>>();
        assert_eq!(payloads.len(), 1);
        let payload_path = &payloads[0];
        let original = fs::read(payload_path).unwrap();
        let mut damaged = original.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        fs::write(payload_path, &damaged).unwrap();
        persistent_chunk_cache().write().unwrap().shrink_to(0);
        let auth_failure = |error: GaussError| {
            assert!(
                matches!(error, GaussError::InvalidRequest(message) if message.contains("AES-GCM authentication failed"))
            );
        };
        assert!(
            db.get_points("docs", &["absent".into()])
                .unwrap()
                .is_empty()
        );
        auth_failure(
            db.get_points("docs", &["a".into(), "z".into()])
                .unwrap_err(),
        );
        auth_failure(db.count("docs", None).unwrap_err());
        auth_failure(db.scroll("docs", None, 2, None).unwrap_err());
        auth_failure(
            db.search(
                "docs",
                serde_json::from_value(serde_json::json!({
                    "vector": [1.0, 2.0], "k": 2
                }))
                .unwrap(),
            )
            .unwrap_err(),
        );
        for filter in [None, Some(crate::Filter(serde_json::json!({"tag": "z"})))] {
            auth_failure(
                db.hybrid_search(
                    "docs",
                    serde_json::from_value(serde_json::json!({
                        "sparse_vector": {"indices": [0], "values": [1.0]}, "k": 2, "filter": filter
                    }))
                    .unwrap(),
                )
                .unwrap_err(),
            );
            auth_failure(
                db.text_hybrid_search_scoped(
                    "docs",
                    crate::TextHybridSearchRequest {
                        vector: vec![],
                        query: "z".into(),
                        text_field: "tag".into(),
                        k: 2,
                        filter,
                        budget_ms: None,
                    },
                    &crate::TenantScope::system(),
                )
                .unwrap_err(),
            );
        }
        auth_failure(
            db.recommend(
                "docs",
                serde_json::from_value(serde_json::json!({
                    "positive": ["z"], "k": 1
                }))
                .unwrap(),
            )
            .unwrap_err(),
        );
        auth_failure(
            db.delete_by_filter("docs", &crate::Filter(serde_json::json!({"tag": "z"})))
                .unwrap_err(),
        );
        auth_failure(
            db.set_payload("docs", "z", serde_json::json!({"tag": "changed"}), false)
                .unwrap_err(),
        );
        assert_eq!(fs::read(payload_path).unwrap(), damaged);
        fs::write(payload_path, &original).unwrap();
        persistent_chunk_cache().write().unwrap().shrink_to(0);
        let recovered = db.get_points("docs", &["a".into(), "z".into()]).unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[1].payload, points[1].payload);
        assert_eq!(db.count("docs", None).unwrap().count, 2);
        drop(db);
        let reopened = crate::Db::open(dir.path()).unwrap();
        assert_eq!(
            reopened.get_points("docs", &["z".into()]).unwrap()[0].payload,
            points[1].payload
        );
    });
}

#[test]
fn cold_primary_vector_read_preserves_encrypted_diskann_failure() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cold");
        let dim = 4096;
        let points = (0..12)
            .map(|i| crate::Point {
                id: format!("p{i}"),
                vector: vec![1.25; dim],
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            })
            .collect::<Vec<_>>();
        crate::seal::build_segment(
            points.as_slice(),
            &path,
            crate::seal::SealConfig {
                vector_dim: dim,
                metric: crate::DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: crate::seal::SealIndexKind::Algorithm2,
                base_lsn: 0,
                end_lsn: 1,
            },
        )
        .unwrap();
        assert!(crate::seal::thin_algorithm2_segment_for_cold(&path).unwrap());
        let store = crate::seal::V4Store::open(&path).unwrap();
        assert_eq!(store.try_vector(0).unwrap(), points[0].vector);
        let diskann = path.join(crate::index::diskann::DISKANN_FILE);
        // DiskANN owns positional File reads, not an mmap of this inode.
        // Inject a physical ciphertext fault after header/marker validation.
        let mut encoded = fs::read(&diskann).unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        fs::write(&diskann, &encoded).unwrap();
        assert!(
            matches!(store.try_vector(11), Err(GaussError::InvalidRequest(message)) if message.contains("AES-GCM authentication failed"))
        );
        assert_eq!(fs::read(diskann).unwrap(), encoded);
    });
}

#[test]
fn encrypted_diskann_header_refusal_releases_owners_and_retries_unchanged() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("segment");
        let points = (0..4)
            .map(|i| crate::Point {
                id: format!("p{i}"),
                vector: vec![1.25; 16],
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            })
            .collect::<Vec<_>>();
        crate::seal::build_segment(
            points.as_slice(),
            &path,
            crate::seal::SealConfig {
                vector_dim: 16,
                metric: crate::DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: crate::seal::SealIndexKind::Algorithm2,
                base_lsn: 0,
                end_lsn: 1,
            },
        )
        .unwrap();
        let diskann = path.join(crate::index::diskann::DISKANN_FILE);
        let original = fs::read(&diskann).unwrap();
        with_test_storage_pool(16 * 1024, |used| {
            assert!(matches!(
                crate::index::diskann::DiskAnnArtifact::open(&diskann, 4, 16),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
        });
        with_test_storage_pool(128 * 1024, |used| {
            let artifact = crate::index::diskann::DiskAnnArtifact::open(&diskann, 4, 16).unwrap();
            assert!(
                used() > 0 && used() < 32 * 1024,
                "retained artifact/path and layout owners remain after constructor scratch"
            );
            assert_eq!(artifact.try_vector(0).unwrap(), points[0].vector);
            drop(artifact);
            assert_eq!(used(), 0);
        });
        assert_eq!(fs::read(diskann).unwrap(), original);
    });
}

#[test]
fn encrypted_object_store_header_and_batch_reads_preserve_authenticated_failure() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("segment");
        let dim = 4096;
        let points = (0..12)
            .map(|i| crate::Point {
                id: format!("p{i}"),
                vector: vec![1.25; dim],
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            })
            .collect::<Vec<_>>();
        crate::seal::build_segment(
            points.as_slice(),
            &path,
            crate::seal::SealConfig {
                vector_dim: dim,
                metric: crate::DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: crate::seal::SealIndexKind::Algorithm2,
                base_lsn: 0,
                end_lsn: 1,
            },
        )
        .unwrap();
        let diskann = path.join(crate::index::diskann::DISKANN_FILE);
        let encoded_len = fs::metadata(&diskann).unwrap().len();
        let provider: Arc<dyn object_store::ObjectStore> =
            Arc::new(object_store::local::LocalFileSystem::new_with_prefix(&path).unwrap());
        let open = || {
            crate::index::diskann::DiskAnnArtifact::open_object_store(
                provider.clone(),
                object_store::path::Path::from(crate::index::diskann::DISKANN_FILE),
                encoded_len,
                points.len(),
                dim,
            )
            .unwrap()
        };
        let source = open();
        let values = source.try_vectors(&[11, 0, 11]).unwrap();
        assert_eq!(
            values,
            vec![
                points[11].vector.clone(),
                points[0].vector.clone(),
                points[11].vector.clone()
            ]
        );
        drop(source);
        let mut encoded = fs::read(&diskann).unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        fs::write(&diskann, &encoded).unwrap();
        let source = open();
        assert!(
            matches!(source.try_vectors(&[0, 11]), Err(GaussError::InvalidRequest(message)) if message.contains("AES-GCM authentication failed"))
        );
        assert_eq!(source.stats().page_read_errors, 1);
        assert_eq!(fs::read(diskann).unwrap(), encoded);
    });
}

#[test]
fn named_vector_source_preserves_late_encrypted_row_failure_during_ivf_build() {
    encrypted_process(|| {
        use crate::index::ivf::VectorSource;
        for scaled in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let count = 12_usize;
            let dim = 4096_usize;
            let path = dir.path().join(crate::seal::named_vector_file("image"));
            let mut rows = Vec::new();
            rows.extend_from_slice(if scaled {
                b"GAUSSV05"
            } else {
                crate::h2qg::HNSW_VECS_MAGIC
            });
            rows.extend_from_slice(&(count as u64).to_le_bytes());
            rows.extend_from_slice(&(dim as u64).to_le_bytes());
            for _ in 0..count {
                if scaled {
                    rows.extend_from_slice(&1.0_f32.to_le_bytes());
                    for _ in 0..dim {
                        rows.extend_from_slice(&half::f16::from_f32(1.25).to_bits().to_le_bytes());
                    }
                } else {
                    for _ in 0..dim {
                        rows.extend_from_slice(&1.25_f32.to_le_bytes());
                    }
                }
            }
            atomic_write_persistent(&path, FileType::Segment, &rows).unwrap();
            let mut ids = Vec::new();
            ids.extend_from_slice(b"GAUSSID4");
            ids.extend_from_slice(&(count as u64).to_le_bytes());
            for i in 0..count {
                let id = format!("p{i}");
                ids.extend_from_slice(&(id.len() as u32).to_le_bytes());
                ids.extend_from_slice(id.as_bytes());
            }
            atomic_write_persistent(
                &dir.path().join(crate::seal::named_ids_file("image")),
                FileType::Segment,
                &ids,
            )
            .unwrap();
            let mut encoded = fs::read(&path).unwrap();
            let last = encoded.len() - 1;
            encoded[last] ^= 1;
            fs::write(&path, &encoded).unwrap();
            let source = crate::seal::NamedV4Store::open(dir.path(), "image").unwrap();
            assert_eq!(source.vector(0).unwrap().as_ref(), vec![1.25; dim]);
            assert!(
                matches!(source.vector(count - 1), Err(GaussError::InvalidRequest(message)) if message.contains("AES-GCM authentication failed"))
            );
            let index = dir.path().join("new.ivf.gdx");
            fs::write(&index, b"previous complete index").unwrap();
            assert!(
                matches!(crate::index::ivf::write_ivf_artifact(&source, dim, 2, &index), Err(GaussError::InvalidRequest(message)) if message.contains("AES-GCM authentication failed"))
            );
            assert_eq!(fs::read(index).unwrap(), b"previous complete index");
            assert_eq!(fs::read(path).unwrap(), encoded);
        }
    });
}

#[test]
fn persistent_and_stream_readers_preserve_authenticated_body_failure() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tampered");
        atomic_write_persistent(&path, FileType::Segment, b"authenticated row").unwrap();
        let mut encoded = fs::read(&path).unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        fs::write(&path, &encoded).unwrap();

        let file = PersistentFile::open(&path).unwrap();
        let direct = file.read_range(0..file.len()).unwrap_err();
        assert!(matches!(&direct, GaussError::InvalidRequest(_)));
        let expected = direct.to_string();
        let mut reader = file.reader();
        let error = GaussError::from(reader.read_exact(&mut [0]).unwrap_err());
        assert!(matches!(&error, GaussError::InvalidRequest(_)));
        assert_eq!(error.to_string(), expected);
        assert_eq!(
            reader.position, 0,
            "failed reads must not advance the cursor"
        );

        let mut stream = open_persistent_reader(&path).unwrap();
        let io_error = stream.read_exact(&mut [0]).unwrap_err();
        assert_eq!(io_error.kind(), std::io::ErrorKind::InvalidData);
        let error = GaussError::from(io_error);
        assert!(matches!(&error, GaussError::InvalidRequest(_)));
        assert_eq!(error.to_string(), expected);
        assert_eq!(fs::read(&path).unwrap(), encoded);
    });
}

#[test]
fn encrypted_io_adapter_preserves_resource_refusal_and_invalid_data_kind() {
    let io_error = invalid_data_error(GaussError::ResourceExhausted("chunk budget".into()));
    assert_eq!(io_error.kind(), std::io::ErrorKind::InvalidData);
    let error = GaussError::from(io_error);
    assert!(matches!(error, GaussError::ResourceExhausted(message) if message == "chunk budget"));
}

#[test]
fn failed_paged_row_aborts_flat_index_build_before_publication() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(crate::h2qg::HNSW_VECS_FILE);
        let dim = 4096;
        let count = 10;
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(crate::h2qg::HNSW_VECS_MAGIC);
        plaintext.extend_from_slice(&(count as u64).to_le_bytes());
        plaintext.extend_from_slice(&(dim as u64).to_le_bytes());
        for _ in 0..count * dim {
            plaintext.extend_from_slice(&1.25_f32.to_le_bytes());
        }
        atomic_write_persistent(&path, FileType::Segment, &plaintext).unwrap();
        let mut encoded = fs::read(&path).unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        fs::write(&path, &encoded).unwrap();

        let paged = crate::h2qg::read_hnsw_vecs(&path).unwrap();
        assert_eq!(paged.try_get(0).unwrap().as_ref(), vec![1.25; dim]);
        assert!(
            matches!(paged.try_get(count - 1), Err(GaussError::InvalidRequest(message)) if message.contains("AES-GCM authentication failed"))
        );
        let index_path = dir.path().join(crate::h2qg::INDEX_FILE);
        fs::write(&index_path, b"previous complete generation").unwrap();
        let ids = (0..count).map(|i| format!("p{i}")).collect::<Vec<_>>();
        let result = crate::h2qg::write_index_paged_from_ids(
            dir.path(),
            &ids,
            dim,
            None,
            None,
            crate::DistanceMetric::L2,
        );
        assert!(
            matches!(result, Err(GaussError::InvalidRequest(message)) if message.contains("AES-GCM authentication failed"))
        );
        assert_eq!(
            fs::read(index_path).unwrap(),
            b"previous complete generation"
        );
        assert_eq!(fs::read(path).unwrap(), encoded);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    });
}

fn encrypted_process(run: impl FnOnce()) {
    const ENV: &str = "CHIRON_ENCRYPTED_READER_ADMISSION_TEST_KEYRING";
    if let Some(path) = std::env::var_os(ENV) {
        install_process_keyring(Keyring::load(Path::new(&path)).unwrap(), false).unwrap();
        run();
        return;
    }
    let (key, _) = keyring();
    let name = std::thread::current().name().unwrap().to_owned();
    assert!(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture"])
            .env(ENV, key.path())
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn file_root_refusal_precedes_io_and_preserves_existing_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plain");
    fs::write(&path, b"untouched").unwrap();
    with_test_storage_pool(1, |used| {
        for path in [&path, &dir.path().join("missing")] {
            assert!(matches!(
                PersistentFile::open(path),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
        }
    });
    assert_eq!(fs::read(path).unwrap(), b"untouched");
}

#[test]
fn raw_stream_reader_retains_owner_after_constructor_and_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plain");
    fs::write(&path, b"retained").unwrap();
    with_test_storage_pool(1024 * 1024, |used| {
        let mut reader = open_persistent_reader(&path).unwrap();
        assert!(used() > 0);
        let before = used();
        assert!(before < 8192, "constructor scratch must not remain pinned");
        let mut bytes = [0; 8];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"retained");
        assert_eq!(used(), before);
        drop(reader);
        assert_eq!(used(), 0);
    });
}

#[test]
fn layout_admission_tracks_header_not_whole_envelope_and_cleans_errors() {
    let (_key, ring) = keyring();
    let envelope = encrypt_bytes(&ring, FileType::Segment, &vec![41; 2 * 1024 * 1024]).unwrap();
    with_test_storage_pool(1, |used| {
        assert!(matches!(
            EncryptedLayout::from_header_with_keyring(&ring, &envelope),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(used(), 0);
    });
    let mut tampered = envelope.clone();
    let body = parse_header(&tampered).unwrap().body_offset;
    tampered[body - 1] ^= 1;
    with_test_storage_pool(32 * 1024, |used| {
        let layout = EncryptedLayout::from_header_with_keyring(&ring, &envelope).unwrap();
        assert!(used() > 0 && used() < 32 * 1024);
        assert_eq!(layout.info().plaintext_len, 2 * 1024 * 1024);
        drop(layout);
        assert_eq!(used(), 0);
        assert!(EncryptedLayout::from_header_with_keyring(&ring, &tampered).is_err());
        assert_eq!(used(), 0);
    });
}

#[test]
fn encrypted_file_owner_survives_shared_pin_and_header_refusal_retries() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("encrypted");
        let plaintext = vec![42; 2 * 1024 * 1024];
        atomic_write_persistent(&path, FileType::Segment, &plaintext).unwrap();
        let before = fs::read(&path).unwrap();
        for capacity in [1, 16 * 1024] {
            with_test_storage_pool(capacity, |used| {
                assert!(matches!(
                    PersistentFile::open(&path),
                    Err(GaussError::ResourceExhausted(_))
                ));
                assert_eq!(used(), 0);
            });
        }
        with_test_storage_pool(64 * 1024, |used| {
            let file = Arc::new(PersistentFile::open(&path).unwrap());
            let reserved = used();
            assert!(reserved > 0 && reserved < 64 * 1024);
            let pin = file.clone();
            assert_eq!(used(), reserved);
            drop(file);
            assert_eq!(used(), reserved);
            assert_eq!(pin.len(), plaintext.len());
            drop(pin);
            assert_eq!(used(), 0);
        });
        assert_eq!(fs::read(&path).unwrap(), before);
    });
}

#[test]
fn stream_chunk_overlap_is_admitted_before_first_read_and_retries() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("encrypted");
        let expected = vec![43; DEFAULT_CHUNK_SIZE + 17];
        atomic_write_persistent(&path, FileType::Segment, &expected).unwrap();
        let before = fs::read(&path).unwrap();
        with_test_storage_pool(64 * 1024, |used| {
            assert!(matches!(
                open_persistent_reader(&path),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
        });
        with_test_storage_pool(1024 * 1024, |used| {
            let mut reader = open_persistent_reader(&path).unwrap();
            let reserved = used();
            assert!(reserved >= 3 * DEFAULT_CHUNK_SIZE as u64);
            let mut actual = Vec::new();
            reader.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(used(), reserved);
            drop(reader);
            assert_eq!(used(), 0);
        });
        assert_eq!(fs::read(&path).unwrap(), before);
    });
}

#[test]
fn stream_header_and_body_errors_release_all_owners_without_mutation() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("encrypted");
        atomic_write_persistent(&path, FileType::Segment, b"authenticated").unwrap();
        let original = fs::read(&path).unwrap();
        let body = parse_header(&original).unwrap().body_offset;
        fs::write(&path, &original[..body - 1]).unwrap();
        with_test_storage_pool(1024 * 1024, |used| {
            assert!(
                matches!(PersistentFile::open(&path), Err(GaussError::InvalidRequest(message)) if message.contains("truncated encrypted header"))
            );
            assert_eq!(used(), 0);
        });
        for (offset, header_error) in [(52, true), (original.len() - 1, false)] {
            let mut bytes = original.clone();
            bytes[offset] ^= 1;
            fs::write(&path, &bytes).unwrap();
            with_test_storage_pool(1024 * 1024, |used| {
                let reader = open_persistent_reader(&path);
                if header_error {
                    assert!(reader.is_err());
                } else {
                    let mut reader = reader.unwrap();
                    assert!(reader.read_to_end(&mut Vec::new()).is_err());
                    drop(reader);
                }
                assert_eq!(used(), 0);
            });
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
    });
}

#[test]
fn stream_admission_refusal_remains_overload_at_wal_recovery_boundary() {
    encrypted_process(|| {
        let (_key, ring) = keyring();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("000000.gdwal");
        let entry = crate::wal::WalEntry::Delete {
            id: "x".repeat(100_000),
        };
        let payload = serde_json::to_vec(&entry).unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
        frame.extend_from_slice(&payload);
        let encoded = encrypt_bytes(&ring, FileType::Wal, &frame).unwrap();
        fs::write(&path, &encoded).unwrap();
        with_test_storage_pool(128 * 1024, |used| {
            assert!(matches!(
                crate::wal::Wal::recover_from(dir.path(), 0, |_| panic!("refused visitor")),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
        });
        assert_eq!(fs::read(&path).unwrap(), encoded);
        with_test_storage_pool(1024 * 1024, |used| {
            let mut visited = 0;
            crate::wal::Wal::recover_from(dir.path(), 0, |record| {
                assert!(matches!(record.entry, crate::wal::WalEntry::Delete { id } if id.len() == 100_000));
                visited += 1;
                Ok(())
            }).unwrap();
            assert_eq!(visited, 1);
            assert_eq!(used(), 0);
        });
        assert_eq!(fs::read(&path).unwrap(), encoded);
    });
}

#[test]
fn plaintext_length_inspection_admits_before_io_and_uses_only_header_metadata() {
    encrypted_process(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("encrypted");
        let expected = vec![44; 2 * 1024 * 1024];
        atomic_write_persistent(&path, FileType::Segment, &expected).unwrap();
        let original = fs::read(&path).unwrap();
        with_test_storage_pool(1, |used| {
            for path in [&path, &dir.path().join("missing")] {
                assert!(matches!(
                    persistent_plaintext_len(path),
                    Err(GaussError::ResourceExhausted(_))
                ));
                assert_eq!(used(), 0);
            }
        });
        with_test_storage_pool(64 * 1024, |used| {
            assert_eq!(
                persistent_plaintext_len(&path).unwrap(),
                expected.len() as u64
            );
            assert_eq!(used(), 0);
        });
        assert_eq!(fs::read(&path).unwrap(), original);
    });
}
