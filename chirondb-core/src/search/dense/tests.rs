use super::*;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

fn point(i: usize) -> Point {
    Point {
        id: format!("p{i:04}"),
        vector: vec![(i % 7) as f32, 1.0],
        vectors: if i.is_multiple_of(3) {
            HashMap::new()
        } else {
            HashMap::from([("named".into(), vec![1.0, (i % 7) as f32])])
        },
        sparse_vector: None,
        payload: json!({"tag": i % 2, "nested": {"value": i % 5}}),
    }
}

#[test]
fn exact_index_proof_rejects_paths_array_ranges_and_residual_predicates() {
    for value in [
        json!({"tenant": "a"}),
        json!({"tenant": {"eq": "a"}}),
        json!({"tenant": {"in": ["a", "b"]}}),
        json!({"price": 4}),
        json!({"missing": null}),
    ] {
        assert!(indexed_filter_is_exact(Some(&Filter(value))));
    }
    for value in [
        json!({}),
        json!({"a.b": "a"}),
        json!({"a[].b": "a"}),
        json!({"price": {"gte": 5, "lte": 6}}),
        json!({"tenant": {"ne": "a"}}),
        json!({"body": {"text": "term"}}),
        json!({"items": {"nested": {"a": 1}}}),
        json!({"price": {"eq": 1, "in": [10]}}),
    ] {
        assert!(
            !indexed_filter_is_exact(Some(&Filter(value.clone()))),
            "{value}"
        );
    }
    assert!(!indexed_filter_is_exact(None));
}

#[test]
fn expired_budget_stops_before_skipping_ineligible_backfill() {
    let point = point(1);
    let excluded = HashSet::new();
    let mut ranker = DenseRanker::new(DenseSearchParams {
        query: &[1.0, 2.0],
        vector_name: None,
        metric: crate::DistanceMetric::L2,
        k: 7,
        filter: None,
        excluded: &excluded,
        eligible: &|_| false,
        should_stop: &|| true,
        parallel: false,
        payload_free: false,
    });
    assert!(
        !ranker
            .visit(&point.id, CandidateRead::Point(&point))
            .unwrap()
    );
    let (rows, searched, scored, degraded) = ranker.finish().unwrap();
    assert!(rows.is_empty());
    assert_eq!(searched, 0);
    assert_eq!(scored, 0);
    assert!(degraded);
}

#[test]
fn proven_membership_reads_only_vectors_until_final_payload_projection() {
    struct VectorOnly(OwnedResolver);
    impl PointResolver for VectorOnly {
        fn resolve_point(&self, _: &str) -> Result<Option<Cow<'_, Point>>> {
            unreachable!()
        }
        fn resolve_candidate(&self, id: &str) -> Result<Option<CandidatePoint<'_>>> {
            self.0.resolve_candidate(id)
        }
        fn resolve_vector(
            &self,
            _: &str,
            _: Option<&str>,
        ) -> Result<Option<crate::index::VectorRead<'_>>> {
            Ok(Some(crate::index::VectorRead::borrowed(
                &self.0.point.vector,
            )))
        }
        fn contains_point(&self, _: &str) -> bool {
            true
        }
    }
    let mut point = point(1);
    point.id = "good".into();
    let resolver = VectorOnly(OwnedResolver {
        point,
        reads: AtomicUsize::new(0),
    });
    let excluded = HashSet::new();
    let mut ranker = DenseRanker::new(DenseSearchParams {
        query: &[1.0, 1.0],
        metric: crate::DistanceMetric::L2,
        k: 1,
        vector_name: None,
        filter: None,
        excluded: &excluded,
        eligible: &|_| true,
        should_stop: &|| false,
        parallel: true,
        payload_free: true,
    });
    for _ in 0..257 {
        ranker
            .visit("good", CandidateRead::Resolver(&resolver))
            .unwrap();
    }
    let (ranked, searched, scored, degraded) = ranker.finish().unwrap();
    assert_eq!(searched, 257);
    assert_eq!(scored, 257);
    assert!(!degraded);
    assert_eq!(resolver.0.reads.load(Ordering::Relaxed), 0);
    dense_hits(&resolver, ranked, true, &|| false).unwrap();
    assert_eq!(resolver.0.reads.load(Ordering::Relaxed), 1);
}

#[test]
fn final_projection_honors_stop_before_and_after_payload_reads() {
    struct StopOnRead {
        points: [Point; 2],
        stopped: std::cell::Cell<bool>,
        reads: std::cell::Cell<usize>,
    }
    impl PointResolver for StopOnRead {
        fn contains_point(&self, id: &str) -> bool {
            self.points.iter().any(|point| point.id == id)
        }

        fn resolve_point(&self, id: &str) -> Result<Option<Cow<'_, Point>>> {
            self.reads.set(self.reads.get() + 1);
            self.stopped.set(true);
            Ok(self
                .points
                .iter()
                .find(|point| point.id == id)
                .map(Cow::Borrowed))
        }
    }
    crate::relational::wal_decode::with_test_storage_pool(1024 * 1024, |used| {
        let resolver = StopOnRead {
            points: [point(1), point(2)],
            stopped: std::cell::Cell::new(false),
            reads: std::cell::Cell::new(0),
        };
        let mut ranked = Rankings::default();
        ranked.copy_push(&resolver.points[0].id, 2.0).unwrap();
        ranked.copy_push(&resolver.points[1].id, 1.0).unwrap();
        let (hits, admission, degraded) =
            dense_hits(&resolver, ranked, true, &|| resolver.stopped.get()).unwrap();
        assert!(degraded);
        assert_eq!(resolver.reads.get(), 1, "no read may start after stopping");
        assert_eq!(hits.len(), 1, "retain the completed winning prefix");
        assert_eq!(hits[0].id, resolver.points[0].id);
        assert_eq!(hits[0].score, 2.0);
        assert_eq!(hits[0].payload, resolver.points[0].payload);
        drop(hits);
        drop(admission);
        assert_eq!(used(), 0);

        for payload in [false, true] {
            let mut ranked = Rankings::default();
            ranked.copy_push(&resolver.points[0].id, 1.0).unwrap();
            let (hits, admission, degraded) =
                dense_hits(&resolver, ranked, payload, &|| resolver.stopped.get()).unwrap();
            assert!(degraded);
            assert!(hits.is_empty());
            assert_eq!(resolver.reads.get(), 1);
            drop(hits);
            drop(admission);
            assert_eq!(used(), 0);
        }
    });
}

#[test]
fn dense_streaming_matches_sorted_oracle_across_batch_boundaries() {
    for count in [0, 7, 127, 128, 257] {
        let points: HashMap<_, _> = (0..count)
            .map(|i| {
                let point = point(i);
                (point.id.clone(), point)
            })
            .collect();
        let mut order = points.values().collect::<Vec<_>>();
        order.sort_by(|a, b| b.id.cmp(&a.id));
        let excluded = HashSet::from(["p0000".to_string()]);
        let filter = Filter(json!({"tag": {"ne": 1}}));
        let query = [1.0, 2.0];
        for metric in [
            crate::DistanceMetric::L2,
            crate::DistanceMetric::Cosine,
            crate::DistanceMetric::Dot,
        ] {
            for vector_name in [None, Some("named")] {
                for parallel in [false, true] {
                    let eligible = |id: &str| id != "p0002";
                    let mut ranker = DenseRanker::new(DenseSearchParams {
                        query: &query,
                        metric,
                        k: 7,
                        vector_name,
                        filter: Some(&filter),
                        excluded: &excluded,
                        eligible: &eligible,
                        should_stop: &|| false,
                        parallel,
                        payload_free: false,
                    });
                    let mut expected = Vec::new();
                    let mut searched = 0;
                    for point in &order {
                        assert!(
                            ranker
                                .visit(&point.id, CandidateRead::Point(point))
                                .unwrap()
                        );
                        if excluded.contains(&point.id)
                            || !eligible(&point.id)
                            || !filter.matches(&point.payload)
                        {
                            continue;
                        }
                        let vector = point_vector(point, vector_name);
                        if !parallel || count < BATCH_SIZE || vector.is_some() {
                            searched += 1;
                        }
                        if let Some(vector) = vector {
                            expected.push(RankedPoint {
                                id: point.id.clone(),
                                score: metric.score(&query, vector).unwrap(),
                            });
                        }
                    }
                    expected.sort_by(rank_order);
                    let expected_scored = expected.len();
                    expected.truncate(7);
                    let (actual, actual_searched, actual_scored, degraded) =
                        ranker.finish().unwrap();
                    assert_eq!(actual_scored, expected_scored);
                    assert!(!degraded);
                    assert_eq!(
                        actual_searched, searched,
                        "count={count} parallel={parallel} name={vector_name:?}"
                    );
                    assert_eq!(
                        actual
                            .iter()
                            .map(|row| (&row.id, row.score))
                            .collect::<Vec<_>>(),
                        expected
                            .iter()
                            .map(|row| (&row.id, row.score))
                            .collect::<Vec<_>>()
                    );
                    for payload in [false, true] {
                        let mut rankings = Rankings::default();
                        for row in actual.iter() {
                            rankings.copy_push(&row.id, row.score).unwrap();
                        }
                        let (hits, _output_admission, degraded) =
                            dense_hits(&points, rankings, payload, &|| false).unwrap();
                        assert!(!degraded);
                        for hit in hits {
                            assert_eq!(
                                hit.payload,
                                if payload {
                                    points[&hit.id].payload.clone()
                                } else {
                                    serde_json::Value::Null
                                }
                            );
                        }
                    }
                }
            }
        }
    }
}

struct OwnedResolver {
    point: Point,
    reads: AtomicUsize,
}
impl PointResolver for OwnedResolver {
    fn resolve_point(&self, _: &str) -> Result<Option<Cow<'_, Point>>> {
        unreachable!("native candidates must retain their allocation admission")
    }
    fn resolve_candidate(&self, id: &str) -> Result<Option<CandidatePoint<'_>>> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if id == "bad" {
            return Err(GaussError::InvalidRequest("bad storage".into()));
        }
        Ok(Some(CandidatePoint::Owned(
            crate::seal::AdmittedPoint::copy(&self.point)?,
        )))
    }
    fn contains_point(&self, _: &str) -> bool {
        true
    }
}

#[test]
fn dense_streaming_bounds_owned_payload_lifetime_and_reads_only_eligible_candidates() {
    crate::relational::wal_decode::with_test_storage_pool(1024 * 1024, |used| {
        let mut point = point(1);
        point.payload = json!({"body": "x".repeat(16 * 1024)});
        let resolver = OwnedResolver {
            point,
            reads: AtomicUsize::new(0),
        };
        let excluded = HashSet::from(["excluded".to_string()]);
        let eligible = |id: &str| id != "bad";
        let mut ranker = DenseRanker::new(DenseSearchParams {
            query: &[1.0, 1.0],
            metric: crate::DistanceMetric::L2,
            k: 1,
            vector_name: None,
            filter: None,
            excluded: &excluded,
            eligible: &eligible,
            should_stop: &|| false,
            parallel: false,
            payload_free: false,
        });
        for _ in 0..512 {
            ranker
                .visit("excluded", CandidateRead::Resolver(&resolver))
                .unwrap();
            ranker
                .visit("bad", CandidateRead::Resolver(&resolver))
                .unwrap();
            ranker
                .visit("good", CandidateRead::Resolver(&resolver))
                .unwrap();
            assert!(used() < 4096, "owned point must be released after scoring");
        }
        assert_eq!(resolver.reads.load(Ordering::Relaxed), 512);
        let (ranked, searched, scored, degraded) = ranker.finish().unwrap();
        assert_eq!(scored, searched);
        assert_eq!(ranked.len(), 1);
        assert_eq!(searched, 512);
        assert!(!degraded);
        drop(ranked);
        assert_eq!(used(), 0);
        let mut eager = AdmittedVec::default();
        let failure = (0..512).find_map(|_| {
            let result = resolver
                .resolve_candidate("good")
                .and_then(|point| eager.push(point.unwrap()));
            result.err()
        });
        assert!(matches!(failure, Some(GaussError::ResourceExhausted(_))));
        drop(eager);
        assert_eq!(used(), 0);
    });
}

#[test]
fn dense_streaming_cancellation_and_errors_release_without_publishing() {
    crate::relational::wal_decode::with_test_storage_pool(1024 * 1024, |used| {
        let resolver = OwnedResolver {
            point: point(1),
            reads: AtomicUsize::new(0),
        };
        let excluded = HashSet::new();
        let stopped = std::cell::Cell::new(false);
        let should_stop = || stopped.get();
        let params = || DenseSearchParams {
            query: &[1.0, 1.0],
            metric: crate::DistanceMetric::L2,
            k: 1,
            vector_name: None,
            filter: None,
            excluded: &excluded,
            eligible: &|_| true,
            should_stop: &should_stop,
            parallel: false,
            payload_free: false,
        };
        let mut ranker = DenseRanker::new(params());
        ranker
            .visit("good", CandidateRead::Resolver(&resolver))
            .unwrap();
        stopped.set(true);
        assert!(
            !ranker
                .visit("bad", CandidateRead::Resolver(&resolver))
                .unwrap()
        );
        let (ranked, searched, scored, degraded) = ranker.finish().unwrap();
        assert_eq!(scored, searched);
        assert_eq!(searched, 1);
        assert!(degraded);
        drop(ranked);
        assert_eq!(used(), 0);
        stopped.set(false);
        let mut ranker = DenseRanker::new(params());
        ranker
            .visit("good", CandidateRead::Resolver(&resolver))
            .unwrap();
        assert!(
            ranker
                .visit("bad", CandidateRead::Resolver(&resolver))
                .is_err()
        );
        drop(ranker);
        assert_eq!(used(), 0);
    });
}
