//! Sparse/fusion workspaces and ranked output retain their allocation leases.
use super::{AdmittedVec, RankedPoint};
use crate::{GaussError, Result, relational::wal_decode::MetadataCharge};
use std::{
    borrow::Cow,
    collections::{BinaryHeap, HashMap},
    mem::size_of,
    ops::Deref,
};

impl PartialEq for RankedPoint {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}
impl Eq for RankedPoint {}
impl PartialOrd for RankedPoint {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for RankedPoint {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        super::rank_order(self, other)
    }
}

/// Standard worst-first top-k heap. Its backing and moved IDs stay charged
/// through the zero-copy transfer to Rankings; upstream ID producers own their
/// allocation until push accepts it.
pub(crate) struct RankedHeap {
    values: BinaryHeap<RankedPoint>,
    extra_bytes: u64,
    memory: MetadataCharge,
    limit: usize,
}
impl RankedHeap {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            values: BinaryHeap::new(),
            extra_bytes: 0,
            memory: Default::default(),
            limit,
        }
    }

    #[cfg(test)]
    pub(crate) fn push(&mut self, id: String, score: f32) -> Result<()> {
        self.offer(Cow::Owned(id), score)
    }

    pub(crate) fn copy_push(&mut self, id: &str, score: f32) -> Result<()> {
        self.offer(Cow::Borrowed(id), score)
    }

    fn offer(&mut self, id: Cow<'_, str>, score: f32) -> Result<()> {
        if self.limit == 0
            || (self.values.len() == self.limit
                && self.values.peek().is_some_and(|worst| {
                    worst
                        .score
                        .total_cmp(&score)
                        .then_with(|| id.as_ref().cmp(&worst.id))
                        .is_ge()
                }))
        {
            return Ok(());
        }
        let incoming = match &id {
            Cow::Owned(id) => id.capacity(),
            Cow::Borrowed(id) => id.len(),
        };
        let replacing = self.values.len() == self.limit;
        let grows = !replacing && self.values.len() == self.values.capacity();
        let capacity = if grows {
            self.values
                .len()
                .checked_add(1)
                .and_then(usize::checked_next_power_of_two)
                .ok_or_else(exhausted)?
        } else {
            self.values.capacity()
        };
        let peak = bytes(capacity, size_of::<RankedPoint>())?
            .checked_add(if grows {
                bytes(self.values.capacity(), size_of::<RankedPoint>())?
            } else {
                0
            })
            .and_then(|n| n.checked_add(self.extra_bytes))
            .and_then(|n| n.checked_add(incoming as u64))
            .and_then(|n| n.checked_add(256))
            .ok_or_else(exhausted)?;
        self.memory.prepare(peak)?;
        self.values
            .try_reserve_exact(capacity - self.values.len())
            .map_err(|_| exhausted())?;
        let id = match id {
            Cow::Owned(id) => id,
            Cow::Borrowed(id) => {
                let mut copied = String::new();
                copied
                    .try_reserve_exact(id.len())
                    .map_err(|_| exhausted())?;
                copied.push_str(id);
                copied
            }
        };
        let row = RankedPoint { id, score };
        let discarded = if replacing {
            self.values.peek().expect("full heap").id.capacity() as u64
        } else {
            0
        };
        let extra = self.extra_bytes - discarded + row.id.capacity() as u64;
        let retained = bytes(self.values.capacity(), size_of::<RankedPoint>())?
            .checked_add(extra)
            .and_then(|n| n.checked_add(128))
            .ok_or_else(exhausted)?;
        if retained > peak {
            return Err(exhausted());
        }
        if replacing {
            *self.values.peek_mut().expect("full heap") = row;
        } else {
            self.values.push(row);
        }
        self.extra_bytes = extra;
        self.memory.reduce(retained);
        Ok(())
    }

    pub(crate) fn finish(self) -> Rankings {
        let mut rows = Rankings {
            values: self.values.into_vec(),
            extra_bytes: self.extra_bytes,
            memory: self.memory,
        };
        rows.sort_unstable_by(super::rank_order);
        rows
    }
}

fn exhausted() -> GaussError {
    GaussError::ResourceExhausted("search ranking memory is full".into())
}
fn bytes(capacity: usize, width: usize) -> Result<u64> {
    (capacity as u64)
        .checked_mul(width as u64)
        .ok_or_else(exhausted)
}

pub(crate) type Rankings = AdmittedVec<RankedPoint>;
impl Rankings {
    pub(crate) fn copy_push(&mut self, id: &str, score: f32) -> Result<()> {
        let grows = self.len() == self.values.capacity();
        let capacity = if grows {
            self.len()
                .checked_add(1)
                .and_then(usize::checked_next_power_of_two)
                .ok_or_else(exhausted)?
        } else {
            self.values.capacity()
        };
        let peak = bytes(capacity, size_of::<RankedPoint>())?
            .checked_add(if grows {
                bytes(self.values.capacity(), size_of::<RankedPoint>())?
            } else {
                0
            })
            .and_then(|n| n.checked_add(self.extra_bytes))
            .and_then(|n| n.checked_add(id.len() as u64))
            .and_then(|n| n.checked_add(256))
            .ok_or_else(exhausted)?;
        self.memory.prepare(peak)?;
        self.values
            .try_reserve_exact(capacity - self.len())
            .map_err(|_| exhausted())?;
        let mut copied = String::new();
        copied
            .try_reserve_exact(id.len())
            .map_err(|_| exhausted())?;
        copied.push_str(id);
        let extra = self
            .extra_bytes
            .checked_add(copied.capacity() as u64)
            .ok_or_else(exhausted)?;
        let retained = bytes(self.values.capacity(), size_of::<RankedPoint>())?
            .checked_add(extra)
            .and_then(|n| n.checked_add(128))
            .ok_or_else(exhausted)?;
        if retained > peak {
            return Err(exhausted());
        }
        self.values.push(RankedPoint { id: copied, score });
        self.extra_bytes = extra;
        self.memory.reduce(retained);
        Ok(())
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        self.values.truncate(len);
        self.extra_bytes = self.values.iter().map(|row| row.id.capacity() as u64).sum();
        if self.values.capacity() != 0 {
            // This is a subset of the admitted allocation; reduction cannot grow.
            self.memory.reduce(
                (self.values.capacity() * size_of::<RankedPoint>()) as u64 + self.extra_bytes + 128,
            );
        }
    }
}

// IDs borrow the pinned input/index rather than allocating a duplicate key.
// T is inline sparse score or fusion score/ranks; no nested allocation.
pub(crate) struct BorrowedMap<'a, T> {
    values: HashMap<&'a str, T>,
    memory: MetadataCharge,
}
impl<T> Default for BorrowedMap<'_, T> {
    fn default() -> Self {
        Self {
            values: HashMap::new(),
            memory: Default::default(),
        }
    }
}
impl<'a, T> Deref for BorrowedMap<'a, T> {
    type Target = HashMap<&'a str, T>;
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
impl<'a, T> BorrowedMap<'a, T> {
    pub(crate) fn get_mut(&mut self, id: &str) -> Option<&mut T> {
        self.values.get_mut(id)
    }
    pub(crate) fn insert(&mut self, id: &'a str, value: T) -> Result<()> {
        if let Some(old) = self.values.get_mut(id) {
            *old = value;
            return Ok(());
        }
        let width = size_of::<(&str, T)>()
            .checked_add(64)
            .ok_or_else(exhausted)?;
        let required = self.len().checked_add(1).ok_or_else(exhausted)?;
        let peak = if required > self.values.capacity() {
            bytes(
                required.checked_next_power_of_two().ok_or_else(exhausted)?,
                width.checked_mul(2).ok_or_else(exhausted)?,
            )?
            .checked_add(bytes(self.values.capacity(), width)?)
            .ok_or_else(exhausted)?
        } else {
            bytes(self.values.capacity(), width)?
        };
        self.memory
            .prepare(peak.checked_add(256).ok_or_else(exhausted)?)?;
        self.values.try_reserve(1).map_err(|_| exhausted())?;
        let retained = bytes(self.values.capacity(), width)?
            .checked_add(128)
            .ok_or_else(exhausted)?;
        if retained > peak + 256 {
            return Err(exhausted());
        }
        self.values.insert(id, value);
        self.memory.reduce(retained);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{model::HybridFusion, relational::wal_decode::with_test_storage_pool};

    #[test]
    fn heap_borrowed_id_copy_admits_before_growth_and_discards_without_copy() {
        let id = "日本語".repeat(4096);
        with_test_storage_pool(1, |used| {
            let mut heap = RankedHeap::new(1);
            assert!(matches!(
                heap.copy_push(&id, 1.0),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(heap.values.capacity(), 0);
            assert!(heap.values.is_empty());
            assert_eq!(used(), 0);
        });
        with_test_storage_pool(1024, |used| {
            let mut heap = RankedHeap::new(1);
            heap.copy_push("kept", 2.0).unwrap();
            let retained = used();
            heap.copy_push(&id, 1.0).unwrap();
            assert_eq!(used(), retained);
            assert!(matches!(
                heap.copy_push(&id, 3.0),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), retained);
            assert_eq!(heap.values.peek().unwrap().id, "kept");
            drop(heap);
            assert_eq!(used(), 0);
        });
        with_test_storage_pool(128 * 1024, |used| {
            let mut heap = RankedHeap::new(1);
            heap.copy_push(&id, 1.0).unwrap();
            let rows = heap.finish();
            assert_eq!(rows[0].id, id);
            assert_ne!(rows[0].id.as_ptr(), id.as_ptr());
            assert!(used() >= id.len() as u64);
            drop(rows);
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn top_k_heap_matches_sort_oracle_and_transfers_backing_without_copy() {
        let input: Vec<_> = (0..500)
            .map(|i| (format!("public-{:03}", 500 - i), ((i * 17) % 31) as f32))
            .collect();
        for k in [0, 1, 17, 501, usize::MAX] {
            let mut expected = input.clone();
            expected.sort_unstable_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
            expected.truncate(k);
            with_test_storage_pool(256 * 1024, |used| {
                let mut heap = RankedHeap::new(k);
                assert_eq!(used(), 0, "limit does not allocate");
                for (id, score) in &input {
                    heap.push(id.clone(), *score).unwrap();
                }
                let backing = heap.values.as_slice().as_ptr();
                let retained = used();
                let rows = heap.finish();
                assert_eq!(rows.as_ptr(), backing);
                assert_eq!(used(), retained);
                assert_eq!(
                    rows.iter()
                        .map(|r| (r.id.clone(), r.score))
                        .collect::<Vec<_>>(),
                    expected
                );
                let mut iter = rows.into_iter();
                let first = iter.next();
                assert_eq!(used(), retained, "consuming iterator retains all backing");
                drop(first);
                drop(iter);
                assert_eq!(used(), 0);
            });
        }
    }

    #[test]
    fn heap_replacement_refusal_discard_and_cancel_preserve_owner() {
        with_test_storage_pool(1024, |used| {
            let mut heap = RankedHeap::new(1);
            let id = String::from("kept");
            let pointer = id.as_ptr();
            heap.push(id, 2.0).unwrap();
            let retained = used();
            // A worse or tied row never grows the heap or its charge.
            heap.push("z".repeat(4096), 1.0).unwrap();
            assert_eq!(used(), retained);
            assert!(matches!(
                heap.push("better".repeat(4096), 3.0),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), retained);
            assert_eq!(heap.values.peek().unwrap().id.as_ptr(), pointer);
            let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            assert!(
                crate::relational::with_sql_cancellation(cancel, || heap
                    .push("cancelled".into(), 3.0))
                .is_err()
            );
            assert_eq!(used(), retained);
            heap.push("a".into(), 2.0).unwrap();
            assert_eq!(heap.values.len(), 1);
            assert_eq!(used(), retained - 3);
            let rows = heap.finish();
            assert_eq!(rows[0].id, "a");
            drop(rows);
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn ranking_growth_truncate_and_consuming_owner_release_backing() {
        let id = "日本語".repeat(1024);
        with_test_storage_pool(1, |used| {
            let mut rows = Rankings::default();
            assert!(matches!(
                rows.copy_push(&id, 1.0),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert!(rows.is_empty());
            assert_eq!(used(), 0);
        });
        with_test_storage_pool(64 * 1024, |used| {
            let mut rows = Rankings::default();
            rows.copy_push(&id, 1.0).unwrap();
            rows.copy_push(&id, 2.0).unwrap();
            assert_ne!(rows[0].id.as_ptr(), id.as_ptr());
            let before = used();
            let freed = rows[1].id.capacity() as u64;
            rows.truncate(1);
            assert_eq!(used(), before - freed);
            let retained = used();
            let mut iter = rows.into_iter();
            let row = iter.next().unwrap();
            assert_eq!(row.id, id);
            assert_eq!(row.score, 1.0);
            assert_eq!(used(), retained);
            drop(row);
            drop(iter);
            assert_eq!(used(), 0);
        });
        with_test_storage_pool(1024, |used| {
            let mut rows = Rankings::default();
            loop {
                let before = (rows.len(), rows.values.capacity(), used());
                match rows.copy_push("row-id", rows.len() as f32) {
                    Ok(()) => assert!(rows.len() < 100),
                    Err(GaussError::ResourceExhausted(_)) => {
                        assert_eq!((rows.len(), rows.values.capacity(), used()), before);
                        assert!(!rows.is_empty());
                        break;
                    }
                    Err(error) => panic!("unexpected error: {error}"),
                }
            }
            drop(rows);
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn borrowed_score_growth_and_wand_threshold_admit_before_allocation() {
        let id = "borrowed".repeat(1024);
        with_test_storage_pool(1024, |used| {
            let mut scores = BorrowedMap::default();
            scores.insert(&id, 3.0_f32).unwrap();
            assert_eq!(scores.keys().next().unwrap().as_ptr(), id.as_ptr());
            assert!(used() < id.len() as u64, "input ID is borrowed");
            let retained = used();
            scores.insert(&id, 2.0).unwrap();
            assert_eq!(used(), retained);
            assert_eq!(scores[&*id], 2.0);
            assert_eq!(
                super::super::sparse_score_threshold(&scores, 1).unwrap(),
                Some(2.0)
            );
            assert_eq!(used(), retained, "threshold workspace is temporary");
            drop(scores);
            assert_eq!(used(), 0);
        });
        let scores = HashMap::from([("a", 1.0_f32), ("b", 3.0), ("c", 2.0)]);
        with_test_storage_pool(1, |used| {
            assert!(matches!(
                super::super::sparse_score_threshold(&scores, 2),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(
                super::super::sparse_score_threshold(&scores, 0).unwrap(),
                None
            );
            assert_eq!(used(), 0);
        });
        with_test_storage_pool(64 * 1024, |used| {
            assert_eq!(
                super::super::sparse_score_threshold(&scores, 2).unwrap(),
                Some(2.0)
            );
            assert_eq!(used(), 0);
        });
        with_test_storage_pool(1, |used| {
            let mut scores = BorrowedMap::default();
            assert!(matches!(
                scores.insert("a", 1.0_f32),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert!(scores.is_empty());
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn fusion_refuses_and_preserves_weighted_rrf_and_duplicate_tie_oracles() {
        let rows = |ids: &[(&str, f32)]| {
            ids.iter()
                .map(|(id, score)| RankedPoint {
                    id: (*id).into(),
                    score: *score,
                })
                .collect::<Vec<_>>()
        };
        let dense = rows(&[("a", 0.9), ("b", 0.85), ("c", 0.1)]);
        let sparse = rows(&[("a", 1.0), ("b", 25.0), ("c", 30.0)]);
        for fusion in [HybridFusion::Rrf, HybridFusion::Weighted] {
            with_test_storage_pool(1, |used| {
                assert!(matches!(
                    super::super::fuse_rankings(&dense, &sparse, fusion, 1.0, 1.0),
                    Err(GaussError::ResourceExhausted(_))
                ));
                assert_eq!(used(), 0);
            });
        }
        with_test_storage_pool(64 * 1024, |used| {
            let ranked =
                super::super::fuse_rankings(&dense, &sparse, HybridFusion::Weighted, 1.0, 1.0)
                    .unwrap();
            assert_eq!(
                ranked.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
                ["b", "a", "c"]
            );
            assert!((ranked[0].score - (0.75_f32 / 0.8 + 24.0 / 29.0)).abs() < 1e-6);
            assert_eq!(ranked[1].score, 1.0);
            assert_eq!(ranked[2].score, 1.0);
            assert!(used() > 0);
            drop(ranked);
            assert_eq!(used(), 0);
            let ranked =
                super::super::fuse_rankings(&dense, &sparse, HybridFusion::Rrf, 1.0, 1.0).unwrap();
            for (rank, row) in ranked.iter().enumerate() {
                assert_eq!(row.score, 2.0 / (61.0 + rank as f32));
            }
            drop(ranked);
            assert_eq!(used(), 0);
            let duplicates = rows(&[("a", 1.0), ("b", 1.0), ("a", 1.0)]);
            for (dense, sparse) in [(&duplicates[..], &[][..]), (&[][..], &duplicates[..])] {
                let ranked =
                    super::super::fuse_rankings(dense, sparse, HybridFusion::Rrf, 0.0, 0.0)
                        .unwrap();
                assert_eq!(
                    ranked.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
                    ["b", "a"],
                    "last duplicate rank controls a tied result"
                );
                drop(ranked);
                assert_eq!(used(), 0);
            }
        });
    }

    #[test]
    fn ranking_cancellation_and_heap_transfer_release_without_publication() {
        with_test_storage_pool(1, |used| {
            assert!(matches!(
                RankedHeap::new(1).push("legacy".repeat(1024), 1.0),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
        });
        with_test_storage_pool(64 * 1024, |used| {
            let mut heap = RankedHeap::new(1);
            heap.push("legacy".repeat(1024), 1.0).unwrap();
            let rows = heap.finish();
            assert!(used() > 6144);
            drop(rows);
            assert_eq!(used(), 0);
            let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let result = crate::relational::with_sql_cancellation(cancel, || {
                let mut rows = Rankings::default();
                rows.copy_push("cancelled", 1.0)
            });
            assert!(
                matches!(result, Err(GaussError::InvalidRequest(message)) if message == "query canceled")
            );
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn fusion_nonnegative_zero_weights_preserve_score_bits() {
        let dense = vec![RankedPoint {
            id: "a".into(),
            score: 1.0,
        }];
        let sparse = vec![RankedPoint {
            id: "b".into(),
            score: 1.0,
        }];
        for fusion in [HybridFusion::Rrf, HybridFusion::Weighted] {
            for (dense_weight, sparse_weight) in [(-0.0, 0.0), (0.0, -0.0), (-0.0, -0.0)] {
                let ranked = super::super::fuse_rankings(
                    &dense,
                    &sparse,
                    fusion,
                    dense_weight,
                    sparse_weight,
                )
                .unwrap();
                assert_eq!(
                    ranked.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
                    ["a", "b"]
                );
                for row in ranked.iter() {
                    assert_eq!(
                        row.score.to_bits(),
                        0.0_f32.to_bits(),
                        "legacy accumulation starts from positive zero"
                    );
                }
            }
        }
    }
}
