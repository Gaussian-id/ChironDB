//! Read the requested sealed replacements before a durable decision. The
//! staging owns only affected rows; projection cannot reread after commit.
use super::Collection;
use crate::relational::wal_decode::MetadataCharge;
use crate::{GaussError, Result, seal::AdmittedPoint, searcher::SegLoc};
use std::{
    collections::HashMap,
    mem::size_of,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
pub(super) struct SealedPoints {
    points: HashMap<String, AdmittedPoint>,
    _memory: MetadataCharge,
}

impl SealedPoints {
    pub(super) fn prepare<'a>(
        collection: &Collection,
        ids: impl Iterator<Item = &'a str> + Clone,
        cancelled: &AtomicBool,
    ) -> Result<Self> {
        let exhausted =
            || GaussError::ResourceExhausted("mutation read staging memory is full".into());
        if collection.graph_lifecycle.is_enabled() {
            return Ok(Self::default());
        }
        let check_cancelled = || {
            if cancelled.load(Ordering::Acquire) {
                Err(GaussError::ResourceExhausted(
                    "mutation read staging canceled".into(),
                ))
            } else {
                Ok(())
            }
        };
        check_cancelled()?;
        let mut count = 0usize;
        let mut key_bytes = 0u64;
        for id in ids.clone() {
            check_cancelled()?;
            if matches!(collection.id_index.get(id), Some(SegLoc::Searcher(_))) {
                count = count.checked_add(1).ok_or_else(exhausted)?;
                key_bytes = key_bytes
                    .checked_add(id.len() as u64)
                    .ok_or_else(exhausted)?;
            }
        }
        let mut staged = Self::default();
        if count == 0 {
            return Ok(staged);
        }
        let budget = (count as u64)
            .checked_mul((size_of::<(String, AdmittedPoint)>() as u64 + 64) * 4)
            .and_then(|n| n.checked_add(key_bytes.checked_mul(2)?))
            .and_then(|n| n.checked_add(8192))
            .ok_or_else(exhausted)?;
        staged._memory.prepare(budget)?;
        staged.points.try_reserve(count).map_err(|_| exhausted())?;
        for id in ids {
            check_cancelled()?;
            if staged.points.contains_key(id) {
                continue;
            }
            let Some(SegLoc::Searcher(index)) = collection.id_index.get(id) else {
                continue;
            };
            let searcher = collection
                .searchers
                .get(*index as usize)
                .ok_or_else(|| GaussError::InvalidRequest("invalid sealed point owner".into()))?;
            let point = searcher
                .store
                .try_get_admitted(id)?
                .ok_or_else(|| GaussError::PointNotFound(id.to_owned()))?;
            staged.points.insert(id.to_owned(), point);
        }
        Ok(staged)
    }

    pub(super) fn take(&mut self, id: &str) -> Option<AdmittedPoint> {
        self.points.remove(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Db, DistanceMetric, Point, relational::wal_decode::with_test_storage_pool};
    use serde_json::json;

    fn point(id: &str, term: u32) -> Point {
        Point {
            id: id.into(),
            vector: vec![1.25, -3.5],
            vectors: Default::default(),
            sparse_vector: Some(crate::SparseVector {
                indices: vec![term],
                values: vec![1.0],
            }),
            payload: json!({"kind":term}),
        }
    }

    fn database(path: &std::path::Path) -> Db {
        let db = Db::open(path).unwrap();
        db.create_collection(
            serde_json::from_value(json!({"name":"docs","vector_dim":2,"metric":"l2"})).unwrap(),
        )
        .unwrap();
        db
    }

    #[test]
    fn staging_admits_only_requested_rows_and_releases_after_last_owner() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(dir.path());
        db.upsert("docs", vec![point("a", 1), point("b", 2)])
            .unwrap();
        db.compact_collection("docs").unwrap();
        let coll = db.inner.read().collections["docs"].clone();
        let coll = coll.read();
        let cancel = AtomicBool::new(false);
        with_test_storage_pool(2 * 1024 * 1024, |used| {
            let mut staged =
                SealedPoints::prepare(&coll, ["a", "a", "missing"].into_iter(), &cancel).unwrap();
            assert_eq!(staged.points.len(), 1);
            let owner = staged.take("a").unwrap();
            let bytes = used();
            assert!(bytes > 0);
            drop(staged);
            assert!(used() > 0 && used() < bytes);
            assert_eq!(serde_json::to_value(&*owner).unwrap(), json!(point("a", 1)));
            drop(owner);
            assert_eq!(used(), 0);
        });
        with_test_storage_pool(1, |used| {
            assert!(matches!(
                SealedPoints::prepare(&coll, ["a"].into_iter(), &cancel),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
            assert!(
                SealedPoints::prepare(&coll, ["missing"].into_iter(), &cancel)
                    .unwrap()
                    .points
                    .is_empty()
            );
            cancel.store(true, Ordering::Release);
            assert!(matches!(
                SealedPoints::prepare(&coll, ["a"].into_iter(), &cancel),
                Err(GaussError::ResourceExhausted(message)) if message.contains("canceled")
            ));
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn duplicate_sealed_mutations_preserve_last_write_and_remove_old_terms() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(dir.path());
        db.upsert("docs", vec![point("a", 1), point("b", 2)])
            .unwrap();
        db.compact_collection("docs").unwrap();
        db.upsert("docs", vec![point("a", 3), point("a", 4)])
            .unwrap();
        let query = |term: u32| {
            serde_json::from_value(json!({
                "sparse_vector":{"indices":[term],"values":[1.0]},"k":10
            }))
            .unwrap()
        };
        for term in [1, 3] {
            assert!(
                db.hybrid_search("docs", query(term))
                    .unwrap()
                    .hits
                    .is_empty()
            );
        }
        assert_eq!(db.hybrid_search("docs", query(4)).unwrap().hits[0].id, "a");
        assert_eq!(db.delete("docs", &["b".into(), "b".into()]).unwrap(), 1);
        assert!(db.hybrid_search("docs", query(2)).unwrap().hits.is_empty());
        db.compact_collection("docs").unwrap();
        assert_eq!(
            db.delete_by_filter("docs", &crate::Filter(json!({"kind":4})))
                .unwrap(),
            1
        );
        assert!(
            db.get_points("docs", &["a".into(), "b".into()])
                .unwrap()
                .is_empty()
        );
        drop(db);
        assert!(
            Db::open(dir.path())
                .unwrap()
                .get_points("docs", &["a".into(), "b".into()])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn failed_advisory_index_insert_keeps_acknowledged_row_searchable_and_durable() {
        let dir = tempfile::tempdir().unwrap();
        let db = database(dir.path());
        let graph_dir = tempfile::tempdir().unwrap();
        let mut foreign = point("foreign", 1);
        foreign.vector.push(0.0);
        crate::h2qg::write_test_paged_graph(graph_dir.path(), &[foreign], DistanceMetric::L2)
            .unwrap();
        db.inner.read().collections["docs"].write().streamer.hnsw =
            Some(crate::h2qg::read_index_paged(graph_dir.path()).unwrap());
        db.upsert("docs", vec![point("accepted", 2)]).unwrap();
        assert!(
            db.inner.read().collections["docs"]
                .read()
                .streamer
                .hnsw
                .is_none()
        );
        let query = || serde_json::from_value(json!({"vector":[1.25,-3.5],"k":1})).unwrap();
        assert_eq!(db.search("docs", query()).unwrap().hits[0].id, "accepted");
        drop(db);
        let reopened = Db::open(dir.path()).unwrap();
        assert_eq!(
            reopened.search("docs", query()).unwrap().hits[0].id,
            "accepted"
        );
    }
}
