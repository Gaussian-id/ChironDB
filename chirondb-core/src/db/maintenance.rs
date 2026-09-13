//! Scheduled collection maintenance admission and deduplication.

use std::{
    collections::{BTreeSet, HashSet},
    sync::{Arc, Mutex as StdMutex},
};

use super::*;

pub(super) struct CollectionCompactionGuard {
    in_flight: Arc<StdMutex<HashSet<String>>>,
    collection: String,
}

impl CollectionCompactionGuard {
    pub(super) fn try_enter(
        in_flight: Arc<StdMutex<HashSet<String>>>,
        collection: &str,
    ) -> Option<Self> {
        let mut active = in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !active.insert(collection.to_string()) {
            return None;
        }
        drop(active);
        Some(Self {
            in_flight,
            collection: collection.to_string(),
        })
    }
}

impl Drop for CollectionCompactionGuard {
    fn drop(&mut self) {
        self.in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.collection);
    }
}

impl Db {
    /// Run one scheduled maintenance sweep over the union of vector and graph
    /// triggers. The legacy WAL threshold remains one trigger; immutable
    /// segment count, vector tombstone density, and Rev 3.4 section 13.2 graph
    /// debt can independently admit the same collection. A deterministic set
    /// deduplicates those reasons before any build starts.
    pub fn compact_collections_for_maintenance(
        &self,
        threshold_bytes: u64,
    ) -> Result<Vec<CompactResponse>> {
        if threshold_bytes == 0 {
            return Err(GaussError::InvalidRequest(
                "auto-compaction WAL threshold must be greater than zero".to_string(),
            ));
        }

        let (mut candidates, graph_candidates) = {
            let inner = self.inner.read();
            let mut candidates = BTreeSet::new();
            let mut graph_candidates = Vec::new();
            for (name, arc_coll) in &inner.collections {
                let collection = arc_coll.read();
                if collection.index_build_in_flight
                    || collection.sealing.is_some()
                    || collection.generation_build_in_flight
                {
                    continue;
                }
                let wal_trigger = collection.wal.retained_bytes()? >= threshold_bytes;
                let segment_trigger = collection.searchers.len() > 8;
                let stored_points = collection
                    .searchers
                    .iter()
                    .map(|searcher| searcher.store.len())
                    .sum::<usize>();
                let tombstones = collection
                    .searchers
                    .iter()
                    .map(|searcher| searcher.tombstones.len())
                    .sum::<usize>();
                let tombstone_trigger =
                    stored_points != 0 && (tombstones as u128) * 5 > stored_points as u128;
                if wal_trigger || segment_trigger || tombstone_trigger {
                    candidates.insert(name.clone());
                }
                if collection.graph_generation.is_some() {
                    graph_candidates.push(name.clone());
                }
            }
            (candidates, graph_candidates)
        };

        // Each census pins its own manifest/resolver/overlay tuple and scans
        // off-lock. Skip the scan when a vector trigger has already admitted
        // the collection; the eventual graph-aware compactor consumes both.
        for name in graph_candidates {
            if candidates.contains(&name) {
                continue;
            }
            match self.graph_maintenance_stats(&name) {
                Ok(Some(stats)) if stats.requires_compaction() => {
                    candidates.insert(name);
                }
                Ok(_) | Err(GaussError::CollectionNotFound(_)) => {}
                Err(error) => return Err(error),
            }
        }

        let mut compacted = Vec::with_capacity(candidates.len());
        for name in candidates {
            let Some(_compaction) = CollectionCompactionGuard::try_enter(
                Arc::clone(&self.compactions_in_flight),
                &name,
            ) else {
                metrics::counter!(
                    "chirondb_auto_compaction_deferred_total",
                    "reason" => "collection_busy"
                )
                .increment(1);
                continue;
            };
            let coll = match self.get_coll(&name) {
                Ok(coll) => coll,
                Err(GaussError::CollectionNotFound(_)) => continue,
                Err(error) => return Err(error),
            };
            let storage_busy = {
                let collection = coll.read();
                collection.index_build_in_flight
                    || collection.sealing.is_some()
                    || collection.generation_build_in_flight
            };
            if storage_busy {
                metrics::counter!(
                    "chirondb_auto_compaction_deferred_total",
                    "reason" => "generation_busy"
                )
                .increment(1);
                continue;
            }
            compacted.push(
                self.compact_collection_with_scope_admitted(
                    &name,
                    LsvecCompactionScope::SizeTiered,
                )?,
            );
        }
        Ok(compacted)
    }
}
