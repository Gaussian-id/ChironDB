//! Experimental WAL streaming/quorum scaffold.
//!
//! This module hardens bounded streaming, voter accounting, and durable local
//! follower apply. It is not a production replication protocol: membership
//! consensus, source-LSN/exactly-once checkpoints, leader fencing, snapshot
//! catch-up orchestration, and catalog/physical-generation replication remain
//! intentionally out of scope. Because it cannot transfer graph generations,
//! every legacy mutation fails closed once a collection has any graph epoch,
//! including after DROP GRAPH.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use tokio::sync::oneshot;

use crate::{
    Db,
    error::{GaussError, Result},
    wal::{Wal, WalEntry, WalRecord, WalScanStats},
};

/// Node identifier — mirrors `raft::NodeId` but defined here to avoid a circular dependency.
pub type NodeId = u64;

// ── Per-follower replication progress ────────────────────────────────────────

/// Tracks replication progress for one explicitly configured voter set.
///
/// This remains an experimental single-leader scaffold. It deliberately does
/// not infer membership from the number of ACKs: doing so lets duplicate or
/// unknown senders manufacture a quorum.
pub struct WalReplicationManager {
    leader_id: NodeId,
    voters: HashSet<NodeId>,
    /// node_id → (collection → last_acked_lsn)
    follower_lsns: HashMap<NodeId, HashMap<String, u64>>,
    /// collection → waiters for a locally durable leader LSN
    quorum_waiters: HashMap<String, Vec<QuorumWaiter>>,
}

struct QuorumWaiter {
    lsn: u64,
    tx: oneshot::Sender<()>,
}

impl WalReplicationManager {
    /// Build a manager for an explicit voter set, which must include the
    /// leader. Membership changes are intentionally outside this scaffold.
    pub fn new(leader_id: NodeId, voters: impl IntoIterator<Item = NodeId>) -> Result<Self> {
        let voters = voters.into_iter().collect::<HashSet<_>>();
        if voters.is_empty() {
            return Err(GaussError::InvalidRequest(
                "WAL replication requires at least one voter".to_string(),
            ));
        }
        if !voters.contains(&leader_id) {
            return Err(GaussError::InvalidRequest(format!(
                "WAL replication voter set does not contain leader {leader_id}"
            )));
        }
        Ok(Self {
            leader_id,
            voters,
            follower_lsns: HashMap::new(),
            quorum_waiters: HashMap::new(),
        })
    }

    fn quorum_size(&self) -> usize {
        self.voters.len() / 2 + 1
    }

    fn has_quorum(&self, collection: &str, lsn: u64) -> bool {
        let follower_acks = self
            .voters
            .iter()
            .filter(|&&node_id| node_id != self.leader_id)
            .filter(|&&node_id| {
                self.follower_lsns
                    .get(&node_id)
                    .and_then(|collections| collections.get(collection))
                    .is_some_and(|acked_lsn| *acked_lsn >= lsn)
            })
            .count();
        // wait_for_quorum is called only after the leader has durably written
        // the target LSN, so the leader contributes exactly one vote.
        follower_acks + 1 >= self.quorum_size()
    }

    /// Record monotonic progress from a configured follower. Returns `true`
    /// only when the ACK advanced that follower's progress. ACKs from the
    /// leader, unknown nodes, and stale/duplicate LSNs are ignored.
    pub fn record_ack(&mut self, node_id: NodeId, collection: &str, lsn: u64) -> bool {
        self.prune_cancelled_waiters();
        if node_id == self.leader_id || !self.voters.contains(&node_id) {
            return false;
        }

        let collections = self.follower_lsns.entry(node_id).or_default();
        if collections
            .get(collection)
            .is_some_and(|previous| lsn <= *previous)
        {
            return false;
        }
        collections.insert(collection.to_string(), lsn);

        if let Some(waiters) = self.quorum_waiters.remove(collection) {
            let mut pending = Vec::with_capacity(waiters.len());
            for waiter in waiters {
                if waiter.tx.is_closed() {
                    continue;
                }
                if self.has_quorum(collection, waiter.lsn) {
                    let _ = waiter.tx.send(());
                } else {
                    pending.push(waiter);
                }
            }
            if !pending.is_empty() {
                self.quorum_waiters.insert(collection.to_string(), pending);
            }
        }
        true
    }

    /// Returns a future that resolves once a majority of the configured
    /// voters have acknowledged `lsn`. Existing follower progress is checked
    /// before registering the waiter, so an ACK cannot be lost by arriving
    /// first.
    pub fn wait_for_quorum(&mut self, collection: &str, lsn: u64) -> oneshot::Receiver<()> {
        self.prune_cancelled_waiters();
        let (tx, rx) = oneshot::channel();
        if self.has_quorum(collection, lsn) {
            let _ = tx.send(());
            return rx;
        }
        self.quorum_waiters
            .entry(collection.to_string())
            .or_default()
            .push(QuorumWaiter { lsn, tx });
        rx
    }

    /// Remove waiters whose receivers were dropped by timed-out/cancelled
    /// requests. Returns the number removed for tests and maintenance metrics.
    pub fn prune_cancelled_waiters(&mut self) -> usize {
        let before = self.quorum_waiters.values().map(Vec::len).sum::<usize>();
        self.quorum_waiters.retain(|_, waiters| {
            waiters.retain(|waiter| !waiter.tx.is_closed());
            !waiters.is_empty()
        });
        let after = self.quorum_waiters.values().map(Vec::len).sum::<usize>();
        before - after
    }

    /// Strictly scan retained WAL records from a record boundary. The visitor
    /// is invoked as records are decoded, so callers can feed a bounded
    /// channel without first materialising the suffix in a `Vec`.
    pub fn scan_wal_entries<F>(wal_dir: &Path, from_lsn: u64, visitor: F) -> Result<WalScanStats>
    where
        F: FnMut(WalRecord) -> Result<()>,
    {
        let retained_base = Wal::retained_base_lsn(wal_dir)?;
        if from_lsn < retained_base {
            return Err(GaussError::InvalidRequest(format!(
                "requested WAL LSN {from_lsn} precedes retained base {retained_base}; snapshot required"
            )));
        }
        Wal::scan_from(wal_dir, from_lsn, visitor)
    }
}

// ── Apply a replicated WAL entry on a follower ────────────────────────────────

/// Deserializes a `WalEntry` JSON and durably applies it to the local follower.
/// The follower WAL is synced before in-memory publication. Request batches
/// remain one local WAL frame and are applied under the normal collection lock.
///
/// Catalog, compact, graph-batch and graph-lifecycle records are intentionally
/// rejected: this experimental scaffold does not coordinate physical graph/
/// vector generations or the root catalog. Legacy point, payload and schema
/// records are accepted only while the target collection has no graph history.
pub async fn apply_replicated_wal_entry(
    db: &Db,
    collection: &str,
    entry_json: &[u8],
) -> Result<()> {
    let entry: WalEntry = serde_json::from_slice(entry_json)?;
    match entry {
        WalEntry::Upsert { point } => {
            db.apply_legacy_replicated_upsert(collection, vec![point])?;
        }
        WalEntry::UpsertBatch { points } => {
            db.apply_legacy_replicated_upsert(collection, points)?;
        }
        WalEntry::Delete { id } => {
            db.apply_legacy_replicated_delete(collection, &[id])?;
        }
        WalEntry::DeleteBatch { ids } => {
            db.apply_legacy_replicated_delete(collection, &ids)?;
        }
        WalEntry::Schema {
            schema_epoch,
            config,
            previous_config: _,
        } => {
            db.apply_schema_replicated(collection, config, schema_epoch)?;
        }
        WalEntry::SetPayload { id, payload, merge } => {
            db.apply_legacy_replicated_payload(collection, &id, payload, merge)?;
        }
        WalEntry::Compact { .. } => {
            return Err(GaussError::InvalidRequest(
                "compact WAL entries are not supported by experimental collection replication"
                    .to_string(),
            ));
        }
        WalEntry::GraphBatch { .. } => {
            return Err(GaussError::InvalidRequest(
                "GraphBatch replication is not supported until follower graph state is activated"
                    .to_string(),
            ));
        }
        WalEntry::GraphEpochAdvance { .. } => {
            return Err(GaussError::InvalidRequest(
                "graph lifecycle replication is not supported until follower graph state is activated"
                    .to_string(),
            ));
        }
        WalEntry::CreateCollection { .. } | WalEntry::DropCollection { .. } => {
            return Err(GaussError::InvalidRequest(
                "catalog WAL entries are not supported by experimental collection replication"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DistanceMetric,
        graph::GraphEpoch,
        model::{CollectionConfig, PayloadType, Point},
        wal::{GraphBatch, Wal, WalEntry},
    };
    use serde_json::json;
    use tempfile::TempDir;

    fn manager(voters: &[NodeId]) -> WalReplicationManager {
        WalReplicationManager::new(1, voters.iter().copied()).unwrap()
    }

    fn config(name: &str) -> CollectionConfig {
        CollectionConfig {
            name: name.to_string(),
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
        }
    }

    fn point(id: &str, value: f32) -> Point {
        Point {
            id: id.to_string(),
            vector: vec![value, 1.0],
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({"value": value}),
        }
    }

    async fn assert_replication_records_rejected(
        db: &Db,
        wal_dir: &Path,
        phase: &str,
        entries: &[(&str, WalEntry)],
    ) {
        let wal_before = Wal::load(wal_dir).unwrap().len();
        let config_before = serde_json::to_value(db.list_collections().remove(0)).unwrap();
        for (label, entry) in entries {
            let error = apply_replicated_wal_entry(db, "docs", &serde_json::to_vec(entry).unwrap())
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("not supported")
                    || error.to_string().contains("has graph history"),
                "{phase}/{label}: {error}"
            );
            assert_eq!(
                Wal::load(wal_dir).unwrap().len(),
                wal_before,
                "{phase}/{label} appended WAL"
            );
            assert_eq!(
                serde_json::to_value(db.list_collections().remove(0)).unwrap(),
                config_before,
                "{phase}/{label} changed config"
            );
            let points = db.get_points("docs", &["seed".to_string()]).unwrap();
            assert_eq!(points.len(), 1, "{phase}/{label} removed seed");
            assert_eq!(points[0].payload, json!({"value": 1.0}));
            assert_eq!(db.count("docs", None).unwrap().count, 1);
        }
    }

    #[test]
    fn stream_wal_entries_filters_by_lsn_without_materialising() {
        let tmp = TempDir::new().unwrap();
        let mut wal = Wal::open(tmp.path()).unwrap();

        let lsn0 = wal
            .append(&WalEntry::Delete {
                id: "a".to_string(),
            })
            .unwrap();
        wal.append(&WalEntry::Delete {
            id: "b".to_string(),
        })
        .unwrap();

        let mut all = Vec::new();
        WalReplicationManager::scan_wal_entries(tmp.path(), 0, |record| {
            all.push(record);
            Ok(())
        })
        .unwrap();
        assert_eq!(all.len(), 2);

        let mut tail = Vec::new();
        WalReplicationManager::scan_wal_entries(tmp.path(), lsn0, |record| {
            tail.push(record);
            Ok(())
        })
        .unwrap();
        assert_eq!(tail.len(), 1);
        assert!(matches!(tail[0].entry, WalEntry::Delete { ref id } if id == "b"));
    }

    #[test]
    fn explicit_membership_is_required() {
        assert!(WalReplicationManager::new(1, []).is_err());
        assert!(WalReplicationManager::new(1, [2, 3]).is_err());
    }

    #[test]
    fn quorum_single_node_resolves_immediately() {
        let mut mgr = manager(&[1]);
        let mut rx = mgr.wait_for_quorum("col", 10);
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn duplicate_stale_leader_and_unknown_acks_do_not_manufacture_quorum() {
        let mut mgr = manager(&[1, 2, 3, 4, 5]);
        let mut rx = mgr.wait_for_quorum("col", 42);

        assert!(!mgr.record_ack(1, "col", 42));
        assert!(!mgr.record_ack(99, "col", 42));
        assert!(mgr.record_ack(2, "col", 42));
        assert!(!mgr.record_ack(2, "col", 42));
        assert!(!mgr.record_ack(2, "col", 41));
        assert!(rx.try_recv().is_err());

        assert!(mgr.record_ack(3, "col", 42));
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn pre_ack_is_recognised_when_waiter_is_registered() {
        let mut mgr = manager(&[1, 2, 3]);
        assert!(mgr.record_ack(2, "col", 100));
        let mut rx = mgr.wait_for_quorum("col", 90);
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn initial_lsn_zero_ack_counts_once() {
        let mut mgr = manager(&[1, 2, 3]);
        assert!(mgr.record_ack(2, "col", 0));
        assert!(!mgr.record_ack(2, "col", 0));
        let mut rx = mgr.wait_for_quorum("col", 0);
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn cancelled_waiters_are_pruned() {
        let mut mgr = manager(&[1, 2, 3]);
        let rx = mgr.wait_for_quorum("col", 10);
        drop(rx);
        assert_eq!(mgr.prune_cancelled_waiters(), 1);
        assert!(mgr.quorum_waiters.is_empty());
    }

    #[tokio::test]
    async fn replicated_batch_and_payload_are_durable_across_reopen() {
        let tmp = TempDir::new().unwrap();
        let db = Db::open(tmp.path()).unwrap();
        db.create_collection(config("docs")).unwrap();

        let batch = WalEntry::UpsertBatch {
            points: vec![point("a", 1.0), point("b", 2.0)],
        };
        apply_replicated_wal_entry(&db, "docs", &serde_json::to_vec(&batch).unwrap())
            .await
            .unwrap();
        let payload = WalEntry::SetPayload {
            id: "a".to_string(),
            payload: json!({"replicated": true}),
            merge: true,
        };
        apply_replicated_wal_entry(&db, "docs", &serde_json::to_vec(&payload).unwrap())
            .await
            .unwrap();

        let records = Wal::load(&tmp.path().join("collections/docs/wal")).unwrap();
        assert_eq!(records.len(), 2);
        assert!(matches!(records[0].entry, WalEntry::UpsertBatch { .. }));
        assert!(matches!(records[1].entry, WalEntry::SetPayload { .. }));
        drop(db);

        let reopened = Db::open(tmp.path()).unwrap();
        let points = reopened
            .get_points("docs", &["a".to_string(), "b".to_string()])
            .unwrap();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].payload["replicated"], true);
    }

    #[tokio::test]
    async fn invalid_replicated_batch_does_not_publish_or_append_a_prefix() {
        let tmp = TempDir::new().unwrap();
        let db = Db::open(tmp.path()).unwrap();
        db.create_collection(config("docs")).unwrap();

        let mut invalid = point("bad", 2.0);
        invalid.vector = vec![2.0];
        let batch = WalEntry::UpsertBatch {
            points: vec![point("would-have-been-valid", 1.0), invalid],
        };
        assert!(
            apply_replicated_wal_entry(&db, "docs", &serde_json::to_vec(&batch).unwrap())
                .await
                .is_err()
        );
        assert_eq!(db.count("docs", None).unwrap().count, 0);
        assert!(
            Wal::load(&tmp.path().join("collections/docs/wal"))
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn replicated_payload_schema_is_durable_and_epoch_idempotent() {
        let tmp = TempDir::new().unwrap();
        let db = Db::open(tmp.path()).unwrap();
        db.create_collection(config("docs")).unwrap();
        let mut next = db.list_collections().remove(0);
        next.payload_schema
            .insert("replicated".to_string(), PayloadType::OptionalBool);
        let schema = WalEntry::Schema {
            schema_epoch: 2,
            config: next,
            previous_config: None,
        };

        let bytes = serde_json::to_vec(&schema).unwrap();
        apply_replicated_wal_entry(&db, "docs", &bytes)
            .await
            .unwrap();
        apply_replicated_wal_entry(&db, "docs", &bytes)
            .await
            .unwrap();
        let records = Wal::load(&tmp.path().join("collections/docs/wal")).unwrap();
        assert_eq!(records.len(), 1);
        drop(db);

        let reopened = Db::open(tmp.path()).unwrap();
        assert_eq!(
            reopened.list_collections()[0].payload_schema["replicated"],
            PayloadType::OptionalBool
        );
    }

    #[tokio::test]
    async fn graph_history_rejects_every_replication_record_without_side_effects() {
        let tmp = TempDir::new().unwrap();
        let db = Db::open(tmp.path()).unwrap();
        db.create_collection(config("docs")).unwrap();
        let wal_dir = tmp.path().join("collections/docs/wal");
        drop(db);
        let mut wal = Wal::open(&wal_dir).unwrap();
        wal.append(&WalEntry::GraphEpochAdvance {
            epoch: GraphEpoch::INITIAL,
            enabled: true,
        })
        .unwrap();
        drop(wal);
        let db = Db::open(tmp.path()).unwrap();
        db.upsert("docs", vec![point("seed", 1.0)]).unwrap();

        let mut fresh_schema = db.list_collections().remove(0);
        fresh_schema
            .payload_schema
            .insert("replicated".to_string(), PayloadType::OptionalBool);
        let stale_schema = fresh_schema.clone();
        let entries = vec![
            (
                "upsert",
                WalEntry::Upsert {
                    point: point("new-single", 2.0),
                },
            ),
            (
                "upsert-batch",
                WalEntry::UpsertBatch {
                    points: vec![point("new-batch", 3.0)],
                },
            ),
            (
                "delete",
                WalEntry::Delete {
                    id: "seed".to_string(),
                },
            ),
            (
                "delete-batch",
                WalEntry::DeleteBatch {
                    ids: vec!["seed".to_string()],
                },
            ),
            (
                "payload",
                WalEntry::SetPayload {
                    id: "seed".to_string(),
                    payload: json!({"replicated": true}),
                    merge: true,
                },
            ),
            (
                "schema-fresh",
                WalEntry::Schema {
                    schema_epoch: 2,
                    config: fresh_schema,
                    previous_config: None,
                },
            ),
            (
                "schema-stale",
                WalEntry::Schema {
                    schema_epoch: 1,
                    config: stale_schema,
                    previous_config: None,
                },
            ),
            (
                "graph-batch",
                WalEntry::GraphBatch {
                    batch: GraphBatch::default(),
                },
            ),
            (
                "graph-lifecycle",
                WalEntry::GraphEpochAdvance {
                    epoch: GraphEpoch::INITIAL,
                    enabled: true,
                },
            ),
            (
                "compact",
                WalEntry::Compact {
                    generation: 7,
                    segments: vec!["forbidden".to_string()],
                },
            ),
            (
                "create-collection",
                WalEntry::CreateCollection {
                    config: config("other"),
                },
            ),
            (
                "drop-collection",
                WalEntry::DropCollection {
                    name: "docs".to_string(),
                },
            ),
        ];

        assert_replication_records_rejected(&db, &wal_dir, "enabled", &entries).await;
        drop(db);
        let mut wal = Wal::open(&wal_dir).unwrap();
        wal.append(&WalEntry::GraphEpochAdvance {
            epoch: GraphEpoch::from_raw(2).unwrap(),
            enabled: false,
        })
        .unwrap();
        drop(wal);

        let db = Db::open(tmp.path()).unwrap();
        assert_replication_records_rejected(&db, &wal_dir, "dropped", &entries).await;
        drop(db);

        let reopened = Db::open(tmp.path()).unwrap();
        assert_replication_records_rejected(&reopened, &wal_dir, "reopen", &entries).await;
    }

    #[tokio::test]
    async fn compact_and_catalog_entries_fail_closed() {
        let tmp = TempDir::new().unwrap();
        let db = Db::open(tmp.path()).unwrap();
        db.create_collection(config("docs")).unwrap();

        for entry in [
            WalEntry::Compact {
                generation: 1,
                segments: vec![],
            },
            WalEntry::DropCollection {
                name: "docs".to_string(),
            },
        ] {
            let error =
                apply_replicated_wal_entry(&db, "docs", &serde_json::to_vec(&entry).unwrap())
                    .await
                    .unwrap_err();
            assert!(error.to_string().contains("not supported"));
        }
    }
}
