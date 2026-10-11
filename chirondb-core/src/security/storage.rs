//! Security metadata shares the collection WAL with content. Checkpointing this
//! state must finish before a covered WAL prefix can be removed.
use super::{capacity, policy, *};
use crate::{
    GaussError, Result,
    model::{CollectionConfig, Point},
    wal::{GraphBatch, GraphPointMutation, Wal, WalEntry},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub(crate) const CHECKPOINT_FILE: &str = "security.checkpoint";
const MAGIC: &[u8; 8] = b"CHIRSEC1";
pub(super) const MAX_CHECKPOINT_BYTES: u64 = 1024 * 1024 * 1024;

pub(crate) fn encode_metadata(magic: &[u8; 8], payload: &[u8]) -> Vec<u8> {
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(payload));
    let mut bytes = Vec::with_capacity(52 + payload.len());
    bytes.extend(magic);
    bytes.extend(digest.as_bytes());
    bytes.push(b'\n');
    bytes.extend(payload);
    bytes
}

pub(crate) fn decode_metadata<'a>(magic: &[u8; 8], bytes: &'a [u8]) -> Result<&'a [u8]> {
    if bytes.len() < 52 || !bytes.starts_with(magic) || bytes[51] != b'\n' {
        return Err(invalid("unsupported security metadata envelope"));
    }
    let payload = &bytes[52..];
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(payload));
    if !bool::from(digest.as_bytes().ct_eq(&bytes[8..51])) {
        return Err(invalid("security metadata integrity check failed"));
    }
    Ok(payload)
}

pub(crate) fn serialized_len(value: &impl Serialize, limit: usize) -> Result<usize> {
    struct Counter {
        bytes: usize,
        limit: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .filter(|bytes| *bytes <= self.limit)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::FileTooLarge))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { bytes: 0, limit };
    serde_json::to_writer(&mut counter, value).map_err(|_| SecurityError::BudgetExceeded)?;
    Ok(counter.bytes)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityDelta {
    pub incarnation: Uuid,
    pub expected_revision: u64,
    pub revision: u64,
    pub expected_generation: u64,
    pub generation: u64,
    pub policy: Option<CollectionPolicy>,
    pub bindings: Vec<ResourceRecord>,
}

/// Nonrecursive content envelope. Nested batches and cross-collection writes
/// cannot be expressed by this format.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProtectedContent {
    Upsert {
        points: Vec<Point>,
    },
    Delete {
        ids: Vec<String>,
    },
    Graph {
        batch: GraphBatch,
    },
    Schema {
        schema_epoch: u64,
        config: CollectionConfig,
        previous_config: Option<CollectionConfig>,
    },
    GraphLifecycle {
        epoch: crate::graph::GraphEpoch,
        enabled: bool,
    },
    Policy,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedBatch {
    pub version: u32,
    pub security: SecurityDelta,
    pub content: ProtectedContent,
}

impl ProtectedBatch {
    pub fn validate(&self) -> Result<()> {
        let delta = &self.security;
        if self.version != SECURITY_VERSION
            || delta.incarnation.is_nil()
            || delta.expected_revision == 0
            || delta.expected_generation == 0
            || delta.generation
                != delta
                    .expected_generation
                    .checked_add(1)
                    .ok_or(SecurityError::Unavailable)?
            || !(delta.revision == delta.expected_revision
                || Some(delta.revision) == delta.expected_revision.checked_add(1))
            || (delta.policy.is_some() && delta.revision == delta.expected_revision)
            || delta.bindings.len() > 1024
        {
            return Err(invalid("invalid protected transaction revision or size"));
        }
        if let Some(config) = &delta.policy {
            policy::validate_collection_policy(config)?;
        }
        let mut keys = BTreeSet::new();
        let mut physical = BTreeSet::new();
        for record in &delta.bindings {
            policy::validate_resource(record, delta.incarnation, delta.revision)?;
            if !keys.insert(&record.key) || !physical.insert(record.storage_id) {
                return Err(invalid("duplicate security binding in transaction"));
            }
        }
        if let ProtectedContent::Graph { batch } = &self.content {
            batch.validate()?;
        }
        let (upserts, deletes) = self.content.point_ids();
        if upserts.len() + deletes.len() > 1024 {
            return Err(SecurityError::BudgetExceeded.into());
        }
        let mut ids = BTreeSet::new();
        for id in upserts.iter().chain(&deletes) {
            if Uuid::parse_str(id).is_err() || !ids.insert(*id) {
                return Err(invalid(
                    "protected content requires distinct physical identifiers",
                ));
            }
        }
        Ok(())
    }
}

impl ProtectedContent {
    fn point_ids(&self) -> (Vec<&str>, Vec<&str>) {
        match self {
            Self::Upsert { points } => (points.iter().map(|p| p.id.as_str()).collect(), Vec::new()),
            Self::Delete { ids } => (Vec::new(), ids.iter().map(String::as_str).collect()),
            Self::Graph { batch } => {
                let mut upserts = Vec::new();
                let mut deletes = Vec::new();
                for mutation in &batch.point_mutations {
                    match mutation {
                        GraphPointMutation::Upsert { point } => upserts.push(point.id.as_str()),
                        GraphPointMutation::Delete { point_id, .. } => {
                            deletes.push(point_id.as_str())
                        }
                    }
                }
                (upserts, deletes)
            }
            _ => (Vec::new(), Vec::new()),
        }
    }
    pub(crate) fn into_wal(self) -> Option<WalEntry> {
        Some(match self {
            Self::Upsert { points } => WalEntry::UpsertBatch { points },
            Self::Delete { ids } => WalEntry::DeleteBatch { ids },
            Self::Graph { batch } => WalEntry::GraphBatch { batch },
            Self::Schema {
                schema_epoch,
                config,
                previous_config,
            } => WalEntry::Schema {
                schema_epoch,
                config,
                previous_config,
            },
            Self::GraphLifecycle { epoch, enabled } => {
                WalEntry::GraphEpochAdvance { epoch, enabled }
            }
            Self::Policy => return None,
        })
    }
    pub(crate) fn mutation_counts(&self) -> (usize, usize) {
        let (upserts, deletes) = self.point_ids();
        (upserts.len() + deletes.len(), deletes.len())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredSecurity {
    pub wal_watermark: u64,
    pub authority: SecurityCheckpoint,
}

/// Recovery index updates only the transaction's bindings on ordinary writes.
/// Full inheritance validation is necessary only for control-plane changes.
pub(crate) struct ReplaySecurity {
    checkpoint: SecurityCheckpoint,
    records: BTreeMap<PointKey, ResourceRecord>,
    physical: BTreeMap<Uuid, PointKey>,
    metadata_bytes: usize,
}
impl ReplaySecurity {
    pub(crate) fn new(mut checkpoint: SecurityCheckpoint) -> Result<Self> {
        CollectionAuthority::from_verified_checkpoint(checkpoint.clone())?;
        let mut metadata_bytes = 0usize;
        let mut records = BTreeMap::new();
        let mut physical = BTreeMap::new();
        for record in checkpoint.resources.drain(..) {
            metadata_bytes = metadata_bytes
                .checked_add(capacity::record_bytes(&record)?)
                .ok_or(SecurityError::BudgetExceeded)?;
            physical.insert(record.storage_id, record.key.clone());
            records.insert(record.key.clone(), record);
        }
        Ok(Self {
            checkpoint,
            records,
            physical,
            metadata_bytes,
        })
    }
    pub(crate) fn apply(&mut self, batch: &ProtectedBatch) -> Result<()> {
        batch.validate()?;
        let delta = &batch.security;
        if delta.incarnation != self.checkpoint.incarnation
            || delta.expected_generation != self.checkpoint.data_generation
            || delta.expected_revision != self.checkpoint.revision
        {
            return Err(invalid(
                "protected transaction is not contiguous with its authority",
            ));
        }
        let updated: BTreeMap<_, _> = delta
            .bindings
            .iter()
            .map(|record| (&record.key, record))
            .collect();
        let changed_policy = delta.revision != delta.expected_revision;
        let mut created = BTreeSet::new();
        let mut retired = BTreeSet::new();
        for record in &delta.bindings {
            match self.records.get(&record.key) {
                Some(old) => {
                    if old.storage_id != record.storage_id || old.retired {
                        return Err(invalid(
                            "resource identities cannot be reassigned or revived",
                        ));
                    }
                    if !changed_policy {
                        let mut expected = old.clone();
                        expected.retired = true;
                        if record != &expected {
                            return Err(invalid("content transaction cannot modify permissions"));
                        }
                    }
                    if record.retired {
                        retired.insert(record.storage_id);
                    }
                }
                None => {
                    if self.physical.contains_key(&record.storage_id)
                        || record.retired
                        || record.parent.is_some()
                        || !record.grants.is_empty()
                    {
                        return Err(invalid("invalid new resource binding"));
                    }
                    created.insert(record.storage_id);
                }
            }
        }
        let (upserts, deletes) = batch.content.point_ids();
        let upserts: BTreeSet<_> = upserts
            .into_iter()
            .map(Uuid::parse_str)
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| invalid("invalid content identity"))?;
        let deletes: BTreeSet<_> = deletes
            .into_iter()
            .map(Uuid::parse_str)
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| invalid("invalid content identity"))?;
        if !created.is_subset(&upserts) || retired != deletes {
            return Err(invalid("content and security mutations disagree"));
        }
        for id in &upserts {
            if created.contains(id) {
                continue;
            }
            let key = self
                .physical
                .get(id)
                .ok_or_else(|| invalid("content has no security binding"))?;
            let record = updated.get(key).copied().unwrap_or(&self.records[key]);
            if record.retired {
                return Err(invalid("content revives a retired resource"));
            }
        }
        for id in &deletes {
            if !self.physical.contains_key(id) {
                return Err(invalid("delete has no security binding"));
            }
        }
        if changed_policy {
            // Changes to a parent may lengthen a previously valid descendant's
            // chain. Validate every chain against the proposed overlay.
            for start in self.records.values().chain(delta.bindings.iter()) {
                let mut current = updated.get(&start.key).copied().unwrap_or(start);
                let mut path = BTreeSet::new();
                loop {
                    if !path.insert(&current.key) {
                        return Err(invalid("inheritance cycle"));
                    }
                    if path.len() > MAX_INHERITANCE_DEPTH {
                        return Err(SecurityError::BudgetExceeded.into());
                    }
                    let Some(parent) = &current.parent else { break };
                    if parent.tenant != start.key.tenant
                        || parent.collection != start.key.collection
                    {
                        return Err(invalid("inheritance crosses a security domain"));
                    }
                    current = updated
                        .get(parent)
                        .copied()
                        .or_else(|| self.records.get(parent))
                        .ok_or_else(|| invalid("inheritance parent is absent"))?;
                }
            }
        }
        let metadata_bytes =
            capacity::overlay_bytes(self.metadata_bytes, &self.records, &delta.bindings)?;
        capacity::check(
            &self.checkpoint.collection,
            self.checkpoint.incarnation,
            delta.policy.as_ref().unwrap_or(&self.checkpoint.policy),
            metadata_bytes,
            capacity::LIMIT,
        )?;
        for record in &delta.bindings {
            self.physical.insert(record.storage_id, record.key.clone());
            self.records.insert(record.key.clone(), record.clone());
        }
        if let Some(config) = &delta.policy {
            self.checkpoint.policy = config.clone();
        }
        self.checkpoint.revision = delta.revision;
        self.checkpoint.data_generation = delta.generation;
        self.metadata_bytes = metadata_bytes;
        Ok(())
    }
    pub(crate) fn finish(mut self) -> SecurityCheckpoint {
        self.checkpoint.resources = self.records.into_values().collect();
        self.checkpoint
    }
}

pub(crate) fn read(collection_dir: &Path) -> Result<Option<StoredSecurity>> {
    let path = collection_dir.join(CHECKPOINT_FILE);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_CHECKPOINT_BYTES
    {
        return Err(invalid("invalid security checkpoint file"));
    }
    let bytes = crate::encryption::read_persistent(&path)?;
    if bytes.len() as u64 > MAX_CHECKPOINT_BYTES || !bytes.starts_with(MAGIC) {
        return Err(invalid("unsupported security checkpoint format"));
    }
    let checkpoint: StoredSecurity = serde_json::from_slice(decode_metadata(MAGIC, &bytes)?)?;
    ReplaySecurity::new(checkpoint.authority.clone())?;
    Ok(Some(checkpoint))
}

pub(crate) fn write(collection_dir: &Path, checkpoint: &StoredSecurity) -> Result<()> {
    // Reject before allocating a buffer which could exceed the readable format.
    serialized_len(checkpoint, capacity::LIMIT - 52)?;
    let bytes = encode_metadata(MAGIC, &serde_json::to_vec(checkpoint)?);
    if bytes.len() as u64 > MAX_CHECKPOINT_BYTES {
        return Err(SecurityError::BudgetExceeded.into());
    }
    crate::encryption::atomic_write_persistent(
        &collection_dir.join(CHECKPOINT_FILE),
        crate::encryption::FileType::Metadata,
        &bytes,
    )
}

pub(crate) fn recover(collection_dir: &Path, cut: Option<u64>) -> Result<Option<StoredSecurity>> {
    recover_with_journal(collection_dir, cut, None)
}

pub(crate) fn recover_with_journal(
    collection_dir: &Path,
    cut: Option<u64>,
    journal: Option<(&crate::transaction_journal::TransactionJournal, &str)>,
) -> Result<Option<StoredSecurity>> {
    let Some(stored) = read(collection_dir)? else {
        return Ok(None);
    };
    let wal_dir = collection_dir.join("wal");
    if Wal::retained_base_lsn(&wal_dir)? > stored.wal_watermark {
        return Err(invalid("WAL no longer covers the security checkpoint"));
    }
    if cut.is_some_and(|cut| cut < stored.wal_watermark) {
        return Err(invalid("cannot rewind authority checkpoint"));
    }
    let watermark = stored.wal_watermark;
    let mut state = ReplaySecurity::new(stored.authority)?;
    let visitor = |record: crate::wal::WalRecord| {
        if cut.is_none_or(|cut| record.lsn < cut) {
            match record.entry {
                WalEntry::ProtectedBatch { batch } => state.apply(&batch)?,
                WalEntry::TransactionApply {
                    transaction_id,
                    entry,
                } => {
                    if let Some((journal, name)) = journal {
                        journal.validate_storage_projection(
                            transaction_id,
                            crate::transaction_journal::StorageTarget::Collection(name),
                            &entry,
                        )?;
                    }
                    match *entry {
                        WalEntry::ProtectedBatch { batch } => state.apply(&batch)?,
                        _ => {
                            return Err(invalid(
                                "unprotected transaction mutation in a protected collection WAL",
                            ));
                        }
                    }
                }
                WalEntry::Compact { .. } => {}
                _ => {
                    return Err(invalid(
                        "unprotected mutation in a protected collection WAL",
                    ));
                }
            }
        }
        Ok(())
    };
    let stats = if cut.is_some() {
        Wal::scan_from(&wal_dir, watermark, visitor)?
    } else {
        Wal::recover_from(&wal_dir, watermark, visitor)?
    };
    if cut.is_some_and(|cut| cut > stats.end_lsn) {
        return Err(invalid("security checkpoint cut exceeds WAL"));
    }
    Ok(Some(StoredSecurity {
        wal_watermark: cut.unwrap_or(stats.end_lsn),
        authority: state.finish(),
    }))
}

fn invalid(message: &str) -> GaussError {
    SecurityError::Invalid(message.into()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn empty() -> SecurityCheckpoint {
        SecurityCheckpoint {
            version: SECURITY_VERSION,
            collection: "docs".into(),
            incarnation: Uuid::new_v4(),
            revision: 1,
            data_generation: 1,
            policy: CollectionPolicy {
                department_actions: BTreeSet::new(),
                owner_actions: BTreeSet::new(),
                templates: BTreeMap::new(),
            },
            resources: Vec::new(),
        }
    }
    fn create(checkpoint: &SecurityCheckpoint, tenant: &str, id: &str) -> ProtectedBatch {
        let record = ResourceRecord {
            key: PointKey {
                collection: checkpoint.incarnation,
                tenant: tenant.into(),
                id: id.into(),
            },
            storage_id: Uuid::new_v4(),
            labels: ResourceLabels {
                owner: "writer".into(),
                department: "Finance".into(),
                classification: Classification::Confidential,
                quarantined: false,
            },
            properties: BTreeMap::new(),
            representations: BTreeMap::new(),
            grants: Vec::new(),
            parent: None,
            revision: checkpoint.revision,
            retired: false,
            create_receipt: None,
        };
        let point = Point {
            id: record.storage_id.to_string(),
            vector: vec![1.0, 0.0],
            vectors: Default::default(),
            sparse_vector: None,
            payload: serde_json::json!({}),
        };
        ProtectedBatch {
            version: SECURITY_VERSION,
            security: SecurityDelta {
                incarnation: checkpoint.incarnation,
                expected_revision: checkpoint.revision,
                revision: checkpoint.revision,
                expected_generation: checkpoint.data_generation,
                generation: checkpoint.data_generation + 1,
                policy: None,
                bindings: vec![record],
            },
            content: ProtectedContent::Upsert {
                points: vec![point],
            },
        }
    }
    #[test]
    fn protected_transaction_replay_binds_content_before_applying_security() {
        use crate::transaction_journal::{TransactionAudit, TransactionJournal, TransactionTarget};
        let directory = tempfile::tempdir().unwrap();
        let initial = empty();
        write(
            directory.path(),
            &StoredSecurity {
                wal_watermark: 0,
                authority: initial.clone(),
            },
        )
        .unwrap();
        let batch = create(&initial, "acme", "document");
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let committed = journal
            .commit(
                TransactionTarget::Collection {
                    name: "docs".into(),
                },
                WalEntry::ProtectedBatch {
                    batch: batch.clone(),
                },
                TransactionAudit::mutation(
                    "create",
                    Some("docs"),
                    &crate::audit::AuditContext::embedded(),
                    serde_json::Value::Null,
                ),
            )
            .unwrap();
        let mut altered = batch;
        let ProtectedContent::Upsert { points } = &mut altered.content else {
            unreachable!()
        };
        points[0].vector[0] = 2.0;
        // Valid CRC and authority delta, but content differs from COMMIT.
        let mut wal = Wal::open(&directory.path().join("wal")).unwrap();
        wal.append(&WalEntry::TransactionApply {
            transaction_id: committed.prepare.transaction_id,
            entry: Box::new(WalEntry::ProtectedBatch { batch: altered }),
        })
        .unwrap();
        drop(wal);
        assert!(matches!(
            recover_with_journal(directory.path(), None, Some((&journal, "docs"))),
            Err(GaussError::WalCorruption { .. })
        ));
        let stored = read(directory.path()).unwrap().unwrap();
        assert_eq!(stored.authority.data_generation, 1);
        assert!(stored.authority.resources.is_empty());
    }
    #[test]
    fn protected_wal_preserves_authority_before_prefix_removal() {
        let directory = tempfile::tempdir().unwrap();
        let initial = empty();
        write(
            directory.path(),
            &StoredSecurity {
                wal_watermark: 0,
                authority: initial.clone(),
            },
        )
        .unwrap();
        let mut wal = Wal::open(&directory.path().join("wal")).unwrap();
        let batch = create(&initial, "acme", "document");
        wal.append(&WalEntry::ProtectedBatch {
            batch: batch.clone(),
        })
        .unwrap();
        let after_create = recover(directory.path(), None).unwrap().unwrap();
        assert_eq!(after_create.authority.resources, batch.security.bindings);
        assert_eq!(after_create.authority.data_generation, 2);
        assert!(
            wal.append(&WalEntry::Delete {
                id: batch.security.bindings[0].storage_id.to_string()
            })
            .is_err()
        );
        let mut retired = batch.security.bindings[0].clone();
        retired.retired = true;
        let deletion = ProtectedBatch {
            version: 1,
            security: SecurityDelta {
                incarnation: initial.incarnation,
                expected_revision: 1,
                revision: 1,
                expected_generation: 2,
                generation: 3,
                policy: None,
                bindings: vec![retired.clone()],
            },
            content: ProtectedContent::Delete {
                ids: vec![retired.storage_id.to_string()],
            },
        };
        wal.append(&WalEntry::ProtectedBatch { batch: deletion })
            .unwrap();
        let end = wal.len().unwrap();
        wal.drop_prefix(end).unwrap();
        drop(wal);
        assert_eq!(
            Wal::retained_base_lsn(&directory.path().join("wal")).unwrap(),
            end
        );
        let after_delete = recover(directory.path(), None).unwrap().unwrap();
        assert_eq!(after_delete.wal_watermark, end);
        assert_eq!(after_delete.authority.resources, vec![retired]);
        assert_eq!(after_delete.authority.data_generation, 3);
        assert!(Wal::truncate_to_lsn(&directory.path().join("wal"), 0).is_err());
        let revived = create(&after_delete.authority, "acme", "document");
        let mut state = ReplaySecurity::new(after_delete.authority).unwrap();
        assert!(
            state.apply(&revived).is_err(),
            "retired public IDs cannot be rebound"
        );
    }
    #[test]
    fn retention_retry_keeps_a_newer_durable_security_checkpoint() {
        let directory = tempfile::tempdir().unwrap();
        let initial = empty();
        write(
            directory.path(),
            &StoredSecurity {
                wal_watermark: 0,
                authority: initial.clone(),
            },
        )
        .unwrap();
        let mut wal = Wal::open(&directory.path().join("wal")).unwrap();
        wal.append(&WalEntry::ProtectedBatch {
            batch: create(&initial, "acme", "one"),
        })
        .unwrap();
        let first_end = wal.len().unwrap();
        let _frozen = wal.freeze_archive_cut(first_end).unwrap();
        let checkpoint = recover(directory.path(), None).unwrap().unwrap();
        wal.append(&WalEntry::ProtectedBatch {
            batch: create(&checkpoint.authority, "acme", "two"),
        })
        .unwrap();
        let latest = recover(directory.path(), None).unwrap().unwrap();
        // State after a checkpoint became durable but retention crashed before
        // publishing its WAL base. A retry may choose a smaller covered cut.
        write(directory.path(), &latest).unwrap();
        wal.drop_prefix(first_end).unwrap();
        assert_eq!(
            Wal::retained_base_lsn(&directory.path().join("wal")).unwrap(),
            first_end
        );
        assert_eq!(
            read(directory.path()).unwrap().unwrap().wal_watermark,
            latest.wal_watermark
        );
        let recovered = recover(directory.path(), None).unwrap().unwrap();
        assert_eq!(recovered.authority.resources, latest.authority.resources);
        assert_eq!(recovered.authority.data_generation, 3);
    }

    #[test]
    fn namespace_and_batch_binding_validation_are_independent_of_payload() {
        let initial = empty();
        let first = create(&initial, "acme", "same-id");
        let mut state = ReplaySecurity::new(initial).unwrap();
        state.apply(&first).unwrap();
        let checkpoint = state.finish();
        let second = create(&checkpoint, "globex", "same-id");
        let mut state = ReplaySecurity::new(checkpoint.clone()).unwrap();
        state.apply(&second).unwrap();
        assert_eq!(state.finish().resources.len(), 2);
        let mut forged = second.clone();
        forged.security.bindings[0].storage_id = first.security.bindings[0].storage_id;
        assert!(
            ReplaySecurity::new(checkpoint.clone())
                .unwrap()
                .apply(&forged)
                .is_err()
        );
        let mut detached = second.clone();
        detached.security.bindings.clear();
        assert!(
            ReplaySecurity::new(checkpoint.clone())
                .unwrap()
                .apply(&detached)
                .is_err()
        );
        let mut escalation = second;
        escalation.security.bindings[0] = first.security.bindings[0].clone();
        escalation.security.bindings[0].labels.classification = Classification::Public;
        assert!(
            ReplaySecurity::new(checkpoint)
                .unwrap()
                .apply(&escalation)
                .is_err()
        );
    }
    #[test]
    fn torn_tail_cannot_publish_half_a_security_content_transaction() {
        use std::io::Write;
        let directory = tempfile::tempdir().unwrap();
        let initial = empty();
        write(
            directory.path(),
            &StoredSecurity {
                wal_watermark: 0,
                authority: initial.clone(),
            },
        )
        .unwrap();
        let wal_dir = directory.path().join("wal");
        let mut wal = Wal::open(&wal_dir).unwrap();
        let first = create(&initial, "acme", "one");
        wal.append(&WalEntry::ProtectedBatch { batch: first })
            .unwrap();
        let end = wal.len().unwrap();
        drop(wal);
        let path = std::fs::read_dir(&wal_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "gdwal")
            })
            .unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(&[7, 0, 0])
            .unwrap();
        let recovered = recover(directory.path(), None).unwrap().unwrap();
        assert_eq!(recovered.wal_watermark, end);
        assert_eq!(recovered.authority.data_generation, 2);
        assert_eq!(recovered.authority.resources.len(), 1);
    }
}
