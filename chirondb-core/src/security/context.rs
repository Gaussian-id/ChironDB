//! Validated collection policy snapshots and unforgeable request contexts.
//!
//! The engine owns a CollectionAuthority for each protected incarnation.
//! Network inputs can name a tenant/action, but cannot manufacture this context.
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use uuid::Uuid;

use super::{capacity, identity::Epoch, policy, *};

type Result<T> = std::result::Result<T, SecurityError>;

mod read;
pub(crate) use read::AuthorizedRecord;

/// The on-disk form uses a list because JSON object keys cannot encode PointKey.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityCheckpoint {
    pub version: u32,
    pub collection: String,
    pub incarnation: Uuid,
    pub revision: u64,
    pub data_generation: u64,
    pub policy: CollectionPolicy,
    pub resources: Vec<ResourceRecord>,
}

#[derive(Debug)]
struct PolicySnapshot {
    checkpoint: SecurityCheckpoint,
    resources: Arc<RwLock<ResourceIndex>>,
    epoch: Arc<Epoch>,
}

#[derive(Debug)]
struct ResourceIndex {
    records: BTreeMap<PointKey, ResourceRecord>,
    physical: BTreeMap<Uuid, PointKey>,
    generation: u64,
    metadata_bytes: usize,
    create_requests: BTreeMap<(String, String, String), PointKey>,
}

impl PolicySnapshot {
    fn checkpoint(&self) -> SecurityCheckpoint {
        let mut checkpoint = self.checkpoint.clone();
        let resources = self.resources.read();
        checkpoint.resources = resources.records.values().cloned().collect();
        checkpoint.data_generation = resources.generation;
        checkpoint
    }

    fn validate(mut checkpoint: SecurityCheckpoint) -> Result<Self> {
        if checkpoint.version != SECURITY_VERSION
            || checkpoint.revision == 0
            || checkpoint.data_generation == 0
            || checkpoint.incarnation.is_nil()
            || !policy::identifier(&checkpoint.collection)
            || checkpoint.collection.contains(':')
        {
            return Err(SecurityError::Invalid(
                "invalid security checkpoint identity".into(),
            ));
        }
        policy::validate_collection_policy(&checkpoint.policy)?;
        let mut metadata_bytes = 0usize;
        let mut resources = BTreeMap::new();
        let mut physical = BTreeMap::new();
        let mut create_requests = BTreeMap::new();
        for record in &checkpoint.resources {
            metadata_bytes = metadata_bytes
                .checked_add(capacity::record_bytes(record)?)
                .ok_or(SecurityError::BudgetExceeded)?;
            policy::validate_resource(record, checkpoint.incarnation, checkpoint.revision)?;
            if let Some(receipt) = &record.create_receipt
                && create_requests
                    .insert(
                        (
                            record.key.tenant.clone(),
                            receipt.principal.clone(),
                            receipt.request_id.clone(),
                        ),
                        record.key.clone(),
                    )
                    .is_some()
            {
                return Err(SecurityError::Invalid(
                    "duplicate create request binding".into(),
                ));
            }
            if resources
                .insert(record.key.clone(), record.clone())
                .is_some()
                || physical
                    .insert(record.storage_id, record.key.clone())
                    .is_some()
            {
                return Err(SecurityError::Invalid(
                    "duplicate logical or physical resource identity".into(),
                ));
            }
        }
        capacity::check(
            &checkpoint.collection,
            checkpoint.incarnation,
            &checkpoint.policy,
            metadata_bytes,
            capacity::LIMIT,
        )?;
        // Validate every chain at admission, including chains nobody currently
        // has permission to traverse. No malformed dormant grant may be saved.
        for record in resources.values() {
            if let Some(receipt) = &record.create_receipt {
                for id in &receipt.ids {
                    if !resources.contains_key(&PointKey {
                        id: id.clone(),
                        ..record.key.clone()
                    }) {
                        return Err(SecurityError::Invalid(
                            "missing create receipt binding".into(),
                        ));
                    }
                }
            }
            let mut current = record;
            let mut path = BTreeSet::new();
            loop {
                if !path.insert(&current.key) {
                    return Err(SecurityError::Invalid("inheritance cycle".into()));
                }
                if path.len() > MAX_INHERITANCE_DEPTH {
                    return Err(SecurityError::BudgetExceeded);
                }
                let Some(parent) = &current.parent else { break };
                if parent.tenant != record.key.tenant || parent.collection != record.key.collection
                {
                    return Err(SecurityError::Invalid(
                        "inheritance crosses collection or tenant".into(),
                    ));
                }
                current = resources
                    .get(parent)
                    .ok_or_else(|| SecurityError::Invalid("unknown inheritance parent".into()))?;
            }
        }
        let epoch = Epoch::new(checkpoint.revision);
        let generation = checkpoint.data_generation;
        checkpoint.resources.clear();
        Ok(Self {
            checkpoint,
            resources: Arc::new(RwLock::new(ResourceIndex {
                records: resources,
                physical,
                generation,
                metadata_bytes,
                create_requests,
            })),
            epoch,
        })
    }
}

#[derive(Debug)]
pub struct CollectionAuthority {
    current: RwLock<Arc<PolicySnapshot>>,
    /// Per-collection control plane only. Query paths do not take this mutex.
    update: Mutex<()>,
    /// Serializes only create request lookup+commit within this collection.
    pub(crate) create_requests: Mutex<()>,
    #[cfg(test)]
    metadata_limit: std::sync::atomic::AtomicUsize,
}

/// Borrowed only inside a data commit while its identity and collection update
/// leases are held. Delete has drained the publication epoch at this point;
/// reference checks still use the current, unchanged resource policy.
pub(crate) struct DataReferenceAuthorization<'a> {
    context: &'a AccessContext,
}

impl DataReferenceAuthorization<'_> {
    pub(crate) fn tenant(&self) -> &str {
        self.context.tenant()
    }

    pub(crate) fn collection(&self) -> &str {
        self.context.collection()
    }

    pub(crate) fn matches_collection(&self, reference: &crate::RecordRef) -> bool {
        reference.namespace == self.context.collection().to_ascii_lowercase()
    }

    pub(crate) fn authorize(&self, reference: &crate::RecordRef) -> Result<ResourceRecord> {
        let context = self.context;
        if !self.matches_collection(reference)
            || !context
                .identity
                .allows(context.tenant(), context.collection(), Action::Read)
        {
            return Err(SecurityError::Forbidden);
        }
        let resources = context.snapshot.resources.read();
        let key = PointKey {
            collection: context.incarnation(),
            tenant: context.tenant.clone(),
            id: reference.id.clone(),
        };
        let record = resources.records.get(&key).ok_or(SecurityError::NotFound)?;
        policy::authorize_resource(
            context.identity.principal(),
            context.identity.groups(),
            record,
            Action::Read,
            &context.snapshot.checkpoint.policy,
            &resources.records,
        )?;
        Ok(record.clone())
    }
}
impl Drop for CollectionAuthority {
    fn drop(&mut self) {
        self.current.get_mut().epoch.close();
    }
}

pub(crate) struct CreateOptions<'a> {
    pub(crate) ids: Option<&'a [String]>,
    pub(crate) request: Option<(String, [u8; 32])>,
    pub(crate) decision_started: Option<&'a AtomicBool>,
}

impl CollectionAuthority {
    /// Called by trusted recovery after verifying the content/security commit.
    pub fn from_verified_checkpoint(checkpoint: SecurityCheckpoint) -> Result<Self> {
        Ok(Self {
            current: RwLock::new(Arc::new(PolicySnapshot::validate(checkpoint)?)),
            update: Mutex::new(()),
            create_requests: Mutex::new(()),
            #[cfg(test)]
            metadata_limit: std::sync::atomic::AtomicUsize::new(capacity::LIMIT),
        })
    }

    fn metadata_limit(&self) -> usize {
        #[cfg(test)]
        {
            self.metadata_limit
                .load(std::sync::atomic::Ordering::Relaxed)
        }
        #[cfg(not(test))]
        {
            capacity::LIMIT
        }
    }

    #[cfg(test)]
    pub(crate) fn limit_metadata_for_test(&self, limit: usize) {
        assert!(limit <= capacity::LIMIT);
        self.metadata_limit
            .store(limit, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn bind(
        &self,
        identity: &AuthenticatedIdentity,
        active_tenant: &str,
        action: Action,
    ) -> Result<AccessContext> {
        let snapshot = Arc::clone(&self.current.read());
        let identity = identity.for_collection(
            &snapshot.checkpoint.collection,
            snapshot.checkpoint.incarnation,
        );
        if !identity.allows(active_tenant, &snapshot.checkpoint.collection, action) {
            return Err(SecurityError::Forbidden);
        }
        // Acquiring and releasing this pair rejects a context already closed
        // during binding. Every later commit/publication obtains a fresh pair.
        let context = AccessContext {
            identity,
            tenant: active_tenant.into(),
            action,
            snapshot,
        };
        context.publication_permit()?;
        Ok(context)
    }

    pub fn revision(&self) -> u64 {
        self.current.read().checkpoint.revision
    }
    pub fn incarnation(&self) -> Uuid {
        self.current.read().checkpoint.incarnation
    }
    pub(crate) fn accepts(&self, context: &AccessContext) -> bool {
        Arc::ptr_eq(&self.current.read(), &context.snapshot)
    }
    pub fn checkpoint(&self) -> SecurityCheckpoint {
        self.current.read().checkpoint()
    }

    /// Cold content reloads may verify authority, but never replace its live
    /// epoch. Compare without cloning the potentially large resource catalog.
    pub(crate) fn verify_recovered(&self, recovered: &Self) -> Result<()> {
        let live = self.current.read();
        let disk = recovered.current.read();
        let live_index = live.resources.read();
        let disk_index = disk.resources.read();
        if live.checkpoint.version != disk.checkpoint.version
            || live.checkpoint.collection != disk.checkpoint.collection
            || live.checkpoint.incarnation != disk.checkpoint.incarnation
            || live.checkpoint.revision != disk.checkpoint.revision
            || live.checkpoint.policy != disk.checkpoint.policy
            || live_index.generation != disk_index.generation
            || live_index.records != disk_index.records
            || live_index.physical != disk_index.physical
            || live_index.create_requests != disk_index.create_requests
        {
            live.epoch.close();
            return Err(SecurityError::Unavailable);
        }
        Ok(())
    }

    /// A content transaction adds bindings without invalidating unrelated
    /// queries. The engine holds its collection write lock before entering;
    /// `commit` must atomically WAL-log these bindings with their point data.
    /// Publication still requires the caller's fresh AccessPermit.
    #[cfg(test)]
    pub(crate) fn create_with_commit(
        &self,
        context: &AccessContext,
        template: &str,
        points: &[NewPoint],
        request: Option<(String, [u8; 32])>,
        commit: impl FnOnce(&[ResourceRecord], u64) -> crate::Result<()>,
    ) -> crate::Result<Vec<ResourceRecord>> {
        self.create_with_ids_commit(context, template, points, None, request, commit)
    }

    #[cfg(test)]
    pub(crate) fn create_with_ids_commit(
        &self,
        context: &AccessContext,
        template: &str,
        points: &[NewPoint],
        explicit_ids: Option<&[String]>,
        request: Option<(String, [u8; 32])>,
        commit: impl FnOnce(&[ResourceRecord], u64) -> crate::Result<()>,
    ) -> crate::Result<Vec<ResourceRecord>> {
        self.create_with_options(
            context,
            template,
            points,
            CreateOptions {
                ids: explicit_ids,
                request,
                decision_started: None,
            },
            commit,
        )
    }

    /// A transactional planner may reject before attempting a durable decision.
    /// Such validation does not poison the collection's unchanged authority.
    pub(crate) fn create_transaction(
        &self,
        context: &AccessContext,
        template: &str,
        points: &[NewPoint],
        decision_started: &AtomicBool,
        commit: impl FnOnce(&[ResourceRecord], u64) -> crate::Result<()>,
    ) -> crate::Result<Vec<ResourceRecord>> {
        self.create_with_options(
            context,
            template,
            points,
            CreateOptions {
                ids: None,
                request: None,
                decision_started: Some(decision_started),
            },
            commit,
        )
    }

    pub(crate) fn create_with_options(
        &self,
        context: &AccessContext,
        template: &str,
        points: &[NewPoint],
        options: CreateOptions<'_>,
        commit: impl FnOnce(&[ResourceRecord], u64) -> crate::Result<()>,
    ) -> crate::Result<Vec<ResourceRecord>> {
        let CreateOptions {
            ids: explicit_ids,
            request,
            decision_started,
        } = options;
        let _update = self.update.lock();
        let snapshot = Arc::clone(&self.current.read());
        if context.action != Action::Create || !Arc::ptr_eq(&snapshot, &context.snapshot) {
            return Err(SecurityError::Forbidden.into());
        }
        if points.is_empty() || points.len() > 1024 {
            return Err(SecurityError::BudgetExceeded.into());
        }
        if explicit_ids.is_some_and(|ids| {
            ids.len() != points.len() || ids.iter().any(|id| id.is_empty() || id.len() > 1024)
        }) {
            return Err(SecurityError::Invalid("invalid public point ID".into()).into());
        }
        if points.iter().any(|point| {
            !point.vector.is_empty() || !point.vectors.is_empty() || point.sparse_vector.is_some()
        }) && !context
            .identity
            .allows(context.tenant(), context.collection(), Action::Ingest)
        {
            return Err(SecurityError::Forbidden.into());
        }
        let template = snapshot
            .checkpoint
            .policy
            .templates
            .get(template)
            .ok_or(SecurityError::Forbidden)?;
        let attributes = &context.identity.principal().attributes;
        if attributes.clearance < template.classification {
            return Err(SecurityError::Forbidden.into());
        }
        // Bound repeated per-object labels before cloning them across a batch.
        // The remaining half of the WAL envelope covers graph handles, record
        // framing and exact physical identity fields.
        let limit = crate::wal::MAX_WAL_RECORD_BYTES / 2;
        let metadata = super::storage::serialized_len(template, limit)?
            .checked_add(1024)
            .and_then(|bytes| bytes.checked_mul(points.len()))
            .ok_or(SecurityError::BudgetExceeded)?;
        let content_budget = limit
            .checked_sub(metadata)
            .ok_or(SecurityError::BudgetExceeded)?;
        super::storage::serialized_len(&points, content_budget)?;
        let resources = snapshot.resources.write();
        let _permit = context.publication_permit()?;
        let generation = resources
            .generation
            .checked_add(1)
            .ok_or(SecurityError::Unavailable)?;
        let mut created = Vec::with_capacity(points.len());
        let mut public_ids = BTreeSet::new();
        let mut storage_ids = BTreeSet::new();
        for (index, point) in points.iter().enumerate() {
            let key = if let Some(ids) = explicit_ids {
                let key = PointKey {
                    collection: snapshot.checkpoint.incarnation,
                    tenant: context.tenant.clone(),
                    id: ids[index].clone(),
                };
                if resources.records.contains_key(&key) || !public_ids.insert(key.clone()) {
                    return Err(crate::GaussError::DuplicateKey);
                }
                key
            } else {
                loop {
                    let key = PointKey {
                        collection: snapshot.checkpoint.incarnation,
                        tenant: context.tenant.clone(),
                        id: Uuid::new_v4().to_string(),
                    };
                    if !resources.records.contains_key(&key) && public_ids.insert(key.clone()) {
                        break key;
                    }
                }
            };
            let storage_id = loop {
                let id = Uuid::new_v4();
                if !resources.physical.contains_key(&id) && storage_ids.insert(id) {
                    break id;
                }
            };
            let record = ResourceRecord {
                key,
                storage_id,
                labels: ResourceLabels {
                    owner: context.principal_id().into(),
                    department: template.department.clone(),
                    classification: template.classification,
                    quarantined: false,
                },
                properties: template.properties.clone(),
                representations: template.representations.clone(),
                grants: Vec::new(),
                parent: None,
                revision: context.policy_revision(),
                retired: false,
                create_receipt: None,
            };
            policy::validate_payload_write(&record, attributes, &point.payload)?;
            for name in point
                .vectors
                .keys()
                .map(String::as_str)
                .chain((!point.vector.is_empty()).then_some("dense"))
                .chain(point.sparse_vector.is_some().then_some("sparse"))
            {
                let representation = record
                    .representations
                    .get(name)
                    .ok_or(SecurityError::Forbidden)?;
                if attributes.clearance < representation.classification {
                    return Err(SecurityError::Forbidden.into());
                }
                if representation
                    .source_fields
                    .iter()
                    .any(|field| point.payload.pointer(field).is_none())
                {
                    return Err(SecurityError::Invalid(
                        "representation source is absent from ingest input".into(),
                    )
                    .into());
                }
            }
            created.push(record);
        }
        if let Some((request_id, request_digest)) = request {
            if resources.create_requests.contains_key(&(
                context.tenant().into(),
                context.principal_id().into(),
                request_id.clone(),
            )) {
                return Err(SecurityError::Conflict.into());
            }
            let ids = created.iter().map(|record| record.key.id.clone()).collect();
            created[0].create_receipt = Some(CreateReceipt {
                principal: context.principal_id().into(),
                request_id,
                request_digest,
                ids,
            });
        }
        let metadata_bytes =
            capacity::overlay_bytes(resources.metadata_bytes, &resources.records, &created)?;
        capacity::check(
            context.collection(),
            context.incarnation(),
            &snapshot.checkpoint.policy,
            metadata_bytes,
            self.metadata_limit(),
        )?;
        // The update lease and caller's collection write guard still exclude
        // mutation/publication. Let preparation authorize existing references
        // against the old resource map without recursively taking its write lock.
        drop(resources);
        if let Err(error) = commit(&created, generation) {
            if decision_started.is_none_or(|started| started.load(Ordering::Acquire)) {
                snapshot.epoch.close();
            }
            return Err(error);
        }
        let mut resources = snapshot.resources.write();
        for record in &created {
            if let Some(receipt) = &record.create_receipt {
                resources.create_requests.insert(
                    (
                        record.key.tenant.clone(),
                        receipt.principal.clone(),
                        receipt.request_id.clone(),
                    ),
                    record.key.clone(),
                );
            }
            resources
                .physical
                .insert(record.storage_id, record.key.clone());
            resources.records.insert(record.key.clone(), record.clone());
        }
        resources.generation = generation;
        resources.metadata_bytes = metadata_bytes;
        Ok(created)
    }

    /// Serialize standalone SQL reference admission with point retirement in
    /// this collection. The read and identity epochs remain live through the
    /// durable SQL decision; collection data paths keep their own locks.
    pub(crate) fn reference_commit<T>(
        &self,
        context: &AccessContext,
        references: &BTreeSet<crate::RecordRef>,
        commit: impl FnOnce() -> crate::Result<T>,
    ) -> crate::Result<T> {
        let _update = self.update.lock();
        let snapshot = Arc::clone(&self.current.read());
        if context.action != Action::Read || !Arc::ptr_eq(&snapshot, &context.snapshot) {
            return Err(SecurityError::Forbidden.into());
        }
        let _permit = context.publication_permit()?;
        let namespace = context.collection().to_ascii_lowercase();
        for reference in references {
            if reference.namespace != namespace {
                return Err(SecurityError::Forbidden.into());
            }
            context.authorize(&reference.id)?;
        }
        commit()
    }

    /// Native and multi-model preparation may reject before a durable attempt.
    /// Callers mark the first journal write attempt; later errors retain the
    /// conservative fail-closed behavior. Update keeps its old epoch on a proven
    /// predecision refusal; delete rotates the drained epoch without retirement.
    pub(crate) fn data_transaction<T>(
        &self,
        context: &AccessContext,
        retire: &[PointKey],
        decision_started: &AtomicBool,
        commit: impl FnOnce(
            &[ResourceRecord],
            u64,
            u64,
            u64,
            &DataReferenceAuthorization<'_>,
        ) -> crate::Result<T>,
    ) -> crate::Result<T> {
        self.data_with_options(context, retire, Some(decision_started), commit)
    }

    fn data_with_options<T>(
        &self,
        context: &AccessContext,
        retire: &[PointKey],
        decision_started: Option<&AtomicBool>,
        commit: impl FnOnce(
            &[ResourceRecord],
            u64,
            u64,
            u64,
            &DataReferenceAuthorization<'_>,
        ) -> crate::Result<T>,
    ) -> crate::Result<T> {
        let _update = self.update.lock();
        let snapshot = Arc::clone(&self.current.read());
        if !matches!(context.action, Action::Update | Action::Delete)
            || (context.action == Action::Update && !retire.is_empty())
            || !Arc::ptr_eq(&snapshot, &context.snapshot)
        {
            return Err(SecurityError::Forbidden.into());
        }
        let _identity_lease = context.identity.publication_permit()?;
        context.publication_permit()?;
        let resources = snapshot.resources.read();
        let mut retired = Vec::with_capacity(retire.len());
        let mut remaining = crate::wal::MAX_WAL_RECORD_BYTES / 2;
        for key in retire {
            if key.tenant != context.tenant || key.collection != context.incarnation() {
                return Err(SecurityError::NotFound.into());
            }
            let record = resources.records.get(key).ok_or(SecurityError::NotFound)?;
            policy::authorize_resource(
                context.identity.principal(),
                context.identity.groups(),
                record,
                Action::Delete,
                &snapshot.checkpoint.policy,
                &resources.records,
            )?;
            let bytes = super::storage::serialized_len(record, remaining)?;
            remaining = remaining
                .checked_sub(bytes)
                .ok_or(SecurityError::BudgetExceeded)?;
            let mut record = record.clone();
            record.retired = true;
            retired.push(record);
        }
        let metadata_bytes =
            capacity::overlay_bytes(resources.metadata_bytes, &resources.records, &retired)?;
        capacity::check(
            context.collection(),
            context.incarnation(),
            &snapshot.checkpoint.policy,
            metadata_bytes,
            self.metadata_limit(),
        )?;
        let previous = resources.generation;
        let next = previous.checked_add(1).ok_or(SecurityError::Unavailable)?;
        drop(resources);
        // Removing a container also withdraws inherited grants. Conservatively
        // revoke the collection epoch on deletion; never leave queued results
        // authorized by a now-retired parent alive after acknowledgement.
        let revision = if context.action == Action::Delete {
            let revision = snapshot
                .checkpoint
                .revision
                .checked_add(1)
                .ok_or(SecurityError::Unavailable)?;
            snapshot.epoch.close_and_drain()?;
            revision
        } else {
            snapshot.checkpoint.revision
        };
        // The update lease excludes changes to this map through preparation.
        // Reference authorization must not recursively acquire its write lock.
        let references = DataReferenceAuthorization { context };
        let result = match commit(&retired, previous, next, revision, &references) {
            Ok(result) => result,
            Err(error) => {
                if decision_started.is_none_or(|started| started.load(Ordering::Acquire)) {
                    snapshot.epoch.close();
                } else if context.action == Action::Delete {
                    // Delete drained the old epoch before preparation. No
                    // durable decision was attempted and resources are still
                    // unchanged. Install a fresh epoch with the original
                    // revision; never reopen the drained epoch or its permits.
                    *self.current.write() = Arc::new(PolicySnapshot {
                        checkpoint: snapshot.checkpoint.clone(),
                        resources: Arc::clone(&snapshot.resources),
                        epoch: Epoch::new(snapshot.checkpoint.revision),
                    });
                }
                return Err(error);
            }
        };
        let mut resources = snapshot.resources.write();
        for record in retired {
            resources.records.insert(record.key.clone(), record);
        }
        resources.generation = next;
        resources.metadata_bytes = metadata_bytes;
        drop(resources);
        if context.action == Action::Delete {
            let mut checkpoint = snapshot.checkpoint.clone();
            checkpoint.revision = revision;
            checkpoint.data_generation = next;
            *self.current.write() = Arc::new(PolicySnapshot {
                checkpoint,
                resources: Arc::clone(&snapshot.resources),
                epoch: Epoch::new(revision),
            });
        }
        Ok(result)
    }

    /// A graph schema change rotates the policy epoch without copying resources.
    /// The caller holds the collection write lock and has validated its mutation.
    pub(crate) fn schema_with_commit<T>(
        &self,
        context: &AccessContext,
        expected_revision: u64,
        persist: impl FnOnce(u64, u64, u64) -> crate::Result<T>,
    ) -> crate::Result<(u64, T)> {
        let _update = self.update.lock();
        let snapshot = Arc::clone(&self.current.read());
        if context.action != Action::Schema || !Arc::ptr_eq(&snapshot, &context.snapshot) {
            return Err(SecurityError::Forbidden.into());
        }
        if expected_revision != snapshot.checkpoint.revision {
            return Err(SecurityError::Conflict.into());
        }
        let _identity = context.identity.publication_permit()?;
        context.publication_permit()?;
        let previous = snapshot.resources.read().generation;
        let next = previous.checked_add(1).ok_or(SecurityError::Unavailable)?;
        let revision = expected_revision
            .checked_add(1)
            .ok_or(SecurityError::Unavailable)?;
        snapshot.epoch.close_and_drain()?;
        let result = persist(previous, next, revision)?;
        snapshot.resources.write().generation = next;
        let mut checkpoint = snapshot.checkpoint.clone();
        checkpoint.revision = revision;
        checkpoint.data_generation = next;
        *self.current.write() = Arc::new(PolicySnapshot {
            checkpoint,
            resources: Arc::clone(&snapshot.resources),
            epoch: Epoch::new(revision),
        });
        Ok((revision, result))
    }

    /// Internal, representation-only handle backfill after a durable graph enable.
    /// No object content, labels, grants or public IDs may change in this callback.
    pub(crate) fn graph_backfill_with_commit<T>(
        &self,
        persist: impl FnOnce(SecurityDelta) -> crate::Result<T>,
    ) -> crate::Result<T> {
        let _update = self.update.lock();
        let snapshot = Arc::clone(&self.current.read());
        let _permit = snapshot.epoch.enter()?;
        let previous = snapshot.resources.read().generation;
        let next = previous.checked_add(1).ok_or(SecurityError::Unavailable)?;
        let result = persist(SecurityDelta {
            incarnation: snapshot.checkpoint.incarnation,
            expected_revision: snapshot.checkpoint.revision,
            revision: snapshot.checkpoint.revision,
            expected_generation: previous,
            generation: next,
            policy: None,
            bindings: vec![],
        })
        .inspect_err(|_| snapshot.epoch.close())?;
        snapshot.resources.write().generation = next;
        Ok(result)
    }

    /// Commit a bounded label/grant overlay without copying the collection's
    /// entire resource catalog. The collection write lock precedes this gate.
    pub(crate) fn change_resources(
        &self,
        context: &AccessContext,
        expected_revision: u64,
        changed: &[ResourceRecord],
        persist: impl FnOnce(u64, u64, u64) -> crate::Result<()>,
    ) -> crate::Result<u64> {
        let _update = self.update.lock();
        let snapshot = Arc::clone(&self.current.read());
        if !matches!(context.action, Action::LabelsManage | Action::GrantsManage)
            || !Arc::ptr_eq(&snapshot, &context.snapshot)
        {
            return Err(SecurityError::Forbidden.into());
        }
        if expected_revision != snapshot.checkpoint.revision {
            return Err(SecurityError::Conflict.into());
        }
        if changed.is_empty() || changed.len() > 1024 {
            return Err(SecurityError::BudgetExceeded.into());
        }
        super::storage::serialized_len(&changed, crate::wal::MAX_WAL_RECORD_BYTES / 2)?;
        let revision = expected_revision
            .checked_add(1)
            .ok_or(SecurityError::Unavailable)?;
        let _identity_lease = context.identity.publication_permit()?;
        context.publication_permit()?;
        let resources = snapshot.resources.read();
        let previous_generation = resources.generation;
        let generation = previous_generation
            .checked_add(1)
            .ok_or(SecurityError::Unavailable)?;
        let mut overlay = BTreeMap::new();
        for record in changed {
            let old = resources
                .records
                .get(&record.key)
                .ok_or(SecurityError::NotFound)?;
            if old.retired
                || record.retired
                || old.storage_id != record.storage_id
                || record.key.tenant != context.tenant
                || record.revision != revision
                || overlay.insert(&record.key, record).is_some()
            {
                return Err(
                    SecurityError::Invalid("invalid security resource update".into()).into(),
                );
            }
            policy::validate_resource(record, context.incarnation(), revision)?;
        }
        let metadata_bytes =
            capacity::overlay_bytes(resources.metadata_bytes, &resources.records, changed)?;
        capacity::check(
            context.collection(),
            context.incarnation(),
            &snapshot.checkpoint.policy,
            metadata_bytes,
            self.metadata_limit(),
        )?;
        let started = std::time::Instant::now();
        for (index, start) in resources.records.values().enumerate() {
            if index % 64 == 0 {
                context.publication_permit()?;
                if started.elapsed() >= std::time::Duration::from_secs(30) {
                    return Err(SecurityError::BudgetExceeded.into());
                }
            }
            let mut current = overlay.get(&start.key).copied().unwrap_or(start);
            let mut path = BTreeSet::new();
            loop {
                if !path.insert(&current.key) {
                    return Err(SecurityError::Invalid("inheritance cycle".into()).into());
                }
                if path.len() > MAX_INHERITANCE_DEPTH {
                    return Err(SecurityError::BudgetExceeded.into());
                }
                let Some(parent) = &current.parent else { break };
                if parent.tenant != start.key.tenant || parent.collection != start.key.collection {
                    return Err(SecurityError::Invalid(
                        "inheritance crosses a security domain".into(),
                    )
                    .into());
                }
                current = overlay
                    .get(parent)
                    .copied()
                    .or_else(|| resources.records.get(parent))
                    .ok_or_else(|| SecurityError::Invalid("inheritance parent is absent".into()))?;
            }
        }
        drop(resources);
        snapshot.epoch.close_and_drain()?;
        // Any failure after closing admission leaves this epoch closed.
        persist(previous_generation, generation, revision)?;
        let mut resources = snapshot.resources.write();
        for record in changed {
            resources.records.insert(record.key.clone(), record.clone());
        }
        resources.generation = generation;
        resources.metadata_bytes = metadata_bytes;
        drop(resources);
        let mut checkpoint = snapshot.checkpoint.clone();
        checkpoint.revision = revision;
        checkpoint.data_generation = generation;
        *self.current.write() = Arc::new(PolicySnapshot {
            checkpoint,
            resources: Arc::clone(&snapshot.resources),
            epoch: Epoch::new(revision),
        });
        Ok(revision)
    }

    /// Engine-only control transaction. The caller has already authorized the
    /// specific labels/grants/policy operation and prepared its atomic WAL
    /// batch. Durability must finish inside `persist` before installing state.
    pub(crate) fn install(
        &self,
        expected_revision: u64,
        checkpoint: SecurityCheckpoint,
        persist: impl FnOnce(&SecurityCheckpoint) -> Result<()>,
    ) -> Result<()> {
        let _update = self.update.lock();
        let previous = Arc::clone(&self.current.read());
        if previous.checkpoint.revision != expected_revision
            || Some(checkpoint.data_generation)
                != previous.resources.read().generation.checked_add(1)
            || checkpoint.revision
                != expected_revision
                    .checked_add(1)
                    .ok_or(SecurityError::Unavailable)?
        {
            return Err(SecurityError::Conflict);
        }
        if checkpoint.incarnation != previous.checkpoint.incarnation
            || checkpoint.collection != previous.checkpoint.collection
        {
            return Err(SecurityError::Invalid(
                "incarnation changes require verified migration".into(),
            ));
        }
        let next = Arc::new(PolicySnapshot::validate(checkpoint)?);
        capacity::check(
            &next.checkpoint.collection,
            next.checkpoint.incarnation,
            &next.checkpoint.policy,
            next.resources.read().metadata_bytes,
            self.metadata_limit(),
        )?;
        previous.epoch.close_and_drain()?;
        // Failure leaves the previous epoch closed; never reactivate a stale
        // policy after an uncertain durable update.
        persist(&next.checkpoint())?;
        *self.current.write() = next;
        Ok(())
    }
}

/// No Deserialize implementation and no public fields or unchecked constructor.
#[derive(Clone, Debug)]
pub struct AccessContext {
    identity: AuthenticatedIdentity,
    tenant: String,
    action: Action,
    snapshot: Arc<PolicySnapshot>,
}

/// Both identity and policy epochs must remain valid through publication/commit.
#[derive(Debug)]
pub struct AccessPermit {
    _identity: PublicationPermit,
    _policy: PublicationPermit,
}

impl AccessContext {
    pub(crate) fn create_receipt_digest(
        &self,
        request_id: &str,
    ) -> crate::Result<Option<[u8; 32]>> {
        let resources = self.read_resources()?;
        Ok(resources
            .create_receipt(request_id)?
            .map(|receipt| receipt.request_digest))
    }

    pub(crate) fn identity(&self) -> &AuthenticatedIdentity {
        &self.identity
    }
    pub fn principal_id(&self) -> &str {
        &self.identity.principal().id
    }
    pub fn credential_id(&self) -> &str {
        self.identity.credential_id()
    }
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    pub fn collection(&self) -> &str {
        &self.snapshot.checkpoint.collection
    }
    pub fn incarnation(&self) -> Uuid {
        self.snapshot.checkpoint.incarnation
    }
    pub fn identity_revision(&self) -> u64 {
        self.identity.revision()
    }
    pub fn policy_revision(&self) -> u64 {
        self.snapshot.checkpoint.revision
    }
    pub fn action(&self) -> Action {
        self.action
    }
    pub fn publication_permit(&self) -> Result<AccessPermit> {
        let identity = self.identity.publication_permit()?;
        let policy = self.snapshot.epoch.enter()?;
        Ok(AccessPermit {
            _identity: identity,
            _policy: policy,
        })
    }

    pub fn authorize(&self, public_id: &str) -> Result<ResourceRecord> {
        let _permit = self.publication_permit()?;
        let key = PointKey {
            collection: self.incarnation(),
            tenant: self.tenant.clone(),
            id: public_id.into(),
        };
        let resources = self.snapshot.resources.read();
        let record = resources.records.get(&key).ok_or(SecurityError::NotFound)?;
        policy::authorize_resource(
            self.identity.principal(),
            self.identity.groups(),
            record,
            self.action,
            &self.snapshot.checkpoint.policy,
            &resources.records,
        )?;
        Ok(record.clone())
    }

    /// Only the core's create lease supplies candidate bindings. They are not
    /// installed yet, but must obey the same current object policy as live rows.
    pub(crate) fn authorize_candidate(&self, record: &ResourceRecord) -> Result<()> {
        let _permit = self.publication_permit()?;
        if record.key.collection != self.incarnation() || record.key.tenant != self.tenant {
            return Err(SecurityError::NotFound);
        }
        let resources = self.snapshot.resources.read();
        policy::authorize_resource(
            self.identity.principal(),
            self.identity.groups(),
            record,
            self.action,
            &self.snapshot.checkpoint.policy,
            &resources.records,
        )
    }

    /// A consumed transaction may acknowledge its own deletion. This does not
    /// authorize reading or mutating a retired record: only the retained binding
    /// of the original receipt is accepted, under current grants and labels.
    pub(crate) fn authorize_receipt(
        &self,
        public_id: &str,
        storage_id: Uuid,
        retired_by_commit: bool,
    ) -> Result<()> {
        let _permit = self.publication_permit()?;
        let resources = self.snapshot.resources.read();
        let key = PointKey {
            collection: self.incarnation(),
            tenant: self.tenant.clone(),
            id: public_id.into(),
        };
        let mut record = resources
            .records
            .get(&key)
            .filter(|record| {
                record.storage_id == storage_id && (!record.retired || retired_by_commit)
            })
            .ok_or(SecurityError::NotFound)?
            .clone();
        record.retired = false;
        policy::authorize_resource(
            self.identity.principal(),
            self.identity.groups(),
            &record,
            self.action,
            &self.snapshot.checkpoint.policy,
            &resources.records,
        )
    }

    pub fn authorize_physical(&self, storage_id: Uuid) -> Result<ResourceRecord> {
        let id = self
            .snapshot
            .resources
            .read()
            .physical
            .get(&storage_id)
            .filter(|key| key.tenant == self.tenant)
            .map(|key| key.id.clone())
            .ok_or(SecurityError::NotFound)?;
        self.authorize(&id)
    }

    pub fn data_generation(&self) -> u64 {
        self.snapshot.resources.read().generation
    }

    /// Reference domain for exact retrieval and pushdown-equivalence tests.
    /// Evaluation errors are propagated; they never become partial success.
    pub fn authorized_domain(&self) -> Result<BTreeSet<Uuid>> {
        self.authorized_domain_checked(|| Ok(()))
    }

    pub(crate) fn authorized_domain_checked(
        &self,
        check: impl Fn() -> Result<()>,
    ) -> Result<BTreeSet<Uuid>> {
        check()?;
        let _permit = self.publication_permit()?;
        let started = std::time::Instant::now();
        let mut domain = BTreeSet::new();
        let resources = self.snapshot.resources.read();
        let start = PointKey {
            collection: self.incarnation(),
            tenant: self.tenant.clone(),
            id: String::new(),
        };
        for (index, (_, record)) in resources
            .records
            .range(start..)
            .take_while(|(key, _)| {
                key.tenant == self.tenant && key.collection == self.incarnation()
            })
            .enumerate()
        {
            if index % 64 == 0 {
                check()?;
                self.publication_permit()?;
                if started.elapsed() >= std::time::Duration::from_secs(30) {
                    return Err(SecurityError::BudgetExceeded);
                }
            }
            match policy::authorize_resource(
                self.identity.principal(),
                self.identity.groups(),
                record,
                self.action,
                &self.snapshot.checkpoint.policy,
                &resources.records,
            ) {
                Ok(()) => {
                    if domain.len() >= 1_000_000 {
                        return Err(SecurityError::BudgetExceeded);
                    }
                    domain.insert(record.storage_id);
                }
                Err(SecurityError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        check()?;
        Ok(domain)
    }

    pub fn project(&self, public_id: &str, payload: &Value, export: bool) -> Result<Value> {
        if (export && self.action != Action::Export)
            || (!export
                && !matches!(
                    self.action,
                    Action::Read | Action::Search | Action::GraphRead
                ))
        {
            return Err(SecurityError::Forbidden);
        }
        let record = self.authorize(public_id)?;
        Ok(policy::project_payload(
            &record,
            &self.identity.principal().attributes,
            payload,
            if export {
                PropertyAction::Export
            } else {
                PropertyAction::Read
            },
        ))
    }

    pub fn authorize_query_fields(&self, fields: &BTreeSet<String>) -> Result<()> {
        if self.action != Action::Search
            && self.action != Action::Read
            && self.action != Action::Delete
        {
            return Err(SecurityError::Forbidden);
        }
        for id in self.authorized_domain()? {
            let record = self.authorize_physical(id)?;
            if fields.iter().any(|path| {
                !policy::field_allowed(
                    &record,
                    &self.identity.principal().attributes,
                    path,
                    PropertyAction::Query,
                )
            }) {
                return Err(SecurityError::Forbidden);
            }
        }
        Ok(())
    }

    pub fn matches_filter(
        &self,
        public_id: &str,
        filter: &SecurityFilter,
        payload: &Value,
    ) -> Result<bool> {
        if !matches!(
            self.action,
            Action::Read | Action::Search | Action::Delete | Action::GraphRead
        ) {
            return Err(SecurityError::Forbidden);
        }
        let record = self.authorize(public_id)?;
        filter.matches(&record, &self.identity.principal().attributes, payload)
    }

    pub(crate) fn authorize_label_delegation(&self, record: &ResourceRecord) -> Result<()> {
        let resources = self.snapshot.resources.read();
        let mut actions: BTreeSet<_> = self
            .snapshot
            .checkpoint
            .policy
            .owner_actions
            .iter()
            .chain(&self.snapshot.checkpoint.policy.department_actions)
            .copied()
            .collect();
        let mut current = record;
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert(&current.key) || visited.len() > MAX_INHERITANCE_DEPTH {
                return Err(SecurityError::BudgetExceeded);
            }
            for grant in &current.grants {
                actions.extend(&grant.actions);
            }
            let Some(parent) = &current.parent else { break };
            current = resources
                .records
                .get(parent)
                .ok_or(SecurityError::NotFound)?;
        }
        // Labels can expose existing owner/department/ACL permits. Label
        // management alone must not bypass the manager's delegation ceiling.
        self.authorize_delegated_actions(actions)
    }

    pub(crate) fn authorize_delegated_actions(&self, actions: BTreeSet<Action>) -> Result<()> {
        if !policy::may_delegate_identity(
            &self.identity,
            &[ScopeGrant {
                tenants: BTreeSet::from([self.tenant.clone()]),
                collections: BTreeSet::from([self.collection().into()]),
                actions,
            }],
        ) {
            return Err(SecurityError::Forbidden);
        }
        Ok(())
    }

    pub fn authorize_payload_change(
        &self,
        public_id: &str,
        old: &Value,
        new: &Value,
    ) -> Result<()> {
        if self.action != Action::Update {
            return Err(SecurityError::Forbidden);
        }
        let record = self.authorize(public_id)?;
        policy::validate_payload_change(&record, &self.identity.principal().attributes, old, new)
    }

    pub fn authorize_representation_write(&self, public_id: &str, name: &str) -> Result<()> {
        if self.action != Action::Update
            || !self
                .identity
                .allows(self.tenant(), self.collection(), Action::Ingest)
        {
            return Err(SecurityError::Forbidden);
        }
        let record = self.authorize(public_id)?;
        let representation = record
            .representations
            .get(name)
            .ok_or(SecurityError::Forbidden)?;
        if self.identity.principal().attributes.clearance < representation.classification
            || representation.source_fields.iter().any(|path| {
                !policy::field_allowed(
                    &record,
                    &self.identity.principal().attributes,
                    path,
                    PropertyAction::Write,
                )
            })
        {
            return Err(SecurityError::Forbidden);
        }
        Ok(())
    }

    pub fn authorize_representation(&self, public_id: &str, name: &str) -> Result<()> {
        if !matches!(self.action, Action::Search | Action::Read | Action::Export) {
            return Err(SecurityError::Forbidden);
        }
        let record = self.authorize(public_id)?;
        let representation = record
            .representations
            .get(name)
            .ok_or(SecurityError::NotFound)?;
        if self.identity.principal().attributes.clearance < representation.classification
            || representation.source_fields.iter().any(|path| {
                !policy::field_allowed(
                    &record,
                    &self.identity.principal().attributes,
                    path,
                    PropertyAction::Query,
                )
            })
        {
            return Err(SecurityError::NotFound);
        }
        Ok(())
    }
}

/// Deliberately not serializable. An adapter must publish through a fresh lease
/// at its transport boundary; keeping this output queued does not keep an old
/// grant alive. The callback must release data to the transport synchronously.
pub struct AuthorizedOutput<T> {
    value: T,
    context: AccessContext,
    _admission: Option<super::output::OutputAdmission>,
}
impl<T> AuthorizedOutput<T> {
    pub fn publication_context(&self) -> AccessContext {
        self.context.clone()
    }
    pub(crate) fn new(context: AccessContext, value: T) -> Self {
        Self {
            value,
            context,
            _admission: None,
        }
    }
    pub(crate) fn admitted(
        context: AccessContext,
        value: T,
        admission: super::output::OutputAdmission,
    ) -> Self {
        Self {
            value,
            context,
            _admission: Some(admission),
        }
    }
    pub fn publish<R>(self, publish: impl FnOnce(T) -> R) -> crate::Result<R> {
        let _lease = self.context.publication_permit()?;
        Ok(publish(self.value))
    }
    /// Render while authorized, retaining the same publication barrier for the
    /// eventual transport. Serialization is not itself transport publication.
    pub fn map<R>(self, render: impl FnOnce(T) -> R) -> crate::Result<AuthorizedOutput<R>> {
        let _lease = self.context.publication_permit()?;
        Ok(AuthorizedOutput {
            context: self.context,
            value: render(self.value),
            _admission: self._admission,
        })
    }
}
