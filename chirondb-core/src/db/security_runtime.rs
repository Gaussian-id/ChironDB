//! Protected entry points terminate in the same collection engine as legacy
//! protocols. Only contexts minted by this Db's authority can enter these paths.
use super::*;
use crate::search::PointResolver;
use crate::security::{
    AccessContext, Action, AuthenticatedIdentity, AuthorizedOutput, NewPoint, SecurityError,
};
use crate::transaction_journal::TransactionAudit;
use std::collections::BTreeSet;

pub(super) struct ProtectedCreate {
    pub context: AccessContext,
    pub template: String,
    pub points: Vec<NewPoint>,
    pub public_ids: Option<Vec<String>>,
    pub request: Option<(String, [u8; 32])>,
}

pub(super) fn physical_point(point: &NewPoint, id: String) -> Point {
    Point {
        id,
        vector: point.vector.clone(),
        vectors: point.vectors.clone().into_iter().collect(),
        sparse_vector: point.sparse_vector.clone(),
        payload: point.payload.clone(),
    }
}

impl Db {
    fn standalone_reference_context(
        &self,
        identity: &AuthenticatedIdentity,
        references: &BTreeSet<crate::RecordRef>,
    ) -> Result<Option<(AccessContext, Arc<crate::security::CollectionAuthority>)>> {
        let Some(first) = references.first() else {
            return Ok(None);
        };
        if references
            .iter()
            .any(|reference| reference.namespace != first.namespace)
        {
            return Err(GaussError::InvalidRequest(
                "standalone SQL supports one RECORD_REF collection per transaction".into(),
            ));
        }
        let context = self.bind_access(
            identity,
            &first.namespace,
            &identity.principal().tenant,
            Action::Read,
        )?;
        let collection = self.get_coll_authorized(&context)?;
        let authority = collection
            .read()
            .security
            .clone()
            .ok_or(SecurityError::Unavailable)?;
        Ok(Some((context, authority)))
    }

    pub(crate) fn with_standalone_reference_commit<T>(
        &self,
        identity: &AuthenticatedIdentity,
        references: &BTreeSet<crate::RecordRef>,
        commit: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let Some((context, authority)) = self.standalone_reference_context(identity, references)?
        else {
            return commit();
        };
        authority.reference_commit(&context, references, commit)
    }

    /// Bind SQL row references to the current object epoch for final transport
    /// publication. The transport retains the returned context until it
    /// serializes or writes the result.
    pub fn sql_reference_publication_context(
        &self,
        identity: &AuthenticatedIdentity,
        results: &[crate::SqlResult],
    ) -> Result<Option<AccessContext>> {
        self.ensure_current_identity(identity)?;
        let references = crate::RelationalEngine::result_references(results);
        let Some((context, authority)) =
            self.standalone_reference_context(identity, &references)?
        else {
            return Ok(None);
        };
        authority.reference_commit(&context, &references, || Ok(()))?;
        Ok(Some(context))
    }

    /// Production listeners may admit only a verified protected catalog. The
    /// older tenant payload stamp is insufficient for the protected profile.
    pub fn validate_protected_admission(&self) -> Result<()> {
        let _lifecycle = self.lifecycle_gate.read();
        if self.identity_authority.is_none() {
            return Err(SecurityError::Unavailable.into());
        }
        let inner = self.inner.read();
        if inner
            .collections
            .values()
            .any(|collection| collection.read().security.is_none())
        {
            return Err(SecurityError::Invalid(
                "all collections require verified offline security migration".into(),
            )
            .into());
        }
        Ok(())
    }

    /// A collection policy affects every tenant in that collection. It requires
    /// an explicit installation policy capability as well as its named scope;
    /// delegated object managers use the narrower label/grant operations.
    pub fn replace_collection_policy_authorized(
        &self,
        context: &AccessContext,
        update: crate::security::RevisionUpdate<crate::security::CollectionPolicy>,
    ) -> Result<u64> {
        if context.action() != Action::PolicyManage
            || !context.identity().allows_installation(Action::PolicyManage)
        {
            return Err(SecurityError::Forbidden.into());
        }
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let collection = self.get_coll_authorized(context)?;
        let mut collection = collection.write();
        let authority = collection
            .security
            .clone()
            .ok_or(SecurityError::Unavailable)?;
        let _identity_lease = context.identity().publication_permit()?;
        let mut next = authority.checkpoint();
        if update.expected_revision != next.revision {
            return Err(SecurityError::Conflict.into());
        }
        let generation = next.data_generation;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(SecurityError::Unavailable)?;
        next.data_generation = generation
            .checked_add(1)
            .ok_or(SecurityError::Unavailable)?;
        next.policy = update.value;
        let audit_context = audit::AuditContext {
            principal_id: context.principal_id().into(),
            tenant_id: Some(context.tenant().into()),
            transport: "protected".into(),
            request_id: None,
        };
        let audit_details = serde_json::json!({"identity_revision":context.identity_revision(), "expected_policy_revision":update.expected_revision, "policy_revision":next.revision});
        let revision = next.revision;
        let mut committed_transaction = None;
        authority.install(update.expected_revision, next, |checkpoint| {
            let (transaction, _) = self
                .commit_collection_transaction(
                    context.collection(),
                    &mut collection,
                    WalEntry::ProtectedBatch {
                        batch: crate::security::ProtectedBatch {
                            version: crate::security::SECURITY_VERSION,
                            security: crate::security::SecurityDelta {
                                incarnation: checkpoint.incarnation,
                                expected_revision: update.expected_revision,
                                revision: checkpoint.revision,
                                expected_generation: generation,
                                generation: checkpoint.data_generation,
                                policy: Some(checkpoint.policy.clone()),
                                bindings: Vec::new(),
                            },
                            content: crate::security::ProtectedContent::Policy,
                        },
                    },
                    TransactionAudit::new(
                        "security",
                        "policy.replace",
                        Some(context.collection()),
                        &audit_context,
                        audit_details.clone(),
                    ),
                )
                .map_err(|error| {
                    self.mark_durability_degraded("security_policy_commit", &error);
                    SecurityError::Unavailable
                })?;
            committed_transaction = Some(transaction);
            Ok(())
        })?;
        if let Some(transaction) = &committed_transaction {
            self.project_transaction_audit(transaction);
        }
        Ok(revision)
    }

    pub fn bind_access(
        &self,
        identity: &AuthenticatedIdentity,
        collection: &str,
        tenant: &str,
        action: Action,
    ) -> Result<AccessContext> {
        if !self
            .identity_authority
            .as_ref()
            .is_some_and(|authority| authority.accepts(identity))
        {
            return Err(SecurityError::Unauthenticated.into());
        }
        let identity = self.management_identity(identity)?;
        if !identity.allows(tenant, collection, action) {
            return Err(SecurityError::Forbidden.into());
        }
        let collection = self
            .inner
            .read()
            .collections
            .get(collection)
            .cloned()
            .ok_or(SecurityError::NotFound)?;
        let collection = collection.read();
        collection
            .security
            .as_ref()
            .ok_or(SecurityError::Forbidden)?
            .bind(&identity, tenant, action)
            .map_err(Into::into)
    }

    pub(super) fn get_coll_authorized(
        &self,
        context: &AccessContext,
    ) -> Result<Arc<RwLock<Collection>>> {
        if !self
            .identity_authority
            .as_ref()
            .is_some_and(|authority| authority.accepts(context.identity()))
        {
            return Err(SecurityError::Unauthenticated.into());
        }
        let collection = self
            .inner
            .read()
            .collections
            .get(context.collection())
            .cloned()
            .ok_or(SecurityError::NotFound)?;
        if !collection
            .read()
            .security
            .as_ref()
            .is_some_and(|authority| authority.accepts(context))
        {
            return Err(SecurityError::Conflict.into());
        }
        context.publication_permit()?;
        Ok(collection)
    }

    /// Core create primitive. Transport retry/reservation APIs must bind their
    /// retry transaction before calling it; this method never accepts an ID.
    pub fn create_points_authorized(
        &self,
        context: &AccessContext,
        template: &str,
        points: Vec<NewPoint>,
        wait: bool,
    ) -> Result<AuthorizedOutput<Vec<String>>> {
        self.create_points_with_request(context, template, points, wait, None, None)
    }

    /// Atomic protected ingest with caller-chosen IDs for pgvector INSERT.
    /// A duplicate ID is rejected before the WAL or security delta is written.
    pub fn create_points_with_ids_authorized(
        &self,
        context: &AccessContext,
        template: &str,
        points: Vec<NewPoint>,
        ids: Vec<String>,
    ) -> Result<AuthorizedOutput<Vec<String>>> {
        self.create_points_with_request(context, template, points, true, Some(ids), None)
    }

    pub fn create_points_idempotent_authorized(
        &self,
        context: &AccessContext,
        request: crate::security::CreatePoints,
    ) -> Result<AuthorizedOutput<Vec<String>>> {
        if context.action() != Action::Create
            || request.idempotency_key.is_empty()
            || request.idempotency_key.len() > 128
            || !request
                .idempotency_key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
        {
            return Err(SecurityError::Invalid("invalid create request identity".into()).into());
        }
        crate::security::storage::serialized_len(&request, crate::wal::MAX_WAL_RECORD_BYTES / 2)?;
        let digest = crate::security::mutation::fingerprint(&request)?;
        let collection = self.get_coll_authorized(context)?;
        let authority = collection
            .read()
            .security
            .clone()
            .ok_or(SecurityError::Unavailable)?;
        let _request = authority
            .create_requests
            .try_lock()
            .ok_or(SecurityError::BudgetExceeded)?;
        if let Some(previous) = context.create_receipt_digest(&request.idempotency_key)? {
            if previous != digest {
                return Err(SecurityError::Conflict.into());
            }
            // Receipt IDs reveal resources. Reauthorize every one before replay,
            // including a previously successful request whose object was deleted.
            let read = self.bind_access(
                context.identity(),
                context.collection(),
                context.tenant(),
                Action::Read,
            )?;
            let resources = read.read_resources()?;
            let receipt = resources
                .create_receipt(&request.idempotency_key)?
                .ok_or(SecurityError::Unavailable)?;
            if receipt.request_digest != digest {
                return Err(SecurityError::Conflict.into());
            }
            for id in &receipt.ids {
                resources.public(id)?;
            }
            let ids = crate::security::mutation::ids(receipt.ids.iter().map(String::as_str))?;
            drop(resources);
            return Ok(crate::security::output::ids(read, ids));
        }
        self.create_points_with_request(
            context,
            &request.template,
            request.points,
            true,
            None,
            Some((request.idempotency_key, digest)),
        )
    }

    fn create_points_with_request(
        &self,
        context: &AccessContext,
        template: &str,
        points: Vec<NewPoint>,
        wait: bool,
        public_ids: Option<Vec<String>>,
        request: Option<(String, [u8; 32])>,
    ) -> Result<AuthorizedOutput<Vec<String>>> {
        if context.action() != Action::Create {
            return Err(SecurityError::Forbidden.into());
        }
        if points.is_empty() || points.len() > 1024 {
            return Err(SecurityError::BudgetExceeded.into());
        }
        self.get_coll_authorized(context)?;
        let (validation_points, _validation_admission) =
            crate::security::mutation::PointCopies::new_points(&points, None)?.into_parts();
        let receipt = self.upsert_wait_unguarded(
            context.collection(),
            validation_points,
            wait,
            MutationContext {
                audit: audit::AuditContext {
                    principal_id: context.principal_id().into(),
                    tenant_id: Some(context.tenant().into()),
                    transport: "protected".into(),
                    request_id: None,
                },
                origin: MutationOrigin::Client,
                scope: None,
                protected_update: None,
                protected_delete: None,
                protected_filter: None,
                protected_create: Some(ProtectedCreate {
                    context: context.clone(),
                    template: template.into(),
                    points,
                    public_ids,
                    request,
                }),
            },
            None,
            None,
        )?;
        Ok(crate::security::output::ids(
            context.clone(),
            receipt.created_ids,
        ))
    }

    pub fn update_points_authorized(
        &self,
        context: &AccessContext,
        points: Vec<Point>,
        wait: bool,
    ) -> Result<AuthorizedOutput<usize>> {
        if context.action() != Action::Update {
            return Err(SecurityError::Forbidden.into());
        }
        if points.is_empty() || points.len() > 1024 {
            return Err(SecurityError::BudgetExceeded.into());
        }
        let count = points.len();
        self.upsert_wait_unguarded(
            context.collection(),
            points,
            wait,
            MutationContext {
                audit: audit::AuditContext {
                    principal_id: context.principal_id().into(),
                    tenant_id: Some(context.tenant().into()),
                    transport: "protected".into(),
                    request_id: None,
                },
                origin: MutationOrigin::Client,
                scope: None,
                protected_create: None,
                protected_update: Some(context.clone()),
                protected_delete: None,
                protected_filter: None,
            },
            None,
            None,
        )?;
        Ok(AuthorizedOutput::new(context.clone(), count))
    }

    pub fn delete_points_authorized(
        &self,
        context: &AccessContext,
        ids: &[String],
    ) -> Result<AuthorizedOutput<usize>> {
        if context.action() != Action::Delete {
            return Err(SecurityError::Forbidden.into());
        }
        if ids.is_empty() || ids.len() > 1024 {
            return Err(SecurityError::BudgetExceeded.into());
        }
        self.delete_authorized(context, ids, None)
    }

    pub fn delete_filter_authorized(
        &self,
        context: &AccessContext,
        filter: Filter,
    ) -> Result<AuthorizedOutput<usize>> {
        if context.action() != Action::Delete {
            return Err(SecurityError::Forbidden.into());
        }
        self.delete_authorized(
            context,
            &[],
            Some(crate::security::SecurityFilter::compile(filter)?),
        )
    }

    pub(super) fn select_delete_ids_locked(
        collection: &Collection,
        context: &AccessContext,
        filter: &crate::security::SecurityFilter,
        shutdown: &AtomicBool,
    ) -> Result<crate::search::AdmittedVec<String>> {
        let budget = security_retrieval::ReadBudget::new(context, None, None, shutdown);
        let mut ids = crate::search::AdmittedVec::<String>::default();
        let resources = context.read_resources()?;
        resources.for_each_authorized(
            || Ok(budget.check()?),
            |record| {
                budget.check()?;
                let mut storage = [0; 36];
                let point = collection
                    .resolve_candidate(record.storage_name(&mut storage))?
                    .ok_or(SecurityError::Unavailable)?;
                if record.matches_filter(filter, &point.payload)? {
                    if ids.len() >= 1024 {
                        return Err(SecurityError::BudgetExceeded.into());
                    }
                    ids.copy_push(record.id())?;
                }
                Ok(())
            },
        )?;
        Ok(ids)
    }

    fn delete_authorized(
        &self,
        context: &AccessContext,
        ids: &[String],
        filter: Option<crate::security::SecurityFilter>,
    ) -> Result<AuthorizedOutput<usize>> {
        let count = self.delete_unguarded(
            context.collection(),
            ids,
            false,
            MutationContext {
                audit: audit::AuditContext {
                    principal_id: context.principal_id().into(),
                    tenant_id: Some(context.tenant().into()),
                    transport: "protected".into(),
                    request_id: None,
                },
                origin: MutationOrigin::Client,
                scope: None,
                protected_create: None,
                protected_update: None,
                protected_delete: Some(context.clone()),
                protected_filter: filter,
            },
        )?;
        let fresh = self.bind_access(
            context.identity(),
            context.collection(),
            context.tenant(),
            Action::Delete,
        )?;
        Ok(AuthorizedOutput::new(fresh, count))
    }

    pub fn get_points_authorized(
        &self,
        context: &AccessContext,
        ids: &[String],
    ) -> Result<AuthorizedOutput<Vec<Point>>> {
        if context.action() != Action::Read {
            return Err(SecurityError::Forbidden.into());
        }
        if ids.len() > 1024 || ids.iter().any(|id| id.len() > MAX_POINT_ID_BYTES) {
            return Err(SecurityError::BudgetExceeded.into());
        }
        let budget = security_retrieval::ReadBudget::new(
            context,
            None,
            None,
            self.build_lifecycle.cancellation(),
        );
        let _lifecycle = self.lifecycle_gate.read();
        let _admission = self.maintenance_barrier.read();
        budget.check()?;
        self.ensure_collection_cold_materialized_authorized(context)?;
        let collection = self.get_coll_authorized(context)?;
        let collection = collection.read();
        let _lease = context.publication_permit()?;
        let resources = context.read_resources()?;
        let mut result = crate::security::output::Points::default();
        let mut output_bytes = 0usize;
        for id in ids {
            budget.check()?;
            let record = match resources.public(id) {
                Ok(record) => record,
                Err(GaussError::Security(SecurityError::NotFound)) => continue,
                Err(error) => return Err(error),
            };
            let mut storage = [0; 36];
            let point = collection
                .resolve_candidate(record.storage_name(&mut storage))?
                .ok_or(SecurityError::Unavailable)?;
            let point = result.push(record.project_point(&point)?)?;
            output_bytes = output_bytes
                .checked_add(crate::security::storage::serialized_len(
                    point,
                    8 * 1024 * 1024 - output_bytes,
                )?)
                .ok_or(SecurityError::BudgetExceeded)?;
        }
        budget.check()?;
        Ok(result.finish(context.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::*;
    use std::collections::{BTreeMap, BTreeSet};
    use uuid::Uuid;

    mod graph_filters {
        use super::*;
        include!("security_graph_filter_tests.rs");
    }

    mod text {
        use super::*;
        include!("security_text_tests.rs");
    }

    fn fixture(graph: bool) -> (tempfile::TempDir, Db, String, String) {
        let directory = tempfile::tempdir().unwrap();
        crate::storage_layout::initialize_empty(directory.path()).unwrap();
        let db = Db::open(directory.path()).unwrap();
        db.create_collection(
            serde_json::from_value(serde_json::json!({"name":"docs","vector_dim":2})).unwrap(),
        )
        .unwrap();
        let root = db.inner.read().root.clone();
        drop(db);
        let incarnation = Uuid::new_v4();
        let policy = CollectionPolicy {
            department_actions: BTreeSet::new(),
            owner_actions: BTreeSet::from([
                Action::Read,
                Action::Search,
                Action::Update,
                Action::Delete,
                Action::GraphRead,
                Action::GraphWrite,
            ]),
            templates: BTreeMap::from([(
                "standard".into(),
                IngestTemplate {
                    department: "Finance".into(),
                    classification: Classification::Internal,
                    properties: BTreeMap::from([(
                        "/text".into(),
                        PropertyRule {
                            classification: Classification::Internal,
                            actions: BTreeSet::from([
                                PropertyAction::Read,
                                PropertyAction::Query,
                                PropertyAction::Write,
                            ]),
                        },
                    )]),
                    representations: BTreeMap::from([(
                        "dense".into(),
                        Representation {
                            source_fields: BTreeSet::from(["/text".into()]),
                            classification: Classification::Internal,
                        },
                    )]),
                },
            )]),
        };
        crate::security::storage::write(
            &root.join("collections/docs"),
            &crate::security::storage::StoredSecurity {
                wal_watermark: 0,
                authority: SecurityCheckpoint {
                    version: 1,
                    collection: "docs".into(),
                    incarnation,
                    revision: 1,
                    data_generation: 1,
                    policy,
                    resources: Vec::new(),
                },
            },
        )
        .unwrap();
        let mut catalog = read_catalog(&root).unwrap();
        catalog.protected.insert("docs".into(), incarnation);
        let bytes = crate::security::storage::encode_metadata(
            PROTECTED_CATALOG_MAGIC,
            &serde_json::to_vec(&catalog).unwrap(),
        );
        crate::encryption::atomic_write_persistent(
            &root.join(CATALOG_FILE),
            crate::encryption::FileType::Metadata,
            &bytes,
        )
        .unwrap();
        if graph {
            let mut wal = Wal::open(&root.join("collections/docs/wal")).unwrap();
            wal.append(&WalEntry::ProtectedBatch {
                batch: ProtectedBatch {
                    version: 1,
                    security: SecurityDelta {
                        incarnation,
                        expected_revision: 1,
                        revision: 1,
                        expected_generation: 1,
                        generation: 2,
                        policy: None,
                        bindings: Vec::new(),
                    },
                    content: ProtectedContent::GraphLifecycle {
                        epoch: crate::graph::GraphEpoch::INITIAL,
                        enabled: true,
                    },
                },
            })
            .unwrap();
            wal.append(&WalEntry::ProtectedBatch {
                batch: ProtectedBatch {
                    version: 1,
                    security: SecurityDelta {
                        incarnation,
                        expected_revision: 1,
                        revision: 1,
                        expected_generation: 2,
                        generation: 3,
                        policy: None,
                        bindings: Vec::new(),
                    },
                    content: ProtectedContent::Graph {
                        batch: crate::wal::GraphBatch {
                            graph_epoch: crate::graph::GraphEpoch::INITIAL,
                            type_configurations: vec![crate::wal::GraphTypeConfiguration {
                                type_id: crate::graph::TypeId::from_raw(1),
                                name: "cites".into(),
                                weight_property: None,
                            }],
                            ..crate::wal::GraphBatch::default()
                        },
                    },
                },
            })
            .unwrap();
        }
        let mut admin = PrincipalRecord {
            id: "writer".into(),
            tenant: "acme".into(),
            enabled: true,
            attributes: SubjectAttributes {
                department: "Finance".into(),
                clearance: Classification::Confidential,
            },
            grants: vec![ScopeGrant {
                tenants: BTreeSet::from(["acme".into()]),
                collections: BTreeSet::from(["docs".into()]),
                actions: BTreeSet::from([
                    Action::Read,
                    Action::Create,
                    Action::Ingest,
                    Action::Update,
                    Action::Delete,
                    Action::Search,
                    Action::GraphRead,
                    Action::GraphWrite,
                    Action::Schema,
                    Action::PolicyManage,
                    Action::LabelsManage,
                    Action::GrantsManage,
                ]),
            }],
            installation_actions: BTreeSet::from([
                Action::IdentityManage,
                Action::PolicyManage,
                Action::LabelsManage,
                Action::GrantsManage,
                Action::Schema,
            ]),
            delegation: Vec::new(),
        };
        admin.delegation = admin.grants.clone();
        let key = IdentityAuthority::bootstrap(directory.path(), admin.clone()).unwrap();
        let authority = IdentityAuthority::open(directory.path()).unwrap().unwrap();
        let mut hidden = admin;
        hidden.id = "other-reader".into();
        hidden.installation_actions.clear();
        hidden.delegation.clear();
        hidden.grants[0].actions = BTreeSet::from([
            Action::Read,
            Action::Create,
            Action::Ingest,
            Action::Update,
            Action::Delete,
            Action::GraphRead,
            Action::GraphWrite,
        ]);
        let actor = authority.authenticate(&key.secret).unwrap();
        authority.put_principal(&actor, 1, hidden).unwrap();
        let actor = authority.authenticate(&key.secret).unwrap();
        let reader = authority
            .issue_credential(&actor, 2, "other-reader")
            .unwrap();
        drop(authority);
        let db = Db::open(directory.path()).unwrap();
        (directory, db, key.secret, reader.secret)
    }
    fn point(text: &str) -> NewPoint {
        NewPoint {
            vector: vec![1.0, 0.0],
            vectors: BTreeMap::new(),
            sparse_vector: None,
            payload: serde_json::json!({"text":text}),
        }
    }

    #[test]
    fn protected_explicit_id_create_is_atomic_and_duplicate_safe() {
        let (directory, db, key, _) = fixture(false);
        let actor = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let create = db
            .bind_access(&actor, "docs", "acme", Action::Create)
            .unwrap();
        let id = "sql-primary-key-1".to_string();
        let ids = db
            .create_points_with_ids_authorized(
                &create,
                "standard",
                vec![point("first")],
                vec![id.clone()],
            )
            .unwrap()
            .publish(|ids| ids)
            .unwrap();
        assert_eq!(ids, vec![id.clone()]);
        assert!(matches!(
            db.create_points_with_ids_authorized(
                &create,
                "standard",
                vec![point("replacement")],
                vec![id.clone()],
            ),
            Err(GaussError::DuplicateKey)
        ));
        drop(create);
        drop(actor);
        drop(db);
        let db = Db::open(directory.path()).unwrap();
        let actor = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let read = db
            .bind_access(&actor, "docs", "acme", Action::Read)
            .unwrap();
        let points = db
            .get_points_authorized(&read, &[id])
            .unwrap()
            .publish(|p| p)
            .unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].payload["text"], "first");
    }

    #[test]
    fn legacy_text_hybrid_cannot_read_protected_points_even_with_system_scope() {
        let (_directory, db, key, _) = fixture(false);
        let actor = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let create = db
            .bind_access(&actor, "docs", "acme", Action::Create)
            .unwrap();
        db.create_points_idempotent_authorized(
            &create,
            CreatePoints {
                template: "standard".into(),
                points: vec![point("confidential document")],
                idempotency_key: "text-boundary".into(),
            },
        )
        .unwrap()
        .publish(|_| ())
        .unwrap();
        let query = crate::TextHybridSearchRequest {
            vector: vec![1.0, 0.0],
            query: "confidential".into(),
            text_field: "text".into(),
            k: 10,
            filter: None,
            budget_ms: None,
        };
        assert!(matches!(
            db.text_hybrid_search_scoped("docs", query.clone(), &crate::TenantScope::system()),
            Err(GaussError::Security(SecurityError::Forbidden))
        ));
        assert!(matches!(
            db.text_hybrid_search_with_cancellation_scoped(
                "docs",
                query,
                &crate::TenantScope::system(),
                &AtomicBool::new(false),
            ),
            Err(GaussError::Security(SecurityError::Forbidden))
        ));
    }

    #[test]
    fn protected_idempotent_create_is_durable_private_and_never_recreates_tombstones() {
        for graph in [false, true] {
            let (directory, db, key, other_key) = fixture(graph);
            let actor = db.identity_authority().unwrap().authenticate(&key).unwrap();
            let create = db
                .bind_access(&actor, "docs", "acme", Action::Create)
                .unwrap();
            let request = CreatePoints {
                template: "standard".into(),
                points: vec![point("one"), point("two")],
                idempotency_key: "retry-1".into(),
            };
            // Losing the response does not lose the transaction's receipt.
            drop(
                db.create_points_idempotent_authorized(&create, request.clone())
                    .unwrap(),
            );
            let ids = db
                .create_points_idempotent_authorized(&create, request.clone())
                .unwrap()
                .publish(|ids| ids)
                .unwrap();
            let other = db
                .identity_authority()
                .unwrap()
                .authenticate(&other_key)
                .unwrap();
            let other_create = db
                .bind_access(&other, "docs", "acme", Action::Create)
                .unwrap();
            let other_ids = db
                .create_points_idempotent_authorized(&other_create, request.clone())
                .unwrap()
                .publish(|ids| ids)
                .unwrap();
            assert!(
                other_ids.iter().all(|id| !ids.contains(id)),
                "retry namespace is principal-bound"
            );
            let mut conflict = request.clone();
            conflict.points[0].payload = serde_json::json!({"text":"different"});
            assert!(matches!(
                db.create_points_idempotent_authorized(&create, conflict),
                Err(GaussError::Security(SecurityError::Conflict))
            ));
            drop(db);
            let db = Db::open(directory.path()).unwrap();
            let actor = db.identity_authority().unwrap().authenticate(&key).unwrap();
            let create = db
                .bind_access(&actor, "docs", "acme", Action::Create)
                .unwrap();
            assert_eq!(
                db.create_points_idempotent_authorized(&create, request.clone())
                    .unwrap()
                    .publish(|ids| ids)
                    .unwrap(),
                ids
            );
            let delete = db
                .bind_access(&actor, "docs", "acme", Action::Delete)
                .unwrap();
            db.delete_points_authorized(&delete, &ids)
                .unwrap()
                .publish(|_| ())
                .unwrap();
            assert!(
                db.create_points_idempotent_authorized(&create, request.clone())
                    .is_err()
            );
            drop(db);
            let db = Db::open(directory.path()).unwrap();
            let actor = db.identity_authority().unwrap().authenticate(&key).unwrap();
            let create = db
                .bind_access(&actor, "docs", "acme", Action::Create)
                .unwrap();
            assert!(
                db.create_points_idempotent_authorized(&create, request)
                    .is_err()
            );
        }
    }

    #[test]
    fn protected_create_get_and_recovery_use_the_shared_dense_and_graph_engines() {
        for graph in [false, true] {
            let (directory, db, key, reader_key) = fixture(graph);
            db.validate_protected_admission().unwrap();
            let authority = db.identity_authority().unwrap();
            let actor = authority.authenticate(&key).unwrap();
            let create = db
                .bind_access(&actor, "docs", "acme", Action::Create)
                .unwrap();
            let before = db.inner.read().collections["docs"]
                .read()
                .wal
                .len()
                .unwrap();
            let mut invalid = point("bad");
            invalid.vector = vec![1.0];
            assert!(
                db.create_points_authorized(
                    &create,
                    "standard",
                    vec![point("valid"), invalid],
                    true
                )
                .is_err()
            );
            assert_eq!(
                db.inner.read().collections["docs"]
                    .read()
                    .wal
                    .len()
                    .unwrap(),
                before
            );
            let ids = db
                .create_points_authorized(
                    &create,
                    "standard",
                    vec![point("one"), point("two")],
                    true,
                )
                .unwrap()
                .publish(|ids| ids)
                .unwrap();
            assert_eq!(ids.len(), 2);
            assert_ne!(ids[0], ids[1]);
            let read = db
                .bind_access(&actor, "docs", "acme", Action::Read)
                .unwrap();
            let points = db
                .get_points_authorized(&read, &ids)
                .unwrap()
                .publish(|points| points)
                .unwrap();
            assert_eq!(
                points
                    .iter()
                    .map(|point| point.id.clone())
                    .collect::<Vec<_>>(),
                ids
            );
            assert_eq!(points[0].payload, serde_json::json!({"text":"one"}));
            assert_eq!(points[0].vector, vec![1.0, 0.0]);
            let reader = authority.authenticate(&reader_key).unwrap();
            let hidden = db
                .bind_access(&reader, "docs", "acme", Action::Read)
                .unwrap();
            assert!(
                db.get_points_authorized(&hidden, &ids)
                    .unwrap()
                    .publish(|points| points.is_empty())
                    .unwrap()
            );
            assert!(db.get_points("docs", &ids).is_err());
            assert!(
                db.get_points_scoped("docs", &ids, &crate::tenant::TenantScope::system())
                    .is_err()
            );
            assert!(db.list_collections().is_empty());
            assert!(db.collection_wal_dir("docs").is_none());
            assert!(db.snapshot(directory.path().join("export")).is_err());
            let queued = db.get_points_authorized(&read, &ids).unwrap();
            drop(db);
            assert!(queued.publish(|_| ()).is_err());
            let reopened = Db::open(directory.path()).unwrap();
            let actor = reopened
                .identity_authority()
                .unwrap()
                .authenticate(&key)
                .unwrap();
            let read = reopened
                .bind_access(&actor, "docs", "acme", Action::Read)
                .unwrap();
            assert_eq!(
                reopened
                    .get_points_authorized(&read, &ids)
                    .unwrap()
                    .publish(|points| points.len())
                    .unwrap(),
                2
            );
        }
    }

    #[test]
    fn protected_graph_schema_rechecks_revision_and_audits_actor() {
        let (directory, db, key, reader_key) = fixture(false);
        let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let reader = db
            .identity_authority()
            .unwrap()
            .authenticate(&reader_key)
            .unwrap();
        assert!(
            db.bind_access(&reader, "docs", "acme", Action::Schema)
                .is_err()
        );
        let before = db
            .bind_access(&identity, "docs", "acme", Action::Read)
            .unwrap();
        let context = db
            .bind_access(&identity, "docs", "acme", Action::Schema)
            .unwrap();
        assert!(db.set_graph_lifecycle_authorized(&before, 1, true).is_err());
        let (revision, enabled) = db
            .set_graph_lifecycle_authorized(&context, 1, true)
            .unwrap()
            .publish(|result| result)
            .unwrap();
        assert_eq!(revision, 2);
        assert!(enabled.transitioned);
        assert!(before.publication_permit().is_err());
        assert!(
            db.set_graph_lifecycle_authorized(&context, 1, true)
                .is_err()
        );
        let context = db
            .bind_access(&identity, "docs", "acme", Action::Schema)
            .unwrap();
        let request = crate::graph::ConfigureEdgeTypeRequest {
            name: "cites".into(),
            weight_property: None,
        };
        let (revision, configured) = db
            .configure_edge_type_authorized(&context, 2, request.clone())
            .unwrap()
            .publish(|result| result)
            .unwrap();
        assert_eq!(revision, 3);
        assert!(configured.changed);
        let context = db
            .bind_access(&identity, "docs", "acme", Action::Schema)
            .unwrap();
        let (revision, configured) = db
            .configure_edge_type_authorized(&context, 3, request)
            .unwrap()
            .publish(|result| result)
            .unwrap();
        assert_eq!(revision, 3);
        assert!(!configured.changed);
        let records = crate::audit::records_for_test(directory.path()).unwrap();
        let events: Vec<_> = records
            .iter()
            .filter(|row| row["transport"] == "protected-graph-schema")
            .collect();
        assert_eq!(events.len(), 2);
        for event in events {
            assert_eq!(event["principal_id"], identity.principal().id);
            assert_eq!(event["tenant_id"], "acme");
            assert_eq!(event["outcome"], "success");
        }
        let (revision, disabled) = db
            .set_graph_lifecycle_authorized(&context, 3, false)
            .unwrap()
            .publish(|result| result)
            .unwrap();
        assert_eq!(revision, 4);
        assert!(disabled.transitioned && !disabled.enabled);
        drop(db);
        let db = Db::open(directory.path()).unwrap();
        let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let context = db
            .bind_access(&identity, "docs", "acme", Action::Schema)
            .unwrap();
        assert_eq!(context.policy_revision(), 4);
        let (_, result) = db
            .set_graph_lifecycle_authorized(&context, 4, false)
            .unwrap()
            .publish(|result| result)
            .unwrap();
        assert!(!result.transitioned);
    }

    #[test]
    fn protected_atomic_insert_allocates_binds_retries_and_reopens() {
        use crate::{
            MultiModelInsertRequest, NewRecord, NewRelation, RecordEndpoint, RecordRef,
            RelationalValue, SqlExecutionRequest, SqlResult, SqlStatementRequest,
        };
        let (directory, db, key, _) = fixture(true);
        let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let sql = |text: &str| SqlExecutionRequest {
            statements: vec![SqlStatementRequest {
                sql: text.into(),
                parameters: vec![],
            }],
            idempotency_key: None,
            retry_id: None,
        };
        db.execute_sql_authorized(&identity, sql("CREATE TABLE docs (id TEXT PRIMARY KEY, chunk RECORD_REF('docs') NOT NULL, source RECORD_REF('docs') NOT NULL)"), "test").unwrap();
        let mut request = MultiModelInsertRequest {
            sql: sql(
                "INSERT INTO docs VALUES ('row', RECORD_REF('docs', NEW_RECORD('chunk')), RECORD_REF('docs', NEW_RECORD('source'))) RETURNING chunk, source",
            ),
            collection: "docs".into(),
            template: "standard".into(),
            records: vec![
                NewRecord {
                    binding: "chunk".into(),
                    point: point("chunk"),
                },
                NewRecord {
                    binding: "source".into(),
                    point: point("source"),
                },
            ],
            relations: vec![NewRelation {
                source: RecordEndpoint::New("chunk".into()),
                target: RecordEndpoint::New("source".into()),
                edge_type: "cites".into(),
                properties: serde_json::json!({"kind":"source"}),
            }],
        };
        request.sql.idempotency_key = Some("atomic-ingest".into());
        db.set_max_points_per_collection(Some(1));
        assert!(matches!(
            db.insert_multimodel_authorized(&identity, request.clone(), "quota"),
            Err(GaussError::ResourceExhausted(_))
        ));
        db.set_max_points_per_collection(None);
        for failure in [
            "unknown-binding",
            "orphan-reference",
            "duplicate-binding",
            "invalid-vector",
        ] {
            let mut invalid = request.clone();
            match failure {
                "unknown-binding" => {
                    invalid.sql.statements[0].sql = invalid.sql.statements[0]
                        .sql
                        .replace("NEW_RECORD('source')", "NEW_RECORD('missing')")
                }
                "orphan-reference" => {
                    invalid.sql.statements[0].sql = invalid.sql.statements[0]
                        .sql
                        .replace("NEW_RECORD('source')", "'missing'")
                }
                "duplicate-binding" => invalid.records[1].binding = "chunk".into(),
                _ => invalid.records[0].point.vector = vec![1.0],
            }
            assert!(
                db.insert_multimodel_authorized(&identity, invalid, "invalid")
                    .is_err(),
                "{failure}"
            );
            assert!(
                db.bind_access(&identity, "docs", "acme", Action::Read)
                    .unwrap()
                    .publication_permit()
                    .is_ok(),
                "validation poisoned authority: {failure}"
            );
            assert!(
                db.inner.read().collections["docs"]
                    .read()
                    .security
                    .as_ref()
                    .unwrap()
                    .checkpoint()
                    .resources
                    .is_empty(),
                "{failure}"
            );
            let rows = db
                .execute_sql_authorized(&identity, sql("SELECT id FROM docs"), "test")
                .unwrap();
            assert!(matches!(&rows.results[0], SqlResult::Rows { rows, .. } if rows.is_empty()));
        }
        let barrier = std::sync::Barrier::new(8);
        let results = std::thread::scope(|scope| {
            let handles = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        db.insert_multimodel_authorized(&identity, request.clone(), "race")
                            .unwrap()
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|r| !r.graph.replayed).count(), 1);
        let first = &results[0];
        assert_eq!(first.records.len(), 2);
        assert_eq!(first.edge_ids.len(), 1);
        for response in &results {
            assert_eq!(response.sql, first.sql);
            assert_eq!(response.records, first.records);
            assert_eq!(response.edge_ids, first.edge_ids);
            response
                .publication_context()
                .unwrap()
                .publication_permit()
                .unwrap();
        }
        let read = db
            .bind_access(&identity, "docs", "acme", Action::Read)
            .unwrap();
        let chunk = first.records["chunk"].clone();
        let source = first.records["source"].clone();
        for record in [&chunk, &source] {
            assert_eq!(record.namespace, "docs");
            let public = Uuid::parse_str(&record.id).unwrap();
            assert_ne!(read.authorize(&record.id).unwrap().storage_id, public);
        }
        assert!(
            matches!(&first.sql.results[0], SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::RecordRef(chunk.clone()), RelationalValue::RecordRef(source.clone())]])
        );
        let stored = db
            .get_points_authorized(&read, &[chunk.id.clone(), source.id.clone()])
            .unwrap()
            .publish(|points| points)
            .unwrap();
        assert_eq!(stored.len(), 2);
        let mut conflict = request.clone();
        conflict.records[0].point.payload = serde_json::json!({"text":"changed"});
        assert!(
            db.insert_multimodel_authorized(&identity, conflict, "conflict")
                .is_err()
        );
        // Existing SQL references are validated even when supplied through typed parameters.
        let mut existing = request.clone();
        existing.sql.idempotency_key = Some("existing-reference".into());
        existing.sql.statements[0].sql =
            "INSERT INTO docs VALUES ('row2', $1, RECORD_REF('docs', NEW_RECORD('source')))".into();
        existing.sql.statements[0].parameters = vec![RelationalValue::RecordRef(RecordRef {
            namespace: "docs".into(),
            id: chunk.id.clone(),
        })];
        let second = db
            .insert_multimodel_authorized(&identity, existing, "existing")
            .unwrap();
        assert_ne!(second.records, first.records);
        let transaction_id = first.sql.transaction_id.clone();
        let records = first.records.clone();
        drop(db);
        let db = Db::open(directory.path()).unwrap();
        let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let replay = db
            .insert_multimodel_authorized(&identity, request.clone(), "reopen")
            .unwrap();
        assert_eq!(replay.sql.transaction_id, transaction_id);
        assert_eq!(replay.records, records);
        assert!(replay.graph.replayed);
        replace_permissions(
            &db,
            &identity,
            &source.id,
            vec![ObjectGrant {
                subject: Subject::Owner,
                actions: BTreeSet::from([Action::Read]),
                effect: Effect::Deny,
                inherit: false,
            }],
            None,
        )
        .unwrap();
        assert!(
            replay
                .publication_context()
                .unwrap()
                .publication_permit()
                .is_err()
        );
        assert!(
            db.insert_multimodel_authorized(&identity, request, "revoked")
                .is_err()
        );
    }

    #[test]
    fn protected_atomic_updates_validate_new_references_and_retirement_before_decision() {
        let (directory, db, key, reader_key) = fixture(true);
        let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let other = db
            .identity_authority()
            .unwrap()
            .authenticate(&reader_key)
            .unwrap();
        let create = db
            .bind_access(&identity, "docs", "acme", Action::Create)
            .unwrap();
        let ids = db
            .create_points_authorized(
                &create,
                "standard",
                vec![point("original"), point("replacement")],
                true,
            )
            .unwrap()
            .publish(|ids| ids)
            .unwrap();
        let hidden = db
            .create_points_authorized(
                &db.bind_access(&other, "docs", "acme", Action::Create)
                    .unwrap(),
                "standard",
                vec![point("hidden")],
                true,
            )
            .unwrap()
            .publish(|ids| ids)
            .unwrap();
        let sql = |text: String| crate::SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql: text,
                parameters: vec![],
            }],
            idempotency_key: None,
            retry_id: None,
        };
        db.execute_sql_authorized(
            &identity,
            sql("CREATE TABLE docs (id TEXT PRIMARY KEY, target RECORD_REF('docs'))".into()),
            "setup",
        )
        .unwrap();
        db.execute_sql_authorized(
            &identity,
            sql(format!(
                "INSERT INTO docs VALUES ('row',RECORD_REF('docs','{}')),('other',NULL)",
                ids[0]
            )),
            "setup",
        )
        .unwrap();
        let request = |statement: String, key: &str| MultiModelTransactionRequest {
            sql: crate::SqlExecutionRequest {
                idempotency_key: Some(key.into()),
                ..sql(statement)
            },
            collection: "docs".into(),
            points: vec![physical_point(&point("changed"), ids[0].clone())],
            point_deletes: vec![],
            relations: vec![],
            edge_deletes: vec![],
            edge_updates: vec![],
        };
        let execute = |db: &Db,
                       identity: &crate::security::AuthenticatedIdentity,
                       request: MultiModelTransactionRequest,
                       action: Action| {
            let vector = db.bind_access(identity, "docs", "acme", action).unwrap();
            let graph = db
                .bind_access(identity, "docs", "acme", Action::GraphWrite)
                .unwrap();
            let expected = request.sql.statements.len() as u64;
            db.execute_multimodel_transaction_authorized_with_sql_rows(
                identity,
                &vector,
                &graph,
                request,
                "reference-test",
                Some(expected),
            )
        };
        for (name, reference) in [
            ("missing", "RECORD_REF('docs','missing')".to_string()),
            ("hidden", format!("RECORD_REF('docs','{}')", hidden[0])),
            ("foreign", format!("RECORD_REF('foreign','{}')", ids[1])),
        ] {
            let invalid = request(
                format!("UPDATE docs SET target={reference} WHERE id='row'"),
                name,
            );
            assert!(
                execute(&db, &identity, invalid, Action::Update).is_err(),
                "{name}"
            );
            let current = db
                .execute_sql_authorized(
                    &identity,
                    sql("SELECT target FROM docs WHERE id='row'".into()),
                    "check",
                )
                .unwrap();
            assert!(matches!(
                &current.results[0],
                crate::SqlResult::Rows { rows, .. }
                    if rows == &vec![vec![crate::RelationalValue::RecordRef(crate::RecordRef {
                        namespace: "docs".into(), id: ids[0].clone(),
                    })]]
            ));
            let read = db
                .bind_access(&identity, "docs", "acme", Action::Read)
                .unwrap();
            let content = db
                .get_points_authorized(&read, &[ids[0].clone()])
                .unwrap()
                .publish(|points| points)
                .unwrap();
            assert_eq!(content[0].payload, point("original").payload);
        }
        // A rejected request has no durable decision or consumed key. Its key
        // can be reused for a valid request, then replays the same receipt.
        let valid = request(
            format!(
                "UPDATE docs SET target=RECORD_REF('docs','{}') WHERE id='row'",
                ids[1]
            ),
            "missing",
        );
        let first = execute(&db, &identity, valid.clone(), Action::Update).unwrap();
        let replay = execute(&db, &identity, valid.clone(), Action::Update).unwrap();
        assert_eq!(first.sql.transaction_id, replay.sql.transaction_id);
        assert!(replay.graph.replayed);
        drop(db);
        let db = Db::open(directory.path()).unwrap();
        let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let replay = execute(&db, &identity, valid.clone(), Action::Update).unwrap();
        assert_eq!(replay.sql.transaction_id, first.sql.transaction_id);
        assert!(replay.graph.replayed);

        // Deleting a referenced point is rejected even when the SQL statement
        // changes an unrelated row; removing the reference in the same atomic
        // candidate makes retirement legal.
        let mut retiring = request("DELETE FROM docs WHERE id='other'".into(), "retire");
        retiring.points.clear();
        retiring.point_deletes.push(ids[1].clone());
        assert!(matches!(
            execute(&db, &identity, retiring.clone(), Action::Delete),
            Err(GaussError::Security(SecurityError::Conflict))
        ));
        let read = db
            .bind_access(&identity, "docs", "acme", Action::Read)
            .unwrap();
        assert_eq!(
            db.get_points_authorized(&read, &[ids[1].clone()])
                .unwrap()
                .publish(|points| points.len())
                .unwrap(),
            1
        );
        retiring.sql.statements.insert(
            0,
            crate::SqlStatementRequest {
                sql: "UPDATE docs SET target=NULL WHERE id='row'".into(),
                parameters: vec![],
            },
        );
        let retired = execute(&db, &identity, retiring, Action::Delete).unwrap();
        assert!(retired.sql.committed);
        drop(db);
        let reopened = Db::open(directory.path()).unwrap();
        let identity = reopened
            .identity_authority()
            .unwrap()
            .authenticate(&key)
            .unwrap();
        // Current authority must prevent an old receipt from publishing a
        // reference to a point retired by the later transaction.
        assert!(matches!(
            execute(&reopened, &identity, valid, Action::Update),
            Err(GaussError::Security(SecurityError::NotFound))
        ));
        let rows = reopened
            .execute_sql_authorized(
                &identity,
                sql("SELECT target FROM docs WHERE id='row'".into()),
                "check",
            )
            .unwrap();
        assert!(
            matches!(&rows.results[0], crate::SqlResult::Rows { rows, .. }
            if rows == &vec![vec![crate::RelationalValue::Null]])
        );
    }

    #[test]
    fn protected_standalone_sql_references_and_point_retirement_are_consistent() {
        let (directory, db, key, reader_key) = fixture(false);
        let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let other = db
            .identity_authority()
            .unwrap()
            .authenticate(&reader_key)
            .unwrap();
        let create = db
            .bind_access(&identity, "docs", "acme", Action::Create)
            .unwrap();
        let ids = db
            .create_points_authorized(&create, "standard", vec![point("valid")], true)
            .unwrap()
            .publish(|ids| ids)
            .unwrap();
        let hidden = db
            .create_points_authorized(
                &db.bind_access(&other, "docs", "acme", Action::Create)
                    .unwrap(),
                "standard",
                vec![point("hidden")],
                true,
            )
            .unwrap()
            .publish(|ids| ids)
            .unwrap();
        let sql = |statement: String, key: Option<&str>| crate::SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql: statement,
                parameters: vec![],
            }],
            idempotency_key: key.map(str::to_owned),
            retry_id: None,
        };
        db.execute_sql_authorized(
            &identity,
            sql(
                "CREATE TABLE docs (id TEXT PRIMARY KEY, target RECORD_REF('docs'))".into(),
                None,
            ),
            "setup",
        )
        .unwrap();
        for reference in [
            "RECORD_REF('docs','missing')".to_string(),
            format!("RECORD_REF('docs','{}')", hidden[0]),
            format!("RECORD_REF('foreign','{}')", ids[0]),
        ] {
            assert!(
                db.execute_sql_authorized(
                    &identity,
                    sql(
                        format!("INSERT INTO docs VALUES ('row',{reference})"),
                        Some("retry")
                    ),
                    "test",
                )
                .is_err()
            );
        }
        let valid = sql(
            format!(
                "INSERT INTO docs VALUES ('row',RECORD_REF('docs','{}'))",
                ids[0]
            ),
            Some("retry"),
        );
        let first = db
            .execute_sql_authorized(&identity, valid.clone(), "test")
            .unwrap();
        let replay = db
            .execute_sql_authorized(&identity, valid.clone(), "test")
            .unwrap();
        assert_eq!(first.transaction_id, replay.transaction_id);
        let delete = db
            .bind_access(&identity, "docs", "acme", Action::Delete)
            .unwrap();
        assert!(matches!(
            db.delete_points_authorized(&delete, &ids),
            Err(GaussError::Security(SecurityError::Conflict))
        ));
        let read = db
            .bind_access(&identity, "docs", "acme", Action::Read)
            .unwrap();
        assert_eq!(
            db.get_points_authorized(&read, &ids)
                .unwrap()
                .publish(|points| points.len())
                .unwrap(),
            1
        );
        let interactive = db
            .begin_sql_transaction_authorized(&identity, "test")
            .unwrap();
        db.execute_sql_transaction_authorized(
            &identity,
            &interactive.handle,
            sql(
                "UPDATE docs SET target=RECORD_REF('docs','missing') WHERE id='row'".into(),
                None,
            ),
            "test",
        )
        .unwrap();
        assert!(
            db.commit_sql_transaction_authorized(&identity, &interactive.handle, "test")
                .is_err()
        );
        let current = db
            .execute_sql_authorized(
                &identity,
                sql("SELECT target FROM docs WHERE id='row'".into(), None),
                "check",
            )
            .unwrap();
        assert!(matches!(
            &current.results[0],
            crate::SqlResult::Rows { rows, .. }
                if rows == &vec![vec![crate::RelationalValue::RecordRef(crate::RecordRef {
                    namespace: "docs".into(), id: ids[0].clone(),
                })]]
        ));
        let queued = db
            .sql_reference_publication_context(&identity, &current.results)
            .unwrap()
            .expect("typed SQL reference requires a publication context");
        queued.publication_permit().unwrap();
        replace_permissions(
            &db,
            &identity,
            &ids[0],
            vec![ObjectGrant {
                subject: Subject::Owner,
                actions: BTreeSet::from([Action::Read]),
                effect: Effect::Deny,
                inherit: false,
            }],
            None,
        )
        .unwrap();
        assert!(queued.publication_permit().is_err());
        assert!(
            db.execute_sql_authorized(
                &identity,
                sql("SELECT target FROM docs WHERE id='row'".into(), None),
                "revoked-select",
            )
            .is_err()
        );
        assert!(
            db.execute_sql_authorized(&identity, valid.clone(), "revoked-replay")
                .is_err()
        );
        let interactive = db
            .begin_sql_transaction_authorized(&identity, "test")
            .unwrap();
        assert!(
            db.execute_sql_transaction_authorized(
                &identity,
                &interactive.handle,
                sql("SELECT target FROM docs WHERE id='row'".into(), None),
                "revoked-interactive-select",
            )
            .is_err()
        );
        db.rollback_sql_transaction_authorized(&identity, &interactive.handle, "test")
            .unwrap();
        db.execute_sql_authorized(
            &identity,
            sql("UPDATE docs SET target=NULL WHERE id='row'".into(), None),
            "unlink",
        )
        .unwrap();
        let delete = db
            .bind_access(&identity, "docs", "acme", Action::Delete)
            .unwrap();
        assert_eq!(
            db.delete_points_authorized(&delete, &ids)
                .unwrap()
                .publish(|deleted| deleted)
                .unwrap(),
            1
        );
        drop(db);
        let reopened = Db::open(directory.path()).unwrap();
        let identity = reopened
            .identity_authority()
            .unwrap()
            .authenticate(&key)
            .unwrap();
        let current = reopened
            .execute_sql_authorized(
                &identity,
                sql("SELECT target FROM docs WHERE id='row'".into(), None),
                "reopen",
            )
            .unwrap();
        assert!(matches!(
            &current.results[0],
            crate::SqlResult::Rows { rows, .. } if rows == &vec![vec![crate::RelationalValue::Null]]
        ));
        assert!(
            reopened
                .execute_sql_authorized(&identity, valid, "replay")
                .is_err()
        );
    }

    #[test]
    fn protected_standalone_reference_insert_races_point_retirement_without_orphans() {
        let (directory, db, key, _) = fixture(false);
        let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let sql = |statement: String| crate::SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql: statement,
                parameters: vec![],
            }],
            idempotency_key: None,
            retry_id: None,
        };
        db.execute_sql_authorized(
            &identity,
            sql("CREATE TABLE docs (id TEXT PRIMARY KEY, target RECORD_REF('docs'))".into()),
            "setup",
        )
        .unwrap();
        for iteration in 0..8 {
            let create = db
                .bind_access(&identity, "docs", "acme", Action::Create)
                .unwrap();
            let ids = db
                .create_points_authorized(
                    &create,
                    "standard",
                    vec![point(&format!("race-{iteration}"))],
                    true,
                )
                .unwrap()
                .publish(|ids| ids)
                .unwrap();
            let barrier = std::sync::Barrier::new(2);
            let (inserted, deleted) = std::thread::scope(|threads| {
                let insert = threads.spawn(|| {
                    barrier.wait();
                    db.execute_sql_authorized(
                        &identity,
                        sql(format!(
                            "INSERT INTO docs VALUES ('race-{iteration}',RECORD_REF('docs','{}'))",
                            ids[0]
                        )),
                        "race-insert",
                    )
                    .is_ok()
                });
                let delete = threads.spawn(|| {
                    barrier.wait();
                    db.bind_access(&identity, "docs", "acme", Action::Delete)
                        .and_then(|context| db.delete_points_authorized(&context, &ids))
                        .is_ok()
                });
                (insert.join().unwrap(), delete.join().unwrap())
            });
            assert_ne!(inserted, deleted, "iteration {iteration}");
            let rows = db
                .execute_sql_authorized(
                    &identity,
                    sql(format!("SELECT id FROM docs WHERE id='race-{iteration}'")),
                    "race-check",
                )
                .unwrap();
            assert!(matches!(
                &rows.results[0],
                crate::SqlResult::Rows { rows, .. } if rows.len() == usize::from(inserted)
            ));
            if inserted {
                assert!(
                    db.bind_access(&identity, "docs", "acme", Action::Read)
                        .unwrap()
                        .authorize(&ids[0])
                        .is_ok()
                );
            }
        }
        drop(db);
        let reopened = Db::open(directory.path()).unwrap();
        let identity = reopened
            .identity_authority()
            .unwrap()
            .authenticate(&key)
            .unwrap();
        let rows = reopened
            .execute_sql_authorized(&identity, sql("SELECT target FROM docs".into()), "reopen")
            .unwrap();
        let crate::SqlResult::Rows { rows, .. } = &rows.results[0] else {
            panic!("expected rows");
        };
        let read = reopened
            .bind_access(&identity, "docs", "acme", Action::Read)
            .unwrap();
        for row in rows {
            let crate::RelationalValue::RecordRef(reference) = &row[0] else {
                panic!("expected typed reference");
            };
            read.authorize(&reference.id).unwrap();
        }
    }

    #[test]
    fn protected_multimodel_sql_row_guard_handles_revision_race_and_reopen() {
        let (directory, db, key, _) = fixture(true);
        let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let sql = |text: &str| crate::SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql: text.into(),
                parameters: vec![],
            }],
            idempotency_key: None,
            retry_id: None,
        };
        for text in [
            "CREATE TABLE docs (id TEXT PRIMARY KEY, revision BIGINT NOT NULL)",
            "INSERT INTO docs VALUES ('row-1', 1)",
        ] {
            db.execute_sql_authorized(&identity, sql(text), "setup")
                .unwrap();
        }
        let create = db
            .bind_access(&identity, "docs", "acme", Action::Create)
            .unwrap();
        let ids = db
            .create_points_authorized(
                &create,
                "standard",
                vec![point("source"), point("target")],
                true,
            )
            .unwrap()
            .publish(|value| value)
            .unwrap();
        let request = |label: &str| MultiModelTransactionRequest {
            sql: crate::SqlExecutionRequest {
                idempotency_key: Some(label.into()),
                ..sql(
                    "UPDATE docs SET revision=2 WHERE id='row-1' AND revision=1 RETURNING revision",
                )
            },
            collection: "docs".into(),
            points: vec![physical_point(&point(label), ids[0].clone())],
            point_deletes: vec![],
            relations: vec![crate::graph::RelateRequest {
                source_point_id: ids[0].clone(),
                target_point_id: ids[1].clone(),
                edge_type: "cites".into(),
                properties: serde_json::json!({"winner":label}),
                scope: crate::graph::GraphRelationScope::Local,
                idempotency_key: None,
            }],
            edge_deletes: vec![],
            edge_updates: vec![],
        };
        let requests = [request("race-a"), request("race-b")];
        let barrier = std::sync::Barrier::new(2);
        let results = std::thread::scope(|threads| {
            let handles = requests
                .iter()
                .map(|request| {
                    let barrier = &barrier;
                    let db = &db;
                    let identity = &identity;
                    threads.spawn(move || {
                        let update = db
                            .bind_access(identity, "docs", "acme", Action::Update)
                            .unwrap();
                        let graph = db
                            .bind_access(identity, "docs", "acme", Action::GraphWrite)
                            .unwrap();
                        barrier.wait();
                        db.execute_multimodel_transaction_authorized_with_sql_rows(
                            identity,
                            &update,
                            &graph,
                            request.clone(),
                            "race",
                            Some(1),
                        )
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let winner = results.iter().position(Result::is_ok).unwrap();
        let receipt = results[winner].as_ref().unwrap();
        let transaction_id = receipt.sql.transaction_id.clone();
        let edge_ids = receipt.edge_ids.clone();
        assert_eq!(edge_ids.len(), 1);
        let loser = 1 - winner;
        let update = db
            .bind_access(&identity, "docs", "acme", Action::Update)
            .unwrap();
        let graph = db
            .bind_access(&identity, "docs", "acme", Action::GraphWrite)
            .unwrap();
        assert!(matches!(
            db.execute_multimodel_transaction_authorized_with_sql_rows(
                &identity,
                &update,
                &graph,
                requests[loser].clone(),
                "fresh-loser",
                Some(1),
            ),
            Err(GaussError::SqlRowPreconditionFailed {
                expected: 1,
                actual: 0
            })
        ));
        let read = db
            .bind_access(&identity, "docs", "acme", Action::Read)
            .unwrap();
        let content = db
            .get_points_authorized(&read, &ids)
            .unwrap()
            .publish(|value| value)
            .unwrap();
        assert_eq!(
            content[0].payload,
            point(if winner == 0 { "race-a" } else { "race-b" }).payload
        );
        let graph_read = db
            .bind_access(&identity, "docs", "acme", Action::GraphRead)
            .unwrap();
        let edges = db
            .traverse_query_authorized(
                &graph_read,
                serde_json::from_value(serde_json::json!({
                    "anchors":[ids[0]], "edge_types":["cites"], "returns":"edges", "limit":10,
                }))
                .unwrap(),
                &AtomicBool::new(false),
            )
            .unwrap()
            .publish(|value| value.result)
            .unwrap();
        let crate::graph::GraphTraversalRows::Edges(edges) = edges else {
            panic!("edges")
        };
        assert_eq!(edges.len(), 1);
        let sql_result = db
            .execute_sql_authorized(&identity, sql("SELECT revision FROM docs"), "check")
            .unwrap();
        let crate::SqlResult::Rows { rows, .. } = &sql_result.results[0] else {
            panic!("rows")
        };
        assert_eq!(rows[0][0], crate::RelationalValue::Integer(2));
        drop(db);
        let db = Db::open(directory.path()).unwrap();
        let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let update = db
            .bind_access(&identity, "docs", "acme", Action::Update)
            .unwrap();
        let graph = db
            .bind_access(&identity, "docs", "acme", Action::GraphWrite)
            .unwrap();
        let replay = db
            .execute_multimodel_transaction_authorized_with_sql_rows(
                &identity,
                &update,
                &graph,
                requests[winner].clone(),
                "reopen",
                Some(1),
            )
            .unwrap();
        assert!(replay.graph.replayed);
        assert_eq!(replay.sql.transaction_id, transaction_id);
        assert_eq!(replay.edge_ids, edge_ids);
        for expected in [None, Some(0), Some(2)] {
            assert!(matches!(
                db.execute_multimodel_transaction_authorized_with_sql_rows(
                    &identity,
                    &update,
                    &graph,
                    requests[winner].clone(),
                    "changed-guard",
                    expected,
                ),
                Err(GaussError::InvalidRequest(_))
            ));
        }
        // An unguarded zero-row SQL mutation preserves the legacy semantics.
        let mut unguarded = requests[loser].clone();
        unguarded.sql.idempotency_key = Some("legacy-zero-rows".into());
        let result = db
            .execute_multimodel_transaction_authorized(
                &identity,
                &update,
                &graph,
                unguarded.clone(),
                "legacy",
            )
            .unwrap();
        assert!(result.sql.committed);
        let replay = db
            .execute_multimodel_transaction_authorized_with_sql_rows(
                &identity,
                &update,
                &graph,
                unguarded,
                "legacy-replay",
                None,
            )
            .unwrap();
        assert_eq!(result.sql.transaction_id, replay.sql.transaction_id);
        assert!(replay.graph.replayed);
    }

    #[test]
    fn protected_multimodel_update_and_delete_share_authority_and_commit() {
        let (directory, db, key, _) = fixture(true);
        let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
        db.execute_sql_authorized(
            &identity,
            crate::SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: "CREATE TABLE docs (id TEXT PRIMARY KEY, title TEXT NOT NULL)".into(),
                    parameters: Vec::new(),
                }],
                idempotency_key: None,
                retry_id: None,
            },
            "test",
        )
        .unwrap();
        db.execute_sql_authorized(
            &identity,
            crate::SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: "INSERT INTO docs (id, title) VALUES ('row-1', 'before')".into(),
                    parameters: Vec::new(),
                }],
                idempotency_key: None,
                retry_id: None,
            },
            "test",
        )
        .unwrap();
        let create = db
            .bind_access(&identity, "docs", "acme", Action::Create)
            .unwrap();
        let ids = db
            .create_points_authorized(
                &create,
                "standard",
                vec![point("source"), point("target")],
                true,
            )
            .unwrap()
            .publish(|ids| ids)
            .unwrap();
        let update = db
            .bind_access(&identity, "docs", "acme", Action::Update)
            .unwrap();
        let graph_write = db
            .bind_access(&identity, "docs", "acme", Action::GraphWrite)
            .unwrap();
        let first_request = MultiModelTransactionRequest {
            sql: crate::SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: "UPDATE docs SET title = 'updated' WHERE id = 'row-1'".into(),
                    parameters: Vec::new(),
                }],
                idempotency_key: Some("protected-first".into()),
                retry_id: Some("protected-mm-update".into()),
            },
            collection: "docs".into(),
            points: vec![physical_point(&point("source-updated"), ids[0].clone())],
            point_deletes: Vec::new(),
            relations: vec![crate::graph::RelateRequest {
                source_point_id: ids[0].clone(),
                target_point_id: ids[1].clone(),
                edge_type: "cites".into(),
                properties: serde_json::json!({"state":"before"}),
                scope: crate::graph::GraphRelationScope::Local,
                idempotency_key: None,
            }],
            edge_deletes: Vec::new(),
            edge_updates: Vec::new(),
        };
        for key in [None, Some("protected-row-count-miss")] {
            let mut rejected = first_request.clone();
            rejected.sql.idempotency_key = key.map(str::to_owned);
            rejected.sql.statements[0].sql =
                "UPDATE docs SET title = 'unexpected' WHERE id = 'missing' RETURNING id".into();
            let frontier = db.multimodel_visibility_frontier().unwrap();
            assert!(matches!(
                db.execute_multimodel_transaction_authorized_with_sql_rows(
                    &identity,
                    &update,
                    &graph_write,
                    rejected,
                    "guard-miss",
                    Some(1),
                ),
                Err(GaussError::SqlRowPreconditionFailed {
                    expected: 1,
                    actual: 0
                })
            ));
            assert_eq!(db.multimodel_visibility_frontier().unwrap(), frontier);
            let read = db
                .bind_access(&identity, "docs", "acme", Action::Read)
                .unwrap();
            let points = db
                .get_points_authorized(&read, &ids)
                .unwrap()
                .publish(|value| value)
                .unwrap();
            assert_eq!(points[0].payload, point("source").payload);
            let graph_read = db
                .bind_access(&identity, "docs", "acme", Action::GraphRead)
                .unwrap();
            let nodes = db
                .traverse_authorized(
                    &graph_read,
                    serde_json::from_value(
                        serde_json::json!({"anchors":[ids[0]], "edge_types":["cites"]}),
                    )
                    .unwrap(),
                    &AtomicBool::new(false),
                )
                .unwrap()
                .publish(|value| value.nodes)
                .unwrap();
            assert_eq!(nodes.len(), 0, "rejected graph relation must be absent");
            let rows = db
                .execute_sql_authorized(
                    &identity,
                    crate::SqlExecutionRequest {
                        statements: vec![crate::SqlStatementRequest {
                            sql: "SELECT title FROM docs".into(),
                            parameters: vec![],
                        }],
                        idempotency_key: None,
                        retry_id: None,
                    },
                    "read-unchanged",
                )
                .unwrap();
            let crate::SqlResult::Rows { rows, .. } = &rows.results[0] else {
                panic!("rows")
            };
            assert_eq!(rows[0][0], crate::RelationalValue::Text("before".into()));
        }
        for key in [None, Some("protected-delete-row-count-miss")] {
            let delete = db
                .bind_access(&identity, "docs", "acme", Action::Delete)
                .unwrap();
            let graph = db
                .bind_access(&identity, "docs", "acme", Action::GraphWrite)
                .unwrap();
            let mut rejected = first_request.clone();
            rejected.sql.idempotency_key = key.map(str::to_owned);
            rejected.sql.statements[0].sql =
                "DELETE FROM docs WHERE id='missing' RETURNING id".into();
            rejected.points.clear();
            rejected.relations.clear();
            rejected.point_deletes = vec![ids[0].clone()];
            let frontier = db.multimodel_visibility_frontier().unwrap();
            assert!(matches!(
                db.execute_multimodel_transaction_authorized_with_sql_rows(
                    &identity,
                    &delete,
                    &graph,
                    rejected,
                    "delete-guard-miss",
                    Some(1),
                ),
                Err(GaussError::SqlRowPreconditionFailed {
                    expected: 1,
                    actual: 0
                })
            ));
            assert_eq!(db.multimodel_visibility_frontier().unwrap(), frontier);
            let read = db
                .bind_access(&identity, "docs", "acme", Action::Read)
                .unwrap();
            assert_eq!(
                db.count_authorized(&read, None)
                    .unwrap()
                    .publish(|value| value.count)
                    .unwrap(),
                2
            );
        }
        // A planner rejection must leave data and collection authority usable.
        for key in [None, Some("protected-invalid-update")] {
            let mut rejected = first_request.clone();
            rejected.sql.idempotency_key = key.map(str::to_owned);
            rejected.sql.statements[0].sql =
                "UPDATE docs SET title = title WHERE id = 'row-1'".into();
            assert!(
                db.execute_multimodel_transaction_authorized(
                    &identity,
                    &update,
                    &graph_write,
                    rejected,
                    "invalid-update",
                )
                .is_err()
            );
            let read = db
                .bind_access(&identity, "docs", "acme", Action::Read)
                .unwrap();
            assert_eq!(
                db.count_authorized(&read, None)
                    .unwrap()
                    .publish(|value| value.count)
                    .unwrap(),
                2
            );
        }
        for key in [None, Some("protected-invalid-delete")] {
            let delete = db
                .bind_access(&identity, "docs", "acme", Action::Delete)
                .unwrap();
            let graph = db
                .bind_access(&identity, "docs", "acme", Action::GraphWrite)
                .unwrap();
            let read = db
                .bind_access(&identity, "docs", "acme", Action::Read)
                .unwrap();
            let queued = db.count_authorized(&read, None).unwrap();
            let revision = delete.policy_revision();
            let mut rejected = first_request.clone();
            rejected.sql.idempotency_key = key.map(str::to_owned);
            rejected.sql.statements[0].sql = "DELETE FROM docs WHERE missing = 1".into();
            rejected.points.clear();
            rejected.relations.clear();
            rejected.point_deletes = vec![ids[0].clone()];
            assert!(
                db.execute_multimodel_transaction_authorized(
                    &identity,
                    &delete,
                    &graph,
                    rejected,
                    "invalid-delete",
                )
                .is_err()
            );
            // The drained epoch stays closed, while fresh requests can read
            // the original unchanged authority and resource bindings.
            assert!(queued.publish(|value| value.count).is_err());
            let read = db
                .bind_access(&identity, "docs", "acme", Action::Read)
                .unwrap();
            assert_eq!(read.policy_revision(), revision);
            assert_eq!(
                db.count_authorized(&read, None)
                    .unwrap()
                    .publish(|value| value.count)
                    .unwrap(),
                2
            );
            let points = db
                .get_points_authorized(&read, &ids)
                .unwrap()
                .publish(|points| points)
                .unwrap();
            assert_eq!(points[0].payload, point("source").payload);
        }
        let update = db
            .bind_access(&identity, "docs", "acme", Action::Update)
            .unwrap();
        let graph_write = db
            .bind_access(&identity, "docs", "acme", Action::GraphWrite)
            .unwrap();
        let first = db
            .execute_multimodel_transaction_authorized(
                &identity,
                &update,
                &graph_write,
                first_request.clone(),
                "test",
            )
            .unwrap();
        assert!(first.sql.committed);
        let replay = db
            .execute_multimodel_transaction_authorized(
                &identity,
                &update,
                &graph_write,
                first_request.clone(),
                "retry",
            )
            .unwrap();
        assert_eq!(replay.sql.transaction_id, first.sql.transaction_id);
        assert_eq!(replay.edge_ids, first.edge_ids);
        assert!(replay.graph.replayed);

        let transaction_id = first.sql.transaction_id.clone().unwrap();
        assert_eq!(
            db.transaction_status_authorized(&identity, &transaction_id)
                .unwrap()
                .state,
            crate::TransactionState::Committed
        );
        let edge = first.edge_ids[0].clone();
        let second_request = MultiModelTransactionRequest {
            sql: crate::SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: "UPDATE docs SET title = 'updated-twice' WHERE id = 'row-1'".into(),
                    parameters: Vec::new(),
                }],
                idempotency_key: Some("protected-second".into()),
                retry_id: Some("protected-mm-edge-update".into()),
            },
            collection: "docs".into(),
            points: vec![physical_point(&point("source-twice"), ids[0].clone())],
            point_deletes: Vec::new(),
            relations: Vec::new(),
            edge_deletes: Vec::new(),
            edge_updates: vec![(
                edge.clone(),
                crate::graph::UpdateEdgeRequest {
                    mode: crate::graph::EdgePropertyMode::Replace,
                    properties: serde_json::json!({"state":"after"}),
                },
            )],
        };
        let second = db
            .execute_multimodel_transaction_authorized(
                &identity,
                &update,
                &graph_write,
                second_request.clone(),
                "test",
            )
            .unwrap();
        assert!(second.sql.committed);
        let queued = db
            .execute_multimodel_transaction_authorized(
                &identity,
                &update,
                &graph_write,
                second_request.clone(),
                "retry",
            )
            .unwrap();
        replace_permissions(
            &db,
            &identity,
            &ids[1],
            vec![ObjectGrant {
                subject: Subject::Principal(identity.principal().id.clone()),
                effect: Effect::Deny,
                actions: BTreeSet::from([Action::GraphWrite]),
                inherit: false,
            }],
            None,
        )
        .unwrap();
        assert!(
            queued
                .publication_context()
                .unwrap()
                .publication_permit()
                .is_err()
        );
        let update = db
            .bind_access(&identity, "docs", "acme", Action::Update)
            .unwrap();
        let graph_write = db
            .bind_access(&identity, "docs", "acme", Action::GraphWrite)
            .unwrap();
        assert!(
            db.execute_multimodel_transaction_authorized(
                &identity,
                &update,
                &graph_write,
                second_request.clone(),
                "revoked-replay"
            )
            .is_err()
        );
        let mut forbidden = second_request.clone();
        forbidden.sql.idempotency_key = Some("new-forbidden-edge".into());
        assert!(
            db.execute_multimodel_transaction_authorized(
                &identity,
                &update,
                &graph_write,
                forbidden,
                "forbidden-token"
            )
            .is_err()
        );
        replace_permissions(&db, &identity, &ids[1], vec![], None).unwrap();
        let graph_write = db
            .bind_access(&identity, "docs", "acme", Action::GraphWrite)
            .unwrap();

        let read = db
            .bind_access(&identity, "docs", "acme", Action::Read)
            .unwrap();
        let points = db
            .get_points_authorized(&read, &[ids[0].clone()])
            .unwrap()
            .publish(|points| points)
            .unwrap();
        assert_eq!(points[0].payload["text"], "source-twice");
        let graph_read = db
            .bind_access(&identity, "docs", "acme", Action::GraphRead)
            .unwrap();
        let traversal = db
            .traverse_authorized(
                &graph_read,
                crate::graph::GraphTraverseRequest {
                    anchors: vec![ids[0].clone()],
                    edge_types: vec!["cites".into()],
                    direction: crate::graph::GraphDirection::Outgoing,
                    node_filter: None,
                    edge_filter: None,
                    budget: crate::graph::TraversalBudget {
                        max_depth: 1,
                        ..crate::graph::TraversalBudget::default()
                    },
                },
                &AtomicBool::new(false),
            )
            .unwrap()
            .publish(|result| result)
            .unwrap();
        assert!(traversal.nodes.iter().any(|node| node.point_id == ids[1]));

        let delete = db
            .bind_access(&identity, "docs", "acme", Action::Delete)
            .unwrap();
        let deleted_request = MultiModelTransactionRequest {
            sql: crate::SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: "DELETE FROM docs WHERE id = 'row-1'".into(),
                    parameters: Vec::new(),
                }],
                idempotency_key: Some("protected-deleted".into()),
                retry_id: Some("protected-mm-delete".into()),
            },
            collection: "docs".into(),
            points: Vec::new(),
            point_deletes: vec![ids[0].clone()],
            relations: Vec::new(),
            edge_deletes: vec![edge],
            edge_updates: Vec::new(),
        };
        let deleted = db
            .execute_multimodel_transaction_authorized(
                &identity,
                &delete,
                &graph_write,
                deleted_request.clone(),
                "test",
            )
            .unwrap();
        assert!(deleted.sql.committed);
        let delete = db
            .bind_access(&identity, "docs", "acme", Action::Delete)
            .unwrap();
        let graph_write = db
            .bind_access(&identity, "docs", "acme", Action::GraphWrite)
            .unwrap();
        let replay = db
            .execute_multimodel_transaction_authorized(
                &identity,
                &delete,
                &graph_write,
                deleted_request.clone(),
                "delete-retry",
            )
            .unwrap();
        assert!(replay.graph.replayed);
        assert_eq!(replay.sql.transaction_id, deleted.sql.transaction_id);
        assert!(
            delete.authorize(&ids[0]).is_err(),
            "receipt never reactivates tombstones"
        );

        let update = db
            .bind_access(&identity, "docs", "acme", Action::Update)
            .unwrap();
        assert!(
            db.execute_multimodel_transaction_authorized(
                &identity,
                &update,
                &graph_write,
                first_request,
                "update-after-delete"
            )
            .is_err(),
            "an old update receipt must not bypass later resource retirement"
        );
        let read = db
            .bind_access(&identity, "docs", "acme", Action::Read)
            .unwrap();
        assert!(
            db.get_points_authorized(&read, &[ids[0].clone()])
                .unwrap()
                .publish(|points| points.is_empty())
                .unwrap()
        );
        drop(db);
        let reopened = Db::open(directory.path()).unwrap();
        let identity = reopened
            .identity_authority()
            .unwrap()
            .authenticate(&key)
            .unwrap();
        let delete = reopened
            .bind_access(&identity, "docs", "acme", Action::Delete)
            .unwrap();
        let graph_write = reopened
            .bind_access(&identity, "docs", "acme", Action::GraphWrite)
            .unwrap();
        let replay = reopened
            .execute_multimodel_transaction_authorized(
                &identity,
                &delete,
                &graph_write,
                deleted_request,
                "reopen-delete",
            )
            .unwrap();
        assert_eq!(replay.sql.transaction_id, deleted.sql.transaction_id);
        let selected = reopened
            .execute_sql_authorized(
                &identity,
                crate::SqlExecutionRequest {
                    statements: vec![crate::SqlStatementRequest {
                        sql: "SELECT id FROM docs WHERE id = 'row-1'".into(),
                        parameters: Vec::new(),
                    }],
                    idempotency_key: None,
                    retry_id: None,
                },
                "test",
            )
            .unwrap();
        assert!(matches!(
            selected.results.as_slice(),
            [crate::SqlResult::Rows { rows, .. }] if rows.is_empty()
        ));
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn protected_multimodel_ambiguous_decision_stays_closed_until_recovery() {
        for key in [None, Some("ambiguous-update")] {
            let (directory, db, secret, _) = fixture(true);
            let identity = db
                .identity_authority()
                .unwrap()
                .authenticate(&secret)
                .unwrap();
            for sql in [
                "CREATE TABLE docs (id TEXT PRIMARY KEY, title TEXT NOT NULL)",
                "INSERT INTO docs VALUES ('row-1', 'before')",
            ] {
                db.execute_sql_authorized(
                    &identity,
                    crate::SqlExecutionRequest {
                        statements: vec![crate::SqlStatementRequest {
                            sql: sql.into(),
                            parameters: vec![],
                        }],
                        idempotency_key: None,
                        retry_id: None,
                    },
                    "setup",
                )
                .unwrap();
            }
            let create = db
                .bind_access(&identity, "docs", "acme", Action::Create)
                .unwrap();
            let ids = db
                .create_points_authorized(&create, "standard", vec![point("before")], true)
                .unwrap()
                .publish(|ids| ids)
                .unwrap();
            let update = db
                .bind_access(&identity, "docs", "acme", Action::Update)
                .unwrap();
            let graph = db
                .bind_access(&identity, "docs", "acme", Action::GraphWrite)
                .unwrap();
            let read = db
                .bind_access(&identity, "docs", "acme", Action::Read)
                .unwrap();
            let queued = db.count_authorized(&read, None).unwrap();
            let request = MultiModelTransactionRequest {
                sql: crate::SqlExecutionRequest {
                    statements: vec![crate::SqlStatementRequest {
                        sql: "UPDATE docs SET title = 'ambiguous' WHERE id = 'row-1'".into(),
                        parameters: vec![],
                    }],
                    idempotency_key: key.map(str::to_owned),
                    retry_id: None,
                },
                collection: "docs".into(),
                points: vec![physical_point(&point("ambiguous"), ids[0].clone())],
                point_deletes: vec![],
                relations: vec![],
                edge_deletes: vec![],
                edge_updates: vec![],
            };
            let result = {
                let _env = crate::failpoint::test_env(
                    "error:transaction.before_commit_fsync",
                    &directory.path().join("marker"),
                    &directory.path().join("release"),
                );
                db.execute_multimodel_transaction_authorized(
                    &identity,
                    &update,
                    &graph,
                    request.clone(),
                    "fault",
                )
            };
            let transaction_id = match result {
                Err(GaussError::CommitOutcomeUnknown { transaction_id }) => transaction_id,
                other => panic!("expected ambiguous decision, got {other:?}"),
            };
            assert!(queued.publish(|value| value.count).is_err());
            assert!(db.count_authorized(&read, None).is_err());
            drop(db);
            let db = Db::open(directory.path()).unwrap();
            let identity = db
                .identity_authority()
                .unwrap()
                .authenticate(&secret)
                .unwrap();
            assert_eq!(
                db.transaction_status_authorized(&identity, &transaction_id)
                    .unwrap()
                    .state,
                crate::transaction_journal::TransactionState::Committed
            );
            let read = db
                .bind_access(&identity, "docs", "acme", Action::Read)
                .unwrap();
            assert_eq!(
                db.get_points_authorized(&read, &ids)
                    .unwrap()
                    .publish(|points| points[0].payload.clone())
                    .unwrap(),
                point("ambiguous").payload
            );
            if key.is_some() {
                let update = db
                    .bind_access(&identity, "docs", "acme", Action::Update)
                    .unwrap();
                let graph = db
                    .bind_access(&identity, "docs", "acme", Action::GraphWrite)
                    .unwrap();
                let replay = db
                    .execute_multimodel_transaction_authorized(
                        &identity, &update, &graph, request, "retry",
                    )
                    .unwrap();
                assert!(replay.graph.replayed);
                assert_eq!(
                    replay.sql.transaction_id.as_deref(),
                    Some(transaction_id.as_str())
                );
            }
        }
    }

    #[test]
    fn protected_collection_requires_outer_authority_and_an_incompatible_catalog() {
        let (directory, db, _, _) = fixture(false);
        let root = db.inner.read().root.clone();
        drop(db);
        let bytes = crate::encryption::read_persistent(&root.join(CATALOG_FILE)).unwrap();
        assert!(
            serde_json::from_slice::<Catalog>(&bytes).is_err(),
            "legacy JSON reader must reject the protected catalog"
        );
        assert!(
            Db::open(&root).is_err(),
            "opening a generation directly must not bypass outer identity authority"
        );
        let checkpoint = root.join("collections/docs/security.checkpoint");
        let saved = std::fs::read(&checkpoint).unwrap();
        std::fs::remove_file(&checkpoint).unwrap();
        assert!(Db::open(directory.path()).is_err());
        std::fs::write(&checkpoint, saved).unwrap();
        let mut unmarked = read_catalog(&root).unwrap();
        unmarked.protected.clear();
        crate::encryption::atomic_write_persistent(
            &root.join(CATALOG_FILE),
            crate::encryption::FileType::Metadata,
            &serde_json::to_vec(&unmarked).unwrap(),
        )
        .unwrap();
        assert!(
            Db::open(directory.path()).is_err(),
            "a sidecar alone cannot silently enable a format old binaries would read"
        );
    }
    #[test]
    fn policy_revocation_drains_publication_and_survives_recovery() {
        let (directory, db, key, _) = fixture(false);
        let actor = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let create = db
            .bind_access(&actor, "docs", "acme", Action::Create)
            .unwrap();
        let ids = db
            .create_points_authorized(&create, "standard", vec![point("secret")], true)
            .unwrap()
            .publish(|ids| ids)
            .unwrap();
        let read = db
            .bind_access(&actor, "docs", "acme", Action::Read)
            .unwrap();
        let queued = db.get_points_authorized(&read, &ids).unwrap();
        let held = read.publication_permit().unwrap();
        let mut policy = db.inner.read().collections["docs"]
            .read()
            .security
            .as_ref()
            .unwrap()
            .checkpoint()
            .policy;
        policy.owner_actions.clear();
        let manage = db
            .bind_access(&actor, "docs", "acme", Action::PolicyManage)
            .unwrap();
        let changing = db.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            tx.send(changing.replace_collection_policy_authorized(
                &manage,
                RevisionUpdate {
                    expected_revision: 1,
                    value: policy,
                },
            ))
            .unwrap()
        });
        let deadline = Instant::now() + Duration::from_secs(3);
        while read.publication_permit().is_ok() {
            assert!(
                Instant::now() < deadline,
                "policy revocation did not close the old epoch"
            );
            std::thread::yield_now();
        }
        assert!(
            rx.try_recv().is_err(),
            "revoke cannot acknowledge an outstanding transport publication"
        );
        drop(held);
        assert_eq!(rx.recv_timeout(Duration::from_secs(3)).unwrap().unwrap(), 2);
        worker.join().unwrap();
        assert!(queued.publish(|_| ()).is_err());
        assert!(db.get_points_authorized(&read, &ids).is_err());
        let fresh = db
            .bind_access(&actor, "docs", "acme", Action::Read)
            .unwrap();
        assert!(
            db.get_points_authorized(&fresh, &ids)
                .unwrap()
                .publish(|points| points.is_empty())
                .unwrap()
        );
        drop(db);
        let reopened = Db::open(directory.path()).unwrap();
        let actor = reopened
            .identity_authority()
            .unwrap()
            .authenticate(&key)
            .unwrap();
        let read = reopened
            .bind_access(&actor, "docs", "acme", Action::Read)
            .unwrap();
        assert_eq!(read.policy_revision(), 2);
        assert!(
            reopened
                .get_points_authorized(&read, &ids)
                .unwrap()
                .publish(|points| points.is_empty())
                .unwrap()
        );
    }
    #[test]
    fn protected_update_authorizes_old_and_new_state_atomically() {
        for graph in [false, true] {
            let (directory, db, key, other_key) = fixture(graph);
            let writer = db.identity_authority().unwrap().authenticate(&key).unwrap();
            let other = db
                .identity_authority()
                .unwrap()
                .authenticate(&other_key)
                .unwrap();
            let create = db
                .bind_access(&writer, "docs", "acme", Action::Create)
                .unwrap();
            let other_create = db
                .bind_access(&other, "docs", "acme", Action::Create)
                .unwrap();
            let own = db
                .create_points_authorized(&create, "standard", vec![point("before")], true)
                .unwrap()
                .publish(|ids| ids[0].clone())
                .unwrap();
            let foreign = db
                .create_points_authorized(&other_create, "standard", vec![point("hidden")], true)
                .unwrap()
                .publish(|ids| ids[0].clone())
                .unwrap();
            let update = db
                .bind_access(&writer, "docs", "acme", Action::Update)
                .unwrap();
            let read = db
                .bind_access(&writer, "docs", "acme", Action::Read)
                .unwrap();
            let before = db.inner.read().collections["docs"]
                .read()
                .wal
                .len()
                .unwrap();
            let changed = physical_point(&point("after"), own.clone());
            let mixed = db.update_points_authorized(
                &update,
                vec![
                    changed.clone(),
                    physical_point(&point("takeover"), foreign.clone()),
                ],
                true,
            );
            assert!(mixed.is_err());
            assert_eq!(
                db.inner.read().collections["docs"]
                    .read()
                    .wal
                    .len()
                    .unwrap(),
                before
            );
            assert_eq!(
                db.get_points_authorized(&read, std::slice::from_ref(&own))
                    .unwrap()
                    .publish(|points| points[0].payload.clone())
                    .unwrap(),
                serde_json::json!({"text":"before"})
            );
            let foreign_error = db
                .update_points_authorized(
                    &update,
                    vec![physical_point(&point("takeover"), foreign)],
                    true,
                )
                .err()
                .unwrap()
                .to_string();
            let missing_error = db
                .update_points_authorized(
                    &update,
                    vec![physical_point(
                        &point("takeover"),
                        Uuid::new_v4().to_string(),
                    )],
                    true,
                )
                .err()
                .unwrap()
                .to_string();
            assert_eq!(foreign_error, missing_error);
            let mut spoofed = changed.clone();
            spoofed.payload["tenant_id"] = serde_json::json!("globex");
            assert!(
                db.update_points_authorized(&update, vec![spoofed], true)
                    .is_err()
            );
            let mut source_missing = changed.clone();
            source_missing.payload = serde_json::json!({});
            assert!(
                db.update_points_authorized(&update, vec![source_missing], true)
                    .is_err()
            );
            assert_eq!(
                db.update_points_authorized(&update, vec![changed], true)
                    .unwrap()
                    .publish(|count| count)
                    .unwrap(),
                1
            );
            assert_eq!(
                db.get_points_authorized(&read, std::slice::from_ref(&own))
                    .unwrap()
                    .publish(|points| points[0].payload.clone())
                    .unwrap(),
                serde_json::json!({"text":"after"})
            );
            drop(db);
            let reopened = Db::open(directory.path()).unwrap();
            let writer = reopened
                .identity_authority()
                .unwrap()
                .authenticate(&key)
                .unwrap();
            let read = reopened
                .bind_access(&writer, "docs", "acme", Action::Read)
                .unwrap();
            assert_eq!(
                reopened
                    .get_points_authorized(&read, &[own])
                    .unwrap()
                    .publish(|points| points[0].payload.clone())
                    .unwrap(),
                serde_json::json!({"text":"after"})
            );
        }
    }
    #[test]
    #[ignore = "requires CHIRONDB_OLD_BINARY built from the pre-protected source"]
    fn old_binary_rejects_protected_root_and_direct_generation() {
        use std::process::{Command, Stdio};

        fn files(
            root: &std::path::Path,
        ) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
            let mut pending = vec![root.to_path_buf()];
            let mut contents = std::collections::BTreeMap::new();
            while let Some(directory) = pending.pop() {
                for entry in std::fs::read_dir(directory).unwrap() {
                    let entry = entry.unwrap();
                    let path = entry.path();
                    let kind = std::fs::symlink_metadata(&path).unwrap().file_type();
                    assert!(!kind.is_symlink(), "protected fixture contains a symlink");
                    if kind.is_dir() {
                        pending.push(path);
                    } else if kind.is_file() {
                        contents.insert(
                            path.strip_prefix(root).unwrap().to_path_buf(),
                            std::fs::read(path).unwrap(),
                        );
                    }
                }
            }
            contents
        }

        let encrypted =
            std::env::var("CHIRONDB_DOWNGRADE_TEST_CHILD").as_deref() == Ok("encrypted");
        let keyring_file = if encrypted {
            use base64::Engine as _;
            let mut file = tempfile::NamedTempFile::new().unwrap();
            serde_json::to_writer(&mut file, &serde_json::json!({"version":1,"active_key_id":"00000000-0000-0000-0000-000000000001","keys":[{"id":"00000000-0000-0000-0000-000000000001","key_base64":base64::engine::general_purpose::STANDARD.encode([19u8;32])}]})).unwrap();
            file.as_file().sync_all().unwrap();
            crate::encryption::install_process_keyring(
                crate::encryption::Keyring::load(file.path()).unwrap(),
                false,
            )
            .unwrap();
            Some(file)
        } else {
            None
        };
        let binary = std::env::var_os("CHIRONDB_OLD_BINARY")
            .expect("provide the verified old server executable");
        let (directory, db, key, _) = fixture(false);
        let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let context = db
            .bind_access(&identity, "docs", "acme", Action::Create)
            .unwrap();
        db.create_points_authorized(&context, "standard", vec![point("protected content")], true)
            .unwrap()
            .publish(|_| ())
            .unwrap();
        let generation = db.inner.read().root.clone();
        drop(db);
        for path in [directory.path(), generation.as_path()] {
            let before = files(directory.path());
            let keyring_before = keyring_file
                .as_ref()
                .map(|file| std::fs::read(file.path()).unwrap());
            let mut command = Command::new(&binary);
            if let Some(keyring) = &keyring_file {
                command.arg("--encryption-keyring-file").arg(keyring.path());
            }
            let mut child = command
                .env_clear()
                .current_dir(directory.path())
                .args([
                    "--listen-http",
                    "127.0.0.1:0",
                    "--listen-grpc",
                    "127.0.0.1:0",
                    "--listen-wire",
                    "127.0.0.1:0",
                    "--data-dir",
                ])
                .arg(path)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut completed = false;
            while Instant::now() < deadline {
                if child.try_wait().unwrap().is_some() {
                    completed = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            if !completed {
                child.kill().unwrap();
            }
            let output = child.wait_with_output().unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                completed,
                "old server remained alive against protected data"
            );
            assert!(
                !output.status.success(),
                "old server admitted protected data"
            );
            assert!(
                stderr.contains("failed to open data dir") && stderr.contains("expected value"),
                "must fail on protected storage format, not a transport/argument error: {stderr}"
            );
            let after = files(directory.path());
            let changed = before
                .keys()
                .chain(after.keys())
                .filter(|path| before.get(*path) != after.get(*path))
                .collect::<std::collections::BTreeSet<_>>();
            // The historical reader creates its advisory lock before it can
            // parse the protected marker. A lock is not authoritative data.
            let changed_data = changed
                .iter()
                .filter(|path| {
                    !path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.ends_with(".chirondb.lock"))
                })
                .collect::<Vec<_>>();
            assert!(
                changed_data.is_empty(),
                "old server changed protected data files: {changed_data:?}"
            );
            if !changed.is_empty() {
                eprintln!("historical reader touched only advisory locks: {changed:?}");
            }
            assert!(
                keyring_file
                    .as_ref()
                    .map(|file| std::fs::read(file.path()).unwrap())
                    == keyring_before,
                "old server changed the storage keyring"
            );
        }
        let reopened = Db::open(directory.path()).unwrap();
        let identity = reopened
            .identity_authority()
            .unwrap()
            .authenticate(&key)
            .unwrap();
        let context = reopened
            .bind_access(&identity, "docs", "acme", Action::Read)
            .unwrap();
        assert_eq!(
            reopened
                .count_authorized(&context, None)
                .unwrap()
                .publish(|count| count.count)
                .unwrap(),
            1
        );
        if !encrypted {
            // The encryption keyring is process-global. Exercise encrypted
            // storage in a child so the normal unit suite cannot inherit it.
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact","db::security_runtime::tests::old_binary_rejects_protected_root_and_direct_generation","--ignored","--test-threads=1"])
                .env("CHIRONDB_DOWNGRADE_TEST_CHILD","encrypted")
                .env("CHIRONDB_OLD_BINARY",&binary).output().unwrap();
            assert!(
                output.status.success(),
                "encrypted downgrade probe failed: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn legacy_schema_validation_cannot_probe_protected_field_types() {
        let (_directory, db, key, _) = fixture(false);
        let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let create = db
            .bind_access(&identity, "docs", "acme", Action::Create)
            .unwrap();
        db.create_points_authorized(&create, "standard", vec![point("private")], true)
            .unwrap()
            .publish(|_| ())
            .unwrap();
        let before = db.inner.read().collections["docs"]
            .read()
            .wal
            .len()
            .unwrap();
        let mut errors = Vec::new();
        for kind in [PayloadType::String, PayloadType::Number, PayloadType::Bool] {
            errors.push(
                db.update_payload_schema("docs", HashMap::from([("text".into(), kind)]))
                    .unwrap_err()
                    .to_string(),
            );
        }
        assert!(
            errors.windows(2).all(|pair| pair[0] == pair[1]),
            "legacy schema probe disclosed a protected field type: {errors:?}"
        );
        assert_eq!(
            db.inner.read().collections["docs"]
                .read()
                .wal
                .len()
                .unwrap(),
            before
        );
    }

    #[test]
    fn legacy_read_rejects_before_inspecting_protected_cold_files() {
        let (_directory, db, key, _) = fixture(false);
        let remote = tempfile::tempdir().unwrap();
        db.set_cold_object_store_dir(Some(remote.path().to_path_buf()));
        let cold = db.inner.read().root.join("collections/docs/cold");
        std::fs::create_dir_all(&cold).unwrap();
        std::fs::write(
            cold.join("cold_index.gdx"),
            b"invalid secret storage metadata",
        )
        .unwrap();
        let error = db.get_points("docs", &["hidden".into()]).unwrap_err();
        assert!(
            matches!(error, GaussError::Security(SecurityError::Forbidden)),
            "legacy admission inspected protected storage before rejecting: {error}"
        );
        let actor = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let read = db
            .bind_access(&actor, "docs", "acme", Action::Read)
            .unwrap();
        assert!(
            matches!(
                db.get_points_authorized(&read, &["hidden".into()]),
                Err(GaussError::Security(SecurityError::Unavailable))
            ),
            "an authorized tenant must not receive internal paths on storage failure"
        );
    }

    #[test]
    fn protected_cold_admission_without_missing_files_shares_the_read_lock() {
        let (_directory, db, key, _) = fixture(false);
        let remote = tempfile::tempdir().unwrap();
        db.set_cold_object_store_dir(Some(remote.path().to_path_buf()));
        let actor = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let read = db
            .bind_access(&actor, "docs", "acme", Action::Read)
            .unwrap();
        let collection = db.inner.read().collections["docs"].clone();
        let guard = collection.read();
        let worker_db = db.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            tx.send(
                worker_db
                    .get_points_authorized(&read, &[])
                    .unwrap()
                    .publish(|points| points.len()),
            )
            .unwrap();
        });
        let result = rx.recv_timeout(Duration::from_secs(2));
        drop(guard);
        worker.join().unwrap();
        assert_eq!(
            result
                .expect("cold admission unnecessarily waited for an exclusive lock")
                .unwrap(),
            0
        );
    }

    #[test]
    fn production_admission_rejects_legacy_and_mixed_catalogs() {
        let directory = tempfile::tempdir().unwrap();
        let db = Db::open(directory.path()).unwrap();
        db.set_tenant_enforcement(crate::tenant::TenantEnforcement::Enforced);
        assert!(
            db.validate_protected_admission().is_err(),
            "tenant stamping does not establish trusted authority"
        );
        let (_protected_directory, protected, _, _) = fixture(false);
        protected.validate_protected_admission().unwrap();
        db.set_tenant_enforcement(crate::tenant::TenantEnforcement::Disabled);
        db.create_collection(
            serde_json::from_value(serde_json::json!({"name":"legacy","vector_dim":2})).unwrap(),
        )
        .unwrap();
        let legacy = db.inner.read().collections["legacy"].clone();
        protected
            .inner
            .write()
            .collections
            .insert("legacy".into(), legacy);
        assert!(
            protected.validate_protected_admission().is_err(),
            "one protected collection cannot authorize an unmigrated sibling"
        );
        protected.inner.write().collections.remove("legacy");
    }

    #[test]
    fn protected_aggregate_metadata_budget_rejects_before_wal_or_revocation() {
        let (directory, db, key, _) = fixture(false);
        let actor = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let create = db
            .bind_access(&actor, "docs", "acme", Action::Create)
            .unwrap();
        let collection = db.inner.read().collections["docs"].clone();
        let authority = collection.read().security.clone().unwrap();
        const LIMIT: usize = 4096;
        authority.limit_metadata_for_test(LIMIT);
        let mut ids = Vec::new();
        loop {
            let before = collection.read().wal.len().unwrap();
            match db.create_points_authorized(&create, "standard", vec![point("bounded")], true) {
                Ok(output) => ids.extend(output.publish(|ids| ids).unwrap()),
                Err(GaussError::Security(SecurityError::BudgetExceeded)) => {
                    assert_eq!(collection.read().wal.len().unwrap(), before);
                    break;
                }
                Err(error) => panic!("unexpected create error: {error}"),
            }
            // Independent oracle: serialize the actual durable envelope, not
            // the incremental accounting helper used by admission.
            let stored = crate::security::storage::StoredSecurity {
                wal_watermark: collection.read().wal.len().unwrap(),
                authority: authority.checkpoint(),
            };
            assert!(52 + serde_json::to_vec(&stored).unwrap().len() <= LIMIT);
            assert!(ids.len() < 20, "aggregate limit was not enforced");
        }
        assert!(!ids.is_empty());
        let read = db
            .bind_access(&actor, "docs", "acme", Action::Read)
            .unwrap();
        let labels = db
            .bind_access(&actor, "docs", "acme", Action::LabelsManage)
            .unwrap();
        let original = authority.checkpoint().resources[0].clone();
        let mut properties = original.properties.clone();
        for i in 0..40 {
            properties.insert(format!("/field{i}"), original.properties["/text"].clone());
        }
        let before = collection.read().wal.len().unwrap();
        assert!(matches!(
            db.replace_object_labels_authorized(
                &labels,
                &original.key.id,
                RevisionUpdate {
                    expected_revision: labels.policy_revision(),
                    value: ObjectLabels {
                        labels: original.labels,
                        properties
                    }
                }
            ),
            Err(GaussError::Security(SecurityError::BudgetExceeded))
        ));
        assert_eq!(collection.read().wal.len().unwrap(), before);
        read.publication_permit().unwrap();

        let policy_context = db
            .bind_access(&actor, "docs", "acme", Action::PolicyManage)
            .unwrap();
        let mut policy = authority.checkpoint().policy;
        let template = policy.templates["standard"].clone();
        for i in 0..40 {
            policy
                .templates
                .insert(format!("template{i}"), template.clone());
        }
        assert!(matches!(
            db.replace_collection_policy_authorized(
                &policy_context,
                RevisionUpdate {
                    expected_revision: policy_context.policy_revision(),
                    value: policy
                }
            ),
            Err(GaussError::Security(SecurityError::BudgetExceeded))
        ));
        assert_eq!(collection.read().wal.len().unwrap(), before);
        assert_eq!(
            db.get_points_authorized(&read, &ids)
                .unwrap()
                .publish(|points| points.len())
                .unwrap(),
            ids.len()
        );

        let delete = db
            .bind_access(&actor, "docs", "acme", Action::Delete)
            .unwrap();
        db.delete_points_authorized(&delete, &ids)
            .unwrap()
            .publish(|_| ())
            .unwrap();
        let create = db
            .bind_access(&actor, "docs", "acme", Action::Create)
            .unwrap();
        let before = collection.read().wal.len().unwrap();
        assert!(matches!(
            db.create_points_authorized(
                &create,
                "standard",
                vec![point("cannot reuse tombstones")],
                true
            ),
            Err(GaussError::Security(SecurityError::BudgetExceeded))
        ));
        assert_eq!(collection.read().wal.len().unwrap(), before);
        assert!(
            authority
                .checkpoint()
                .resources
                .iter()
                .all(|record| record.retired)
        );
        drop(authority);
        drop(collection);
        drop(db);
        let reopened = Db::open(directory.path()).unwrap();
        let actor = reopened
            .identity_authority()
            .unwrap()
            .authenticate(&key)
            .unwrap();
        let read = reopened
            .bind_access(&actor, "docs", "acme", Action::Read)
            .unwrap();
        assert_eq!(
            reopened
                .count_authorized(&read, None)
                .unwrap()
                .publish(|count| count.count)
                .unwrap(),
            0
        );
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn protected_cold_reload_serializes_writes_and_preserves_authority() {
        let (directory, db, key, _) = fixture(false);
        let remote = tempfile::tempdir().unwrap();
        db.set_cold_object_store_dir(Some(remote.path().to_path_buf()));
        let actor = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let create = db
            .bind_access(&actor, "docs", "acme", Action::Create)
            .unwrap();
        let collection = db.inner.read().collections["docs"].clone();
        collection.write().config.streamer_max_bytes = 1;
        let ids = db
            .create_points_authorized(&create, "standard", vec![point("before")], true)
            .unwrap()
            .publish(|ids| ids)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let state = collection.read();
            if state.sealing.is_none() && !state.searchers.is_empty() {
                break;
            }
            drop(state);
            assert!(Instant::now() < deadline, "seal did not complete");
            std::thread::sleep(Duration::from_millis(20));
        }
        collection.write().config.streamer_max_bytes = usize::MAX;
        let root = db.inner.read().root.join("collections/docs");
        // Trusted fixture preparation; public legacy tiering rejects protected collections.
        let cold = root.join("cold");
        let store = ColdObjectStoreConfig::LocalDir(remote.path().to_path_buf());
        crate::segment::tier_searchers_to_cold(
            &root.join("searchers"),
            &cold,
            "docs",
            1,
            Some(&store),
        )
        .unwrap();
        for entry in std::fs::read_dir(&cold).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                std::fs::remove_dir_all(entry.path()).unwrap();
            }
        }
        let read = db
            .bind_access(&actor, "docs", "acme", Action::Read)
            .unwrap();
        let marker = directory.path().join("reload-paused");
        let release = directory.path().join("reload-release");
        let _environment =
            crate::failpoint::test_env("pause:db.cold_reload_loaded", &marker, &release);
        let worker_db = db.clone();
        let worker_read = read.clone();
        let worker = std::thread::spawn(move || {
            worker_db.ensure_collection_cold_materialized_authorized(&worker_read)
        });
        let deadline = Instant::now() + Duration::from_secs(15);
        while !marker.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let reached = marker.exists();
        let excludes_writers = collection.try_write().is_none();
        std::fs::write(&release, b"continue").unwrap();
        worker.join().unwrap().unwrap();
        assert!(reached, "reload did not reach loaded boundary");
        assert!(
            excludes_writers,
            "a commit can occur between recovery and installation"
        );
        assert_eq!(
            db.get_points_authorized(&read, &ids)
                .unwrap()
                .publish(|points| points[0].payload.clone())
                .unwrap(),
            serde_json::json!({"text":"before"})
        );
    }

    #[test]
    fn ordinary_writer_cannot_attest_or_change_representation_sources() {
        let (_directory, db, key, other_key) = fixture(false);
        let authority = db.identity_authority().unwrap();
        let root = authority.authenticate(&key).unwrap();
        let other = authority.authenticate(&other_key).unwrap();
        let manage = db
            .bind_access(&root, "docs", "acme", Action::PolicyManage)
            .unwrap();
        let mut policy = db.inner.read().collections["docs"]
            .read()
            .security
            .as_ref()
            .unwrap()
            .checkpoint()
            .policy;
        policy
            .templates
            .get_mut("standard")
            .unwrap()
            .properties
            .insert(
                "/note".into(),
                PropertyRule {
                    classification: Classification::Internal,
                    actions: BTreeSet::from([PropertyAction::Read, PropertyAction::Write]),
                },
            );
        db.replace_collection_policy_authorized(
            &manage,
            RevisionUpdate {
                expected_revision: manage.policy_revision(),
                value: policy,
            },
        )
        .unwrap();
        let create = db
            .bind_access(&other, "docs", "acme", Action::Create)
            .unwrap();
        let id = db
            .create_points_authorized(&create, "standard", vec![point("attested")], true)
            .unwrap()
            .publish(|ids| ids[0].clone())
            .unwrap();
        let mut writer = other.principal().clone();
        writer.grants[0].actions.remove(&Action::Ingest);
        authority
            .put_principal(&root, authority.revision(), writer)
            .unwrap();
        let writer = authority.authenticate(&other_key).unwrap();
        let create = db
            .bind_access(&writer, "docs", "acme", Action::Create)
            .unwrap();
        let update = db
            .bind_access(&writer, "docs", "acme", Action::Update)
            .unwrap();
        let before = db.inner.read().collections["docs"]
            .read()
            .wal
            .len()
            .unwrap();
        assert!(
            db.create_points_authorized(&create, "standard", vec![point("unattested")], true)
                .is_err()
        );
        assert!(
            db.update_points_authorized(
                &update,
                vec![physical_point(&point("changed source"), id.clone())],
                true
            )
            .is_err()
        );
        let mut changed = physical_point(&point("attested"), id.clone());
        changed.vector = vec![0.0, 1.0];
        assert!(
            db.update_points_authorized(&update, vec![changed], true)
                .is_err()
        );
        assert_eq!(
            db.inner.read().collections["docs"]
                .read()
                .wal
                .len()
                .unwrap(),
            before
        );
        let mut unrelated = physical_point(&point("attested"), id.clone());
        unrelated.payload["note"] = serde_json::json!("ordinary content edit");
        db.update_points_authorized(&update, vec![unrelated], true)
            .unwrap()
            .publish(|_| ())
            .unwrap();
        let read = db
            .bind_access(&writer, "docs", "acme", Action::Read)
            .unwrap();
        let result = db
            .get_points_authorized(&read, &[id])
            .unwrap()
            .publish(|points| points)
            .unwrap();
        assert_eq!(result[0].payload["note"], "ordinary content edit");
        assert_eq!(result[0].vector, vec![1.0, 0.0]);
    }

    #[test]
    fn protected_seal_retention_update_and_delete_recover_one_authority() {
        for graph in [false, true] {
            let (directory, db, key, other_key) = fixture(graph);
            let root = db.identity_authority().unwrap().authenticate(&key).unwrap();
            let create = db
                .bind_access(&root, "docs", "acme", Action::Create)
                .unwrap();
            let collection = db.inner.read().collections["docs"].clone();
            collection.write().config.streamer_max_bytes = 1;
            let ids = db
                .create_points_authorized(
                    &create,
                    "standard",
                    vec![point("one"), point("two")],
                    true,
                )
                .unwrap()
                .publish(|ids| ids)
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                let state = collection.read();
                if state.sealing.is_none() && !state.searchers.is_empty() {
                    break;
                }
                drop(state);
                assert!(
                    Instant::now() < deadline,
                    "protected automatic seal did not complete"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(collection.read().wal_watermark > 0);
            collection.write().config.streamer_max_bytes = usize::MAX;
            let update = db
                .bind_access(&root, "docs", "acme", Action::Update)
                .unwrap();
            db.update_points_authorized(
                &update,
                vec![physical_point(&point("updated"), ids[0].clone())],
                true,
            )
            .unwrap()
            .publish(|_| ())
            .unwrap();
            let delete = db
                .bind_access(&root, "docs", "acme", Action::Delete)
                .unwrap();
            db.delete_points_authorized(&delete, std::slice::from_ref(&ids[1]))
                .unwrap()
                .publish(|_| ())
                .unwrap();
            drop(collection);
            drop(db);
            let db = Db::open(directory.path()).unwrap();
            let root = db.identity_authority().unwrap().authenticate(&key).unwrap();
            let read = db.bind_access(&root, "docs", "acme", Action::Read).unwrap();
            let points = db
                .get_points_authorized(&read, &ids)
                .unwrap()
                .publish(|points| points)
                .unwrap();
            assert_eq!(points.len(), 1);
            assert_eq!(points[0].id, ids[0]);
            assert_eq!(points[0].payload, serde_json::json!({"text":"updated"}));
            assert_eq!(
                db.count_authorized(&read, None)
                    .unwrap()
                    .publish(|count| count.count)
                    .unwrap(),
                1
            );
            let other = db
                .identity_authority()
                .unwrap()
                .authenticate(&other_key)
                .unwrap();
            let read = db
                .bind_access(&other, "docs", "acme", Action::Read)
                .unwrap();
            assert_eq!(
                db.count_authorized(&read, None)
                    .unwrap()
                    .publish(|count| count.count)
                    .unwrap(),
                0
            );
        }
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn protected_write_retains_collection_lock_through_authority_commit() {
        for graph in [false, true] {
            let (directory, db, key, _) = fixture(graph);
            let root = db.identity_authority().unwrap().authenticate(&key).unwrap();
            let context = db
                .bind_access(&root, "docs", "acme", Action::Create)
                .unwrap();
            let marker = directory.path().join("commit-paused");
            let release = directory.path().join("commit-release");
            let _environment =
                crate::failpoint::test_env("pause:db.after_upsert_durable", &marker, &release);
            let worker_db = db.clone();
            let worker = std::thread::spawn(move || {
                worker_db
                    .create_points_authorized(&context, "standard", vec![point("atomic")], true)
                    .unwrap()
                    .publish(|ids| ids)
                    .unwrap()
            });
            let deadline = Instant::now() + Duration::from_secs(15);
            while !marker.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            let reached = marker.exists();
            let collection = db.inner.read().collections["docs"].clone();
            let retained = collection.try_read().is_none();
            // Always release the worker before assertions, including failures.
            std::fs::write(&release, b"continue").unwrap();
            let ids = worker.join().unwrap();
            assert!(
                reached,
                "writer did not reach the post-content/pre-security boundary"
            );
            assert!(
                retained,
                "content became readable before its security transaction finished"
            );
            let read = db.bind_access(&root, "docs", "acme", Action::Read).unwrap();
            assert_eq!(
                db.get_points_authorized(&read, &ids)
                    .unwrap()
                    .publish(|points| points.len())
                    .unwrap(),
                1
            );
        }
    }

    fn replace_permissions(
        db: &Db,
        actor: &AuthenticatedIdentity,
        id: &str,
        grants: Vec<ObjectGrant>,
        parent: Option<String>,
    ) -> Result<u64> {
        let context = db.bind_access(actor, "docs", "acme", Action::GrantsManage)?;
        db.replace_object_permissions_authorized(
            &context,
            id,
            RevisionUpdate {
                expected_revision: context.policy_revision(),
                value: ObjectPermissions { grants, parent },
            },
        )?
        .publish(|revision| revision)
    }

    #[test]
    fn object_permission_management_enforces_delegation_and_inheritance() {
        for graph in [false, true] {
            let (directory, db, key, other_key) = fixture(graph);
            let authority = db.identity_authority().unwrap();
            let root = authority.authenticate(&key).unwrap();
            let mut manager = authority
                .authenticate(&other_key)
                .unwrap()
                .principal()
                .clone();
            manager.attributes.department = "HR".into();
            manager.attributes.clearance = Classification::Internal;
            manager.grants[0].actions.insert(Action::GrantsManage);
            manager.delegation = vec![ScopeGrant {
                tenants: BTreeSet::from(["acme".into()]),
                collections: BTreeSet::from(["docs".into()]),
                actions: BTreeSet::from([Action::Read]),
            }];
            authority
                .put_principal(&root, authority.revision(), manager)
                .unwrap();
            let root = authority.authenticate(&key).unwrap();
            let manager = authority.authenticate(&other_key).unwrap();
            let create = db
                .bind_access(&root, "docs", "acme", Action::Create)
                .unwrap();
            let ids = db
                .create_points_authorized(
                    &create,
                    "standard",
                    vec![point("managed"), point("container"), point("child")],
                    true,
                )
                .unwrap()
                .publish(|ids| ids)
                .unwrap();
            assert!(
                replace_permissions(&db, &manager, &ids[0], Vec::new(), None).is_err(),
                "installation scope alone grants no object management"
            );
            let managed = ObjectGrant {
                subject: Subject::Principal("other-reader".into()),
                effect: Effect::Permit,
                actions: BTreeSet::from([Action::GrantsManage]),
                inherit: false,
            };
            let share = ObjectGrant {
                subject: Subject::Department("HR".into()),
                effect: Effect::Permit,
                actions: BTreeSet::from([Action::Read]),
                inherit: true,
            };
            replace_permissions(&db, &root, &ids[0], vec![managed.clone()], None).unwrap();
            replace_permissions(
                &db,
                &manager,
                &ids[0],
                vec![managed.clone(), share.clone()],
                None,
            )
            .unwrap();
            let read = db
                .bind_access(&manager, "docs", "acme", Action::Read)
                .unwrap();
            assert_eq!(
                db.get_points_authorized(&read, std::slice::from_ref(&ids[0]))
                    .unwrap()
                    .publish(|points| points.len())
                    .unwrap(),
                1,
                "explicit grant crosses departments"
            );
            let before = db.inner.read().collections["docs"]
                .read()
                .wal
                .len()
                .unwrap();
            let escalation = ObjectGrant {
                actions: BTreeSet::from([Action::Update]),
                ..share.clone()
            };
            assert!(
                replace_permissions(
                    &db,
                    &manager,
                    &ids[0],
                    vec![managed.clone(), share.clone(), escalation],
                    None
                )
                .is_err()
            );
            let unknown = ObjectGrant {
                subject: Subject::Group("missing".into()),
                ..share.clone()
            };
            assert!(replace_permissions(&db, &root, &ids[0], vec![unknown], None).is_err());
            assert_eq!(
                db.inner.read().collections["docs"]
                    .read()
                    .wal
                    .len()
                    .unwrap(),
                before
            );
            replace_permissions(&db, &root, &ids[1], vec![share.clone()], None).unwrap();
            replace_permissions(&db, &root, &ids[2], Vec::new(), Some(ids[1].clone())).unwrap();
            let read = db
                .bind_access(&manager, "docs", "acme", Action::Read)
                .unwrap();
            let queued = db
                .get_points_authorized(&read, std::slice::from_ref(&ids[2]))
                .unwrap();
            assert_eq!(
                db.get_points_authorized(&read, std::slice::from_ref(&ids[2]))
                    .unwrap()
                    .publish(|points| points.len())
                    .unwrap(),
                1
            );
            let before = db.inner.read().collections["docs"]
                .read()
                .wal
                .len()
                .unwrap();
            assert!(
                replace_permissions(
                    &db,
                    &root,
                    &ids[1],
                    vec![share.clone()],
                    Some(ids[2].clone())
                )
                .is_err(),
                "cycle must fail before commit"
            );
            assert_eq!(
                db.inner.read().collections["docs"]
                    .read()
                    .wal
                    .len()
                    .unwrap(),
                before
            );
            let deny = ObjectGrant {
                effect: Effect::Deny,
                ..share.clone()
            };
            replace_permissions(&db, &root, &ids[2], vec![deny], Some(ids[1].clone())).unwrap();
            assert!(queued.publish(|_| ()).is_err());
            let read = db
                .bind_access(&manager, "docs", "acme", Action::Read)
                .unwrap();
            assert!(
                db.get_points_authorized(&read, std::slice::from_ref(&ids[2]))
                    .unwrap()
                    .publish(|points| points.is_empty())
                    .unwrap()
            );
            // A parent change cannot be used by a child manager to remove a
            // deny or acquire authority held only on another container.
            replace_permissions(
                &db,
                &root,
                &ids[0],
                vec![managed, share.clone()],
                Some(ids[1].clone()),
            )
            .unwrap();
            assert!(replace_permissions(&db, &manager, &ids[0], vec![share], None).is_err());
            drop(db);
            let db = Db::open(directory.path()).unwrap();
            let manager = db
                .identity_authority()
                .unwrap()
                .authenticate(&other_key)
                .unwrap();
            let read = db
                .bind_access(&manager, "docs", "acme", Action::Read)
                .unwrap();
            let visible = db
                .get_points_authorized(&read, &ids)
                .unwrap()
                .publish(|points| {
                    points
                        .into_iter()
                        .map(|point| point.id)
                        .collect::<BTreeSet<_>>()
                })
                .unwrap();
            assert_eq!(visible, BTreeSet::from([ids[0].clone(), ids[1].clone()]));
        }
    }

    #[test]
    fn label_changes_revoke_old_outputs_and_raise_derived_classification() {
        for graph in [false, true] {
            let (directory, db, key, other_key) = fixture(graph);
            let authority = db.identity_authority().unwrap();
            let root = authority.authenticate(&key).unwrap();
            let mut reader = authority
                .authenticate(&other_key)
                .unwrap()
                .principal()
                .clone();
            reader.attributes.clearance = Classification::Internal;
            authority
                .put_principal(&root, authority.revision(), reader)
                .unwrap();
            let root = authority.authenticate(&key).unwrap();
            let reader = authority.authenticate(&other_key).unwrap();
            let create = db
                .bind_access(&root, "docs", "acme", Action::Create)
                .unwrap();
            let id = db
                .create_points_authorized(&create, "standard", vec![point("classified")], true)
                .unwrap()
                .publish(|ids| ids[0].clone())
                .unwrap();
            let share = ObjectGrant {
                subject: Subject::Principal("other-reader".into()),
                effect: Effect::Permit,
                actions: BTreeSet::from([Action::Read]),
                inherit: false,
            };
            replace_permissions(&db, &root, &id, vec![share], None).unwrap();
            let read = db
                .bind_access(&reader, "docs", "acme", Action::Read)
                .unwrap();
            let queued = db
                .get_points_authorized(&read, std::slice::from_ref(&id))
                .unwrap();
            let labels = db
                .bind_access(&root, "docs", "acme", Action::LabelsManage)
                .unwrap();
            let record = labels.authorize(&id).unwrap();
            let mut value = ObjectLabels {
                labels: record.labels,
                properties: record.properties,
            };
            value.labels.classification = Classification::Confidential;
            value.properties.get_mut("/text").unwrap().classification =
                Classification::Confidential;
            assert!(
                db.replace_object_labels_authorized(
                    &read,
                    &id,
                    RevisionUpdate {
                        expected_revision: labels.policy_revision(),
                        value: value.clone()
                    }
                )
                .is_err()
            );
            let before = db.inner.read().collections["docs"]
                .read()
                .wal
                .len()
                .unwrap();
            assert!(
                db.replace_object_labels_authorized(
                    &labels,
                    &id,
                    RevisionUpdate {
                        expected_revision: labels.policy_revision() - 1,
                        value: value.clone()
                    }
                )
                .is_err()
            );
            let mut invalid = value.clone();
            invalid.labels.owner = "unknown-owner".into();
            assert!(
                db.replace_object_labels_authorized(
                    &labels,
                    &id,
                    RevisionUpdate {
                        expected_revision: labels.policy_revision(),
                        value: invalid
                    }
                )
                .is_err()
            );
            assert_eq!(
                db.inner.read().collections["docs"]
                    .read()
                    .wal
                    .len()
                    .unwrap(),
                before
            );
            db.replace_object_labels_authorized(
                &labels,
                &id,
                RevisionUpdate {
                    expected_revision: labels.policy_revision(),
                    value,
                },
            )
            .unwrap()
            .publish(|_| ())
            .unwrap();
            assert!(queued.publish(|_| ()).is_err());
            let read = db
                .bind_access(&reader, "docs", "acme", Action::Read)
                .unwrap();
            assert!(
                db.get_points_authorized(&read, std::slice::from_ref(&id))
                    .unwrap()
                    .publish(|points| points.is_empty())
                    .unwrap()
            );
            let labels = db
                .bind_access(&root, "docs", "acme", Action::LabelsManage)
                .unwrap();
            assert_eq!(
                labels.authorize(&id).unwrap().representations["dense"].classification,
                Classification::Confidential
            );
            drop(db);
            let db = Db::open(directory.path()).unwrap();
            let reader = db
                .identity_authority()
                .unwrap()
                .authenticate(&other_key)
                .unwrap();
            let read = db
                .bind_access(&reader, "docs", "acme", Action::Read)
                .unwrap();
            assert!(
                db.get_points_authorized(&read, std::slice::from_ref(&id))
                    .unwrap()
                    .publish(|points| points.is_empty())
                    .unwrap()
            );
        }
    }

    #[test]
    fn protected_count_scroll_and_dense_search_ignore_hidden_data() {
        for graph in [false, true] {
            let (_directory, db, key, other_key) = fixture(graph);
            let writer = db.identity_authority().unwrap().authenticate(&key).unwrap();
            let other = db
                .identity_authority()
                .unwrap()
                .authenticate(&other_key)
                .unwrap();
            let manage = db
                .bind_access(&writer, "docs", "acme", Action::PolicyManage)
                .unwrap();
            let mut policy = db.inner.read().collections["docs"]
                .read()
                .security
                .as_ref()
                .unwrap()
                .checkpoint()
                .policy;
            policy
                .templates
                .get_mut("standard")
                .unwrap()
                .properties
                .insert(
                    "/secret".into(),
                    PropertyRule {
                        classification: Classification::Internal,
                        actions: BTreeSet::from([PropertyAction::Write]),
                    },
                );
            let mut nonquery = policy.templates["standard"].clone();
            nonquery
                .properties
                .get_mut("/text")
                .unwrap()
                .actions
                .remove(&PropertyAction::Query);
            policy.templates.insert("nonquery".into(), nonquery);
            db.replace_collection_policy_authorized(
                &manage,
                RevisionUpdate {
                    expected_revision: manage.policy_revision(),
                    value: policy,
                },
            )
            .unwrap();
            let create = db
                .bind_access(&writer, "docs", "acme", Action::Create)
                .unwrap();
            let mut inputs = vec![point("one"), point("two"), point("three")];
            inputs[0].payload["secret"] = serde_json::json!("private");
            inputs[1].vector = vec![0.0, 1.0];
            inputs[2].vector = vec![-1.0, 0.0];
            let ids = db
                .create_points_authorized(&create, "standard", inputs, true)
                .unwrap()
                .publish(|ids| ids)
                .unwrap();
            let read = db
                .bind_access(&writer, "docs", "acme", Action::Read)
                .unwrap();
            let search = db
                .bind_access(&writer, "docs", "acme", Action::Search)
                .unwrap();
            let query: SearchRequest =
                serde_json::from_value(serde_json::json!({"vector":[1.0,0.0],"k":10})).unwrap();
            let baseline = db
                .search_authorized(&search, query.clone(), None)
                .unwrap()
                .publish(|hits| hits)
                .unwrap();
            assert_eq!(
                baseline
                    .iter()
                    .map(|hit| hit.id.clone())
                    .collect::<Vec<_>>(),
                ids
            );
            assert_eq!(
                baseline.iter().map(|hit| hit.score).collect::<Vec<_>>(),
                vec![1.0, 0.0, -1.0]
            );
            assert!(
                baseline
                    .iter()
                    .all(|hit| hit.payload.get("secret").is_none())
            );
            let other_create = db
                .bind_access(&other, "docs", "acme", Action::Create)
                .unwrap();
            db.create_points_authorized(&other_create, "standard", vec![point("one"); 7], true)
                .unwrap()
                .publish(|_| ())
                .unwrap();
            let after = db
                .search_authorized(&search, query.clone(), None)
                .unwrap()
                .publish(|hits| hits)
                .unwrap();
            assert_eq!(
                serde_json::to_value(&after).unwrap(),
                serde_json::to_value(&baseline).unwrap()
            );
            assert_eq!(
                db.count_authorized(&read, None)
                    .unwrap()
                    .publish(|count| count.count)
                    .unwrap(),
                3
            );
            assert_eq!(
                db.count_authorized(&read, Some(Filter(serde_json::json!({"text":"two"}))))
                    .unwrap()
                    .publish(|count| count.count)
                    .unwrap(),
                1
            );
            let mut expected = ids.clone();
            expected.sort();
            let mut offset = None;
            let mut returned = Vec::new();
            loop {
                let page = db
                    .scroll_authorized(
                        &read,
                        crate::model::ScrollRequest {
                            offset,
                            limit: 1,
                            filter: None,
                        },
                    )
                    .unwrap()
                    .publish(|page| page)
                    .unwrap();
                assert!(
                    page.points
                        .iter()
                        .all(|point| point.payload.get("secret").is_none())
                );
                returned.extend(page.points.into_iter().map(|point| point.id));
                offset = page.next_offset;
                if offset.is_none() {
                    break;
                }
            }
            assert_eq!(returned, expected);
            for filter in [
                Filter(serde_json::json!({"secret":"private"})),
                Filter(serde_json::json!({"unknown":{"ne":null}})),
            ] {
                assert!(db.count_authorized(&read, Some(filter.clone())).is_err());
                assert!(
                    db.scroll_authorized(
                        &read,
                        crate::model::ScrollRequest {
                            offset: None,
                            limit: 1,
                            filter: Some(filter.clone())
                        }
                    )
                    .is_err()
                );
                let mut query = query.clone();
                query.filter = Some(filter);
                assert!(db.search_authorized(&search, query, None).is_err());
            }
            db.create_points_authorized(
                &create,
                "nonquery",
                vec![point("unqueryable source")],
                true,
            )
            .unwrap()
            .publish(|_| ())
            .unwrap();
            let after = db
                .search_authorized(&search, query.clone(), None)
                .unwrap()
                .publish(|hits| hits)
                .unwrap();
            assert_eq!(
                serde_json::to_value(after).unwrap(),
                serde_json::to_value(baseline).unwrap()
            );
            assert!(db.search_authorized(&read, query.clone(), None).is_err());
            assert!(
                db.search_authorized(&search, query.clone(), Some(&AtomicBool::new(true)))
                    .is_err()
            );
            let mut expired = query;
            expired.budget_ms = Some(0);
            assert!(db.search_authorized(&search, expired, None).is_err());
        }
    }

    #[test]
    fn protected_filter_delete_uses_write_domain_and_validates_before_wal() {
        for graph in [false, true] {
            let (_directory, db, key, other_key) = fixture(graph);
            let writer = db.identity_authority().unwrap().authenticate(&key).unwrap();
            let other = db
                .identity_authority()
                .unwrap()
                .authenticate(&other_key)
                .unwrap();
            let manage = db
                .bind_access(&writer, "docs", "acme", Action::PolicyManage)
                .unwrap();
            let mut policy = db.inner.read().collections["docs"]
                .read()
                .security
                .as_ref()
                .unwrap()
                .checkpoint()
                .policy;
            policy.department_actions.insert(Action::Read);
            policy
                .templates
                .get_mut("standard")
                .unwrap()
                .properties
                .insert(
                    "/secret".into(),
                    PropertyRule {
                        classification: Classification::Internal,
                        actions: BTreeSet::from([PropertyAction::Write]),
                    },
                );
            db.replace_collection_policy_authorized(
                &manage,
                RevisionUpdate {
                    expected_revision: manage.policy_revision(),
                    value: policy,
                },
            )
            .unwrap();
            let create = db
                .bind_access(&writer, "docs", "acme", Action::Create)
                .unwrap();
            let mut selected = point("delete");
            selected.payload["secret"] = serde_json::json!("hidden");
            let ids = db
                .create_points_authorized(&create, "standard", vec![selected, point("keep")], true)
                .unwrap()
                .publish(|ids| ids)
                .unwrap();
            let other_create = db
                .bind_access(&other, "docs", "acme", Action::Create)
                .unwrap();
            let foreign = db
                .create_points_authorized(&other_create, "standard", vec![point("delete")], true)
                .unwrap()
                .publish(|ids| ids[0].clone())
                .unwrap();
            let read = db
                .bind_access(&writer, "docs", "acme", Action::Read)
                .unwrap();
            assert_eq!(
                db.get_points_authorized(&read, std::slice::from_ref(&foreign))
                    .unwrap()
                    .publish(|points| points.len())
                    .unwrap(),
                1
            );
            assert!(
                db.delete_filter_authorized(&read, Filter(serde_json::json!({})))
                    .is_err()
            );
            let delete = db
                .bind_access(&writer, "docs", "acme", Action::Delete)
                .unwrap();
            let before = db.inner.read().collections["docs"]
                .read()
                .wal
                .len()
                .unwrap();
            assert!(
                db.delete_filter_authorized(
                    &delete,
                    Filter(serde_json::json!({"secret":"hidden"}))
                )
                .is_err()
            );
            assert_eq!(
                db.inner.read().collections["docs"]
                    .read()
                    .wal
                    .len()
                    .unwrap(),
                before
            );
            assert_eq!(
                db.delete_filter_authorized(&delete, Filter(serde_json::json!({"text":"absent"})))
                    .unwrap()
                    .publish(|count| count)
                    .unwrap(),
                0
            );
            assert_eq!(
                db.inner.read().collections["docs"]
                    .read()
                    .wal
                    .len()
                    .unwrap(),
                before
            );
            assert_eq!(
                db.delete_filter_authorized(&delete, Filter(serde_json::json!({"text":"delete"})))
                    .unwrap()
                    .publish(|count| count)
                    .unwrap(),
                1
            );
            let read = db
                .bind_access(&writer, "docs", "acme", Action::Read)
                .unwrap();
            let returned = db
                .get_points_authorized(&read, &[ids[0].clone(), ids[1].clone(), foreign.clone()])
                .unwrap()
                .publish(|points| {
                    points
                        .into_iter()
                        .map(|point| point.id)
                        .collect::<BTreeSet<_>>()
                })
                .unwrap();
            assert_eq!(returned, BTreeSet::from([ids[1].clone(), foreign]));
        }
    }

    #[test]
    fn protected_delete_retires_identity_atomically_and_revokes_queued_results() {
        for graph in [false, true] {
            let (directory, db, key, other_key) = fixture(graph);
            let writer = db.identity_authority().unwrap().authenticate(&key).unwrap();
            let other = db
                .identity_authority()
                .unwrap()
                .authenticate(&other_key)
                .unwrap();
            let create = db
                .bind_access(&writer, "docs", "acme", Action::Create)
                .unwrap();
            let other_create = db
                .bind_access(&other, "docs", "acme", Action::Create)
                .unwrap();
            let own = db
                .create_points_authorized(&create, "standard", vec![point("mine")], true)
                .unwrap()
                .publish(|ids| ids[0].clone())
                .unwrap();
            let foreign = db
                .create_points_authorized(&other_create, "standard", vec![point("hidden")], true)
                .unwrap()
                .publish(|ids| ids[0].clone())
                .unwrap();
            let delete = db
                .bind_access(&writer, "docs", "acme", Action::Delete)
                .unwrap();
            let read = db
                .bind_access(&writer, "docs", "acme", Action::Read)
                .unwrap();
            let before = db.inner.read().collections["docs"]
                .read()
                .wal
                .len()
                .unwrap();
            assert!(
                db.delete_points_authorized(&delete, &[own.clone(), foreign.clone()])
                    .is_err()
            );
            assert_eq!(
                db.inner.read().collections["docs"]
                    .read()
                    .wal
                    .len()
                    .unwrap(),
                before
            );
            let foreign_error = db
                .delete_points_authorized(&delete, &[foreign])
                .err()
                .unwrap()
                .to_string();
            let missing_error = db
                .delete_points_authorized(&delete, &[Uuid::new_v4().to_string()])
                .err()
                .unwrap()
                .to_string();
            assert_eq!(foreign_error, missing_error);
            let queued = db
                .get_points_authorized(&read, std::slice::from_ref(&own))
                .unwrap();
            assert_eq!(
                db.delete_points_authorized(&delete, std::slice::from_ref(&own))
                    .unwrap()
                    .publish(|count| count)
                    .unwrap(),
                1
            );
            assert!(queued.publish(|_| ()).is_err());
            assert!(
                db.get_points_authorized(&read, std::slice::from_ref(&own))
                    .is_err()
            );
            drop(db);
            let reopened = Db::open(directory.path()).unwrap();
            let writer = reopened
                .identity_authority()
                .unwrap()
                .authenticate(&key)
                .unwrap();
            let read = reopened
                .bind_access(&writer, "docs", "acme", Action::Read)
                .unwrap();
            assert_eq!(read.policy_revision(), 2);
            assert!(
                reopened
                    .get_points_authorized(&read, std::slice::from_ref(&own))
                    .unwrap()
                    .publish(|points| points.is_empty())
                    .unwrap()
            );
            let update = reopened
                .bind_access(&writer, "docs", "acme", Action::Update)
                .unwrap();
            assert!(
                reopened
                    .update_points_authorized(
                        &update,
                        vec![physical_point(&point("revive"), own.clone())],
                        true
                    )
                    .is_err()
            );
            let create = reopened
                .bind_access(&writer, "docs", "acme", Action::Create)
                .unwrap();
            let new_id = reopened
                .create_points_authorized(&create, "standard", vec![point("new")], true)
                .unwrap()
                .publish(|ids| ids[0].clone())
                .unwrap();
            assert_ne!(new_id, own);
        }
    }
}
