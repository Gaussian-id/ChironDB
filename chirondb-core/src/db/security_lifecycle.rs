//! Atomic protected collection provisioning through the shared catalog WAL.
use super::*;
use crate::security::{AuthenticatedIdentity, CollectionPolicy, SecurityError};

impl Db {
    fn require_installation_admin(&self, identity: &AuthenticatedIdentity) -> Result<()> {
        if !self
            .identity_authority()
            .is_some_and(|a| a.accepts(identity) && a.installation_id().is_some())
            || !identity.is_installation_admin()
        {
            return Err(SecurityError::Forbidden.into());
        }
        Ok(())
    }
    pub fn catalog_revision_authorized(&self, identity: &AuthenticatedIdentity) -> Result<u64> {
        let _lifecycle = self.lifecycle_gate.read();
        self.require_installation_admin(identity)?;
        let _lease = identity.publication_permit()?;
        Ok(read_catalog(&self.inner.read().root)?.security_revision)
    }
    pub fn create_protected_collection_authorized(
        &self,
        identity: &AuthenticatedIdentity,
        expected: u64,
        config: CollectionConfig,
    ) -> Result<CollectionConfig> {
        self.create_collection_inner(config, Some((identity, expected)))
    }
    pub fn protected_collection_config_authorized(
        &self,
        identity: &AuthenticatedIdentity,
        name: &str,
    ) -> Result<CollectionConfig> {
        let _lifecycle = self.lifecycle_gate.read();
        let inner = self.inner.read();
        let collection = inner
            .collections
            .get(name)
            .ok_or(SecurityError::NotFound)?
            .read();
        if collection.security.is_none()
            || !self
                .identity_authority()
                .is_some_and(|authority| authority.accepts(identity))
            || !identity.allows(
                &identity.principal().tenant,
                name,
                crate::security::Action::Read,
            )
        {
            return Err(SecurityError::NotFound.into());
        }
        let _permit = identity.publication_permit()?;
        Ok(collection.config.clone())
    }
    pub fn protected_collection_exists_admin(
        &self,
        identity: &AuthenticatedIdentity,
        name: &str,
    ) -> Result<bool> {
        let _lifecycle = self.lifecycle_gate.read();
        self.require_installation_admin(identity)?;
        let _permit = identity.publication_permit()?;
        Ok(self
            .inner
            .read()
            .collections
            .get(name)
            .is_some_and(|collection| collection.read().security.is_some()))
    }
    pub fn list_collections_authorized(
        &self,
        identity: &AuthenticatedIdentity,
    ) -> Result<Vec<CollectionConfig>> {
        let _lifecycle = self.lifecycle_gate.read();
        if !self
            .identity_authority()
            .is_some_and(|authority| authority.accepts(identity))
        {
            return Err(SecurityError::Unauthenticated.into());
        }
        let _permit = identity.publication_permit()?;
        let mut collections: Vec<_> = self
            .inner
            .read()
            .collections
            .values()
            .filter_map(|collection| {
                let collection = collection.read();
                (collection.security.is_some()
                    && identity.allows(
                        &identity.principal().tenant,
                        &collection.config.name,
                        crate::security::Action::Read,
                    ))
                .then(|| collection.config.clone())
            })
            .collect();
        collections.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(collections)
    }
    pub fn collection_policy_authorized(
        &self,
        identity: &AuthenticatedIdentity,
        name: &str,
    ) -> Result<crate::security::AuthorizedOutput<(u64, CollectionPolicy)>> {
        let ctx = self.bind_access(
            identity,
            name,
            &identity.principal().tenant,
            crate::security::Action::PolicyManage,
        )?;
        let _permit = ctx.publication_permit()?;
        let collection = self.get_coll_authorized(&ctx)?;
        let checkpoint = collection
            .read()
            .security
            .as_ref()
            .ok_or(SecurityError::Unavailable)?
            .checkpoint();
        Ok(crate::security::AuthorizedOutput::new(
            ctx,
            (checkpoint.revision, checkpoint.policy),
        ))
    }
    /// Expand only the designated installation administrator, over the current
    /// verified catalog. This never adds content privileges.
    pub fn management_identity(
        &self,
        identity: &AuthenticatedIdentity,
    ) -> Result<AuthenticatedIdentity> {
        if !self
            .identity_authority()
            .is_some_and(|a| a.accepts(identity))
        {
            return Err(SecurityError::Unauthenticated.into());
        }
        if self
            .identity_authority()
            .is_some_and(|a| a.installation_id().is_some())
            && !self.durability_ready()
        {
            return Err(SecurityError::Unavailable.into());
        }
        if !identity.is_installation_admin() {
            return Ok(identity.clone());
        }
        let inner = self.inner.read();
        let tables = self.relational_tables();
        if inner.collections.len() + tables.len() > crate::security::MAX_POLICY_GRANTS {
            return Err(SecurityError::BudgetExceeded.into());
        }
        let mut names: Vec<_> = inner
            .collections
            .iter()
            .filter(|(_, c)| c.read().security.is_some())
            .map(|(name, _)| name.clone())
            .collect();
        names.extend(
            tables
                .into_iter()
                .filter(|table| {
                    table.tenant_id.as_deref() == Some(identity.principal().tenant.as_str())
                })
                .map(|table| table.name),
        );
        Ok(identity.with_managed_collections(names))
    }
    pub(super) fn create_collection_inner(
        &self,
        config: CollectionConfig,
        protected: Option<(&crate::security::AuthenticatedIdentity, u64)>,
    ) -> Result<CollectionConfig> {
        if self.identity_authority.is_some() && protected.is_none() {
            return Err(crate::security::SecurityError::Forbidden.into());
        }
        let _lifecycle = self.lifecycle_gate.write();
        let _identity_lease = if let Some((identity, _)) = protected {
            self.require_installation_admin(identity)?;
            Some(identity.publication_permit()?)
        } else {
            None
        };
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let (audit_category, audit_operation_name, audit_context, audit_details) =
            if let Some((identity, _)) = protected {
                (
                    "security",
                    "collection.create_protected",
                    audit::AuditContext {
                        principal_id: identity.principal().id.clone(),
                        tenant_id: Some(identity.principal().tenant.clone()),
                        transport: "protected".into(),
                        request_id: None,
                    },
                    serde_json::json!({"identity_revision":identity.revision()}),
                )
            } else {
                (
                    "mutation",
                    "create_collection",
                    audit::AuditContext::embedded(),
                    serde_json::Value::Null,
                )
            };
        let mut operation_metrics = OperationGuard::start("create_collection");
        let config = config.normalize();
        validate_config(&config)?;

        let mut inner = self.inner.write();
        if inner.collections.contains_key(&config.name) {
            return Err(if protected.is_some() {
                crate::security::SecurityError::Conflict.into()
            } else {
                GaussError::CollectionExists(config.name)
            });
        }
        let authority = if let Some((_, expected)) = protected {
            let catalog = read_catalog(&inner.root)?;
            if catalog.security_revision != expected {
                return Err(crate::security::SecurityError::Conflict.into());
            }
            Some(crate::security::SecurityCheckpoint {
                version: crate::security::SECURITY_VERSION,
                collection: config.name.clone(),
                incarnation: uuid::Uuid::new_v4(),
                revision: 1,
                data_generation: 1,
                resources: vec![],
                policy: crate::security::CollectionPolicy {
                    department_actions: Default::default(),
                    owner_actions: Default::default(),
                    templates: Default::default(),
                },
            })
        } else {
            None
        };
        // Validate the complete security identity before staging or committing
        // any catalog state, including for callers that bypass ChironQL.
        let verified_authority = authority
            .clone()
            .map(crate::security::CollectionAuthority::from_verified_checkpoint)
            .transpose()?
            .map(Arc::new);

        let root = inner.root.clone();
        let collection_dir = collection_dir(&root, &config.name);
        let staging_dir = collection_create_staging_dir(&root, &config.name);
        if collection_dir.exists() || staging_dir.exists() {
            return Err(GaussError::WalUnavailable(format!(
                "collection '{}' has an unresolved filesystem generation",
                config.name
            )));
        }
        fs::create_dir_all(staging_dir.join("wal"))?;
        fs::create_dir_all(staging_dir.join("searchers"))?;
        let staging_wal = Wal::open(&staging_dir.join("wal"))?;
        let schema_epoch = 1;
        let checkpoint = CollectionCheckpoint::new(&config, schema_epoch, 0, 0, None)?;
        write_checkpoint(&staging_dir, &checkpoint)?;
        let empty_segments = HashSet::new();
        drop(crate::overlay::OverlayStore::open(
            &staging_dir,
            0,
            &empty_segments,
            crate::ordinal::SegmentOrdinalSet::new(),
            crate::overlay::OverlayOpenMode::Recover,
        )?);
        drop(staging_wal);
        if let Some(checkpoint) = &authority {
            crate::security::storage::write(
                &staging_dir,
                &crate::security::storage::StoredSecurity {
                    wal_watermark: 0,
                    authority: checkpoint.clone(),
                },
            )?;
        }
        sync_tree(&staging_dir)?;
        crate::failpoint::check("protected_collection.staged")?;
        let entry = if let (Some(checkpoint), Some((_, expected))) = (&authority, protected) {
            WalEntry::CreateProtectedCollection {
                config: config.clone(),
                security: checkpoint.clone(),
                expected_revision: expected,
                revision: expected
                    .checked_add(1)
                    .ok_or(crate::security::SecurityError::Unavailable)?,
            }
        } else {
            WalEntry::CreateCollection {
                config: config.clone(),
            }
        };
        let (transaction, _, storage_projected) = self.commit_catalog_transaction(
            &mut inner,
            entry,
            TransactionAudit::new(
                audit_category,
                audit_operation_name,
                Some(&config.name),
                &audit_context,
                audit_details,
            ),
        )?;
        if protected.is_some() {
            if let Err(error) = inner.catalog_wal.sync() {
                self.mark_durability_degraded("protected_catalog_sync", &error);
            }
            if let Err(error) = crate::failpoint::check("protected_collection.committed") {
                self.mark_durability_degraded("protected_collection_commit", &error);
            }
        }
        #[cfg(feature = "fault-injection")]
        if let Err(error) = crate::fs_util::fault_injection::crash_hook(
            crate::fs_util::fault_injection::HOOK_CATALOG_AFTER_DURABLE_COMMIT,
        ) {
            let error = GaussError::Io(error);
            self.mark_durability_degraded("create_collection_publication", &error);
        }
        if let Err(error) = durable_rename(&staging_dir, &collection_dir) {
            let error = GaussError::WalUnavailable(format!(
                "catalog committed collection '{}' but generation install failed: {error}",
                config.name
            ));
            self.mark_durability_degraded("create_collection_install", &error);
            drop(inner);
            self.project_transaction_audit(&transaction);
            operation_metrics.succeed();
            return Ok(config);
        }
        let wal = match Wal::open(&collection_dir.join("wal")) {
            Ok(wal) => wal,
            Err(error) => {
                self.mark_durability_degraded("create_collection_wal_open", &error);
                drop(inner);
                self.project_transaction_audit(&transaction);
                operation_metrics.succeed();
                return Ok(config);
            }
        };
        let overlays = match crate::overlay::OverlayStore::open(
            &collection_dir,
            0,
            &empty_segments,
            crate::ordinal::SegmentOrdinalSet::new(),
            crate::overlay::OverlayOpenMode::Recover,
        ) {
            Ok(overlays) => overlays,
            Err(error) => {
                self.mark_durability_degraded("create_collection_overlay_open", &error);
                drop(inner);
                self.project_transaction_audit(&transaction);
                operation_metrics.succeed();
                return Ok(config);
            }
        };
        inner.collections.insert(
            config.name.clone(),
            Arc::new(RwLock::new(Collection {
                security: verified_authority,
                config: config.clone(),
                streamer: crate::streamer::Streamer::new(),
                sealing: None,
                searchers: Vec::new(),
                id_index: HashMap::new(),
                graph_lifecycle: crate::graph_lifecycle::GraphLifecycleState::default(),
                graph_resolver: None,
                graph_mutable: None,
                graph_generation: None,
                graph_calibration: None,
                sparse_index: SparseIndex::default(),
                payload_index: PayloadIndex::default(),
                overlays,
                rabitq: None,
                vamana: None,
                ivf: None,
                wal,
                wal_watermark: 0,
                schema_epoch,
                last_segment_id: None,
                recall_curve: None,
                hnsw_dirty: true,
                index_build_in_flight: false,
                generation_build_in_flight: false,
                graph_backfill_in_flight: false,
            })),
        );
        if protected.is_some() {
            if let Err(error) = write_catalog(&inner)
                .and_then(|()| crate::failpoint::check("protected_collection.activated"))
            {
                self.mark_durability_degraded("protected_catalog_checkpoint", &error);
            }
        } else {
            self.checkpoint_catalog_after_commit(&mut inner);
        }
        if storage_projected
            && let Err(error) = self
                .transaction_journal
                .mark_projected(transaction.prepare.transaction_id, ProjectionKind::Storage)
        {
            self.mark_durability_degraded("transaction_catalog_marker", &error);
        }
        drop(inner);
        self.project_transaction_audit(&transaction);
        self.refresh_metrics();
        operation_metrics.succeed();
        Ok(config)
    }
}
