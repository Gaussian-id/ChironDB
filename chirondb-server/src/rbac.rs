use std::{collections::HashSet, path::Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use chirondb_core::{
    graph::GraphCapability,
    tenant::{TenantCapability, TenantEnforcement, TenantScope},
};
use subtle::ConstantTimeEq;

/// Access role associated with an API key.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Can only call read operations (search, count, scroll, recommend).
    #[default]
    ReadOnly,
    /// Can read and write points, manage collections.
    ReadWrite,
    /// Full access including admin operations (snapshot, restore, shard_move).
    Admin,
}

impl Role {
    pub fn allows_write(self) -> bool {
        self >= Role::ReadWrite
    }

    pub fn allows_admin(self) -> bool {
        self == Role::Admin
    }
}

/// A single API key with its associated tenant and access policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApiKeyEntry {
    /// Stable, non-secret identity used by audit, quotas, and rate limits.
    /// Required for secure (non-loopback) deployments.
    #[serde(default)]
    pub id: Option<String>,
    /// The API key value.
    pub key: String,
    /// Logical tenant identifier carried in audit/tracing contexts.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Role granted to this key.
    #[serde(default)]
    pub role: Role,
    /// Collections this key may access.  Empty = all collections allowed.
    #[serde(default)]
    pub allowed_collections: Vec<String>,
    /// Maximum number of collections this key may create.  `None` = no limit.
    #[serde(default)]
    pub max_collections: Option<usize>,
    /// Explicit capabilities by name: `tenant:cross_read`,
    /// `tenant:cross_write`, `graph:read`, `graph:write`, `graph:admin`,
    /// `graph:type_configure`, and `installation:admin`.
    ///
    /// `installation:admin` lets a tenant-bound `admin` key run
    /// installation-wide operations (snapshot, restore, collection
    /// delete/schema/compaction and other collection maintenance, shard moves,
    /// metrics and event streams) while tenant enforcement is `enforced`. An
    /// `admin` key without a `tenant_id` already holds that authority.
    ///
    /// Deliberately not implied by `role`. An admin key administers the
    /// cluster; reading another tenant's rows is a separate grant, so the
    /// everyday admin path stays scoped and a cross-tenant one is something
    /// somebody had to write down.
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// Capability name granting installation-wide administration to a
/// tenant-bound admin key. See [`authorize_installation`].
pub const INSTALLATION_ADMIN_CAPABILITY: &str = "installation:admin";

/// Where operators find the RT-11 upgrade procedure. Shared by the 403 body,
/// the dry-run warning and `chironctl security installation-check`.
pub const INSTALLATION_MIGRATION_DOC: &str =
    "docs/TENANT_ISOLATION.md#installation-wide-administration-needs-installation-authority";

/// Body of the 403 / `PERMISSION_DENIED` an admin key gets on an
/// installation-wide operation under enforcement. Names only the remedy, never
/// the tenant or the rows involved.
pub const INSTALLATION_DENIED_MESSAGE: &str = "installation-wide operation requires the \
'installation:admin' capability for tenant-bound admin keys; run `chironctl security \
installation-check --rbac-config-file <file>` or see \
docs/TENANT_ISOLATION.md#installation-wide-administration-needs-installation-authority";

/// Why an `admin` key will be refused installation-wide operations once
/// tenant enforcement is `enforced`. Mirrors [`authorize_installation`]; the
/// unit tests pin the two together.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallationGap {
    /// Tenant-bound without `installation:admin`: every installation-wide
    /// operation is refused.
    MissingCapability,
    /// Has installation authority but an `allowed_collections` list: the
    /// operations without a collection (snapshot, restore, shard move,
    /// metrics, event streams) are refused.
    CollectionAllowlist,
}

impl InstallationGap {
    /// The one-line fix, identical in the scan tool and the dry-run warning.
    pub fn fix(self) -> &'static str {
        match self {
            Self::MissingCapability => {
                "add \"installation:admin\" to this key's capabilities, or remove its tenant_id"
            }
            Self::CollectionAllowlist => {
                "remove allowed_collections from this key, or use a separate operator key \
                 for snapshot/restore/shard move/metrics"
            }
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingCapability => "missing_installation_capability",
            Self::CollectionAllowlist => "collection_allowlist",
        }
    }
}

/// The top-level RBAC configuration loaded from a JSON file.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RbacConfig {
    pub keys: Vec<ApiKeyEntry>,
}

impl RbacConfig {
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read rbac config {}: {e}", path.display()))?;
        let config: Self = serde_json::from_str(&raw)
            .map_err(|e| format!("failed to parse rbac config {}: {e}", path.display()))?;
        config.validate(false)?;
        Ok(config)
    }

    /// Validate identities and grants before any listener is admitted.
    ///
    /// `require_ids` is enabled for secure deployments. Loopback-only
    /// compatibility mode may omit an id; the principal then receives a
    /// deterministic, non-secret fingerprint and a startup warning.
    pub fn validate(&self, require_ids: bool) -> Result<(), String> {
        let mut keys = HashSet::new();
        let mut ids = HashSet::new();
        for entry in &self.keys {
            if entry.key.len() < 32 {
                return Err(format!(
                    "RBAC key for principal {:?} is weak: at least 32 bytes are required",
                    entry.id
                ));
            }
            if !keys.insert(entry.key.as_str()) {
                return Err("duplicate API key in RBAC config".to_string());
            }
            match entry.id.as_deref() {
                Some(id) if valid_identifier(id) => {
                    if !ids.insert(id) {
                        return Err(format!("duplicate principal id in RBAC config: {id}"));
                    }
                }
                Some(id) => return Err(format!("invalid principal id in RBAC config: {id}")),
                None if require_ids => {
                    return Err("RBAC principal id is required for secure deployment".to_string());
                }
                None => {}
            }
            if let Some(tenant_id) = entry.tenant_id.as_deref()
                && !valid_identifier(tenant_id)
            {
                return Err(format!("invalid tenant id in RBAC config: {tenant_id}"));
            }
            for collection in &entry.allowed_collections {
                if !valid_collection_name(collection) {
                    return Err(format!(
                        "invalid collection name in RBAC allowlist: {collection}"
                    ));
                }
            }
            for capability in &entry.capabilities {
                if TenantCapability::parse(capability).is_none()
                    && GraphCapability::parse(capability).is_none()
                    && capability != INSTALLATION_ADMIN_CAPABILITY
                {
                    return Err(format!("unknown RBAC capability: {capability}"));
                }
            }
        }
        Ok(())
    }

    /// Returns the `ApiKeyEntry` for `candidate`, or `None` if not found.
    /// Comparison is done in constant time to prevent timing attacks.
    pub fn find_key(&self, candidate: &str) -> Option<&ApiKeyEntry> {
        self.keys
            .iter()
            .find(|entry| entry.key.as_bytes().ct_eq(candidate.as_bytes()).unwrap_u8() == 1)
    }
}

/// The resolved access policy for a successfully authenticated principal.
#[derive(Clone, Debug)]
pub struct Principal {
    pub id: String,
    pub role: Role,
    pub tenant_id: Option<String>,
    pub max_collections: Option<usize>,
    allowed: CollectionAccess,
    tenant_capabilities: Vec<TenantCapability>,
    graph_capabilities: Vec<GraphCapability>,
    installation_admin: bool,
}

#[derive(Clone, Debug)]
enum CollectionAccess {
    All,
    Restricted(HashSet<String>),
}

/// Compatibility name retained for internal callers while the protocol
/// façades migrate to the principal terminology.
pub type Permission = Principal;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Read,
    Write,
    Admin,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationError {
    InsufficientRole,
    MissingGraphCapability(GraphCapability),
    CollectionDenied,
    /// The operation spans every tenant of the installation, and the
    /// principal is bound to one tenant without `installation:admin`.
    InstallationAuthorityRequired,
}

pub fn authorize(
    principal: &Principal,
    action: Action,
    collection: Option<&str>,
) -> Result<(), AuthorizationError> {
    let role_allowed = match action {
        Action::Read => true,
        Action::Write => principal.allows_write(),
        Action::Admin => principal.allows_admin(),
    };
    if !role_allowed {
        return Err(AuthorizationError::InsufficientRole);
    }
    if let Some(collection) = collection
        && !principal.allows_collection(collection)
    {
        return Err(AuthorizationError::CollectionDenied);
    }
    Ok(())
}

/// Authorize an installation-wide operation: snapshot, restore, collection
/// deletion, payload-schema change, compaction and other whole-collection
/// maintenance, shard moves, and installation metrics/event streams.
///
/// Collections are a global namespace whose rows carry a `tenant_id`, so these
/// operations act on every tenant's rows at once. Beyond the `admin` role they
/// therefore require installation authority while tenant enforcement blocks:
/// a key with no `tenant_id`, or one granted `installation:admin`. With
/// enforcement `disabled` or `dry_run` the admin role alone suffices, exactly
/// as before (dry-run logs the would-be denial).
pub fn authorize_installation(
    principal: &Principal,
    enforcement: TenantEnforcement,
    collection: Option<&str>,
    operation: &str,
) -> Result<(), AuthorizationError> {
    authorize(principal, Action::Admin, collection)?;
    // An operation with no collection (snapshot, restore, shard move,
    // metrics) reaches every collection, which a collection allowlist does
    // not grant.
    let whole_installation_denied = collection.is_none() && principal.is_restricted();
    if principal.has_installation_authority() && !whole_installation_denied {
        return Ok(());
    }
    if enforcement.blocks() {
        return Err(AuthorizationError::InstallationAuthorityRequired);
    }
    if enforcement.active() {
        let gap = if principal.has_installation_authority() {
            InstallationGap::CollectionAllowlist
        } else {
            InstallationGap::MissingCapability
        };
        tracing::warn!(
            principal = %principal.id,
            tenant = principal.tenant_id.as_deref().unwrap_or_default(),
            operation,
            reason = gap.as_str(),
            fix = gap.fix(),
            doc = INSTALLATION_MIGRATION_DOC,
            "tenant dry-run: installation-wide operation would be denied under enforcement"
        );
    }
    Ok(())
}

/// Authorize one topology operation independently from the principal's point
/// role. Protocol handlers combine this with point authorization only when an
/// operation also reads or mutates point data.
pub fn authorize_graph(
    principal: &Principal,
    capability: GraphCapability,
    collection: &str,
) -> Result<(), AuthorizationError> {
    let role_allowed = match capability {
        GraphCapability::Read => true,
        GraphCapability::Write | GraphCapability::TypeConfigure => principal.allows_write(),
        GraphCapability::Admin => principal.allows_admin(),
    };
    if !role_allowed {
        return Err(AuthorizationError::InsufficientRole);
    }
    if !principal.has_graph_capability(capability) {
        return Err(AuthorizationError::MissingGraphCapability(capability));
    }
    if !principal.allows_collection(collection) {
        return Err(AuthorizationError::CollectionDenied);
    }
    Ok(())
}

impl Principal {
    /// A full-access permission used when RBAC is disabled.
    pub fn unrestricted() -> Self {
        Self {
            id: "local-unrestricted".to_string(),
            role: Role::Admin,
            tenant_id: None,
            max_collections: None,
            allowed: CollectionAccess::All,
            // RBAC disabled means there are no tenants to separate, so this
            // principal may reach everything. Under enforcement an operator is
            // expected to have configured real keys.
            tenant_capabilities: vec![TenantCapability::CrossRead, TenantCapability::CrossWrite],
            graph_capabilities: vec![
                GraphCapability::Read,
                GraphCapability::Write,
                GraphCapability::Admin,
                GraphCapability::TypeConfigure,
            ],
            installation_admin: true,
        }
    }

    pub fn unrestricted_for(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ..Self::unrestricted()
        }
    }

    pub fn from_entry(entry: &ApiKeyEntry) -> Self {
        let allowed = if entry.allowed_collections.is_empty() {
            CollectionAccess::All
        } else {
            CollectionAccess::Restricted(entry.allowed_collections.iter().cloned().collect())
        };
        let tenant_capabilities = entry
            .capabilities
            .iter()
            .filter_map(|name| TenantCapability::parse(name))
            .collect();
        let graph_capabilities = entry
            .capabilities
            .iter()
            .filter_map(|name| GraphCapability::parse(name))
            .collect();

        Self {
            id: entry
                .id
                .clone()
                .unwrap_or_else(|| legacy_principal_id(&entry.key)),
            role: entry.role,
            tenant_id: entry.tenant_id.clone(),
            max_collections: entry.max_collections,
            allowed,
            tenant_capabilities,
            graph_capabilities,
            installation_admin: entry
                .capabilities
                .iter()
                .any(|name| name == INSTALLATION_ADMIN_CAPABILITY),
        }
    }

    /// Returns `true` when this permission is scoped to a specific set of
    /// collections (i.e. `allowed_collections` was non-empty in the config).
    pub fn is_restricted(&self) -> bool {
        matches!(self.allowed, CollectionAccess::Restricted(_))
    }

    /// The collections this permission is scoped to. Empty when unrestricted
    /// — callers should check [`Self::is_restricted`] first.
    pub fn allowed_collections(&self) -> Vec<String> {
        match &self.allowed {
            CollectionAccess::All => Vec::new(),
            CollectionAccess::Restricted(set) => set.iter().cloned().collect(),
        }
    }

    /// Returns `true` if this permission may access `collection`.
    pub fn allows_collection(&self, collection: &str) -> bool {
        match &self.allowed {
            CollectionAccess::All => true,
            CollectionAccess::Restricted(set) => set.contains(collection),
        }
    }

    pub fn allows_write(&self) -> bool {
        self.role.allows_write()
    }

    pub fn allows_admin(&self) -> bool {
        self.role.allows_admin()
    }

    pub fn has_capability(&self, capability: TenantCapability) -> bool {
        self.tenant_capabilities.contains(&capability)
    }

    pub fn has_graph_capability(&self, capability: GraphCapability) -> bool {
        self.graph_capabilities.contains(&capability)
    }

    /// Whether this principal may administer the whole installation rather
    /// than one tenant: the `admin` role plus either no tenant binding or the
    /// explicit `installation:admin` capability.
    pub fn has_installation_authority(&self) -> bool {
        self.allows_admin() && (self.tenant_id.is_none() || self.installation_admin)
    }

    /// What, if anything, stops this `admin` key from running installation-wide
    /// operations under `enforced`. `None` for non-admin keys: they were never
    /// allowed these operations, so the upgrade changes nothing for them.
    pub fn installation_gap(&self) -> Option<InstallationGap> {
        if !self.allows_admin() {
            None
        } else if !self.has_installation_authority() {
            Some(InstallationGap::MissingCapability)
        } else if self.is_restricted() {
            Some(InstallationGap::CollectionAllowlist)
        } else {
            None
        }
    }

    /// Whether installation-wide aggregates (row totals across tenants) may be
    /// shown to this principal under `enforcement`.
    pub fn sees_installation_aggregates(&self, enforcement: TenantEnforcement) -> bool {
        !enforcement.blocks()
            || self.has_installation_authority()
            || self.has_capability(TenantCapability::CrossRead)
    }

    /// The tenant scope this principal acts under.
    ///
    /// Everything the core needs to decide what these credentials may reach:
    /// the tenant itself, the cross-tenant capabilities, and an actor name for
    /// the audit record. Built here so no request handler has to assemble it,
    /// and so it can never be assembled from anything the caller sent.
    pub fn tenant_scope(&self, actor: impl Into<String>) -> TenantScope {
        let scope = match &self.tenant_id {
            Some(tenant_id) => TenantScope::tenant(actor, tenant_id),
            None => TenantScope::untenanted(actor),
        };
        scope
            .with_capabilities(self.tenant_capabilities.iter().copied())
            .with_graph_capabilities(self.graph_capabilities.iter().copied())
    }

    pub fn rate_limit_key(&self) -> &str {
        self.tenant_id.as_deref().unwrap_or(&self.id)
    }
}

pub(crate) fn legacy_principal_id(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    format!("legacy-key-{}", hex_prefix(&digest, 8))
}

fn hex_prefix(bytes: &[u8], len: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(len * 2);
    for byte in bytes.iter().take(len) {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0x0f) as usize] as char);
    }
    value
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':'))
}

fn valid_collection_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn role_ordering() {
        assert!(Role::Admin > Role::ReadWrite);
        assert!(Role::ReadWrite > Role::ReadOnly);
        assert!(Role::Admin.allows_write());
        assert!(Role::Admin.allows_admin());
        assert!(Role::ReadWrite.allows_write());
        assert!(!Role::ReadWrite.allows_admin());
        assert!(!Role::ReadOnly.allows_write());
        assert!(!Role::ReadOnly.allows_admin());
    }

    #[test]
    fn permission_unrestricted_allows_all_collections() {
        let perm = Permission::unrestricted();
        assert!(perm.allows_collection("any-collection"));
        assert!(perm.allows_collection("another"));
        assert!(perm.allows_write());
        assert!(perm.allows_admin());
    }

    #[test]
    fn permission_restricted_allows_only_listed_collections() {
        let entry = ApiKeyEntry {
            id: Some("writer".to_string()),
            key: "key".to_string(),
            tenant_id: None,
            role: Role::ReadWrite,
            allowed_collections: vec!["allowed-col".to_string()],
            max_collections: None,
            capabilities: Vec::new(),
        };
        let perm = Permission::from_entry(&entry);
        assert!(perm.allows_collection("allowed-col"));
        assert!(!perm.allows_collection("other-col"));
        assert!(perm.allows_write());
        assert!(!perm.allows_admin());
    }

    #[test]
    fn permission_empty_allowlist_allows_all() {
        let entry = ApiKeyEntry {
            id: Some("reader".to_string()),
            key: "key".to_string(),
            tenant_id: Some("tenant-a".to_string()),
            role: Role::ReadOnly,
            allowed_collections: vec![],
            max_collections: None,
            capabilities: Vec::new(),
        };
        let perm = Permission::from_entry(&entry);
        assert!(perm.allows_collection("anything"));
        assert_eq!(perm.tenant_id.as_deref(), Some("tenant-a"));
        assert!(!perm.allows_write());
    }

    #[test]
    fn rbac_config_find_key_constant_time() {
        let config = RbacConfig {
            keys: vec![
                ApiKeyEntry {
                    id: Some("admin".to_string()),
                    key: "secret-a".to_string(),
                    tenant_id: Some("ta".to_string()),
                    role: Role::Admin,
                    allowed_collections: vec![],
                    max_collections: None,
                    capabilities: Vec::new(),
                },
                ApiKeyEntry {
                    id: Some("reader".to_string()),
                    key: "secret-b".to_string(),
                    tenant_id: None,
                    role: Role::ReadOnly,
                    allowed_collections: vec!["col1".to_string()],
                    max_collections: None,
                    capabilities: Vec::new(),
                },
            ],
        };

        let entry_a = config.find_key("secret-a").unwrap();
        assert_eq!(entry_a.tenant_id.as_deref(), Some("ta"));
        assert_eq!(entry_a.role, Role::Admin);

        let entry_b = config.find_key("secret-b").unwrap();
        assert_eq!(entry_b.role, Role::ReadOnly);
        assert_eq!(entry_b.allowed_collections, vec!["col1"]);

        assert!(config.find_key("unknown").is_none());
    }

    #[test]
    fn rbac_config_loads_from_json_file() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("rbac.json");
        std::fs::write(
            &path,
            r#"{
                "keys": [
                    {
                        "id": "admin",
                        "key": "admin-key-that-is-at-least-32-bytes-long",
                        "tenant_id": "ops",
                        "role": "admin"
                    },
                    {
                        "id": "reader",
                        "key": "reader-key-that-is-at-least-32-bytes-long",
                        "role": "read_only",
                        "allowed_collections": ["public"]
                    }
                ]
            }"#,
        )
        .unwrap();

        let config = RbacConfig::load_from_file(&path).unwrap();
        assert_eq!(config.keys.len(), 2);

        let admin = config
            .find_key("admin-key-that-is-at-least-32-bytes-long")
            .unwrap();
        assert_eq!(admin.role, Role::Admin);
        assert_eq!(admin.tenant_id.as_deref(), Some("ops"));
        assert!(admin.allowed_collections.is_empty());

        let reader = config
            .find_key("reader-key-that-is-at-least-32-bytes-long")
            .unwrap();
        assert_eq!(reader.role, Role::ReadOnly);
        assert_eq!(reader.allowed_collections, vec!["public"]);
    }

    #[test]
    fn rbac_config_load_rejects_bad_json() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("bad.json");
        std::fs::write(&path, "not json").unwrap();
        assert!(RbacConfig::load_from_file(&path).is_err());
    }

    #[test]
    fn secure_rbac_validation_rejects_ambiguous_or_unsafe_entries() {
        fn entry(id: Option<&str>, key: &str) -> ApiKeyEntry {
            ApiKeyEntry {
                id: id.map(str::to_string),
                key: key.to_string(),
                tenant_id: Some("tenant-a".to_string()),
                role: Role::ReadWrite,
                allowed_collections: vec!["docs".to_string()],
                max_collections: Some(2),
                capabilities: Vec::new(),
            }
        }

        let key_a = "a".repeat(32);
        let key_b = "b".repeat(32);
        let cases = [
            (
                RbacConfig {
                    keys: vec![entry(None, &key_a)],
                },
                "principal id is required",
            ),
            (
                RbacConfig {
                    keys: vec![entry(Some("one"), "short")],
                },
                "is weak",
            ),
            (
                RbacConfig {
                    keys: vec![entry(Some("one"), &key_a), entry(Some("two"), &key_a)],
                },
                "duplicate API key",
            ),
            (
                RbacConfig {
                    keys: vec![entry(Some("same"), &key_a), entry(Some("same"), &key_b)],
                },
                "duplicate principal id",
            ),
            (
                RbacConfig {
                    keys: vec![entry(Some("invalid id"), &key_a)],
                },
                "invalid principal id",
            ),
        ];
        for (config, message) in cases {
            let error = config.validate(true).unwrap_err();
            assert!(error.contains(message), "{error}");
        }

        let mut invalid_collection = entry(Some("one"), &key_a);
        invalid_collection.allowed_collections = vec!["invalid/name".to_string()];
        assert!(
            RbacConfig {
                keys: vec![invalid_collection]
            }
            .validate(true)
            .unwrap_err()
            .contains("invalid collection name")
        );

        let mut invalid_capability = entry(Some("one"), &key_a);
        invalid_capability.capabilities = vec!["tenant:become_root".to_string()];
        assert!(
            RbacConfig {
                keys: vec![invalid_capability]
            }
            .validate(true)
            .unwrap_err()
            .contains("unknown RBAC capability")
        );
    }

    #[test]
    fn permission_allows_collection_list_filtering() {
        let entry = ApiKeyEntry {
            id: Some("cross-reader".to_string()),
            key: "k".to_string(),
            tenant_id: None,
            role: Role::ReadOnly,
            allowed_collections: vec!["col-a".to_string()],
            max_collections: None,
            capabilities: Vec::new(),
        };
        let perm = Permission::from_entry(&entry);
        assert!(perm.allows_collection("col-a"));
        assert!(!perm.allows_collection("col-b"));
    }

    #[test]
    fn rbac_config_max_collections_field() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("rbac.json");
        std::fs::write(
            &path,
            r#"{
                "keys": [
                    {
                        "id": "tenant",
                        "key": "tenant-key-that-is-at-least-32-bytes-long",
                        "role": "read_write",
                        "max_collections": 2
                    }
                ]
            }"#,
        )
        .unwrap();
        let config = RbacConfig::load_from_file(&path).unwrap();
        let entry = config
            .find_key("tenant-key-that-is-at-least-32-bytes-long")
            .unwrap();
        assert_eq!(entry.max_collections, Some(2));
    }

    #[test]
    fn graph_capabilities_are_validated_and_resolved_separately() {
        let entry = ApiKeyEntry {
            id: Some("graph-writer".to_string()),
            key: "graph-writer-key-that-is-at-least-32-bytes".to_string(),
            tenant_id: Some("tenant-a".to_string()),
            role: Role::ReadWrite,
            allowed_collections: vec!["docs".to_string()],
            max_collections: None,
            capabilities: vec![
                "tenant:cross_read".to_string(),
                "graph:read".to_string(),
                "graph:write".to_string(),
                "graph:type_configure".to_string(),
            ],
        };
        RbacConfig {
            keys: vec![entry.clone()],
        }
        .validate(true)
        .unwrap();

        let principal = Principal::from_entry(&entry);
        assert!(principal.has_capability(TenantCapability::CrossRead));
        assert!(!principal.has_capability(TenantCapability::CrossWrite));
        assert!(principal.has_graph_capability(GraphCapability::Read));
        assert!(principal.has_graph_capability(GraphCapability::Write));
        assert!(principal.has_graph_capability(GraphCapability::TypeConfigure));
        assert!(!principal.has_graph_capability(GraphCapability::Admin));
    }

    #[test]
    fn point_roles_never_imply_topology_permissions() {
        fn principal(role: Role, capabilities: &[&str]) -> Principal {
            Principal::from_entry(&ApiKeyEntry {
                id: Some("principal".to_string()),
                key: "key".to_string(),
                tenant_id: Some("tenant-a".to_string()),
                role,
                allowed_collections: vec!["docs".to_string()],
                max_collections: None,
                capabilities: capabilities
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            })
        }

        let point_admin = principal(Role::Admin, &[]);
        assert_eq!(
            authorize_graph(&point_admin, GraphCapability::Admin, "docs"),
            Err(AuthorizationError::MissingGraphCapability(
                GraphCapability::Admin
            ))
        );

        let graph_writer_with_read_only_role = principal(Role::ReadOnly, &["graph:write"]);
        assert_eq!(
            authorize_graph(
                &graph_writer_with_read_only_role,
                GraphCapability::Write,
                "docs"
            ),
            Err(AuthorizationError::InsufficientRole)
        );

        let graph_writer = principal(Role::ReadWrite, &["graph:write"]);
        assert_eq!(
            authorize_graph(&graph_writer, GraphCapability::Write, "docs"),
            Ok(())
        );
        assert_eq!(
            authorize_graph(&graph_writer, GraphCapability::Write, "other"),
            Err(AuthorizationError::CollectionDenied)
        );

        let graph_admin = principal(Role::Admin, &["graph:admin"]);
        assert_eq!(
            authorize_graph(&graph_admin, GraphCapability::Admin, "docs"),
            Ok(())
        );
        assert_eq!(
            authorize_graph(&graph_admin, GraphCapability::Read, "docs"),
            Err(AuthorizationError::MissingGraphCapability(
                GraphCapability::Read
            ))
        );
    }

    #[test]
    fn installation_operations_need_installation_authority_under_enforcement() {
        fn principal(
            tenant: Option<&str>,
            role: Role,
            allowed: &[&str],
            caps: &[&str],
        ) -> Principal {
            Principal::from_entry(&ApiKeyEntry {
                id: Some("principal".to_string()),
                key: "key".to_string(),
                tenant_id: tenant.map(str::to_string),
                role,
                allowed_collections: allowed.iter().map(|value| value.to_string()).collect(),
                max_collections: None,
                capabilities: caps.iter().map(|value| value.to_string()).collect(),
            })
        }
        let enforced = TenantEnforcement::Enforced;
        let tenant_admin = principal(Some("tenant-b"), Role::Admin, &[], &[]);
        let cross_tenant_admin = principal(
            Some("tenant-b"),
            Role::Admin,
            &[],
            &["tenant:cross_read", "tenant:cross_write"],
        );
        let installation_admin = principal(
            Some("tenant-b"),
            Role::Admin,
            &[],
            &[INSTALLATION_ADMIN_CAPABILITY],
        );
        let operator = principal(None, Role::Admin, &[], &[]);
        let scoped_operator = principal(None, Role::Admin, &["docs"], &[]);
        let writer = principal(None, Role::ReadWrite, &[], &[INSTALLATION_ADMIN_CAPABILITY]);

        for collection in [None, Some("docs")] {
            for principal in [&tenant_admin, &cross_tenant_admin] {
                assert_eq!(
                    authorize_installation(principal, enforced, collection, "test"),
                    Err(AuthorizationError::InstallationAuthorityRequired)
                );
            }
            assert_eq!(
                authorize_installation(&writer, enforced, collection, "test"),
                Err(AuthorizationError::InsufficientRole)
            );
            for principal in [&installation_admin, &operator] {
                assert_eq!(
                    authorize_installation(principal, enforced, collection, "test"),
                    Ok(())
                );
            }
            assert_eq!(
                authorize_installation(&Principal::unrestricted(), enforced, collection, "test"),
                Ok(())
            );
        }
        assert_eq!(
            authorize_installation(&scoped_operator, enforced, Some("docs"), "test"),
            Ok(())
        );
        assert_eq!(
            authorize_installation(&scoped_operator, enforced, None, "test"),
            Err(AuthorizationError::InstallationAuthorityRequired)
        );

        // The migration scan reports exactly the keys enforcement refuses.
        for principal in [
            &tenant_admin,
            &cross_tenant_admin,
            &installation_admin,
            &operator,
            &scoped_operator,
            &writer,
        ] {
            let gap = principal.installation_gap();
            let whole = authorize_installation(principal, enforced, None, "test");
            let scoped = authorize_installation(principal, enforced, Some("docs"), "test");
            match gap {
                None => assert!(
                    whole.is_ok() || whole == Err(AuthorizationError::InsufficientRole),
                    "{}",
                    principal.id
                ),
                Some(InstallationGap::MissingCapability) => {
                    assert_eq!(
                        whole,
                        Err(AuthorizationError::InstallationAuthorityRequired)
                    );
                    assert_eq!(
                        scoped,
                        Err(AuthorizationError::InstallationAuthorityRequired)
                    );
                }
                Some(InstallationGap::CollectionAllowlist) => {
                    assert_eq!(
                        whole,
                        Err(AuthorizationError::InstallationAuthorityRequired)
                    );
                    assert_eq!(scoped, Ok(()));
                }
            }
        }
        assert_eq!(
            tenant_admin.installation_gap(),
            Some(InstallationGap::MissingCapability)
        );
        assert_eq!(
            cross_tenant_admin.installation_gap(),
            Some(InstallationGap::MissingCapability)
        );
        assert_eq!(installation_admin.installation_gap(), None);
        assert_eq!(operator.installation_gap(), None);
        assert_eq!(
            scoped_operator.installation_gap(),
            Some(InstallationGap::CollectionAllowlist)
        );
        assert_eq!(writer.installation_gap(), None);
        assert!(INSTALLATION_DENIED_MESSAGE.contains(INSTALLATION_ADMIN_CAPABILITY));
        assert!(INSTALLATION_DENIED_MESSAGE.contains(INSTALLATION_MIGRATION_DOC));

        // Disabled and dry-run keep the historical role-only rule.
        for mode in [TenantEnforcement::Disabled, TenantEnforcement::DryRun] {
            assert_eq!(
                authorize_installation(&tenant_admin, mode, None, "test"),
                Ok(())
            );
            assert_eq!(
                authorize_installation(&scoped_operator, mode, None, "test"),
                Ok(())
            );
            assert_eq!(
                authorize_installation(&writer, mode, None, "test"),
                Err(AuthorizationError::InsufficientRole)
            );
        }

        RbacConfig {
            keys: vec![ApiKeyEntry {
                id: Some("ops".to_string()),
                key: "k".repeat(32),
                tenant_id: Some("tenant-b".to_string()),
                role: Role::Admin,
                allowed_collections: Vec::new(),
                max_collections: None,
                capabilities: vec![INSTALLATION_ADMIN_CAPABILITY.to_string()],
            }],
        }
        .validate(true)
        .expect("installation:admin is a known capability");
    }

    #[test]
    fn unrestricted_principal_has_every_graph_capability() {
        let principal = Principal::unrestricted();
        for capability in [
            GraphCapability::Read,
            GraphCapability::Write,
            GraphCapability::Admin,
            GraphCapability::TypeConfigure,
        ] {
            assert_eq!(
                authorize_graph(&principal, capability, "any-collection"),
                Ok(())
            );
        }
    }
}
