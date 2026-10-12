//! Durable identity outside content generations. No plaintext credential storage.
use super::{policy, *};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use parking_lot::{Mutex, RwLock};
use ring::{
    digest, hmac, pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use uuid::Uuid;

type Result<T> = std::result::Result<T, SecurityError>;
const IDENTITY_FILE: &str = "identity.v1";
// Keep the mandatory old-reader path, replace its envelope. An old binary
// cannot accidentally find a still-valid v1 authority beside the new one.
const IDENTITY_MAGIC: &[u8; 8] = b"CHRNID02";
const IDENTITY_VERSION: u32 = 2;
const INSTALLATION_IDENTITY_MAGIC: &[u8; 8] = b"CHRNID03";
const SQL_IDENTITY_MAGIC: &[u8; 8] = b"CHRNID04";
const TABLE_IDENTITY_MAGIC: &[u8; 8] = b"CHRNID05";
const STRICT_SQL_IDENTITY_MAGIC: &[u8; 8] = b"CHRNID06";
const SQL_SCRAM_ITERATIONS: u32 = 4096;
const MAX_IDENTITY_BYTES: u64 = 16 * 1024 * 1024;
const REVOCATION_TIMEOUT: Duration = Duration::from_secs(30);

mod administration;
#[cfg(test)]
mod administration_tests;
pub mod onboarding;
mod table_authority;

/// An epoch never reopens after revocation. Old handles cannot revive after ABA.
#[derive(Debug)]
pub(crate) struct Epoch {
    revision: u64,
    closed: AtomicBool,
    active: AtomicUsize,
}

impl Epoch {
    pub(crate) fn new(revision: u64) -> Arc<Self> {
        Arc::new(Self {
            revision,
            closed: AtomicBool::new(false),
            active: AtomicUsize::new(0),
        })
    }
    pub(crate) fn enter(self: &Arc<Self>) -> Result<PublicationPermit> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SecurityError::Conflict);
        }
        self.active.fetch_add(1, Ordering::SeqCst);
        let permit = PublicationPermit(Arc::clone(self));
        // Pairs with close_and_drain: a racing admission either belongs to the
        // old active set or observes closure before it may publish/commit.
        if self.closed.load(Ordering::SeqCst) {
            return Err(SecurityError::Conflict);
        }
        Ok(permit)
    }
    pub(crate) fn close_and_drain(&self) -> Result<()> {
        self.close();
        let started = Instant::now();
        while self.active.load(Ordering::SeqCst) != 0 {
            if started.elapsed() >= REVOCATION_TIMEOUT {
                return Err(SecurityError::Unavailable);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
    pub(crate) fn cancelled(&self) -> &AtomicBool {
        &self.closed
    }
}

/// Lightweight read-only cancellation handle. Retains only the authority epoch,
/// without copying principal, role, or credential data.
#[derive(Clone, Debug)]
pub struct IdentityCancellation(Arc<Epoch>);
impl IdentityCancellation {
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled().load(Ordering::Acquire)
    }
}

/// Hold through the actual commit or transport publication, not merely lookup.
#[derive(Debug)]
pub struct PublicationPermit(Arc<Epoch>);
impl Drop for PublicationPermit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Debug)]
pub struct AuthenticatedIdentity {
    principal: PrincipalRecord,
    user_name: String,
    roles: Vec<RoleRecord>,
    groups: BTreeSet<String>,
    credential_id: String,
    epoch: Arc<Epoch>,
    installation_admin: bool,
    table_authority: bool,
    strict_sql_scopes: bool,
}
impl AuthenticatedIdentity {
    pub fn user_name(&self) -> &str {
        &self.user_name
    }
    pub fn roles(&self) -> &[RoleRecord] {
        &self.roles
    }
    pub fn principal(&self) -> &PrincipalRecord {
        &self.principal
    }
    pub fn is_installation_admin(&self) -> bool {
        self.installation_admin && self.allows_installation(Action::IdentityManage)
    }

    /// Mint only after the Db has resolved a current protected incarnation.
    pub(crate) fn with_managed_collections(
        &self,
        collections: impl IntoIterator<Item = String>,
    ) -> Self {
        let mut identity = self.clone();
        if identity.is_installation_admin() {
            // A transport may already have expanded this same verified catalog.
            // Do not duplicate scopes or alter durable content grants.
            for collection in collections {
                let scope = ScopeGrant {
                    tenants: BTreeSet::from([identity.principal.tenant.clone()]),
                    collections: BTreeSet::from([collection.clone()]),
                    actions: BTreeSet::from([
                        Action::Schema,
                        Action::PolicyManage,
                        Action::LabelsManage,
                        Action::GrantsManage,
                    ]),
                };
                if !identity.principal.grants.contains(&scope) {
                    identity.principal.grants.push(scope);
                }
                let scope = ScopeGrant {
                    tenants: BTreeSet::from([identity.principal.tenant.clone()]),
                    collections: BTreeSet::from([collection]),
                    actions: BTreeSet::from([
                        Action::Read,
                        Action::Search,
                        Action::Create,
                        Action::Ingest,
                        Action::Update,
                        Action::Delete,
                        Action::GraphRead,
                        Action::GraphWrite,
                        Action::Schema,
                        Action::PolicyManage,
                        Action::LabelsManage,
                        Action::GrantsManage,
                    ]),
                };
                if !identity.principal.delegation.contains(&scope) {
                    identity.principal.delegation.push(scope);
                }
            }
        }
        identity
    }
    pub(crate) fn supports_table_grants(&self) -> bool {
        self.table_authority
    }

    /// Collection-name capabilities no longer authorize SQL in this mode.
    pub fn has_strict_sql_scopes(&self) -> bool {
        self.strict_sql_scopes
    }

    pub(crate) fn owns_table(&self, tenant: &str, creator: Option<&str>) -> bool {
        self.strict_sql_scopes
            && !self.cancelled().load(Ordering::Acquire)
            && self.principal.enabled
            && self.principal.tenant == tenant
            && creator == Some(self.principal.id.as_str())
    }

    pub(crate) fn allows_table(
        &self,
        tenant: &str,
        table: &str,
        table_id: u64,
        incarnation: Uuid,
        action: Action,
    ) -> bool {
        (!self.strict_sql_scopes && self.allows(tenant, table, action))
            || (!self.cancelled().load(Ordering::Acquire)
                && self.principal.enabled
                && self.principal.tenant == tenant
                && self.roles.iter().any(|role| {
                    role.tenant == tenant
                        && role.table_grants.iter().any(|grant| {
                            grant.table_id == table_id
                                && grant.incarnation == incarnation
                                && grant.actions.contains(&action)
                        })
                }))
    }

    pub fn groups(&self) -> &BTreeSet<String> {
        &self.groups
    }
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }
    pub fn revision(&self) -> u64 {
        self.epoch.revision
    }
    pub fn publication_permit(&self) -> Result<PublicationPermit> {
        self.epoch.enter()
    }
    pub fn cancelled(&self) -> &AtomicBool {
        self.epoch.cancelled()
    }
    pub fn cancellation(&self) -> IdentityCancellation {
        IdentityCancellation(Arc::clone(&self.epoch))
    }
    pub fn allows(&self, tenant: &str, collection: &str, action: Action) -> bool {
        !self.cancelled().load(Ordering::Acquire)
            && (policy::scope_allows(&self.principal, tenant, collection, action)
                || self.roles.iter().any(|role| {
                    role.tenant == tenant
                        && role.grants.iter().any(|grant| {
                            grant.collection == collection && grant.actions.contains(&action)
                        })
                }))
    }
    /// Used only at the final collection binding, where the incarnation is
    /// known. Subsequent checks cannot accidentally use a role's old scope.
    pub(super) fn for_collection(&self, collection: &str, incarnation: Uuid) -> Self {
        let mut identity = self.clone();
        for role in &self.roles {
            for grant in &role.grants {
                if grant.collection == collection && grant.incarnation == incarnation {
                    identity.principal.grants.push(ScopeGrant {
                        tenants: BTreeSet::from([role.tenant.clone()]),
                        collections: BTreeSet::from([collection.into()]),
                        actions: grant.actions.clone(),
                    });
                }
            }
        }
        // Collection binding consumes only collection capabilities. Atomic
        // SQL/vector/graph work still needs the independently bound table
        // grants when it rechecks its relational receipt through this context.
        for role in &mut identity.roles {
            role.grants.clear();
        }
        identity.roles.retain(|role| !role.table_grants.is_empty());
        identity
    }
    pub fn allows_installation(&self, action: Action) -> bool {
        !self.cancelled().load(Ordering::Acquire)
            && self.principal.enabled
            && self.principal.installation_actions.contains(&action)
    }
}
impl PartialEq for AuthenticatedIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.credential_id == other.credential_id && Arc::ptr_eq(&self.epoch, &other.epoch)
    }
}
impl Eq for AuthenticatedIdentity {}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    principal: String,
    sha256: [u8; 32],
    revoked: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SqlCredential {
    principal: String,
    salt: [u8; 16],
    stored_key: [u8; 32],
    server_key: [u8; 32],
    iterations: u32,
    revoked: bool,
}

#[derive(Clone)]
pub struct SqlVerifier {
    pub id: String,
    pub salt: [u8; 16],
    pub stored_key: [u8; 32],
    pub server_key: [u8; 32],
    pub iterations: u32,
}

#[derive(Serialize)]
pub struct IssuedSqlCredential {
    pub id: String,
    pub username: String,
    pub password: String,
    pub revision: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityState {
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    installation: Option<onboarding::Installation>,
    revision: u64,
    principals: BTreeMap<String, PrincipalRecord>,
    groups: BTreeMap<String, GroupRecord>,
    credentials: BTreeMap<String, Credential>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    sql_credentials: BTreeMap<String, SqlCredential>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scram_decoy_key: Option<[u8; 32]>,
    user_names: BTreeMap<String, String>,
    retired_users: BTreeSet<String>,
    roles: BTreeMap<Uuid, RoleRecord>,
    memberships: BTreeMap<String, BTreeSet<Uuid>>,
}
impl IdentityState {
    fn validate(&self) -> Result<()> {
        if !matches!(self.version, IDENTITY_VERSION | 3 | 4 | 5 | 6)
            || self.revision == 0
            || (self.version >= 3) != self.installation.is_some()
            || (self.version < 4 && !self.sql_credentials.is_empty())
            || (self.version >= 4 && self.scram_decoy_key.is_none())
            || (self.version < 4 && self.scram_decoy_key.is_some())
        {
            return Err(SecurityError::Invalid(
                "unsupported identity format or revision".into(),
            ));
        }
        if let Some(installation) = &self.installation {
            installation.validate(self)?;
        }
        for (id, principal) in &self.principals {
            if id != &principal.id {
                return Err(SecurityError::Invalid("principal key mismatch".into()));
            }
            policy::validate_principal(principal)?;
        }
        policy::validate_groups(&self.groups, &self.principals)?;
        self.validate_administration()?;
        for (id, credential) in &self.credentials {
            if Uuid::parse_str(id).is_err()
                || !self.principals.contains_key(&credential.principal)
                || credential.sha256 == [0; 32]
            {
                return Err(SecurityError::Invalid("invalid credential binding".into()));
            }
        }
        let mut active_sql_users = BTreeSet::new();
        for (id, credential) in &self.sql_credentials {
            if Uuid::parse_str(id).is_err()
                || self.credentials.contains_key(id)
                || !self.principals.contains_key(&credential.principal)
                || credential.iterations != SQL_SCRAM_ITERATIONS
                || credential.stored_key == [0; 32]
                || credential.server_key == [0; 32]
                || (!credential.revoked && !active_sql_users.insert(&credential.principal))
            {
                return Err(SecurityError::Invalid(
                    "invalid SQL credential binding".into(),
                ));
            }
        }
        Ok(())
    }
}

struct Current {
    state: IdentityState,
    epoch: Arc<Epoch>,
}

pub struct IdentityAuthority {
    root: PathBuf,
    current: RwLock<Current>,
    /// Only control-plane updates serialize here; data paths never take it.
    update: Mutex<()>,
    audit: Arc<crate::audit::AuditWriter>,
    work: Arc<tokio::sync::Semaphore>,
    frames: Arc<tokio::sync::Semaphore>,
    wire_connections: Arc<tokio::sync::Semaphore>,
    wire_controls: Arc<tokio::sync::Semaphore>,
    _data_dir_lock: Arc<crate::data_dir_lock::DataDirLock>,
}
impl Drop for IdentityAuthority {
    fn drop(&mut self) {
        self.current.get_mut().epoch.close();
    }
}
impl std::fmt::Debug for IdentityAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityAuthority")
            .field("revision", &self.current.read().state.revision)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
pub struct IssuedCredential {
    pub id: String,
    pub secret: String,
    pub revision: u64,
}

impl IdentityAuthority {
    /// Trusted offline bootstrap, protected by the same exclusive lease as Db.
    pub fn bootstrap(data_dir: &Path, bootstrap: PrincipalRecord) -> Result<IssuedCredential> {
        let _lease = crate::data_dir_lock::DataDirLock::acquire(data_dir)
            .map_err(|_| SecurityError::Unavailable)?;
        policy::validate_principal(&bootstrap)?;
        if !bootstrap.enabled
            || !bootstrap
                .installation_actions
                .contains(&Action::IdentityManage)
        {
            return Err(SecurityError::Invalid(
                "bootstrap principal must manage identities".into(),
            ));
        }
        let root = data_dir.join("security");
        if root.exists() {
            return Err(SecurityError::Invalid(
                "security authority already exists".into(),
            ));
        }
        let audit =
            crate::audit::AuditWriter::open(data_dir).map_err(|_| SecurityError::Unavailable)?;
        let intent = audit
            .operation_with_details(
                "security",
                "identity.bootstrap",
                None,
                crate::audit::AuditContext {
                    principal_id: bootstrap.id.clone(),
                    tenant_id: Some(bootstrap.tenant.clone()),
                    transport: "offline".into(),
                    request_id: None,
                },
                serde_json::json!({"identity_revision":1}),
            )
            .map_err(|_| SecurityError::Unavailable)?;
        std::fs::create_dir(&root).map_err(|_| SecurityError::Unavailable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| SecurityError::Unavailable)?;
        }
        let (id, secret, credential) = new_credential(&bootstrap.id)?;
        let state = IdentityState {
            version: IDENTITY_VERSION,
            installation: None,
            revision: 1,
            user_names: BTreeMap::from([(bootstrap.id.clone(), bootstrap.id.clone())]),
            principals: BTreeMap::from([(bootstrap.id.clone(), bootstrap)]),
            groups: BTreeMap::new(),
            credentials: BTreeMap::from([(id.clone(), credential)]),
            sql_credentials: BTreeMap::new(),
            scram_decoy_key: None,
            retired_users: BTreeSet::new(),
            roles: BTreeMap::new(),
            memberships: BTreeMap::new(),
        };
        persist(&root, &state)?;
        intent
            .success(serde_json::json!({"identity_revision":1}))
            .map_err(|_| SecurityError::Unavailable)?;
        Ok(IssuedCredential {
            id,
            secret,
            revision: 1,
        })
    }

    pub fn open(data_dir: &Path) -> Result<Option<Arc<Self>>> {
        let lease = Arc::new(
            crate::data_dir_lock::DataDirLock::acquire(data_dir)
                .map_err(|_| SecurityError::Unavailable)?,
        );
        onboarding::validate_identity_ready(data_dir).map_err(|_| SecurityError::Unavailable)?;
        let audit =
            crate::audit::AuditWriter::open(data_dir).map_err(|_| SecurityError::Unavailable)?;
        Self::open_with_audit(data_dir, audit, lease)
    }

    pub(crate) fn open_with_audit(
        data_dir: &Path,
        audit: Arc<crate::audit::AuditWriter>,
        lease: Arc<crate::data_dir_lock::DataDirLock>,
    ) -> Result<Option<Arc<Self>>> {
        onboarding::validate_identity_ready(data_dir).map_err(|_| SecurityError::Unavailable)?;
        let root = data_dir.join("security");
        let Some(state) = read_state(&root)? else {
            return Ok(None);
        };
        let epoch = Epoch::new(state.revision);
        let profile = crate::resource_profile::current();
        Ok(Some(Arc::new(Self {
            root,
            current: RwLock::new(Current { state, epoch }),
            update: Mutex::new(()),
            audit,
            work: Arc::new(tokio::sync::Semaphore::new(profile.query_workers)),
            frames: Arc::new(tokio::sync::Semaphore::new(
                profile.query_workers.saturating_mul(2).clamp(2, 8),
            )),
            // Idle connections own protocol/TLS state, not query contexts or
            // workers. The active work semaphore above remains the CPU gate.
            wire_connections: Arc::new(tokio::sync::Semaphore::new(512)),
            // A bounded TLS control lane lets existing PostgreSQL sessions
            // cancel work even when all regular connection slots are occupied.
            wire_controls: Arc::new(tokio::sync::Semaphore::new(
                profile.query_workers.clamp(1, 4),
            )),
            _data_dir_lock: lease,
        })))
    }

    pub fn authenticate(&self, token: &str) -> Result<AuthenticatedIdentity> {
        let mut parts = token.split('.');
        if token.len() > 128 || parts.next() != Some("chiron") {
            return Err(SecurityError::Unauthenticated);
        }
        let id = parts.next().ok_or(SecurityError::Unauthenticated)?;
        let secret = parts
            .next()
            .filter(|secret| secret.len() == 43)
            .ok_or(SecurityError::Unauthenticated)?;
        if parts.next().is_some() {
            return Err(SecurityError::Unauthenticated);
        }
        let current = self.current.read();
        if current.epoch.closed.load(Ordering::Acquire) {
            return Err(SecurityError::Unavailable);
        }
        let credential = current
            .state
            .credentials
            .get(id)
            .filter(|credential| !credential.revoked)
            .ok_or(SecurityError::Unauthenticated)?;
        let digest: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
        if !bool::from(digest.ct_eq(&credential.sha256)) {
            return Err(SecurityError::Unauthenticated);
        }
        let principal = current
            .state
            .principals
            .get(&credential.principal)
            .filter(|principal| principal.enabled)
            .ok_or(SecurityError::Unauthenticated)?;
        let groups = policy::expand_groups(principal, &current.state.groups)?;
        let roles: Vec<_> = current
            .state
            .memberships
            .get(&principal.id)
            .into_iter()
            .flatten()
            .filter_map(|id| current.state.roles.get(id))
            .filter(|role| !role.retired)
            .cloned()
            .collect();
        let mut principal = principal.clone();
        for role in &roles {
            principal
                .installation_actions
                .extend(&role.installation_actions);
        }
        Ok(AuthenticatedIdentity {
            table_authority: current.state.version >= 5,
            strict_sql_scopes: current.state.version >= 6,
            installation_admin: current
                .state
                .installation
                .as_ref()
                .is_some_and(|i| i.admin_id == principal.id),
            user_name: current.state.user_name(&principal.id)?.into(),
            principal,
            roles,
            groups,
            credential_id: id.to_string(),
            epoch: Arc::clone(&current.epoch),
        })
    }

    /// The startup user is a durable user-name alias. Return no principal
    /// until the PostgreSQL SCRAM proof has been verified by the transport.
    pub fn sql_verifier_for_user(&self, username: &str) -> Option<SqlVerifier> {
        let current = self.current.read();
        if current.epoch.closed.load(Ordering::Acquire) {
            return None;
        }
        let principal_id = current.state.user_names.get(username)?;
        let principal = current.state.principals.get(principal_id)?;
        if !principal.enabled {
            return None;
        }
        current
            .state
            .sql_credentials
            .iter()
            .find_map(|(id, credential)| {
                (credential.principal == *principal_id && !credential.revoked).then(|| {
                    SqlVerifier {
                        id: id.clone(),
                        salt: credential.salt,
                        stored_key: credential.stored_key,
                        server_key: credential.server_key,
                        iterations: credential.iterations,
                    }
                })
            })
    }

    /// Synthetic verifier prevents the SCRAM challenge from revealing whether
    /// a username exists. It is stable across process restarts in v4 stores.
    pub fn sql_decoy_verifier(&self, username: &str) -> SqlVerifier {
        let current = self.current.read();
        let key = current.state.scram_decoy_key.unwrap_or([0u8; 32]);
        let derive = |label: &[u8]| {
            let mut input = Vec::with_capacity(label.len() + username.len());
            input.extend_from_slice(label);
            input.extend_from_slice(username.as_bytes());
            hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), &input)
        };
        let salt_digest = derive(b"salt:");
        SqlVerifier {
            id: String::new(),
            salt: salt_digest.as_ref()[..16].try_into().expect("salt length"),
            stored_key: derive(b"stored:")
                .as_ref()
                .try_into()
                .expect("SHA-256 output"),
            server_key: derive(b"server:")
                .as_ref()
                .try_into()
                .expect("SHA-256 output"),
            iterations: SQL_SCRAM_ITERATIONS,
        }
    }

    /// Re-resolve after proof verification, so rotation and revocation during
    /// the handshake cannot bind a stale SQL session.
    pub fn authenticate_sql(
        &self,
        username: &str,
        credential_id: &str,
    ) -> Result<AuthenticatedIdentity> {
        let current = self.current.read();
        if current.epoch.closed.load(Ordering::Acquire) {
            return Err(SecurityError::Unavailable);
        }
        let credential = current
            .state
            .sql_credentials
            .get(credential_id)
            .filter(|credential| !credential.revoked)
            .ok_or(SecurityError::Unauthenticated)?;
        let principal_id = current
            .state
            .user_names
            .get(username)
            .filter(|id| **id == credential.principal)
            .ok_or(SecurityError::Unauthenticated)?;
        let principal = current
            .state
            .principals
            .get(principal_id)
            .filter(|principal| principal.enabled)
            .ok_or(SecurityError::Unauthenticated)?;
        let groups = policy::expand_groups(principal, &current.state.groups)?;
        let roles: Vec<_> = current
            .state
            .memberships
            .get(principal_id)
            .into_iter()
            .flatten()
            .filter_map(|id| current.state.roles.get(id))
            .filter(|role| !role.retired)
            .cloned()
            .collect();
        let mut principal = principal.clone();
        for role in &roles {
            principal
                .installation_actions
                .extend(&role.installation_actions);
        }
        Ok(AuthenticatedIdentity {
            table_authority: current.state.version >= 5,
            strict_sql_scopes: current.state.version >= 6,
            installation_admin: current
                .state
                .installation
                .as_ref()
                .is_some_and(|i| i.admin_id == principal.id),
            user_name: username.into(),
            principal,
            roles,
            groups,
            credential_id: credential_id.into(),
            epoch: Arc::clone(&current.epoch),
        })
    }

    pub fn revision(&self) -> u64 {
        self.current.read().state.revision
    }
    pub(crate) fn with_frontier_lock<T>(
        &self,
        deadline: Instant,
        operation: impl FnOnce() -> crate::Result<T>,
    ) -> crate::Result<T> {
        if Instant::now() >= deadline {
            return Err(crate::GaussError::ResourceExhausted(
                "common frontier authority deadline".into(),
            ));
        }
        // SQL callers may hold an epoch permit while queued on lifecycle.
        // Never wait here for a revocation that is draining those callers.
        let _update = self.update.try_lock().ok_or_else(|| {
            crate::GaussError::ResourceExhausted("common frontier authority busy".into())
        })?;
        operation()
    }

    pub fn wire_connection_pool(&self) -> Arc<tokio::sync::Semaphore> {
        Arc::clone(&self.wire_connections)
    }

    pub fn wire_control_pool(&self) -> Arc<tokio::sync::Semaphore> {
        Arc::clone(&self.wire_controls)
    }

    pub fn frame_pool(&self) -> Arc<tokio::sync::Semaphore> {
        Arc::clone(&self.frames)
    }

    pub fn work_pool(&self) -> Arc<tokio::sync::Semaphore> {
        Arc::clone(&self.work)
    }
    pub(crate) fn accepts(&self, identity: &AuthenticatedIdentity) -> bool {
        let current = self.current.read();
        Arc::ptr_eq(&current.epoch, &identity.epoch)
            && !current.epoch.closed.load(Ordering::Acquire)
    }

    pub(crate) fn validate_object_subjects(
        &self,
        actor: &AuthenticatedIdentity,
        tenant: &str,
        owner: &str,
        grants: &[ObjectGrant],
    ) -> Result<()> {
        let _lease = actor.publication_permit()?;
        let current = self.current.read();
        if !Arc::ptr_eq(&current.epoch, &actor.epoch) {
            return Err(SecurityError::Unauthenticated);
        }
        if current
            .state
            .principals
            .get(owner)
            .is_none_or(|principal| principal.tenant != tenant)
        {
            return Err(SecurityError::Invalid(
                "unknown or cross-tenant owner".into(),
            ));
        }
        for grant in grants {
            let valid = match &grant.subject {
                Subject::Principal(id) => current
                    .state
                    .principals
                    .get(id)
                    .is_some_and(|principal| principal.tenant == tenant),
                Subject::Group(id) => current
                    .state
                    .groups
                    .get(id)
                    .is_some_and(|group| group.tenant == tenant),
                Subject::Department(id) => policy::identifier(id),
                Subject::Owner => true,
            };
            if !valid {
                return Err(SecurityError::Invalid(
                    "unknown or cross-tenant grant subject".into(),
                ));
            }
        }
        Ok(())
    }

    fn change<T>(
        &self,
        actor: &AuthenticatedIdentity,
        expected: u64,
        operation: &str,
        edit: impl FnOnce(&mut IdentityState) -> Result<T>,
    ) -> Result<(T, u64)> {
        let _update = self.update.lock();
        if !actor.allows_installation(Action::IdentityManage) {
            return Err(SecurityError::Forbidden);
        }
        let (mut next, epoch) = {
            let current = self.current.read();
            if expected != current.state.revision || !Arc::ptr_eq(&actor.epoch, &current.epoch) {
                return Err(SecurityError::Conflict);
            }
            (current.state.clone(), Arc::clone(&current.epoch))
        };
        let result = edit(&mut next)?;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(SecurityError::Unavailable)?;
        next.validate()?;
        let intent = self.audit.operation_with_details("security", operation, None, crate::audit::AuditContext {
            principal_id: actor.principal.id.clone(), tenant_id: Some(actor.principal.tenant.clone()),
            transport: "authority".into(), request_id: None,
        }, serde_json::json!({"identity_revision": expected, "next_identity_revision": next.revision}))
            .map_err(|_| SecurityError::Unavailable)?;
        // A failed drain or persistence leaves this process closed. It must
        // not serve the old permissions after an uncertain control-plane write.
        epoch.close_and_drain()?;
        persist(&self.root, &next)?;
        let revision = next.revision;
        intent
            .success(serde_json::json!({"identity_revision": revision}))
            .map_err(|_| SecurityError::Unavailable)?;
        *self.current.write() = Current {
            state: next,
            epoch: Epoch::new(revision),
        };
        Ok((result, revision))
    }

    pub fn put_principal(
        &self,
        actor: &AuthenticatedIdentity,
        expected: u64,
        principal: PrincipalRecord,
    ) -> Result<u64> {
        if self
            .current
            .read()
            .state
            .installation
            .as_ref()
            .is_some_and(|i| principal.tenant != i.tenant)
        {
            return Err(SecurityError::Forbidden);
        }
        may_manage_principal(actor, &principal)?;
        // Identity management is the trust root, not a delegable tenant role.
        if principal.id != actor.principal.id
            && principal
                .installation_actions
                .contains(&Action::IdentityManage)
        {
            return Err(SecurityError::Forbidden);
        }
        self.change(actor, expected, "identity.put_principal", |state| {
            if state.retired_users.contains(&principal.id) {
                return Err(SecurityError::Forbidden);
            }
            if let Some(previous) = state.principals.get(&principal.id) {
                state.may_manage_user(actor, previous)?;
                if previous.tenant != principal.tenant {
                    return Err(SecurityError::Invalid(
                        "principal tenant is immutable".into(),
                    ));
                }
            }
            if !state.principals.contains_key(&principal.id) {
                if state.user_names.contains_key(&principal.id) {
                    return Err(SecurityError::Conflict);
                }
                state
                    .user_names
                    .insert(principal.id.clone(), principal.id.clone());
            }
            state.principals.insert(principal.id.clone(), principal);
            Ok(())
        })
        .map(|(_, revision)| revision)
    }

    pub fn put_group(
        &self,
        actor: &AuthenticatedIdentity,
        expected: u64,
        group: GroupRecord,
    ) -> Result<u64> {
        if group.tenant != actor.principal.tenant {
            return Err(SecurityError::Forbidden);
        }
        self.change(actor, expected, "identity.put_group", |state| {
            if state
                .groups
                .get(&group.id)
                .is_some_and(|previous| previous.tenant != group.tenant)
            {
                return Err(SecurityError::Invalid("group tenant is immutable".into()));
            }
            state.groups.insert(group.id.clone(), group);
            Ok(())
        })
        .map(|(_, revision)| revision)
    }

    pub fn issue_credential(
        &self,
        actor: &AuthenticatedIdentity,
        expected: u64,
        principal: &str,
    ) -> Result<IssuedCredential> {
        let (id, secret, credential) = new_credential(principal)?;
        let (_, revision) = self.change(actor, expected, "identity.issue_credential", |state| {
            let target = state
                .principals
                .get(principal)
                .ok_or(SecurityError::NotFound)?;
            if target.id != actor.principal.id {
                state.may_manage_user(actor, target)?;
            }
            if !target.enabled {
                return Err(SecurityError::Forbidden);
            }
            state.credentials.insert(id.clone(), credential);
            Ok(())
        })?;
        Ok(IssuedCredential {
            id,
            secret,
            revision,
        })
    }

    /// Issue or rotate the single SQL password for a principal. Its bearer
    /// credentials remain valid and cannot be used as SQL passwords.
    pub fn issue_sql_credential(
        &self,
        actor: &AuthenticatedIdentity,
        expected: u64,
        principal: &str,
    ) -> Result<IssuedSqlCredential> {
        let (id, password, credential) = new_sql_credential(principal)?;
        let (username, revision) =
            self.change(actor, expected, "identity.issue_sql_credential", |state| {
                if state.installation.is_none() {
                    return Err(SecurityError::Forbidden);
                }
                let target = state
                    .principals
                    .get(principal)
                    .ok_or(SecurityError::NotFound)?;
                if target.id != actor.principal.id {
                    state.may_manage_user(actor, target)?;
                }
                if !target.enabled {
                    return Err(SecurityError::Forbidden);
                }
                let username = state.user_name(principal)?.to_string();
                for previous in state
                    .sql_credentials
                    .values_mut()
                    .filter(|previous| previous.principal == principal)
                {
                    previous.revoked = true;
                }
                state.sql_credentials.insert(id.clone(), credential);
                if state.scram_decoy_key.is_none() {
                    let mut key = [0u8; 32];
                    SystemRandom::new()
                        .fill(&mut key)
                        .map_err(|_| SecurityError::Unavailable)?;
                    state.scram_decoy_key = Some(key);
                }
                state.version = state.version.max(4);
                Ok(username)
            })?;
        Ok(IssuedSqlCredential {
            id,
            username,
            password,
            revision,
        })
    }

    pub fn revoke_credential(
        &self,
        actor: &AuthenticatedIdentity,
        expected: u64,
        credential_id: &str,
    ) -> Result<u64> {
        self.change(actor, expected, "identity.revoke_credential", |state| {
            let principal_id = state
                .credentials
                .get(credential_id)
                .map(|credential| credential.principal.as_str())
                .or_else(|| {
                    state
                        .sql_credentials
                        .get(credential_id)
                        .map(|credential| credential.principal.as_str())
                })
                .ok_or(SecurityError::NotFound)?;
            let target = state
                .principals
                .get(principal_id)
                .ok_or(SecurityError::NotFound)?;
            if target.id != actor.principal.id {
                state.may_manage_user(actor, target)?;
            }
            if let Some(credential) = state.credentials.get_mut(credential_id) {
                credential.revoked = true;
            } else if let Some(credential) = state.sql_credentials.get_mut(credential_id) {
                credential.revoked = true;
            }
            Ok(())
        })
        .map(|(_, revision)| revision)
    }

    pub fn rotate_credential(
        &self,
        actor: &AuthenticatedIdentity,
        expected: u64,
        credential_id: &str,
    ) -> Result<IssuedCredential> {
        let (issued, revision) =
            self.change(actor, expected, "identity.rotate_credential", |state| {
                let previous = state
                    .credentials
                    .get(credential_id)
                    .filter(|credential| !credential.revoked)
                    .ok_or(SecurityError::NotFound)?;
                let target = state
                    .principals
                    .get(&previous.principal)
                    .ok_or(SecurityError::NotFound)?;
                if target.id != actor.principal.id {
                    state.may_manage_user(actor, target)?;
                }
                if !target.enabled {
                    return Err(SecurityError::Forbidden);
                }
                let (id, secret, credential) = new_credential(&target.id)?;
                state
                    .credentials
                    .get_mut(credential_id)
                    .ok_or(SecurityError::NotFound)?
                    .revoked = true;
                state.credentials.insert(id.clone(), credential);
                Ok((id, secret))
            })?;
        Ok(IssuedCredential {
            id: issued.0,
            secret: issued.1,
            revision,
        })
    }
}

fn may_manage_principal(actor: &AuthenticatedIdentity, target: &PrincipalRecord) -> Result<()> {
    if target.attributes.clearance > actor.principal.attributes.clearance
        || (target.tenant != actor.principal.tenant
            && !actor
                .principal
                .delegation
                .iter()
                .any(|scope| scope.tenants.contains(&target.tenant)))
        || !policy::may_delegate_identity(actor, &target.grants)
        || !policy::may_delegate_identity(actor, &target.delegation)
        || !target
            .installation_actions
            .is_subset(&actor.principal.installation_actions)
    {
        return Err(SecurityError::Forbidden);
    }
    Ok(())
}

fn new_credential(principal: &str) -> Result<(String, String, Credential)> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| SecurityError::Unavailable)?;
    let secret = URL_SAFE_NO_PAD.encode(bytes);
    let id = Uuid::new_v4().to_string();
    let credential = Credential {
        principal: principal.into(),
        sha256: Sha256::digest(secret.as_bytes()).into(),
        revoked: false,
    };
    Ok((id.clone(), format!("chiron.{id}.{secret}"), credential))
}

fn new_sql_credential(principal: &str) -> Result<(String, String, SqlCredential)> {
    let mut password_bytes = [0u8; 32];
    let mut salt = [0u8; 16];
    SystemRandom::new()
        .fill(&mut password_bytes)
        .map_err(|_| SecurityError::Unavailable)?;
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| SecurityError::Unavailable)?;
    let password = URL_SAFE_NO_PAD.encode(password_bytes);
    let mut salted = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(SQL_SCRAM_ITERATIONS).expect("nonzero SCRAM iterations"),
        &salt,
        password.as_bytes(),
        &mut salted,
    );
    let client_key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &salted), b"Client Key");
    let stored_key: [u8; 32] = digest::digest(&digest::SHA256, client_key.as_ref())
        .as_ref()
        .try_into()
        .expect("SHA-256 output");
    let server_key: [u8; 32] =
        hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &salted), b"Server Key")
            .as_ref()
            .try_into()
            .expect("SHA-256 output");
    zeroize::Zeroize::zeroize(&mut salted);
    zeroize::Zeroize::zeroize(&mut password_bytes);
    Ok((
        Uuid::new_v4().to_string(),
        password,
        SqlCredential {
            principal: principal.into(),
            salt,
            stored_key,
            server_key,
            iterations: SQL_SCRAM_ITERATIONS,
            revoked: false,
        },
    ))
}

fn read_state(root: &Path) -> Result<Option<IdentityState>> {
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(SecurityError::Unavailable),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(SecurityError::Unavailable);
    }
    let path = root.join(IDENTITY_FILE);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| SecurityError::Unavailable)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_IDENTITY_BYTES
    {
        return Err(SecurityError::Unavailable);
    }
    let bytes =
        crate::encryption::read_persistent(&path).map_err(|_| SecurityError::Unavailable)?;
    if bytes.len() as u64 > MAX_IDENTITY_BYTES {
        return Err(SecurityError::Unavailable);
    }
    let magic = if bytes.starts_with(STRICT_SQL_IDENTITY_MAGIC) {
        STRICT_SQL_IDENTITY_MAGIC
    } else if bytes.starts_with(TABLE_IDENTITY_MAGIC) {
        TABLE_IDENTITY_MAGIC
    } else if bytes.starts_with(SQL_IDENTITY_MAGIC) {
        SQL_IDENTITY_MAGIC
    } else if bytes.starts_with(INSTALLATION_IDENTITY_MAGIC) {
        INSTALLATION_IDENTITY_MAGIC
    } else {
        IDENTITY_MAGIC
    };
    let payload =
        super::storage::decode_metadata(magic, &bytes).map_err(|_| SecurityError::Unavailable)?;
    let state: IdentityState =
        serde_json::from_slice(payload).map_err(|_| SecurityError::Unavailable)?;
    state.validate()?;
    if (magic == INSTALLATION_IDENTITY_MAGIC && state.version != 3)
        || (magic == TABLE_IDENTITY_MAGIC && state.version != 5)
        || (magic == STRICT_SQL_IDENTITY_MAGIC && state.version != 6)
        || (magic == SQL_IDENTITY_MAGIC && state.version != 4)
        || (magic == IDENTITY_MAGIC && state.version != IDENTITY_VERSION)
    {
        return Err(SecurityError::Unavailable);
    }
    Ok(Some(state))
}

fn encode_state(state: &IdentityState) -> Result<Vec<u8>> {
    let bytes = super::storage::encode_metadata(
        if state.version == 6 {
            STRICT_SQL_IDENTITY_MAGIC
        } else if state.version == 5 {
            TABLE_IDENTITY_MAGIC
        } else if state.version == 4 {
            SQL_IDENTITY_MAGIC
        } else if state.version == 3 {
            INSTALLATION_IDENTITY_MAGIC
        } else {
            IDENTITY_MAGIC
        },
        &serde_json::to_vec(state).map_err(|_| SecurityError::Unavailable)?,
    );
    if bytes.len() as u64 > MAX_IDENTITY_BYTES {
        return Err(SecurityError::BudgetExceeded);
    }
    let encoded =
        crate::encryption::encode_persistent(crate::encryption::FileType::Metadata, &bytes)
            .map_err(|_| SecurityError::Unavailable)?
            .into_owned();
    // Admission must include the metadata envelope and encryption framing:
    // read_state bounds the physical file before reading or decrypting it.
    if encoded.len() as u64 > MAX_IDENTITY_BYTES {
        return Err(SecurityError::BudgetExceeded);
    }
    Ok(encoded)
}

fn persist(root: &Path, state: &IdentityState) -> Result<()> {
    let bytes = encode_state(state)?;
    persist_encoded(root, state, &bytes)
}

fn persist_encoded(root: &Path, state: &IdentityState, bytes: &[u8]) -> Result<()> {
    if state.version >= 4 {
        let installation = state
            .installation
            .as_ref()
            .ok_or(SecurityError::Unavailable)?;
        // Persist the reader fence before publishing bytes that older readers
        // cannot understand. Never roll it back after an uncertain write.
        onboarding::write_marker(
            root.parent().ok_or(SecurityError::Unavailable)?,
            installation.id,
            match state.version {
                6 => 5,
                5 => 4,
                _ => 2,
            },
        )
        .map_err(|_| SecurityError::Unavailable)?;
        crate::failpoint::check("identity.after_reader_fence")
            .map_err(|_| SecurityError::Unavailable)?;
    }
    crate::fs_util::atomic_write(&root.join(IDENTITY_FILE), bytes)
        .map_err(|_| SecurityError::Unavailable)
}
