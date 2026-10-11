//! User names are aliases; immutable principal/role IDs own all references.
use super::*;

impl IdentityState {
    pub(super) fn user_name(&self, id: &str) -> Result<&str> {
        self.user_names
            .iter()
            .find_map(|(name, value)| (value == id).then_some(name.as_str()))
            .ok_or(SecurityError::NotFound)
    }

    fn user(&self, name: &str) -> Result<&PrincipalRecord> {
        self.user_names
            .get(name)
            .and_then(|id| self.principals.get(id))
            .ok_or(SecurityError::NotFound)
    }

    pub(super) fn role(&self, name: &str) -> Result<&RoleRecord> {
        self.roles
            .values()
            .find(|role| !role.retired && role.name == name)
            .ok_or(SecurityError::NotFound)
    }

    fn user_info(&self, principal: &PrincipalRecord) -> Result<UserInfo> {
        Ok(UserInfo {
            id: principal.id.clone(),
            name: self.user_name(&principal.id)?.into(),
            enabled: principal.enabled,
            attributes: principal.attributes.clone(),
            roles: self
                .memberships
                .get(&principal.id)
                .into_iter()
                .flatten()
                .filter_map(|id| self.roles.get(id))
                .filter(|role| !role.retired)
                .map(|role| role.name.clone())
                .collect(),
        })
    }

    pub(super) fn may_manage_user(
        &self,
        actor: &AuthenticatedIdentity,
        user: &PrincipalRecord,
    ) -> Result<()> {
        may_manage_principal(actor, user)?;
        for id in self.memberships.get(&user.id).into_iter().flatten() {
            may_manage_role(actor, self.roles.get(id).ok_or(SecurityError::Unavailable)?)?;
        }
        Ok(())
    }

    pub(super) fn validate_administration(&self) -> Result<()> {
        let mut live_ids = BTreeSet::new();
        for (name, id) in &self.user_names {
            if !policy::identifier(name)
                || !self.principals.contains_key(id)
                || self.retired_users.contains(id)
                || !live_ids.insert(id)
            {
                return Err(SecurityError::Invalid("invalid user name binding".into()));
            }
        }
        for (id, principal) in &self.principals {
            if !live_ids.contains(id) && !self.retired_users.contains(id)
                || self.retired_users.contains(id) && principal.enabled
            {
                return Err(SecurityError::Invalid("invalid retired user".into()));
            }
        }
        if self
            .retired_users
            .iter()
            .any(|id| !self.principals.contains_key(id))
        {
            return Err(SecurityError::Invalid("unknown retired user".into()));
        }
        let mut role_names = BTreeSet::new();
        for (id, role) in &self.roles {
            validate_role(role)?;
            if self.version < 5 && !role.table_grants.is_empty() {
                return Err(SecurityError::Invalid(
                    "table grants require identity format 5".into(),
                ));
            }
            if id != &role.id || !role.retired && !role_names.insert((&role.tenant, &role.name)) {
                return Err(SecurityError::Invalid("invalid role identity".into()));
            }
        }
        for (id, memberships) in &self.memberships {
            let principal = self.principals.get(id).ok_or(SecurityError::Unavailable)?;
            if self.retired_users.contains(id) || memberships.len() > MAX_POLICY_GRANTS {
                return Err(SecurityError::Invalid("invalid role membership".into()));
            }
            let mut grants = principal.grants.len();
            for id in memberships {
                let role = self.roles.get(id).ok_or(SecurityError::Unavailable)?;
                if role.retired || role.tenant != principal.tenant {
                    return Err(SecurityError::Invalid(
                        "cross-domain role membership".into(),
                    ));
                }
                grants = grants
                    .checked_add(role.grants.len() + role.table_grants.len())
                    .ok_or(SecurityError::BudgetExceeded)?;
            }
            if grants > MAX_POLICY_GRANTS {
                return Err(SecurityError::BudgetExceeded);
            }
        }
        if self
            .credentials
            .values()
            .any(|key| self.retired_users.contains(&key.principal) && !key.revoked)
            || self
                .sql_credentials
                .values()
                .any(|key| self.retired_users.contains(&key.principal) && !key.revoked)
        {
            return Err(SecurityError::Invalid(
                "live credential of retired user".into(),
            ));
        }
        Ok(())
    }
}

pub(super) fn validate_role(role: &RoleRecord) -> Result<()> {
    if role.id.is_nil()
        || !policy::identifier(&role.name)
        || !policy::identifier(&role.tenant)
        || role.grants.len().saturating_add(role.table_grants.len()) > MAX_POLICY_GRANTS
        || role
            .installation_actions
            .iter()
            .any(|action| action.is_data() || *action == Action::IdentityManage)
    {
        return Err(SecurityError::Invalid(
            "invalid role or nondelegable action".into(),
        ));
    }
    let mut scopes = BTreeSet::new();
    for grant in &role.grants {
        if grant.incarnation.is_nil()
            || !policy::identifier(&grant.collection)
            || grant.collection.contains(':')
            || grant.actions.is_empty()
            || grant.actions.contains(&Action::IdentityManage)
            || !scopes.insert((&grant.collection, grant.incarnation))
        {
            return Err(SecurityError::Invalid(
                "invalid role collection scope".into(),
            ));
        }
    }
    let mut tables = BTreeSet::new();
    for grant in &role.table_grants {
        if grant.table_id == 0
            || grant.incarnation.is_nil()
            || grant.table.is_empty()
            || grant.table.len() > 128
            || grant.actions.is_empty()
            || grant.actions.iter().any(|action| {
                !matches!(
                    action,
                    Action::Read | Action::Create | Action::Update | Action::Delete
                )
            })
            || !tables.insert((grant.table_id, grant.incarnation))
        {
            return Err(SecurityError::Invalid("invalid role table scope".into()));
        }
    }
    Ok(())
}

pub(super) fn may_manage_role(actor: &AuthenticatedIdentity, role: &RoleRecord) -> Result<()> {
    if role.tenant != actor.principal.tenant
        || !role
            .installation_actions
            .is_subset(&actor.principal.installation_actions)
    {
        return Err(SecurityError::Forbidden);
    }
    if !role.table_grants.is_empty() && !actor.is_installation_admin() {
        return Err(SecurityError::Forbidden);
    }
    let scopes: Vec<_> = role
        .grants
        .iter()
        .map(|grant| ScopeGrant {
            tenants: BTreeSet::from([role.tenant.clone()]),
            collections: BTreeSet::from([grant.collection.clone()]),
            actions: grant.actions.clone(),
        })
        .collect();
    if !policy::may_delegate_identity(actor, &scopes) {
        return Err(SecurityError::Forbidden);
    }
    Ok(())
}

impl IdentityAuthority {
    pub(crate) fn resolve_security_subject(
        &self,
        context: &AccessContext,
        subject: &Subject,
    ) -> Result<Subject> {
        if !matches!(
            context.action(),
            Action::GrantsManage | Action::LabelsManage
        ) {
            return Err(SecurityError::Forbidden);
        }
        let _lease = context.publication_permit()?;
        let current = self.current.read();
        if !Arc::ptr_eq(&context.identity().epoch, &current.epoch) {
            return Err(SecurityError::Conflict);
        }
        match subject {
            Subject::Principal(name) => {
                let user = current.state.user(name)?;
                if user.tenant != context.tenant() {
                    return Err(SecurityError::NotFound);
                }
                Ok(Subject::Principal(user.id.clone()))
            }
            Subject::Group(name) => {
                let group = current
                    .state
                    .groups
                    .get(name)
                    .ok_or(SecurityError::NotFound)?;
                if group.tenant != context.tenant() {
                    return Err(SecurityError::NotFound);
                }
                Ok(subject.clone())
            }
            _ => Err(SecurityError::Forbidden),
        }
    }

    /// Explicit offline migration. No reader silently upgrades an authority,
    /// and no v1 authority is left active beside the v2 file.
    pub fn migrate_v1(data_dir: &Path) -> Result<bool> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Legacy {
            version: u32,
            revision: u64,
            principals: BTreeMap<String, PrincipalRecord>,
            groups: BTreeMap<String, GroupRecord>,
            credentials: BTreeMap<String, Credential>,
        }
        let _lease = crate::data_dir_lock::DataDirLock::acquire(data_dir)
            .map_err(|_| SecurityError::Unavailable)?;
        let root = data_dir.join("security");
        let metadata = std::fs::symlink_metadata(&root).map_err(|_| SecurityError::Unavailable)?;
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
            return Err(SecurityError::BudgetExceeded);
        }
        if let Ok(payload) = super::super::storage::decode_metadata(IDENTITY_MAGIC, &bytes) {
            let state: IdentityState =
                serde_json::from_slice(payload).map_err(|_| SecurityError::Unavailable)?;
            state.validate()?;
            return Ok(false);
        }
        let payload = super::super::storage::decode_metadata(b"CHRNID01", &bytes)
            .map_err(|_| SecurityError::Unavailable)?;
        let old: Legacy =
            serde_json::from_slice(payload).map_err(|_| SecurityError::Unavailable)?;
        if old.version != 1 || old.revision == 0 {
            return Err(SecurityError::Unavailable);
        }
        let state = IdentityState {
            version: IDENTITY_VERSION,
            installation: None,
            revision: old
                .revision
                .checked_add(1)
                .ok_or(SecurityError::Unavailable)?,
            user_names: old
                .principals
                .keys()
                .map(|id| (id.clone(), id.clone()))
                .collect(),
            principals: old.principals,
            groups: old.groups,
            credentials: old.credentials,
            sql_credentials: BTreeMap::new(),
            scram_decoy_key: None,
            retired_users: BTreeSet::new(),
            roles: BTreeMap::new(),
            memberships: BTreeMap::new(),
        };
        state.validate()?;
        let audit =
            crate::audit::AuditWriter::open(data_dir).map_err(|_| SecurityError::Unavailable)?;
        let intent = audit.operation_with_details("security", "identity.migrate_v2", None,
            crate::audit::AuditContext { principal_id: "offline-authority-migration".into(), tenant_id: None,
                transport: "offline".into(), request_id: None },
            serde_json::json!({"identity_revision":old.revision,"next_identity_revision":state.revision}))
            .map_err(|_| SecurityError::Unavailable)?;
        crate::failpoint::check("identity.before_migration_publish")
            .map_err(|_| SecurityError::Unavailable)?;
        persist(&root, &state)?;
        crate::failpoint::check("identity.after_migration_publish")
            .map_err(|_| SecurityError::Unavailable)?;
        intent
            .success(serde_json::json!({"identity_revision":state.revision}))
            .map_err(|_| SecurityError::Unavailable)?;
        Ok(true)
    }

    fn read_admin<T>(
        &self,
        actor: &AuthenticatedIdentity,
        read: impl FnOnce(&IdentityState) -> Result<T>,
    ) -> Result<T> {
        let _lease = actor.publication_permit()?;
        if !actor.allows_installation(Action::IdentityManage) {
            return Err(SecurityError::Forbidden);
        }
        let current = self.current.read();
        if !Arc::ptr_eq(&actor.epoch, &current.epoch) {
            return Err(SecurityError::Conflict);
        }
        read(&current.state)
    }

    pub fn current_user(&self, actor: &AuthenticatedIdentity) -> Result<UserInfo> {
        let _lease = actor.publication_permit()?;
        let current = self.current.read();
        if !Arc::ptr_eq(&actor.epoch, &current.epoch) {
            return Err(SecurityError::Conflict);
        }
        current.state.user_info(&actor.principal)
    }

    pub fn list_users(&self, actor: &AuthenticatedIdentity) -> Result<Vec<UserInfo>> {
        self.read_admin(actor, |state| {
            state
                .user_names
                .values()
                .map(|id| {
                    let user = &state.principals[id];
                    if user.tenant != actor.principal.tenant {
                        return Err(SecurityError::Forbidden);
                    }
                    state.user_info(user)
                })
                .collect()
        })
    }

    pub fn list_roles(&self, actor: &AuthenticatedIdentity) -> Result<Vec<RoleRecord>> {
        self.read_admin(actor, |state| {
            Ok(state
                .roles
                .values()
                .filter(|role| !role.retired && role.tenant == actor.principal.tenant)
                .cloned()
                .collect())
        })
    }

    pub fn resolve_user(&self, actor: &AuthenticatedIdentity, name: &str) -> Result<String> {
        self.read_admin(actor, |state| {
            let user = state.user(name)?;
            if user.tenant != actor.principal.tenant {
                return Err(SecurityError::Forbidden);
            }
            Ok(user.id.clone())
        })
    }

    pub fn list_credentials(
        &self,
        actor: &AuthenticatedIdentity,
        name: &str,
    ) -> Result<Vec<CredentialInfo>> {
        self.read_admin(actor, |state| {
            let user = state.user(name)?;
            if user.tenant != actor.principal.tenant {
                return Err(SecurityError::Forbidden);
            }
            Ok(state
                .credentials
                .iter()
                .filter(|(_, credential)| credential.principal == user.id)
                .map(|(id, credential)| CredentialInfo {
                    id: id.clone(),
                    principal: user.id.clone(),
                    revoked: credential.revoked,
                })
                .collect())
        })
    }

    pub fn create_user(
        &self,
        actor: &AuthenticatedIdentity,
        expected: u64,
        name: &str,
        attributes: SubjectAttributes,
    ) -> Result<u64> {
        if !policy::identifier(name) {
            return Err(SecurityError::Invalid("invalid user name".into()));
        }
        let user = PrincipalRecord {
            id: Uuid::new_v4().to_string(),
            tenant: actor.principal.tenant.clone(),
            enabled: true,
            attributes,
            grants: vec![],
            installation_actions: BTreeSet::new(),
            delegation: vec![],
        };
        may_manage_principal(actor, &user)?;
        self.change(actor, expected, "identity.create_user", |state| {
            if state.user_names.contains_key(name) || state.principals.contains_key(&user.id) {
                return Err(SecurityError::Conflict);
            }
            state.user_names.insert(name.into(), user.id.clone());
            state.principals.insert(user.id.clone(), user);
            Ok(())
        })
        .map(|(_, revision)| revision)
    }

    pub fn alter_user(
        &self,
        actor: &AuthenticatedIdentity,
        expected: u64,
        name: &str,
        changes: UserChanges,
    ) -> Result<u64> {
        self.change(actor, expected, "identity.alter_user", |state| {
            let mut user = state.user(name)?.clone();
            state.may_manage_user(actor, &user)?;
            if let Some(enabled) = changes.enabled {
                user.enabled = enabled;
            }
            if let Some(department) = changes.department {
                user.attributes.department = department;
            }
            if let Some(clearance) = changes.clearance {
                user.attributes.clearance = clearance;
            }
            state.may_manage_user(actor, &user)?;
            state.principals.insert(user.id.clone(), user);
            Ok(())
        })
        .map(|(_, revision)| revision)
    }

    pub fn rename_user(
        &self,
        actor: &AuthenticatedIdentity,
        expected: u64,
        name: &str,
        new_name: &str,
    ) -> Result<u64> {
        if !policy::identifier(new_name) {
            return Err(SecurityError::Invalid("invalid user name".into()));
        }
        self.change(actor, expected, "identity.rename_user", |state| {
            let user = state.user(name)?;
            state.may_manage_user(actor, user)?;
            let id = user.id.clone();
            if state.user_names.contains_key(new_name) {
                return Err(SecurityError::Conflict);
            }
            state.user_names.remove(name);
            state.user_names.insert(new_name.into(), id);
            Ok(())
        })
        .map(|(_, revision)| revision)
    }

    pub fn drop_user(
        &self,
        actor: &AuthenticatedIdentity,
        expected: u64,
        name: &str,
    ) -> Result<u64> {
        self.change(actor, expected, "identity.drop_user", |state| {
            let user = state.user(name)?;
            state.may_manage_user(actor, user)?;
            let id = user.id.clone();
            state
                .principals
                .get_mut(&id)
                .ok_or(SecurityError::NotFound)?
                .enabled = false;
            state.user_names.remove(name);
            state.retired_users.insert(id.clone());
            state.memberships.remove(&id);
            for credential in state
                .credentials
                .values_mut()
                .filter(|key| key.principal == id)
            {
                credential.revoked = true;
            }
            for credential in state
                .sql_credentials
                .values_mut()
                .filter(|key| key.principal == id)
            {
                credential.revoked = true;
            }
            for group in state.groups.values_mut() {
                group.members.remove(&GroupMember::Principal(id.clone()));
            }
            Ok(())
        })
        .map(|(_, revision)| revision)
    }

    pub fn create_role(
        &self,
        actor: &AuthenticatedIdentity,
        expected: u64,
        name: &str,
    ) -> Result<u64> {
        let role = RoleRecord {
            id: Uuid::new_v4(),
            name: name.into(),
            tenant: actor.principal.tenant.clone(),
            retired: false,
            grants: vec![],
            table_grants: vec![],
            installation_actions: BTreeSet::new(),
        };
        validate_role(&role)?;
        self.change(actor, expected, "identity.create_role", |state| {
            if state.role(name).is_ok() || state.roles.contains_key(&role.id) {
                return Err(SecurityError::Conflict);
            }
            state.roles.insert(role.id, role);
            Ok(())
        })
        .map(|(_, revision)| revision)
    }

    pub fn rename_role(
        &self,
        actor: &AuthenticatedIdentity,
        expected: u64,
        name: &str,
        new_name: &str,
    ) -> Result<u64> {
        if !policy::identifier(new_name) {
            return Err(SecurityError::Invalid("invalid role name".into()));
        }
        self.change(actor, expected, "identity.rename_role", |state| {
            let role = state.role(name)?;
            may_manage_role(actor, role)?;
            let id = role.id;
            if state.role(new_name).is_ok() {
                return Err(SecurityError::Conflict);
            }
            state
                .roles
                .get_mut(&id)
                .ok_or(SecurityError::NotFound)?
                .name = new_name.into();
            Ok(())
        })
        .map(|(_, revision)| revision)
    }

    pub fn drop_role(
        &self,
        actor: &AuthenticatedIdentity,
        expected: u64,
        name: &str,
    ) -> Result<u64> {
        self.change(actor, expected, "identity.drop_role", |state| {
            let role = state.role(name)?;
            may_manage_role(actor, role)?;
            let id = role.id;
            state
                .roles
                .get_mut(&id)
                .ok_or(SecurityError::NotFound)?
                .retired = true;
            for memberships in state.memberships.values_mut() {
                memberships.remove(&id);
            }
            Ok(())
        })
        .map(|(_, revision)| revision)
    }

    pub fn assign_role(
        &self,
        actor: &AuthenticatedIdentity,
        expected: u64,
        role: &str,
        user: &str,
        grant: bool,
    ) -> Result<u64> {
        self.change(
            actor,
            expected,
            if grant {
                "identity.grant_role"
            } else {
                "identity.revoke_role"
            },
            |state| {
                let role = state.role(role)?;
                let user = state.user(user)?;
                may_manage_role(actor, role)?;
                state.may_manage_user(actor, user)?;
                if role.tenant != user.tenant {
                    return Err(SecurityError::Forbidden);
                }
                let role_id = role.id;
                let user_id = user.id.clone();
                let memberships = state.memberships.entry(user_id).or_default();
                if grant {
                    memberships.insert(role_id);
                } else {
                    memberships.remove(&role_id);
                }
                Ok(())
            },
        )
        .map(|(_, revision)| revision)
    }

    /// The server resolves collection/incarnation under a collection lifecycle
    /// lease before calling this authority transaction.
    pub fn change_role_privileges(
        &self,
        actor: &AuthenticatedIdentity,
        expected: u64,
        name: &str,
        changes: RolePrivilegeChanges,
    ) -> Result<u64> {
        let RolePrivilegeChanges {
            collection,
            actions,
            grant,
        } = changes;
        if actions.is_empty() || actions.contains(&Action::IdentityManage) {
            return Err(SecurityError::Forbidden);
        }
        self.change(actor, expected, "identity.role_privileges", |state| {
            let mut role = state.role(name)?.clone();
            may_manage_role(actor, &role)?;
            if let Some((collection, incarnation)) = collection {
                if let Some(scope) = role.grants.iter_mut().find(|scope| {
                    scope.collection == collection && scope.incarnation == incarnation
                }) {
                    if grant {
                        scope.actions.extend(&actions);
                    } else {
                        scope.actions.retain(|action| !actions.contains(action));
                    }
                } else if grant {
                    role.grants.push(RoleCollectionGrant {
                        collection,
                        incarnation,
                        actions,
                    });
                }
                role.grants.retain(|scope| !scope.actions.is_empty());
            } else if grant {
                role.installation_actions.extend(actions);
            } else {
                role.installation_actions
                    .retain(|action| !actions.contains(action));
            }
            validate_role(&role)?;
            may_manage_role(actor, &role)?;
            let role_id = role.id;
            state.roles.insert(role.id, role);
            for (id, roles) in &state.memberships {
                if roles.contains(&role_id) {
                    state.may_manage_user(
                        actor,
                        state.principals.get(id).ok_or(SecurityError::Unavailable)?,
                    )?;
                }
            }
            Ok(())
        })
        .map(|(_, revision)| revision)
    }
}
