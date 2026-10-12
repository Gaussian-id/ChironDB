//! Offline installation and credential delivery. No listener may open pending work.
use super::*;
use crate::{GaussError, encryption, fs_util};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};

pub const MARKER: &str = ".protected-installation";
pub const PENDING: &str = ".security-onboarding";
const JOURNAL_MAGIC: &[u8; 8] = b"CHRNINI1";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Installation {
    pub id: Uuid,
    pub tenant: String,
    pub admin_id: String,
}
impl Installation {
    pub(super) fn validate(&self, state: &IdentityState) -> Result<()> {
        if self.id.is_nil()
            || !policy::identifier(&self.tenant)
            || !state.principals.contains_key(&self.admin_id)
            || state.principals.values().any(|p| p.tenant != self.tenant)
        {
            return Err(SecurityError::Unavailable);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    operation: String,
    data_dir: PathBuf,
    keyring: PathBuf,
    key_out: PathBuf,
    state: IdentityState,
    credential: String,
    generation: String,
}

#[derive(Debug, Serialize)]
pub struct InstallationReport {
    pub installation_id: Uuid,
    pub principal_id: String,
    pub admin: String,
    pub tenant: String,
    pub identity_revision: u64,
    pub admin_key_file: PathBuf,
    pub storage_keyring_file: PathBuf,
    pub next_steps: [&'static str; 2],
}

fn invalid(message: &str) -> GaussError {
    GaussError::InvalidRequest(message.into())
}

/// Resolve every component without following symlinks. Caller-owned parent
/// directories prevent path replacement by another local account.
fn checked_path(path: &Path) -> crate::Result<PathBuf> {
    use std::path::Component;
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut resolved = PathBuf::new();
    for part in path.components() {
        match part {
            Component::ParentDir => return Err(invalid("parent traversal is not allowed")),
            Component::CurDir => continue,
            _ => resolved.push(part.as_os_str()),
        }
        match fs::symlink_metadata(&resolved) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(invalid("symlinks are not allowed in security paths"));
            }
            Ok(metadata) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = metadata.permissions().mode();
                    if metadata.is_dir() && mode & 0o022 != 0 && mode & 0o1000 == 0 {
                        return Err(invalid("security path has a writable ancestor"));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(resolved)
}

fn private_dir(path: &Path) -> crate::Result<()> {
    if !path.exists() {
        let mut directory = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory.mode(0o700);
        }
        directory.create(path)?;
        fs_util::sync_directory(path.parent().ok_or_else(|| invalid("missing parent"))?)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("security parent must be a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(invalid(
                "security directory must be owned by the caller and have mode 0700",
            ));
        }
    }
    Ok(())
}

fn private_bytes(path: &Path) -> crate::Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(invalid("secret must be a private regular file"));
    }
    let file = File::open(path)?;
    let after = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || after.permissions().mode() & 0o077 != 0
            || after.uid() != unsafe { libc::geteuid() }
        {
            return Err(invalid("secret permissions or ownership are invalid"));
        }
    }
    if after.len() > 1024 * 1024 {
        return Err(invalid("secret file exceeds size limit"));
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(invalid("secret file exceeds size limit"));
    }
    Ok(bytes)
}

fn write_secret(path: &Path, bytes: &[u8]) -> crate::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs_util::sync_directory(
        path.parent()
            .ok_or_else(|| invalid("missing secret parent"))?,
    )?;
    Ok(())
}

fn administrator(id: String, tenant: &str) -> PrincipalRecord {
    PrincipalRecord {
        id,
        tenant: tenant.into(),
        enabled: true,
        attributes: SubjectAttributes {
            department: "Security".into(),
            clearance: Classification::Restricted,
        },
        grants: vec![],
        delegation: vec![],
        installation_actions: BTreeSet::from([
            Action::IdentityManage,
            Action::CollectionCreate,
            Action::PolicyManage,
            Action::LabelsManage,
            Action::GrantsManage,
            Action::Observe,
            Action::Schema,
        ]),
    }
}

/// Metadata probe only. Presence, including a malformed marker, selects the
/// protected startup path; corruption must never select legacy admission.
pub fn requires_protected_startup(data_dir: &Path) -> bool {
    [MARKER, PENDING].iter().any(|name| {
        !matches!(fs::symlink_metadata(data_dir.join(name)), Err(error)
            if error.kind() == std::io::ErrorKind::NotFound)
    })
}

pub fn validate_ready(data_dir: &Path) -> crate::Result<()> {
    match fs::symlink_metadata(data_dir.join(PENDING)) {
        Ok(_) => {
            return Err(invalid(
                "security initialization/recovery is pending; resume offline",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if requires_protected_startup(data_dir) {
        read_marker(data_dir)?;
    }
    Ok(())
}

/// Requires the process keyring. The server's earlier configuration check
/// uses validate_ready, which only inspects the plaintext admission marker.
pub(crate) fn validate_identity_ready(data_dir: &Path) -> crate::Result<()> {
    validate_ready(data_dir)?;
    let marker = if requires_protected_startup(data_dir) {
        Some(read_marker(data_dir)?)
    } else {
        None
    };
    // This is deliberately read-only and precedes journal, graph, audit and
    // projection recovery. Unsupported authority bytes cannot mutate content.
    if let Some(state) = read_state(&data_dir.join("security"))? {
        if let Some(installation) = state.installation {
            let (version, id) = marker.ok_or_else(|| invalid("missing installation marker"))?;
            if id != installation.id {
                return Err(invalid("installation marker identity mismatch"));
            }
            if state.version >= 6 && version < 5 {
                return Err(invalid(
                    "strict SQL scopes require installation reader format 5",
                ));
            }
            if state.version >= 5 && version < 4 {
                return Err(invalid(
                    "table authority requires installation reader format 4",
                ));
            }
            if state.version >= 4 && version < 2 {
                return Err(invalid(
                    "SQL identity requires offline chironctl security migrate-sql-guard",
                ));
            }
        } else if marker.is_some() {
            return Err(invalid("installation marker has no matching authority"));
        }
    } else if marker.is_some() {
        return Err(invalid("installation marker has no matching authority"));
    }
    Ok(())
}

fn read_marker(data_dir: &Path) -> crate::Result<(u32, Uuid)> {
    let metadata = fs::symlink_metadata(data_dir.join(MARKER))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 128 {
        return Err(invalid("invalid security installation marker"));
    }
    let marker = fs::read_to_string(data_dir.join(MARKER))?;
    let (version, rest) = if let Some(rest) = marker.strip_prefix("CHRNINSTALL1\n") {
        (1, rest)
    } else if let Some(rest) = marker.strip_prefix("CHRNINSTALL2\n") {
        (2, rest)
    // Format 3 belongs to non-runnable backup/archive capsules. Never accept
    // it here: restore must reconcile current authority before activation.
    } else if let Some(rest) = marker.strip_prefix("CHRNINSTALL4\n") {
        (4, rest)
    } else if let Some(rest) = marker.strip_prefix("CHRNINSTALL5\n") {
        (5, rest)
    } else if let Some(rest) = marker.strip_prefix("CHRNINSTALL6\n") {
        (6, rest)
    } else if let Some(rest) = marker.strip_prefix("CHRNINSTALL7\n") {
        (7, rest)
    } else {
        return Err(invalid("unsupported security installation marker"));
    };
    let id = rest
        .strip_suffix('\n')
        .and_then(|id| Uuid::parse_str(id).ok())
        .filter(|id| !id.is_nil())
        .ok_or_else(|| invalid("invalid installation identity"))?;
    Ok((version, id))
}

pub(super) fn write_marker(data_dir: &Path, id: Uuid, minimum: u32) -> crate::Result<bool> {
    let current = match fs::symlink_metadata(data_dir.join(MARKER)) {
        Ok(_) => {
            let (version, stored_id) = read_marker(data_dir)?;
            if stored_id != id {
                return Err(invalid("installation marker identity mismatch"));
            }
            version
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error.into()),
    };
    if current >= minimum {
        // A previous rename may have succeeded before directory fsync failed.
        // Re-establish durability before any dependent identity publication.
        fs_util::sync_directory(data_dir)?;
        return Ok(false);
    }
    fs_util::atomic_write(
        &data_dir.join(MARKER),
        format!("CHRNINSTALL{minimum}\n{id}\n").as_bytes(),
    )?;
    Ok(true)
}

/// Restore has copied and verified current authority into private staging.
/// Choose its reader fence without treating the backup capsule as runnable.
pub(crate) fn restored_installation_format(data_dir: &Path, id: Uuid) -> crate::Result<u32> {
    let state = read_state(&data_dir.join("security"))?
        .ok_or_else(|| invalid("restored authority is missing"))?;
    if state
        .installation
        .as_ref()
        .map(|installation| installation.id)
        != Some(id)
    {
        return Err(invalid("restored authority installation mismatch"));
    }
    if crate::transaction_journal::TransactionJournal::has_authority_format(data_dir)? {
        return Ok(6);
    }
    Ok(match state.version {
        6 => 5,
        5 => 4,
        _ => 2,
    })
}

/// Protected installations fence old readers before journal format upgrades.
/// Legacy installations check their journal FORMAT before opening its WAL.
pub(crate) fn installation_id_for_journal(data_dir: &Path) -> crate::Result<Option<Uuid>> {
    if requires_protected_startup(data_dir) {
        validate_ready(data_dir)?;
        return Ok(Some(read_marker(data_dir)?.1));
    }
    Ok(None)
}

pub(crate) fn fence_transaction_reader(data_dir: &Path) -> crate::Result<Option<Uuid>> {
    let id = installation_id_for_journal(data_dir)?;
    if let Some(id) = id {
        validate_identity_ready(data_dir)?;
        write_marker(data_dir, id, 2)?;
    }
    Ok(id)
}

pub(crate) fn validate_transaction_authority_reader(data_dir: &Path) -> crate::Result<()> {
    if requires_protected_startup(data_dir) && read_marker(data_dir)?.0 < 6 {
        return Err(invalid(
            "transaction authority requires installation reader format 6",
        ));
    }
    Ok(())
}

pub(crate) fn validate_frontier_identity(
    data_dir: &Path,
    installation: Uuid,
    minimum_revision: u64,
) -> crate::Result<()> {
    let state = read_state(&data_dir.join("security"))?
        .ok_or_else(|| invalid("common frontier identity missing"))?;
    if state.installation.as_ref().map(|i| i.id) != Some(installation)
        || state.revision < minimum_revision
    {
        return Err(invalid(
            "common frontier identity revision or installation mismatch",
        ));
    }
    Ok(())
}

pub(crate) fn has_common_frontier(data_dir: &Path) -> crate::Result<bool> {
    if requires_protected_startup(data_dir) {
        return Ok(read_marker(data_dir)?.0 >= 7);
    }
    Ok(false)
}

pub(crate) fn activate_common_frontier(data_dir: &Path, expected: Uuid) -> crate::Result<()> {
    if installation_id_for_journal(data_dir)? != Some(expected) {
        return Err(invalid("common frontier installation mismatch"));
    }
    write_marker(data_dir, expected, 7)?;
    Ok(())
}

pub(crate) fn fence_transaction_authority_reader(
    data_dir: &Path,
    expected: Uuid,
) -> crate::Result<()> {
    let id = installation_id_for_journal(data_dir)?.ok_or_else(|| {
        invalid("transaction authority migration requires a protected installation")
    })?;
    if id != expected {
        return Err(invalid("transaction authority installation mismatch"));
    }
    validate_identity_ready(data_dir)?;
    write_marker(data_dir, id, 6)?;
    Ok(())
}

/// Fence existing SQL preview installations while offline. Only the startup
/// marker changes: identity revision, credentials and content stay intact.
pub fn migrate_sql_guard(data_dir: &Path, keyring: &Path) -> crate::Result<bool> {
    let data_dir = checked_path(data_dir)?;
    let _lease = crate::data_dir_lock::DataDirLock::acquire(&data_dir)?;
    install_keyring(&checked_path(keyring)?)?;
    match fs::symlink_metadata(data_dir.join(PENDING)) {
        Ok(_) => {
            return Err(invalid(
                "security initialization/recovery is pending; resume offline",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let state = read_state(&data_dir.join("security"))?
        .ok_or_else(|| invalid("missing identity authority"))?;
    let installation = state
        .installation
        .as_ref()
        .ok_or_else(|| invalid("SQL reader guard requires an initialized installation"))?;
    let (_, id) = read_marker(&data_dir)?;
    if id != installation.id {
        return Err(invalid("installation marker identity mismatch"));
    }
    crate::audit::verify_hash_chain(&data_dir)?;
    let audit = crate::audit::AuditWriter::open(&data_dir)?;
    let intent = audit.operation_with_details(
        "security",
        "identity.migrate_sql_guard",
        None,
        crate::audit::AuditContext {
            principal_id: "offline-authority-migration".into(),
            tenant_id: Some(installation.tenant.clone()),
            transport: "offline".into(),
            request_id: None,
        },
        serde_json::json!({"identity_revision": state.revision, "installation_format": 2}),
    )?;
    crate::failpoint::check("security_sql_guard.before_marker")?;
    let changed = write_marker(&data_dir, id, 2)?;
    crate::failpoint::check("security_sql_guard.after_marker")?;
    intent.success(serde_json::json!({"installation_format": 2, "migrated": changed}))?;
    Ok(changed)
}

pub fn initialize(
    data_dir: &Path,
    tenant: &str,
    admin: &str,
    keyring_out: &Path,
    admin_key_out: &Path,
    resume: bool,
) -> crate::Result<InstallationReport> {
    if !policy::identifier(tenant) || !policy::identifier(admin) {
        return Err(invalid("invalid tenant or administrator name"));
    }
    let data_dir = checked_path(data_dir)?;
    let keyring = checked_path(keyring_out)?;
    let key_out = checked_path(admin_key_out)?;
    validate_outputs(&data_dir, &keyring, &key_out)?;
    let _lease = crate::data_dir_lock::DataDirLock::acquire(&data_dir)?;
    let journal = if resume {
        install_keyring(&keyring)?;
        let j = read_journal(&data_dir)?;
        if j.operation != "initialize"
            || j.data_dir != data_dir
            || j.keyring != keyring
            || j.key_out != key_out
            || j.state.user_names.get(admin) != j.state.installation.as_ref().map(|i| &i.admin_id)
            || j.state
                .installation
                .as_ref()
                .is_none_or(|i| i.tenant != tenant)
        {
            return Err(invalid(
                "resume arguments do not match recorded initialization",
            ));
        }
        j
    } else {
        if data_dir.exists() && fs::read_dir(&data_dir)?.next().is_some() {
            return Err(invalid("initialization requires an empty data directory"));
        }
        if keyring.exists() || key_out.exists() {
            return Err(invalid("secret destinations must not exist"));
        }
        private_dir(&data_dir)?;
        private_dir(
            keyring
                .parent()
                .ok_or_else(|| invalid("missing keyring parent"))?,
        )?;
        private_dir(
            key_out
                .parent()
                .ok_or_else(|| invalid("missing credential parent"))?,
        )?;
        fs_util::atomic_write(&data_dir.join(MARKER), b"pending\n")?;
        let key_id = Uuid::new_v4();
        let mut material = [0u8; 32];
        SystemRandom::new()
            .fill(&mut material)
            .map_err(|_| SecurityError::Unavailable)?;
        let document = serde_json::json!({"version":1,"active_key_id":key_id,
            "keys":[{"id":key_id,"key_base64":base64::engine::general_purpose::STANDARD.encode(material)}]});
        write_secret(&keyring, &serde_json::to_vec(&document)?)?;
        install_keyring(&keyring)?;
        let principal = administrator(Uuid::new_v4().to_string(), tenant);
        let (id, credential, record) = new_credential(&principal.id)?;
        let installation = Installation {
            id: Uuid::new_v4(),
            tenant: tenant.into(),
            admin_id: principal.id.clone(),
        };
        let state = IdentityState {
            version: 3,
            installation: Some(installation),
            revision: 1,
            user_names: BTreeMap::from([(admin.into(), principal.id.clone())]),
            principals: BTreeMap::from([(principal.id.clone(), principal)]),
            groups: BTreeMap::new(),
            credentials: BTreeMap::from([(id, record)]),
            sql_credentials: BTreeMap::new(),
            scram_decoy_key: None,
            retired_users: BTreeSet::new(),
            roles: BTreeMap::new(),
            memberships: BTreeMap::new(),
        };
        let j = Journal {
            version: 1,
            operation: "initialize".into(),
            data_dir: data_dir.clone(),
            keyring,
            key_out,
            state,
            credential,
            generation: format!("g-{}", Uuid::new_v4()),
        };
        write_journal(&j)?;
        crate::failpoint::check("security_init.prepared")?;
        j
    };
    finish(&journal)
}

fn validate_outputs(data: &Path, keyring: &Path, key: &Path) -> crate::Result<()> {
    if keyring == key
        || keyring.starts_with(data)
        || key.starts_with(data)
        || data.starts_with(keyring)
        || data.starts_with(key)
        || key.starts_with(keyring)
        || keyring.starts_with(key)
    {
        return Err(invalid(
            "security outputs must be distinct files outside the data directory",
        ));
    }
    Ok(())
}

fn install_keyring(path: &Path) -> crate::Result<()> {
    private_bytes(path)?;
    encryption::install_process_keyring(encryption::Keyring::load(path)?, true)
}

fn write_journal(journal: &Journal) -> crate::Result<()> {
    encryption::atomic_write_persistent(
        &journal.data_dir.join(PENDING),
        encryption::FileType::Metadata,
        &super::super::storage::encode_metadata(JOURNAL_MAGIC, &serde_json::to_vec(journal)?),
    )
}
fn read_journal(data: &Path) -> crate::Result<Journal> {
    let metadata = fs::symlink_metadata(data.join(PENDING))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_IDENTITY_BYTES + 32768
    {
        return Err(invalid("invalid onboarding journal file"));
    }
    let bytes = encryption::read_persistent(&data.join(PENDING))?;
    if bytes.len() > MAX_IDENTITY_BYTES as usize + 16384 {
        return Err(invalid("onboarding journal exceeds size limit"));
    }
    let j: Journal = serde_json::from_slice(super::super::storage::decode_metadata(
        JOURNAL_MAGIC,
        &bytes,
    )?)?;
    if j.version != 1
        || j.data_dir != data
        || !matches!(j.operation.as_str(), "initialize" | "recover")
    {
        return Err(invalid("invalid onboarding journal"));
    }
    j.state.validate()?;
    Ok(j)
}

fn finish(j: &Journal) -> crate::Result<InstallationReport> {
    let installation = j
        .state
        .installation
        .as_ref()
        .ok_or_else(|| invalid("missing installation binding"))?;
    private_dir(
        j.key_out
            .parent()
            .ok_or_else(|| invalid("missing credential parent"))?,
    )?;
    private_dir(
        j.keyring
            .parent()
            .ok_or_else(|| invalid("missing keyring parent"))?,
    )?;
    let identity_path = j.data_dir.join("security").join(IDENTITY_FILE);
    if identity_path.try_exists()? {
        let existing = read_state(&j.data_dir.join("security"))?
            .ok_or_else(|| invalid("missing identity authority"))?;
        let same_state = serde_json::to_vec(&existing)? == serde_json::to_vec(&j.state)?;
        let previous_recovery = j.operation == "recover"
            && existing.revision.checked_add(1) == Some(j.state.revision)
            && existing.installation.as_ref().map(|i| i.id) == Some(installation.id);
        if !same_state && !previous_recovery {
            return Err(invalid(
                "pending delivery cannot replace a different authority revision",
            ));
        }
    } else if j.operation == "recover" {
        return Err(invalid("pending recovery requires the existing authority"));
    }
    let audit = crate::audit::AuditWriter::open(&j.data_dir)?;
    crate::audit::verify_hash_chain(&j.data_dir)?;
    let intent = audit.operation_with_details(
        "security",
        format!("installation.{}", j.operation),
        None,
        crate::audit::AuditContext {
            principal_id: installation.admin_id.clone(),
            tenant_id: Some(installation.tenant.clone()),
            transport: "offline".into(),
            request_id: Some(installation.id.to_string()),
        },
        serde_json::json!({"identity_revision":j.state.revision}),
    )?;
    let expected = format!("{}\n", j.credential);
    if j.key_out.try_exists()? {
        if private_bytes(&j.key_out)? != expected.as_bytes() {
            return Err(invalid(
                "credential destination does not match pending delivery",
            ));
        }
    } else {
        write_secret(&j.key_out, expected.as_bytes())?;
    }
    crate::failpoint::check("security_init.key_delivered")?;
    if j.operation == "initialize" {
        let generation = j.data_dir.join("generations").join(&j.generation);
        fs::create_dir_all(generation.join("collections"))?;
        crate::db::initialize_installation_catalog(&generation, installation.id)?;
        fs_util::sync_tree(&generation)?;
        fs_util::atomic_write(
            &j.data_dir.join("CURRENT"),
            format!("{}\n", j.generation).as_bytes(),
        )?;
    }
    let security = j.data_dir.join("security");
    private_dir(&security)?;
    persist(&security, &j.state)?;
    crate::failpoint::check("security_init.authority_committed")?;
    intent.success(serde_json::json!({"identity_revision":j.state.revision}))?;
    if j.operation == "initialize" {
        // Initialization replaces its deliberate `pending` marker only after
        // the complete authority and content generation are durable.
        fs_util::atomic_write(
            &j.data_dir.join(MARKER),
            format!("CHRNINSTALL1\n{}\n", installation.id).as_bytes(),
        )?;
    } else {
        write_marker(
            &j.data_dir,
            installation.id,
            match j.state.version {
                6 => 5,
                5 => 4,
                4 => 2,
                _ => 1,
            },
        )?;
    }
    fs_util::durable_remove_file(&j.data_dir.join(PENDING))?;
    crate::failpoint::check("security_init.ready")?;
    Ok(InstallationReport {
        installation_id: installation.id,
        principal_id: installation.admin_id.clone(),
        admin: j.state.user_name(&installation.admin_id)?.into(),
        tenant: installation.tenant.clone(),
        identity_revision: j.state.revision,
        admin_key_file: j.key_out.clone(),
        storage_keyring_file: j.keyring.clone(),
        next_steps: [
            "Start chirondb with operator-provided TLS, this external keyring and --tenant-enforcement enforced.",
            "Connect using chironql --url https://<server-hostname>:7401 --ca-cert <ca.pem> --api-key-file <admin_key_file>.",
        ],
    })
}

pub fn recover_admin(
    data_dir: &Path,
    keyring: &Path,
    key_out: &Path,
    resume: bool,
) -> crate::Result<InstallationReport> {
    let data_dir = checked_path(data_dir)?;
    let keyring = checked_path(keyring)?;
    let key_out = checked_path(key_out)?;
    validate_outputs(&data_dir, &keyring, &key_out)?;
    let lease = Arc::new(crate::data_dir_lock::DataDirLock::acquire(&data_dir)?);
    install_keyring(&keyring)?;
    let journal = if resume {
        let j = read_journal(&data_dir)?;
        if j.operation != "recover" || j.keyring != keyring || j.key_out != key_out {
            return Err(invalid("recovery resume arguments changed"));
        }
        j
    } else {
        validate_ready(&data_dir)?;
        if key_out.exists() {
            return Err(invalid("credential output already exists"));
        }
        private_dir(
            key_out
                .parent()
                .ok_or_else(|| invalid("missing credential parent"))?,
        )?;
        crate::audit::verify_hash_chain(&data_dir)?;
        encryption::verify_tree(&encryption::Keyring::load(&keyring)?, &data_dir)?;
        let audit = crate::audit::AuditWriter::open(&data_dir)?;
        let authority = IdentityAuthority::open_with_audit(&data_dir, audit, lease.clone())?
            .ok_or(SecurityError::Unavailable)?;
        let mut state = authority.current.read().state.clone();
        crate::db::verify_installation_catalog(
            &data_dir,
            authority
                .installation_id()
                .ok_or(SecurityError::Unavailable)?,
        )?;
        let installation = state
            .installation
            .as_mut()
            .ok_or_else(|| invalid("recovery requires an initialized installation"))?;
        let old = installation.admin_id.clone();
        let new = administrator(Uuid::new_v4().to_string(), &installation.tenant);
        installation.admin_id = new.id.clone();
        let name = state
            .user_names
            .iter()
            .find_map(|(name, id)| (id == &old).then(|| name.clone()))
            .unwrap_or_else(|| format!("recovered-{}", Uuid::new_v4()));
        state.user_names.retain(|_, id| id != &old);
        state
            .principals
            .get_mut(&old)
            .ok_or(SecurityError::Unavailable)?
            .enabled = false;
        state.retired_users.insert(old.clone());
        state.memberships.remove(&old);
        for credential in state
            .credentials
            .values_mut()
            .filter(|c| c.principal == old)
        {
            credential.revoked = true;
        }
        for credential in state
            .sql_credentials
            .values_mut()
            .filter(|c| c.principal == old)
        {
            credential.revoked = true;
        }
        let (id, credential, record) = new_credential(&new.id)?;
        state.user_names.insert(name, new.id.clone());
        state.principals.insert(new.id.clone(), new);
        state.credentials.insert(id, record);
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or(SecurityError::Unavailable)?;
        state.validate()?;
        let j = Journal {
            version: 1,
            operation: "recover".into(),
            data_dir: data_dir.clone(),
            keyring,
            key_out,
            state,
            credential,
            generation: String::new(),
        };
        write_journal(&j)?;
        crate::failpoint::check("security_recover.prepared")?;
        j
    };
    finish(&journal)
}

impl IdentityAuthority {
    pub fn installation_id(&self) -> Option<Uuid> {
        self.current
            .read()
            .state
            .installation
            .as_ref()
            .map(|i| i.id)
    }
}
