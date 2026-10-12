//! One immutable materialized prefix for all models. Only explicit offline
//! activation makes it authoritative. Original journal/audit bytes are retained;
//! current identity, allocator and consumed keys never roll back with content.
use super::*;
use crate::relational::wal_decode::{self, MetadataCharge, Owned};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
};

const DIRECTORY: &str = "common-frontier";
const MANIFEST: &str = "manifest.gdx";
const LINEAGE: &str = ".common-frontier-lineage";
const MAX_MANIFEST: u64 = 8 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileProof {
    bytes: u64,
    digest: [u8; 32],
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u16,
    installation: uuid::Uuid,
    id: uuid::Uuid,
    source_generation: String,
    commit_frontier: u64,
    identity_revision: u64,
    incarnations: BTreeMap<String, uuid::Uuid>,
    files: BTreeMap<String, FileProof>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Lineage {
    version: u16,
    installation: uuid::Uuid,
    base: uuid::Uuid,
    frontier: u64,
}

fn invalid(message: &str) -> GaussError {
    GaussError::WalCorruption {
        path: DIRECTORY.into(),
        message: message.into(),
    }
}
fn check(deadline: Instant) -> Result<()> {
    crate::relational::check_sql_cancelled()?;
    if Instant::now() >= deadline {
        return Err(GaussError::ResourceExhausted(
            "common frontier deadline exceeded".into(),
        ));
    }
    Ok(())
}
fn read_owned<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Owned<T>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_MANIFEST {
        return Err(invalid("invalid common frontier metadata file"));
    }
    let mut memory = MetadataCharge::default();
    memory.prepare(
        metadata
            .len()
            .checked_mul(4)
            .and_then(|n| n.checked_add(4096))
            .ok_or_else(|| invalid("common frontier metadata too large"))?,
    )?;
    let bytes = crate::encryption::read_persistent(path)?;
    if bytes.len() as u64 > MAX_MANIFEST {
        return Err(invalid("common frontier metadata too large"));
    }
    wal_decode::decode(&bytes)
}
fn write<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = wal_decode::encode(value)?;
    if bytes.len() as u64 > MAX_MANIFEST {
        return Err(invalid("common frontier manifest too large"));
    }
    let mut memory = MetadataCharge::default();
    memory.prepare(bytes.len() as u64 * 2 + 4096)?;
    crate::encryption::atomic_write_persistent(path, crate::encryption::FileType::Metadata, &bytes)
}
fn proof(path: &Path, bytes: u64, deadline: Instant) -> Result<FileProof> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() < bytes {
        return Err(invalid("missing or truncated common frontier file"));
    }
    let mut memory = MetadataCharge::default();
    memory.prepare(72 * 1024)?;
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    let mut remaining = bytes;
    while remaining != 0 {
        check(deadline)?;
        let count = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    Ok(FileProof {
        bytes,
        digest: hash.finalize().into(),
    })
}
fn skipped(root: &Path, path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some(".chirondb.lock" | LINEAGE)
    ) || path.strip_prefix(root).ok() == Some(Path::new("relational/query-spill"))
        || crate::relational::disk_map::DiskMap::is_journal_scratch(path)
        || Wal::is_snapshot_scratch(path)
}
fn copy(source: &Path, destination: &Path, deadline: Instant) -> Result<()> {
    copy_tree(source, source, destination, deadline)
}
fn copy_tree(root: &Path, source: &Path, destination: &Path, deadline: Instant) -> Result<()> {
    check(deadline)?;
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        return Err(invalid("common frontier refuses symlinks"));
    }
    let mut memory = MetadataCharge::default();
    memory.prepare(
        (source.as_os_str().len() as u64 + destination.as_os_str().len() as u64) * 8 + 72 * 1024,
    )?;
    if metadata.is_dir() {
        durable_create_dir(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            if entry.file_type()?.is_symlink() {
                return Err(invalid("common frontier refuses symlinks"));
            }
            if skipped(root, &entry.path()) {
                continue;
            }
            copy_tree(
                root,
                &entry.path(),
                &destination.join(entry.file_name()),
                deadline,
            )?;
        }
        sync_directory(destination)?;
    } else if metadata.is_file() {
        let mut input = fs::File::open(source)?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        let mut buffer = [0; 64 * 1024];
        loop {
            check(deadline)?;
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            output.write_all(&buffer[..count])?;
        }
        output.sync_all()?;
    } else {
        return Err(invalid("common frontier refuses special files"));
    }
    Ok(())
}
fn inventory(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, FileProof>,
    memory: &mut MetadataCharge,
    charged: &mut u64,
    deadline: Instant,
) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        check(deadline)?;
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("common frontier refuses symlinks"));
        }
        if metadata.is_dir() {
            inventory(root, &path, files, memory, charged, deadline)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| invalid("common frontier path escaped"))?;
            let length = relative.as_os_str().len() as u64;
            *charged = charged
                .checked_add(length * 8 + 1024)
                .ok_or_else(|| invalid("common frontier inventory too large"))?;
            memory.prepare(*charged)?;
            let name = relative
                .to_str()
                .ok_or_else(|| invalid("non-UTF8 common frontier path"))?
                .replace(std::path::MAIN_SEPARATOR, "/");
            files.insert(name, proof(&path, metadata.len(), deadline)?);
        } else {
            return Err(invalid("common frontier refuses special files"));
        }
    }
    Ok(())
}
// Offline/open holds the installation lease. Remove only our unpublished
// UUID-named staging directories; selected and completed roots remain retained.
fn cleanup_staging(data: &Path) -> Result<()> {
    for (directory, suffix, generation) in [
        (data.join(DIRECTORY), ".staging", false),
        (
            data.join(crate::storage_layout::GENERATIONS_DIR),
            ".frontier-staging",
            true,
        ),
    ] {
        if !directory.try_exists()? {
            continue;
        }
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(id) = name.strip_prefix('.').and_then(|s| s.strip_suffix(suffix)) else {
                continue;
            };
            let id = if generation {
                id.strip_prefix("gen-").unwrap_or("")
            } else {
                id
            };
            if uuid::Uuid::parse_str(id).is_ok() {
                let metadata = fs::symlink_metadata(entry.path())?;
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(invalid("invalid common frontier staging directory"));
                }
                durable_remove_dir_all(&entry.path())?;
            }
        }
    }
    Ok(())
}

fn current(data: &Path) -> Result<(PathBuf, Owned<Manifest>)> {
    let directory = data.join(DIRECTORY);
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("invalid common frontier directory"));
    }
    let pointer: Owned<uuid::Uuid> = read_owned(&directory.join("CURRENT"))?;
    let root = directory.join(pointer.to_string());
    let metadata = fs::symlink_metadata(&root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("invalid common frontier generation"));
    }
    let manifest: Owned<Manifest> = read_owned(&root.join(MANIFEST))?;
    if manifest.version != 1 || manifest.id != *pointer || manifest.installation.is_nil() {
        return Err(invalid("common frontier identity or version mismatch"));
    }
    Ok((root, manifest))
}

impl Db {
    /// Opt into materialized-prefix recovery while stopped. Existing readers
    /// keep legacy behavior until installation format 7 is durably activated.
    pub fn migrate_common_frontier_offline(data_dir: impl AsRef<Path>) -> Result<bool> {
        let db = Self::open_for_offline_maintenance(data_dir)?;
        if crate::security::onboarding::has_common_frontier(&db.data_dir)? {
            return Ok(false);
        }
        if !TransactionJournal::has_authority_format(&db.data_dir)? {
            return Err(GaussError::InvalidRequest(
                "common frontier requires offline transaction authority migration first".into(),
            ));
        }
        let intent = db.audit_writer.operation_with_details(
            "storage",
            "storage.migrate_common_frontier",
            None,
            audit::AuditContext {
                principal_id: "offline-authority-migration".into(),
                tenant_id: None,
                transport: "offline".into(),
                request_id: None,
            },
            serde_json::json!({"installation_format": 7, "common_frontier_format": 1}),
        )?;
        db.checkpoint_common_frontier_inner(Instant::now() + Duration::from_secs(300), true)?;
        intent.success(serde_json::json!({"installation_format": 7, "migrated": true}))?;
        Ok(true)
    }
    pub(crate) fn checkpoint_common_frontier(&self, deadline: Instant) -> Result<()> {
        if !crate::security::onboarding::has_common_frontier(&self.data_dir)? {
            return Ok(());
        }
        self.checkpoint_common_frontier_inner(deadline, false)
    }
    pub(super) fn checkpoint_common_frontier_inner(
        &self,
        deadline: Instant,
        activate: bool,
    ) -> Result<()> {
        crate::relational::with_sql_deadline(deadline, || {
            self.capture_common_frontier(deadline, activate)
        })
    }
    fn capture_common_frontier(&self, deadline: Instant, activate: bool) -> Result<()> {
        check(deadline)?;
        let _lifecycle = self
            .lifecycle_gate
            .try_write_until(deadline)
            .ok_or_else(|| invalid("common frontier lifecycle deadline"))?;
        let _maintenance = self
            .maintenance_barrier
            .try_write_until(deadline)
            .ok_or_else(|| invalid("common frontier maintenance deadline"))?;
        let authority = self
            .identity_authority
            .as_ref()
            .ok_or(crate::security::SecurityError::Unavailable)?;
        authority.with_frontier_lock(deadline, || {
            let _pause = self.relational.read().pause_checkpoints_until(deadline)?;
            self.relational.read().ensure_restore_idle()?;
            let inner = self.inner.read();
            if inner.collections.values().any(|collection| {
                let collection = collection.read();
                collection.sealing.is_some()
                    || collection.index_build_in_flight
                    || collection.generation_build_in_flight
            }) {
                return Err(GaussError::ResourceExhausted(
                    "common frontier storage busy".into(),
                ));
            }
            drop(inner);
            self.flush_wals()?;
            let frontier = self
                .transaction_journal
                .completed_commit_frontier()?
                .ok_or_else(|| invalid("common frontier has unfinished decisions"))?;
            if !activate {
                let (_, previous) = current(&self.data_dir)?;
                if previous.commit_frontier == frontier
                    && previous.identity_revision == authority.revision()
                {
                    return Ok(());
                }
            }
            self.transaction_journal.checkpoint_completed_frontier()?;
            self.audit_writer.checkpoint_recovery()?;
            let id = authority
                .installation_id()
                .ok_or(crate::security::SecurityError::Unavailable)?;
            let layout = crate::storage_layout::resolve(&self.data_dir)?;
            let generation = layout
                .generation
                .ok_or_else(|| invalid("common frontier needs generations"))?;
            // Serialize against all audit writers during the copy, including
            // identity/admin operations that do not acquire the lifecycle gate.
            self.audit_writer.with_frozen_frontier(deadline, || {
                let directory = self.data_dir.join(DIRECTORY);
                durable_create_dir(&directory)?;
                cleanup_staging(&self.data_dir)?;
                let snapshot_id = uuid::Uuid::new_v4();
                let staging = directory.join(format!(".{snapshot_id}.staging"));
                let destination = directory.join(snapshot_id.to_string());
                durable_create_dir(&staging)?;
                let result = (|| {
                    copy(&layout.active_root, &staging.join("content"), deadline)?;
                    durable_create_dir(&staging.join("control"))?;
                    for name in ["security", "transactions", "audit"] {
                        copy(
                            &self.data_dir.join(name),
                            &staging.join("control").join(name),
                            deadline,
                        )?;
                    }
                    copy(
                        &self.data_dir.join(GRAPH_IDENTITY_FILE),
                        &staging.join("control").join(GRAPH_IDENTITY_FILE),
                        deadline,
                    )?;
                    let catalog = read_catalog(&layout.active_root)?;
                    if catalog.installation != Some(id) {
                        return Err(invalid("common frontier catalog installation mismatch"));
                    }
                    let mut memory = MetadataCharge::default();
                    let mut charged = 4096;
                    memory.prepare(charged)?;
                    let mut files = BTreeMap::new();
                    inventory(
                        &staging,
                        &staging.join("content"),
                        &mut files,
                        &mut memory,
                        &mut charged,
                        deadline,
                    )?;
                    inventory(
                        &staging,
                        &staging.join("control"),
                        &mut files,
                        &mut memory,
                        &mut charged,
                        deadline,
                    )?;
                    let manifest = Manifest {
                        version: 1,
                        installation: id,
                        id: snapshot_id,
                        source_generation: generation,
                        commit_frontier: frontier,
                        identity_revision: authority.revision(),
                        incarnations: catalog.protected,
                        files,
                    };
                    write(&staging.join(MANIFEST), &manifest)?;
                    check(deadline)?;
                    crate::failpoint::check("common_frontier.after_stage_sync")?;
                    durable_rename(&staging, &destination)?;
                    crate::failpoint::check("common_frontier.before_publish")?;
                    write(&directory.join("CURRENT"), &snapshot_id)?;
                    crate::failpoint::check("common_frontier.after_publish")?;
                    if activate {
                        crate::security::onboarding::activate_common_frontier(&self.data_dir, id)?;
                        crate::failpoint::check("common_frontier.after_activation")?;
                    }
                    metrics::counter!("chirondb_common_frontier_checkpoints_total").increment(1);
                    Ok(())
                })();
                if result.is_err() && staging.exists() {
                    let _ = durable_remove_dir_all(&staging);
                }
                result
            })
        })
    }
}

/// Validate before any model/control repair; build an entire private content
/// root from the immutable base and committed suffix, then publish CURRENT.
/// Current identity, audit, graph allocator and transaction authority stay put.
pub(super) struct Validated {
    snapshot: PathBuf,
    manifest: Owned<Manifest>,
}

pub(super) fn preflight(
    data: &Path,
    layout: &crate::storage_layout::StorageLayout,
) -> Result<Option<Validated>> {
    if !crate::security::onboarding::has_common_frontier(data)? {
        return Ok(None);
    }
    let (snapshot, manifest) = current(data)?;
    if crate::security::onboarding::installation_id_for_journal(data)?
        != Some(manifest.installation)
        || !TransactionJournal::has_authority_format(data)?
    {
        return Err(invalid(
            "common frontier installation or authority mismatch",
        ));
    }
    TransactionJournal::validate_materialized_frontier(
        data,
        manifest.installation,
        manifest.commit_frontier,
    )?;
    if layout.generation.as_deref() != Some(manifest.source_generation.as_str()) {
        let lineage: Owned<Lineage> = read_owned(&layout.active_root.join(LINEAGE))?;
        if lineage.version != 1
            || lineage.installation != manifest.installation
            || lineage.base != manifest.id
            || lineage.frontier != manifest.commit_frontier
        {
            return Err(invalid(
                "common frontier active generation lineage mismatch",
            ));
        }
    }
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut memory = MetadataCharge::default();
    let mut charged = 4096;
    let mut actual = BTreeMap::new();
    inventory(
        &snapshot,
        &snapshot.join("content"),
        &mut actual,
        &mut memory,
        &mut charged,
        deadline,
    )?;
    inventory(
        &snapshot,
        &snapshot.join("control"),
        &mut actual,
        &mut memory,
        &mut charged,
        deadline,
    )?;
    if actual.len() != manifest.files.len() {
        return Err(invalid("common frontier inventory changed"));
    }
    for (name, expected) in &manifest.files {
        let Some(found) = actual.get(name) else {
            return Err(invalid("common frontier file missing"));
        };
        if found.bytes != expected.bytes || found.digest != expected.digest {
            return Err(invalid("common frontier file binding changed"));
        }
        if let Some(path) = name.strip_prefix("control/transactions/journal/") {
            let live = data
                .join(crate::transaction_journal::TRANSACTION_JOURNAL_DIR)
                .join(path);
            if proof(&live, expected.bytes, deadline)?.digest != expected.digest {
                return Err(invalid("common frontier journal lineage changed"));
            }
        }
    }
    crate::security::onboarding::validate_frontier_identity(
        &snapshot.join("control"),
        manifest.installation,
        manifest.identity_revision,
    )?;
    crate::graph_identity::validate_materialized_allocator(data, &snapshot.join("control"))?;
    let base_catalog = read_catalog(&snapshot.join("content"))?;
    if base_catalog.installation != Some(manifest.installation)
        || base_catalog.protected != manifest.incarnations
    {
        return Err(invalid("common frontier catalog incarnation changed"));
    }
    crate::security::onboarding::validate_frontier_identity(
        data,
        manifest.installation,
        manifest.identity_revision,
    )?;
    if !super::protected_backup::audit_is_prefix(&snapshot.join("control"), data)? {
        return Err(invalid("common frontier audit lineage changed"));
    }
    Ok(Some(Validated { snapshot, manifest }))
}

pub(super) fn recover(
    data: &Path,
    layout: &crate::storage_layout::StorageLayout,
    journal: &Arc<TransactionJournal>,
    cold: Option<&ColdObjectStoreConfig>,
    validated: Option<Validated>,
) -> Result<(PathBuf, u64)> {
    let Some(Validated { snapshot, manifest }) = validated else {
        return Ok((layout.active_root.clone(), 0));
    };
    let deadline = Instant::now() + Duration::from_secs(300);
    cleanup_staging(data)?;
    journal.for_each_recovery_after(manifest.commit_frontier, |_| Ok(false), |_| unreachable!())?;
    let generations = data.join(crate::storage_layout::GENERATIONS_DIR);
    let generation = crate::storage_layout::new_generation_id();
    let staging = generations.join(format!(".{generation}.frontier-staging"));
    let destination = generations.join(&generation);
    let result = (|| {
        copy(&snapshot.join("content"), &staging, deadline)?;
        super::transaction_recovery::materialize_suffix(
            journal,
            &staging,
            manifest.commit_frontier,
        )?;
        let loaded =
            load_db_root_with_journal(&staging, cold, journal.storage_projection_authority()?)?;
        if loaded.catalog_replayed {
            write_catalog_state(&staging, &loaded.collections, &loaded.catalog_wal)?;
        }
        drop(loaded);
        drop(crate::relational::RelationalEngine::open(
            &staging,
            Arc::clone(journal),
        )?);
        write(
            &staging.join(LINEAGE),
            &Lineage {
                version: 1,
                installation: manifest.installation,
                base: manifest.id,
                frontier: manifest.commit_frontier,
            },
        )?;
        sync_tree(&staging)?;
        crate::failpoint::check("common_frontier.before_root_publish")?;
        durable_rename(&staging, &destination)?;
        crate::storage_layout::switch_current(data, &generation)?;
        crate::failpoint::check("common_frontier.after_root_publish")?;
        metrics::counter!("chirondb_common_frontier_recoveries_total").increment(1);
        Ok((destination, manifest.commit_frontier))
    })();
    if result.is_err() && staging.exists() {
        let _ = durable_remove_dir_all(&staging);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checkpoint_refusal_releases_admission_and_resumes_mutations() {
        const CHILD: &str = "CHIRON_COMMON_GUARDRAILS";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "db::common_frontier::tests::checkpoint_refusal_releases_admission_and_resumes_mutations", "--nocapture"])
                .env(CHILD, "1")
                .env_remove("CHIRONDB_FAILPOINT")
                .env_remove("CHIRONDB_FAILPOINT_MARKER")
                .env_remove("CHIRONDB_FAILPOINT_RELEASE")
                .output().unwrap();
            assert!(
                output.status.success(),
                "{} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let data = root.join("data");
        crate::security::onboarding::initialize(
            &data,
            "acme",
            "admin",
            &root.join("keys"),
            &root.join("admin"),
            false,
        )
        .unwrap();
        Db::migrate_transaction_authority_offline(&data).unwrap();
        Db::migrate_common_frontier_offline(&data).unwrap();
        let db = Db::open(&data).unwrap();
        let before = fs::read(data.join(DIRECTORY).join("CURRENT")).unwrap();
        let result = db.checkpoint_common_frontier_inner(Instant::now(), true);
        assert!(result.is_err());
        let result =
            crate::relational::with_sql_cancellation(Arc::new(AtomicBool::new(true)), || {
                db.checkpoint_common_frontier_inner(Instant::now() + Duration::from_secs(3), true)
            });
        assert!(result.is_err());
        let (result, used) = crate::relational::with_storage_test_limit(128, || {
            db.checkpoint_common_frontier_inner(Instant::now() + Duration::from_secs(3), true)
        });
        assert!(matches!(result, Err(GaussError::ResourceExhausted(_))));
        assert_eq!(used, 0, "failed publication must release all reservations");
        assert_eq!(
            before,
            fs::read(data.join(DIRECTORY).join("CURRENT")).unwrap()
        );
        // These scopes must release their lifecycle/checkpoint guards even on error.
        let identity = db
            .identity_authority()
            .unwrap()
            .authenticate(fs::read_to_string(root.join("admin")).unwrap().trim())
            .unwrap();
        db.execute_sql_authorized(&identity, serde_json::from_value(serde_json::json!({"statements":[{"sql":"CREATE TABLE after_refusal (id BIGINT PRIMARY KEY)"}]})).unwrap(), "guards").unwrap();
        db.checkpoint_common_frontier_inner(Instant::now() + Duration::from_secs(5), true)
            .unwrap();
        for directory in [
            data.join(DIRECTORY),
            data.join(crate::storage_layout::GENERATIONS_DIR),
        ] {
            assert!(!fs::read_dir(directory).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with("staging")
            }));
        }
        assert!(crate::relational::check_sql_cancelled().is_ok());
        let writing = db.clone();
        let user = identity.clone();
        let worker = std::thread::spawn(move || {
            for index in 0..12 {
                writing.execute_sql_authorized(&user, serde_json::from_value(serde_json::json!({"statements":[{"sql":format!("CREATE TABLE concurrent_{index} (id BIGINT PRIMARY KEY)")}]})).unwrap(), "concurrent-frontier").unwrap();
            }
        });
        while !worker.is_finished() {
            match db
                .checkpoint_common_frontier_inner(Instant::now() + Duration::from_secs(5), false)
            {
                Ok(()) | Err(GaussError::ResourceExhausted(_)) => {}
                Err(error) => panic!("unexpected frontier failure: {error}"),
            }
            std::thread::yield_now();
        }
        worker.join().unwrap();
        db.checkpoint_common_frontier_inner(Instant::now() + Duration::from_secs(5), false)
            .unwrap();
        drop(db);
        let reopened = Db::open(&data).unwrap();
        assert_eq!(reopened.relational_tables().len(), 13);
    }
}
