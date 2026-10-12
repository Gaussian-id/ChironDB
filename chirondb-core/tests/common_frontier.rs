use chirondb_core::{
    Db, SqlExecutionRequest, SqlResult,
    db::{
        create_offline_protected_backup, create_offline_protected_journal_archive,
        restore_offline_protected_backup,
    },
    encryption,
    security::{Action, ScopeGrant, SecurityError, onboarding},
};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Command,
};

fn request(sql: &str, key: Option<&str>) -> SqlExecutionRequest {
    serde_json::from_value(serde_json::json!({"statements":[{"sql":sql}],"idempotency_key":key}))
        .unwrap()
}
fn install(root: &Path) {
    if !encryption::encryption_enabled() {
        encryption::install_process_keyring(
            encryption::Keyring::load(root.join("storage.json")).unwrap(),
            true,
        )
        .unwrap();
    }
}
fn actor(db: &Db, root: &Path) -> chirondb_core::security::AuthenticatedIdentity {
    let secret = std::fs::read_to_string(root.join("admin.key")).unwrap();
    db.identity_authority()
        .unwrap()
        .authenticate(secret.trim())
        .unwrap()
}
fn prepare(root: &Path) {
    onboarding::initialize(
        &root.join("live"),
        "acme",
        "admin",
        &root.join("storage.json"),
        &root.join("admin.key"),
        false,
    )
    .unwrap();
    let db = Db::open(root.join("live")).unwrap();
    let user = actor(&db, root);
    db.execute_sql_authorized(
        &user,
        request(
            "CREATE TABLE knowledge (id BIGINT PRIMARY KEY, title TEXT)",
            None,
        ),
        "frontier-test",
    )
    .unwrap();
    let mut principal = user.principal().clone();
    principal.grants.push(ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: BTreeSet::from(["knowledge".into()]),
        actions: BTreeSet::from([Action::Create, Action::Read]),
    });
    db.identity_authority()
        .unwrap()
        .put_principal(&user, user.revision(), principal)
        .unwrap();
    let user = actor(&db, root);
    db.execute_sql_authorized(
        &user,
        request("INSERT INTO knowledge VALUES (1, 'base')", Some("base")),
        "frontier-test",
    )
    .unwrap();
    drop(db);
    Db::migrate_transaction_authority_offline(root.join("live")).unwrap();
}
fn migrate(root: &Path) {
    install(root);
    Db::migrate_common_frontier_offline(root.join("live")).unwrap();
}
fn suffix(root: &Path) {
    install(root);
    let db = Db::open(root.join("live")).unwrap();
    let user = actor(&db, root);
    db.execute_sql_authorized(
        &user,
        request("INSERT INTO knowledge VALUES (2, 'suffix')", Some("suffix")),
        "frontier-test",
    )
    .unwrap();
}
fn verify(root: &Path) {
    install(root);
    let db = Db::open(root.join("live")).unwrap();
    for directory in [
        root.join("live/common-frontier"),
        root.join("live/generations"),
    ] {
        assert!(
            !std::fs::read_dir(directory).unwrap().any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with("staging")),
            "interrupted staging must be cleaned after validation"
        );
    }
    let user = actor(&db, root);
    let selected = db
        .execute_sql_authorized(
            &user,
            request("SELECT id, title FROM knowledge ORDER BY id", None),
            "frontier-test",
        )
        .unwrap();
    assert!(matches!(&selected.results[0], SqlResult::Rows { rows, .. } if rows.len()==2));
    let retry = db
        .execute_sql_authorized(
            &user,
            request("INSERT INTO knowledge VALUES (2, 'suffix')", Some("suffix")),
            "frontier-test",
        )
        .unwrap();
    assert!(retry.committed);
    assert!(
        db.execute_sql_authorized(
            &user,
            request(
                "INSERT INTO knowledge VALUES (3, 'changed')",
                Some("suffix")
            ),
            "frontier-test"
        )
        .is_err()
    );
}
fn hashes(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, current: &Path, files: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(current).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                walk(root, &path, files);
            } else {
                files.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut files = std::collections::BTreeMap::new();
    walk(root, root, &mut files);
    files
}
fn setup_multimodel(root: &Path) {
    install(root);
    let db = Db::open(root.join("live")).unwrap();
    let user = actor(&db, root);
    db.create_protected_collection_authorized(
        &user,
        db.catalog_revision_authorized(&user).unwrap(),
        serde_json::from_value(serde_json::json!({"name":"vectors","vector_dim":2})).unwrap(),
    )
    .unwrap();
    db.execute_sql_authorized(&user,request("CREATE TABLE links (id BIGINT PRIMARY KEY, source RECORD_REF('vectors'), target RECORD_REF('vectors'))",None),"frontier-test").unwrap();
    let mut principal = user.principal().clone();
    principal.grants.push(ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: BTreeSet::from(["links".into()]),
        actions: BTreeSet::from([Action::Create, Action::Read]),
    });
    principal.grants.push(ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: BTreeSet::from(["vectors".into()]),
        actions: BTreeSet::from([
            Action::Create,
            Action::Read,
            Action::Ingest,
            Action::Search,
            Action::GraphRead,
            Action::GraphWrite,
        ]),
    });
    db.identity_authority()
        .unwrap()
        .put_principal(&user, user.revision(), principal)
        .unwrap();
    let user = actor(&db, root);
    let schema = db
        .bind_access(&user, "vectors", "acme", Action::Schema)
        .unwrap();
    db.set_graph_lifecycle_authorized(&schema, schema.policy_revision(), true)
        .unwrap()
        .publish(|v| v)
        .unwrap();
    let schema = db
        .bind_access(&user, "vectors", "acme", Action::Schema)
        .unwrap();
    db.configure_edge_type_authorized(
        &schema,
        schema.policy_revision(),
        serde_json::from_value(serde_json::json!({"name":"cites","weight_property":null})).unwrap(),
    )
    .unwrap()
    .publish(|v| v)
    .unwrap();
    let manage = db
        .bind_access(&user, "vectors", "acme", Action::PolicyManage)
        .unwrap();
    db.replace_collection_policy_authorized(&manage,chirondb_core::security::RevisionUpdate {
        expected_revision:manage.policy_revision(), value:serde_json::from_value(serde_json::json!({
            "department_actions":[],"owner_actions":["read","graph_read","graph_write"],
            "templates":{"standard":{"department":"Security","classification":"internal",
                "properties":{"/text":{"classification":"internal","actions":["read","query","write"]}},
                "representations":{"dense":{"source_fields":["/text"],"classification":"internal"}}}}
        })).unwrap() }).unwrap();
}
fn bundle_request(id: i64) -> chirondb_core::db::MultiModelInsertRequest {
    serde_json::from_value(serde_json::json!({
        "sql":{"statements":[{"sql":format!("INSERT INTO links VALUES ({id}, RECORD_REF('vectors', NEW_RECORD('source')), RECORD_REF('vectors', NEW_RECORD('target'))) ")}],"idempotency_key":format!("bundle-{id}")},
        "collection":"vectors","template":"standard",
        "records":[{"binding":"source","point":{"vector":[1.0,0.0],"payload":{"text":"source"}}},{"binding":"target","point":{"vector":[0.0,1.0],"payload":{"text":"target"}}}],
        "relations":[{"source":{"kind":"new","value":"source"},"target":{"kind":"new","value":"target"},"edge_type":"cites","properties":{}}]
    })).unwrap()
}
fn bundle(root: &Path, id: i64) {
    install(root);
    let db = Db::open(root.join("live")).unwrap();
    let user = actor(&db, root);
    let receipt = db
        .insert_multimodel_authorized(&user, bundle_request(id), "frontier-test")
        .unwrap();
    std::fs::write(
        root.join(format!("bundle-{id}.json")),
        serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap();
}
fn verify_bundles(root: &Path) {
    install(root);
    let db = Db::open(root.join("live")).unwrap();
    let user = actor(&db, root);
    for id in [1, 2] {
        let expected: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join(format!("bundle-{id}.json"))).unwrap())
                .unwrap();
        let actual = serde_json::to_value(
            db.insert_multimodel_authorized(&user, bundle_request(id), "frontier-test")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(actual["records"], expected["records"]);
        assert_eq!(actual["edge_ids"], expected["edge_ids"]);
        assert_eq!(
            actual["sql"]["transaction_id"],
            expected["sql"]["transaction_id"]
        );
    }
    let selected = db
        .execute_sql_authorized(
            &user,
            request("SELECT id, source, target FROM links ORDER BY id", None),
            "frontier-test",
        )
        .unwrap();
    assert!(matches!(&selected.results[0],SqlResult::Rows { rows,.. } if rows.len()==2));
}

fn command(root: &Path, mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "fixture_process",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("CHIRON_FRONTIER_ROOT", root.canonicalize().unwrap())
        .env("CHIRON_FRONTIER_MODE", mode)
        .env_remove("CHIRONDB_FAILPOINT")
        .env_remove("CHIRONDB_FAILPOINT_MARKER")
        .env_remove("CHIRONDB_FAILPOINT_RELEASE");
    command
}
fn child(root: &Path, mode: &str) {
    let output = command(root, mode).output().unwrap();
    assert!(
        output.status.success(),
        "mode={mode}\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn fixture() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    child(temp.path(), "prepare");
    temp
}
fn snapshot(root: &Path) -> PathBuf {
    install(root);
    let id: String = serde_json::from_slice(
        &encryption::read_persistent(&root.join("live/common-frontier/CURRENT")).unwrap(),
    )
    .unwrap();
    root.join("live/common-frontier").join(id)
}
#[test]
fn fixture_process() {
    let Some(root) = std::env::var_os("CHIRON_FRONTIER_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let mode = std::env::var("CHIRON_FRONTIER_MODE").unwrap();
    match mode.as_str() {
        "prepare" => prepare(&root),
        "setup-multimodel" => setup_multimodel(&root),
        "bundle-base" => bundle(&root, 1),
        "bundle-suffix" => bundle(&root, 2),
        "verify-bundles" => verify_bundles(&root),
        "migrate" => migrate(&root),
        "suffix" => suffix(&root),
        "catalog-base" | "catalog-recreate" | "catalog-verify" | "catalog-verify-base" => {
            install(&root);
            let db = Db::open(root.join("live")).unwrap();
            let mut user = actor(&db, &root);
            if mode == "catalog-base" {
                let mut principal = user.principal().clone();
                principal.grants.push(ScopeGrant {
                    tenants: BTreeSet::from(["acme".into()]),
                    collections: BTreeSet::from(["query-spill".into()]),
                    actions: BTreeSet::from([Action::Read]),
                });
                db.identity_authority()
                    .unwrap()
                    .put_principal(&user, user.revision(), principal)
                    .unwrap();
                user = actor(&db, &root);
            }
            if mode == "catalog-recreate" {
                db.delete_protected_collection_authorized(&user, "query-spill")
                    .unwrap();
            }
            if mode == "catalog-verify" || mode == "catalog-verify-base" {
                assert_eq!(
                    db.protected_collection_config_authorized(&user, "query-spill")
                        .unwrap()
                        .vector_dim,
                    if mode == "catalog-verify-base" { 2 } else { 3 }
                );
            } else {
                db.create_protected_collection_authorized(&user,
                    db.catalog_revision_authorized(&user).unwrap(),
                    serde_json::from_value(serde_json::json!({"name":"query-spill", "vector_dim": if mode == "catalog-base" {2} else {3}})).unwrap()).unwrap();
            }
        }
        "new-key-context" | "missing-old-key" | "rewrap-refuse" => {
            use base64::Engine;
            let path = root.join("storage.json");
            let mut value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            let new_id = uuid::Uuid::new_v4().to_string();
            value["keys"].as_array_mut().unwrap().push(serde_json::json!({"id":new_id, "key_base64":base64::engine::general_purpose::STANDARD.encode([29;32])}));
            value["active_key_id"] = new_id.clone().into();
            if mode == "missing-old-key" {
                value["keys"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|k| k["id"] == new_id);
            }
            std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            if mode == "rewrap-refuse" {
                let before = hashes(&root.join("live"));
                let keyring = encryption::Keyring::load(&path).unwrap();
                assert!(encryption::rewrap_tree_resumable(&keyring, &root.join("live")).is_err());
                assert_eq!(before, hashes(&root.join("live")));
            } else if mode == "missing-old-key" {
                install(&root);
                let before = hashes(&root.join("live"));
                assert!(Db::open(root.join("live")).is_err());
                assert_eq!(before, hashes(&root.join("live")));
            } else {
                verify(&root);
            }
        }
        "verify" => verify(&root),
        "refuse" => {
            install(&root);
            let before = hashes(&root.join("live"));
            assert!(Db::open(root.join("live")).is_err());
            assert_eq!(
                before,
                hashes(&root.join("live")),
                "refusal must precede startup writes"
            );
        }
        "backup" => {
            install(&root);
            let keyring = encryption::Keyring::load(root.join("storage.json")).unwrap();
            create_offline_protected_backup(&root.join("live"), &root.join("backup"), &keyring)
                .unwrap();
        }
        "restore" | "restore-revoked" => {
            install(&root);
            let keyring = encryption::Keyring::load(root.join("storage.json")).unwrap();
            create_offline_protected_journal_archive(
                &root.join("live"),
                &root.join("archive"),
                &keyring,
            )
            .unwrap();
            restore_offline_protected_backup(
                &root.join("backup"),
                &root.join("archive"),
                &root.join("restored"),
                &keyring,
            )
            .unwrap();
            assert!(
                std::fs::read(root.join("restored/.protected-installation"))
                    .unwrap()
                    .starts_with(b"CHRNINSTALL7\n")
            );
            let db = Db::open(root.join("restored")).unwrap();
            let user = actor(&db, &root);
            let selected = db
                .execute_sql_authorized(
                    &user,
                    request("SELECT id FROM knowledge ORDER BY id", None),
                    "frontier-test",
                )
                .unwrap();
            assert!(matches!(&selected.results[0], SqlResult::Rows { rows, .. } if rows.len()==2));
            if mode == "restore-revoked" {
                for key in ["suffix", "new-after-restore"] {
                    assert!(matches!(
                        db.execute_sql_authorized(
                            &user,
                            request("INSERT INTO knowledge VALUES (2, 'suffix')", Some(key)),
                            "frontier-test"
                        ),
                        Err(chirondb_core::GaussError::Security(
                            SecurityError::Forbidden
                        ))
                    ));
                }
            }
        }
        "revoke" => {
            install(&root);
            let db = Db::open(root.join("live")).unwrap();
            let user = actor(&db, &root);
            let mut principal = user.principal().clone();
            for grant in &mut principal.grants {
                grant.actions.remove(&Action::Create);
            }
            db.identity_authority()
                .unwrap()
                .put_principal(&user, user.revision(), principal)
                .unwrap();
        }
        "verify-revoke" => {
            install(&root);
            let db = Db::open(root.join("live")).unwrap();
            let user = actor(&db, &root);
            assert!(matches!(
                db.execute_sql_authorized(
                    &user,
                    request(
                        "INSERT INTO knowledge VALUES (3, 'forbidden')",
                        Some("forbidden")
                    ),
                    "frontier-test"
                ),
                Err(chirondb_core::GaussError::Security(
                    SecurityError::Forbidden
                ))
            ));
            let selected = db
                .execute_sql_authorized(
                    &user,
                    request("SELECT id FROM knowledge ORDER BY id", None),
                    "frontier-test",
                )
                .unwrap();
            assert!(matches!(&selected.results[0], SqlResult::Rows { rows, .. } if rows.len()==2));
        }
        "remove-manifest" => {
            let snapshot = snapshot(&root);
            std::fs::remove_file(snapshot.join("manifest.gdx")).unwrap();
        }
        "corrupt-content" => {
            let snapshot = snapshot(&root);
            let path = snapshot.join("content/catalog.json");
            assert!(path.exists());
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[0] ^= 1;
            std::fs::write(path, bytes).unwrap();
        }
        "foreign-manifest" | "ahead-manifest" => {
            let snapshot = snapshot(&root);
            let path = snapshot.join("manifest.gdx");
            let mut value: serde_json::Value =
                serde_json::from_slice(&encryption::read_persistent(&path).unwrap()).unwrap();
            if mode == "ahead-manifest" {
                value["commit_frontier"] = u64::MAX.into();
            } else {
                value["installation"] = uuid::Uuid::new_v4().to_string().into();
            }
            encryption::atomic_write_persistent(
                &path,
                encryption::FileType::Metadata,
                &serde_json::to_vec(&value).unwrap(),
            )
            .unwrap();
        }
        _ => panic!("unknown mode {mode}"),
    }
}
#[test]
fn materialized_base_and_committed_suffix_keep_retry_identity_after_repeated_reopen() {
    let temp = fixture();
    child(temp.path(), "migrate");
    child(temp.path(), "suffix");
    child(temp.path(), "verify");
    child(temp.path(), "verify");
}
#[test]
fn missing_authoritative_manifest_refuses_before_repair() {
    let temp = fixture();
    child(temp.path(), "migrate");
    child(temp.path(), "remove-manifest");
    child(temp.path(), "refuse");
}
#[test]
fn corrupted_materialized_content_refuses_before_repair() {
    let temp = fixture();
    child(temp.path(), "migrate");
    child(temp.path(), "corrupt-content");
    child(temp.path(), "refuse");
}
#[test]
fn foreign_installation_manifest_refuses_before_repair() {
    let temp = fixture();
    child(temp.path(), "migrate");
    child(temp.path(), "foreign-manifest");
    child(temp.path(), "refuse");
}
#[test]
fn current_revocation_outlives_materialized_content_recovery() {
    let temp = fixture();
    child(temp.path(), "migrate");
    child(temp.path(), "suffix");
    child(temp.path(), "revoke");
    child(temp.path(), "verify-revoke");
}
#[test]
fn protected_backup_archive_restore_keeps_frontier_activation_and_suffix() {
    let temp = fixture();
    child(temp.path(), "migrate");
    child(temp.path(), "backup");
    child(temp.path(), "suffix");
    child(temp.path(), "restore");
}
#[cfg(all(unix, feature = "fault-injection"))]
#[test]
fn physical_sigkill_publication_boundaries_keep_complete_roots() {
    use std::{
        os::unix::process::ExitStatusExt,
        process::Stdio,
        time::{Duration, Instant},
    };
    for point in [
        "common_frontier.after_stage_sync",
        "common_frontier.before_publish",
        "common_frontier.after_publish",
        "common_frontier.after_activation",
        "common_frontier.before_root_publish",
        "common_frontier.after_root_publish",
    ] {
        let temp = fixture();
        let recover = point.contains("root_publish");
        if recover {
            child(temp.path(), "migrate");
            child(temp.path(), "suffix");
        }
        let marker = temp.path().join("paused");
        let log = std::fs::File::create(temp.path().join("child.log")).unwrap();
        let mut process = command(temp.path(), if recover { "verify" } else { "migrate" })
            .env("CHIRONDB_FAILPOINT", format!("pause:{point}"))
            .env("CHIRONDB_FAILPOINT_MARKER", &marker)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(45);
        while !marker.exists() {
            if let Some(status) = process.try_wait().unwrap() {
                panic!(
                    "{point}: {status}\n{}",
                    std::fs::read_to_string(temp.path().join("child.log")).unwrap()
                );
            }
            if Instant::now() >= deadline {
                process.kill().unwrap();
                process.wait().unwrap();
                panic!("cut not reached: {point}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        process.kill().unwrap();
        assert_eq!(process.wait().unwrap().signal(), Some(9));
        if !recover {
            child(temp.path(), "migrate");
            child(temp.path(), "suffix");
        }
        child(temp.path(), "verify");
    }
}

#[test]
fn atomic_sql_vector_graph_suffix_preserves_allocated_records_and_edges() {
    let temp = fixture();
    child(temp.path(), "setup-multimodel");
    child(temp.path(), "bundle-base");
    child(temp.path(), "migrate");
    child(temp.path(), "bundle-suffix");
    child(temp.path(), "verify-bundles");
    child(temp.path(), "verify-bundles");
}

#[test]
fn frontier_ahead_of_current_authority_refuses_without_startup_writes() {
    let temp = fixture();
    child(temp.path(), "migrate");
    child(temp.path(), "ahead-manifest");
    child(temp.path(), "refuse");
}

#[test]
fn missing_current_allocator_refuses_without_regenerating_identity() {
    let temp = fixture();
    child(temp.path(), "migrate");
    std::fs::remove_file(temp.path().join("live/graph_identity.gdx")).unwrap();
    child(temp.path(), "refuse");
}

#[test]
fn collection_drop_recreate_recovers_latest_incarnation() {
    let temp = fixture();
    child(temp.path(), "catalog-base");
    child(temp.path(), "migrate");
    child(temp.path(), "catalog-verify-base");
    child(temp.path(), "catalog-recreate");
    child(temp.path(), "catalog-verify");
    child(temp.path(), "catalog-verify");
}

#[test]
fn changed_key_context_keeps_recovery_and_missing_old_key_refuses() {
    let temp = fixture();
    child(temp.path(), "migrate");
    child(temp.path(), "suffix");
    child(temp.path(), "new-key-context");
    child(temp.path(), "missing-old-key");
}

#[test]
fn unsupported_envelope_rewrap_refuses_before_changing_frontier_proofs() {
    let temp = fixture();
    child(temp.path(), "migrate");
    child(temp.path(), "rewrap-refuse");
}

#[test]
fn protected_restore_does_not_restore_revoked_write_or_receipt_access() {
    let temp = fixture();
    child(temp.path(), "migrate");
    child(temp.path(), "backup");
    child(temp.path(), "suffix");
    child(temp.path(), "revoke");
    child(temp.path(), "restore-revoked");
}
