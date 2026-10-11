use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::AtomicBool,
};

use chirondb_core::{
    Db, GaussError, MultiModelInsertRequest, NewRecord, NewRelation, RecordEndpoint,
    RelationalValue, SqlResult, audit,
    db::{
        create_offline_protected_backup, create_offline_protected_journal_archive,
        restore_offline_protected_backup, verify_offline_protected_backup,
        verify_offline_protected_journal_archive,
    },
    encryption,
    graph::{ConfigureEdgeTypeRequest, GraphDirection, GraphTraverseRequest, TraversalBudget},
    resource_profile::{self, ResourceProfile},
    security::{
        Action, Classification, CollectionPolicy, IngestTemplate, NewPoint, PropertyAction,
        PropertyRule, Representation, RevisionUpdate, ScopeGrant, SecurityError, onboarding,
    },
};

#[test]
fn offline_protected_backup_copies_authority_audit_and_sql_with_a_restore_fence() {
    resource_profile::install(ResourceProfile::from_limits(2 * 1024 * 1024 * 1024, 2));
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let data = root.join("live");
    let keyring_path = root.join("storage.json");
    let admin_key = root.join("admin.key");
    let installation =
        onboarding::initialize(&data, "acme", "admin", &keyring_path, &admin_key, false).unwrap();
    let keyring = encryption::Keyring::load(&keyring_path).unwrap();
    let secret = std::fs::read_to_string(&admin_key).unwrap();
    let db = Db::open(&data).unwrap();
    let authority = db.identity_authority().unwrap();
    let actor = authority.authenticate(secret.trim()).unwrap();
    let catalog_revision = db.catalog_revision_authorized(&actor).unwrap();
    db.create_protected_collection_authorized(
        &actor,
        catalog_revision,
        serde_json::from_value(serde_json::json!({"name":"vectors","vector_dim":2})).unwrap(),
    )
    .unwrap();
    let request: chirondb_core::SqlExecutionRequest = serde_json::from_value(serde_json::json!({
        "statements": [{"sql": "CREATE TABLE knowledge (id BIGINT PRIMARY KEY, title TEXT, chunk RECORD_REF('vectors'), source RECORD_REF('vectors'))"}]
    }))
    .unwrap();
    db.execute_sql_authorized(&actor, request, "backup-test")
        .unwrap();
    let insert: chirondb_core::SqlExecutionRequest = serde_json::from_value(serde_json::json!({
        "statements": [{"sql": "INSERT INTO knowledge (id, title) VALUES (1, 'atlas')"}]
    }))
    .unwrap();
    assert!(matches!(
        db.execute_sql_authorized(&actor, insert.clone(), "backup-test"),
        Err(GaussError::Security(SecurityError::Forbidden))
    ));
    for (tenant, action) in [("other", Action::Create), ("acme", Action::IdentityManage)] {
        let mut invalid = actor.principal().clone();
        invalid.grants.push(ScopeGrant {
            tenants: BTreeSet::from([tenant.into()]),
            collections: BTreeSet::from(["knowledge".into()]),
            actions: BTreeSet::from([action]),
        });
        assert!(matches!(
            authority.put_principal(&actor, actor.revision(), invalid),
            Err(SecurityError::Forbidden)
        ));
    }
    let mut admin = actor.principal().clone();
    admin.grants.push(ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: BTreeSet::from(["knowledge".into()]),
        actions: BTreeSet::from([Action::Create, Action::Read]),
    });
    admin.grants.push(ScopeGrant {
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
    authority
        .put_principal(&actor, actor.revision(), admin)
        .unwrap();
    let actor = authority.authenticate(secret.trim()).unwrap();
    db.execute_sql_authorized(&actor, insert, "backup-test")
        .unwrap();
    let select: chirondb_core::SqlExecutionRequest = serde_json::from_value(serde_json::json!({
        "statements": [{"sql": "SELECT id, title FROM knowledge"}]
    }))
    .unwrap();
    let selected = db
        .execute_sql_authorized(&actor, select.clone(), "backup-test")
        .unwrap();
    assert!(matches!(&selected.results[0], SqlResult::Rows { rows, .. } if rows.len() == 1));
    let schema = db
        .bind_access(&actor, "vectors", "acme", Action::Schema)
        .unwrap();
    let (revision, _) = db
        .set_graph_lifecycle_authorized(&schema, schema.policy_revision(), true)
        .unwrap()
        .publish(|result| result)
        .unwrap();
    let schema = db
        .bind_access(&actor, "vectors", "acme", Action::Schema)
        .unwrap();
    let (revision, _) = db
        .configure_edge_type_authorized(
            &schema,
            revision,
            ConfigureEdgeTypeRequest {
                name: "cites".into(),
                weight_property: None,
            },
        )
        .unwrap()
        .publish(|result| result)
        .unwrap();
    let manage = db
        .bind_access(&actor, "vectors", "acme", Action::PolicyManage)
        .unwrap();
    let policy = CollectionPolicy {
        department_actions: BTreeSet::new(),
        owner_actions: BTreeSet::from([Action::Read, Action::GraphRead, Action::GraphWrite]),
        templates: BTreeMap::from([(
            "standard".into(),
            IngestTemplate {
                department: "Security".into(),
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
    db.replace_collection_policy_authorized(
        &manage,
        RevisionUpdate {
            expected_revision: revision,
            value: policy,
        },
    )
    .unwrap();
    let linked_request = MultiModelInsertRequest {
                sql: serde_json::from_value(serde_json::json!({
                    "statements": [{"sql": "INSERT INTO knowledge (id, title, chunk, source) VALUES (2, 'linked', RECORD_REF('vectors', NEW_RECORD('chunk')), RECORD_REF('vectors', NEW_RECORD('source')))"}],
                    "idempotency_key": "backup-linked-ingest"
                }))
                .unwrap(),
                collection: "vectors".into(),
                template: "standard".into(),
                records: [
                    ("chunk", [1.0, 0.0]),
                    ("source", [0.0, 1.0]),
                ]
                .into_iter()
                .map(|(binding, vector)| NewRecord {
                    binding: binding.into(),
                    point: NewPoint {
                        vector: vector.to_vec(),
                        vectors: BTreeMap::new(),
                        sparse_vector: None,
                        payload: serde_json::json!({"text": binding}),
                    },
                })
                .collect(),
                relations: vec![NewRelation {
                    source: RecordEndpoint::New("chunk".into()),
                    target: RecordEndpoint::New("source".into()),
                    edge_type: "cites".into(),
                    properties: serde_json::json!({"kind":"source"}),
                }],
            };
    let linked = db
        .insert_multimodel_authorized(&actor, linked_request.clone(), "backup-test")
        .unwrap();
    assert_eq!(linked.records.len(), 2);
    assert_eq!(linked.edge_ids.len(), 1);
    let linked_transaction = linked.sql.transaction_id;
    let linked_refs = linked.records;
    let destination = root.join("backup-1");
    assert!(create_offline_protected_backup(&data, &destination, &keyring).is_err());
    assert!(!destination.exists());
    drop(actor);
    let shutdown = db.shutdown(std::time::Instant::now() + std::time::Duration::from_secs(30));
    assert!(shutdown.audit_flushed && !shutdown.deadline_exceeded);
    let audit_checkpoint = data.join("audit/.chiron-decision-checkpoint/CURRENT");
    assert!(
        std::fs::read(&audit_checkpoint)
            .unwrap()
            .starts_with(encryption::MAGIC)
    );
    drop(db);

    let manifest = create_offline_protected_backup(&data, &destination, &keyring).unwrap();
    assert!(
        !destination
            .join("data/audit/.chiron-decision-checkpoint")
            .exists()
    );
    let metadata = serde_json::to_value(&manifest).unwrap();
    assert_eq!(
        serde_json::to_value(verify_offline_protected_backup(&destination, &keyring).unwrap())
            .unwrap(),
        metadata
    );
    assert_eq!(
        metadata["installation"],
        installation.installation_id.to_string()
    );
    assert!(metadata["completed_commit_frontier"].as_u64().unwrap() >= 1);
    assert!(
        metadata["files"]
            .as_object()
            .unwrap()
            .keys()
            .any(|name| name.starts_with("transactions/"))
    );
    assert!(
        metadata["files"]
            .as_object()
            .unwrap()
            .keys()
            .any(|name| name.starts_with("audit/"))
    );
    assert!(
        metadata["files"]
            .as_object()
            .unwrap()
            .keys()
            .any(|name| name.starts_with("security/"))
    );
    assert!(
        metadata["files"]
            .as_object()
            .unwrap()
            .keys()
            .any(|name| { name.contains("collections/vectors/") })
    );
    let encrypted_manifest = std::fs::read(destination.join("backup.manifest")).unwrap();
    assert!(encrypted_manifest.starts_with(b"CHIRENC1"));
    let parsed: serde_json::Value = serde_json::from_slice(
        &encryption::read_persistent(&destination.join("backup.manifest")).unwrap(),
    )
    .unwrap();
    assert_eq!(parsed, metadata);
    assert_eq!(
        std::fs::read_to_string(destination.join("data/.protected-installation")).unwrap(),
        format!("CHRNINSTALL3\n{}\n", installation.installation_id)
    );
    assert!(Db::open(destination.join("data")).is_err());
    verify_offline_protected_backup(&destination, &keyring).unwrap();
    if let Some(old_binary) = std::env::var_os("CHIRONDB_OLD_BINARY") {
        use std::{
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        let mut child = Command::new(old_binary)
            .env_clear()
            .arg("--encryption-keyring-file")
            .arg(&keyring_path)
            .args([
                "--listen-http",
                "127.0.0.1:0",
                "--listen-grpc",
                "127.0.0.1:0",
                "--listen-wire",
                "127.0.0.1:0",
                "--data-dir",
            ])
            .arg(destination.join("data"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut exited = false;
        while Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                exited = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if !exited {
            child.kill().unwrap();
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            exited && !output.status.success(),
            "old reader admitted backup"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("security installation is incomplete or corrupt"),
            "old reader failed outside format admission: {stderr}"
        );
        verify_offline_protected_backup(&destination, &keyring).unwrap();
    }
    audit::verify_hash_chain(&destination.join("data")).unwrap();
    let live = Db::open(&data).unwrap();
    let authority = live.identity_authority().unwrap();
    let actor = authority.authenticate(secret.trim()).unwrap();
    let mut later_request = linked_request.clone();
    later_request.sql.statements[0].sql = later_request.sql.statements[0]
        .sql
        .replace("VALUES (2,", "VALUES (3,");
    later_request.sql.idempotency_key = Some("backup-later-ingest".into());
    let later = live
        .insert_multimodel_authorized(&actor, later_request.clone(), "backup-test")
        .unwrap();
    let later_transaction = later.sql.transaction_id;
    let later_refs = later.records;
    let mut admin = actor.principal().clone();
    admin.grants.clear();
    authority
        .put_principal(&actor, actor.revision(), admin)
        .unwrap();
    let current_revision = authority.revision();
    let revoked = authority.authenticate(secret.trim()).unwrap();
    assert!(matches!(
        live.execute_sql_authorized(&revoked, select.clone(), "backup-test"),
        Err(GaussError::Security(SecurityError::Forbidden))
    ));
    drop(actor);
    drop(revoked);
    drop(live);
    let reopened = Db::open(&data).unwrap();
    let revoked = reopened
        .identity_authority()
        .unwrap()
        .authenticate(secret.trim())
        .unwrap();
    assert!(matches!(
        reopened.execute_sql_authorized(&revoked, select, "backup-test"),
        Err(GaussError::Security(SecurityError::Forbidden))
    ));
    drop(revoked);
    drop(reopened);
    let live_source_restore = root.join("live-source-restore");
    let live_receipt =
        restore_offline_protected_backup(&destination, &data, &live_source_restore, &keyring)
            .unwrap();
    assert_eq!(live_receipt.active_identity_revision, current_revision);
    // Keep the live-source legacy replay above, then exercise SQL/vector/graph
    // replay from independently activated current authority and its archives.
    assert!(Db::migrate_transaction_authority_offline(&data).unwrap());
    let authority_backup = root.join("authority-backup");
    let authority_manifest =
        create_offline_protected_backup(&data, &authority_backup, &keyring).unwrap();
    let authority_metadata = serde_json::to_value(authority_manifest).unwrap();
    assert!(
        authority_metadata["completed_commit_frontier"]
            .as_u64()
            .unwrap()
            > metadata["completed_commit_frontier"].as_u64().unwrap()
    );
    let same_artifact = root.join("same-artifact-restore");
    assert!(
        restore_offline_protected_backup(&destination, &destination, &same_artifact, &keyring)
            .is_err()
    );
    assert!(!same_artifact.exists());
    #[cfg(feature = "fault-injection")]
    {
        let interrupted_archive = root.join("journal-archive-interrupted");
        unsafe {
            std::env::set_var(
                "CHIRONDB_FAILPOINT",
                "error:protected_journal_archive.after_stage_sync",
            );
        }
        let result =
            create_offline_protected_journal_archive(&data, &interrupted_archive, &keyring);
        unsafe {
            std::env::remove_var("CHIRONDB_FAILPOINT");
        }
        assert!(result.is_err());
        assert!(!interrupted_archive.exists());
    }
    let journal_archive = root.join("journal-archive");
    let archive_manifest =
        create_offline_protected_journal_archive(&data, &journal_archive, &keyring).unwrap();
    let archive_metadata = serde_json::to_value(archive_manifest).unwrap();
    assert_eq!(
        archive_metadata,
        serde_json::to_value(
            verify_offline_protected_journal_archive(&journal_archive, &keyring).unwrap()
        )
        .unwrap()
    );
    assert_eq!(
        archive_metadata["completed_commit_frontier"],
        authority_metadata["completed_commit_frontier"]
    );
    assert!(
        archive_metadata["files"]
            .as_object()
            .unwrap()
            .keys()
            .all(|name| !name.starts_with("generations/") && !name.starts_with("collections/"))
    );
    let full_backup_restore = root.join("full-backup-authority-restore");
    restore_offline_protected_backup(
        &destination,
        &authority_backup,
        &full_backup_restore,
        &keyring,
    )
    .unwrap();
    let parked_source = root.join("source-offline-after-restore");
    std::fs::rename(&data, &parked_source).unwrap();
    #[cfg(feature = "fault-injection")]
    {
        for (name, failpoint) in [
            (
                "restore-interrupted-before-open",
                "protected_restore.after_stage_sync",
            ),
            (
                "restore-interrupted-after-open",
                "protected_restore.after_validation",
            ),
        ] {
            let interrupted = root.join(name);
            unsafe {
                std::env::set_var("CHIRONDB_FAILPOINT", format!("error:{failpoint}"));
            }
            let result = restore_offline_protected_backup(
                &destination,
                &journal_archive,
                &interrupted,
                &keyring,
            );
            unsafe {
                std::env::remove_var("CHIRONDB_FAILPOINT");
            }
            assert!(result.is_err());
            assert!(!interrupted.exists());
            let staging_prefix = format!(".{name}.restore-");
            assert!(std::fs::read_dir(&root).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&staging_prefix)
            }));
        }
    }
    let restored_path = root.join("restored");
    let restored_manifest =
        restore_offline_protected_backup(&destination, &journal_archive, &restored_path, &keyring)
            .unwrap();
    let receipt = serde_json::to_value(restored_manifest).unwrap();
    assert_eq!(receipt["installation"], metadata["installation"]);
    assert_eq!(
        receipt["backup_identity_revision"],
        metadata["identity_revision"]
    );
    assert_eq!(receipt["active_identity_revision"], current_revision);
    assert_eq!(
        receipt["backup_commit_frontier"],
        metadata["completed_commit_frontier"]
    );
    assert_eq!(
        receipt["completed_commit_frontier"],
        authority_metadata["completed_commit_frontier"]
    );
    let restored = Db::open(&restored_path).unwrap();
    let restored_authority = restored.identity_authority().unwrap();
    assert_eq!(restored_authority.revision(), current_revision);
    let restored_actor = restored_authority.authenticate(secret.trim()).unwrap();
    let restored_select: chirondb_core::SqlExecutionRequest =
        serde_json::from_value(serde_json::json!({
            "statements": [{"sql": "SELECT id, title FROM knowledge"}]
        }))
        .unwrap();
    assert!(matches!(
        restored.execute_sql_authorized(&restored_actor, restored_select.clone(), "backup-test"),
        Err(GaussError::Security(SecurityError::Forbidden))
    ));
    let mut restored_admin = restored_actor.principal().clone();
    restored_admin.grants.push(ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: BTreeSet::from(["knowledge".into()]),
        actions: BTreeSet::from([Action::Read, Action::Create]),
    });
    restored_admin.grants.push(ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: BTreeSet::from(["vectors".into()]),
        actions: BTreeSet::from([
            Action::Read,
            Action::Create,
            Action::Ingest,
            Action::Search,
            Action::GraphRead,
            Action::GraphWrite,
        ]),
    });
    restored_authority
        .put_principal(&restored_actor, restored_actor.revision(), restored_admin)
        .unwrap();
    let restored_actor = restored_authority.authenticate(secret.trim()).unwrap();
    let selected = restored
        .execute_sql_authorized(&restored_actor, restored_select, "backup-test")
        .unwrap();
    assert!(matches!(&selected.results[0], SqlResult::Rows { rows, .. } if rows.len() == 3));
    let references = restored
        .execute_sql_authorized(
            &restored_actor,
            serde_json::from_value(serde_json::json!({
                "statements": [{"sql": "SELECT chunk, source FROM knowledge WHERE id = 2"}]
            }))
            .unwrap(),
            "backup-test",
        )
        .unwrap();
    assert!(
        matches!(&references.results[0], SqlResult::Rows { rows, .. }
        if rows == &vec![vec![
            RelationalValue::RecordRef(linked_refs["chunk"].clone()),
            RelationalValue::RecordRef(linked_refs["source"].clone())
        ]])
    );
    let later_references = restored
        .execute_sql_authorized(
            &restored_actor,
            serde_json::from_value(serde_json::json!({
                "statements": [{"sql": "SELECT chunk, source FROM knowledge WHERE id = 3"}]
            }))
            .unwrap(),
            "backup-test",
        )
        .unwrap();
    assert!(
        matches!(&later_references.results[0], SqlResult::Rows { rows, .. }
        if rows == &vec![vec![
            RelationalValue::RecordRef(later_refs["chunk"].clone()),
            RelationalValue::RecordRef(later_refs["source"].clone())
        ]])
    );
    let read = restored
        .bind_access(&restored_actor, "vectors", "acme", Action::Read)
        .unwrap();
    let points = restored
        .get_points_authorized(
            &read,
            &[
                linked_refs["chunk"].id.clone(),
                linked_refs["source"].id.clone(),
            ],
        )
        .unwrap()
        .publish(|points| points)
        .unwrap();
    assert_eq!(points.len(), 2);
    let later_points = restored
        .get_points_authorized(
            &read,
            &[
                later_refs["chunk"].id.clone(),
                later_refs["source"].id.clone(),
            ],
        )
        .unwrap()
        .publish(|points| points)
        .unwrap();
    assert_eq!(later_points.len(), 2);
    let graph = restored
        .bind_access(&restored_actor, "vectors", "acme", Action::GraphRead)
        .unwrap();
    let traversal_request = GraphTraverseRequest {
        anchors: vec![linked_refs["chunk"].id.clone()],
        edge_types: vec!["cites".into()],
        direction: GraphDirection::Outgoing,
        node_filter: None,
        edge_filter: None,
        budget: TraversalBudget {
            max_depth: 1,
            ..Default::default()
        },
    };
    let traversal = restored
        .traverse_authorized(&graph, traversal_request.clone(), &AtomicBool::new(false))
        .unwrap()
        .publish(|result| result)
        .unwrap();
    assert_eq!(traversal.nodes.len(), 1);
    assert_eq!(traversal.nodes[0].point_id, linked_refs["source"].id);
    let mut later_traversal_request = traversal_request;
    later_traversal_request.anchors = vec![later_refs["chunk"].id.clone()];
    let later_traversal = restored
        .traverse_authorized(&graph, later_traversal_request, &AtomicBool::new(false))
        .unwrap()
        .publish(|result| result)
        .unwrap();
    assert_eq!(later_traversal.nodes.len(), 1);
    assert_eq!(later_traversal.nodes[0].point_id, later_refs["source"].id);
    let replay = restored
        .insert_multimodel_authorized(&restored_actor, linked_request, "restore-retry")
        .unwrap();
    assert!(replay.graph.replayed);
    assert_eq!(replay.sql.transaction_id, linked_transaction);
    assert_eq!(replay.records, linked_refs);
    let later_replay = restored
        .insert_multimodel_authorized(&restored_actor, later_request, "restore-retry")
        .unwrap();
    assert!(later_replay.graph.replayed);
    assert_eq!(later_replay.sql.transaction_id, later_transaction);
    assert_eq!(later_replay.records, later_refs);
    drop(restored_actor);
    drop(restored);
    std::fs::rename(&parked_source, &data).unwrap();
    verify_offline_protected_backup(&destination, &keyring).unwrap();

    let source = Db::open(&data).unwrap();
    let actor = source
        .identity_authority()
        .unwrap()
        .authenticate(secret.trim())
        .unwrap();
    source
        .create_protected_collection_authorized(
            &actor,
            source.catalog_revision_authorized(&actor).unwrap(),
            serde_json::from_value(serde_json::json!({
                "name": "later_vectors",
                "vector_dim": 2
            }))
            .unwrap(),
        )
        .unwrap();
    drop(actor);
    drop(source);
    let stale = root.join("stale-restore");
    restore_offline_protected_backup(&destination, &data, &stale, &keyring).unwrap();
    let recovered = Db::open(&stale).unwrap();
    let recovered_actor = recovered
        .identity_authority()
        .unwrap()
        .authenticate(secret.trim())
        .unwrap();
    assert!(
        recovered
            .protected_collection_exists_admin(&recovered_actor, "later_vectors")
            .unwrap()
    );
    drop(recovered_actor);
    drop(recovered);
    let archive_format = journal_archive.join("data/transactions/FORMAT");
    let mut archive_format_bytes = std::fs::read(&archive_format).unwrap();
    archive_format_bytes[0] ^= 1;
    std::fs::write(archive_format, archive_format_bytes).unwrap();
    assert!(verify_offline_protected_journal_archive(&journal_archive, &keyring).is_err());
    assert!(create_offline_protected_backup(&data, &destination, &keyring).is_err());
    assert!(create_offline_protected_backup(&data, &data.join("nested"), &keyring).is_err());
    let format_path = destination.join("data/transactions/FORMAT");
    let mut format = std::fs::read(&format_path).unwrap();
    format[0] ^= 1;
    std::fs::write(format_path, format).unwrap();
    assert!(verify_offline_protected_backup(&destination, &keyring).is_err());
    #[cfg(feature = "fault-injection")]
    {
        let interrupted = root.join("backup-interrupted");
        // This binary contains one test, so its fault environment has no
        // parallel in-process user. The guard is cleared before assertions.
        unsafe {
            std::env::set_var(
                "CHIRONDB_FAILPOINT",
                "error:protected_backup.after_stage_sync",
            );
        }
        let result = create_offline_protected_backup(&data, &interrupted, &keyring);
        unsafe {
            std::env::remove_var("CHIRONDB_FAILPOINT");
        }
        assert!(result.is_err());
        assert!(!interrupted.exists());
        assert!(Db::open(&data).is_ok());
        assert!(!std::fs::read_dir(&root).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".backup-interrupted.backup-")
        }));
    }
}
