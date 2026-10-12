use std::collections::{BTreeMap, BTreeSet};

use chirondb_core::{
    Db,
    db::{
        create_offline_protected_backup, create_offline_protected_journal_archive,
        restore_offline_protected_backup, verify_offline_protected_journal_archive,
    },
    encryption,
    security::{
        Action, Classification, CollectionPolicy, IngestTemplate, NewPoint, PropertyAction,
        PropertyRule, Representation, RevisionUpdate, ScopeGrant, onboarding,
    },
};

#[test]
fn protected_journal_archive_restores_catalog_drop_and_recreate() {
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
    onboarding::initialize(&data, "acme", "admin", &keyring_path, &admin_key, false).unwrap();
    let keyring = encryption::Keyring::load(&keyring_path).unwrap();
    let secret = std::fs::read_to_string(&admin_key).unwrap();
    let db = Db::open(&data).unwrap();
    let authority = db.identity_authority().unwrap();
    let actor = authority.authenticate(secret.trim()).unwrap();
    let mut admin = actor.principal().clone();
    admin.grants.push(ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: BTreeSet::from(["replaced".into(), "removed".into(), "added".into()]),
        actions: BTreeSet::from([
            Action::Read,
            Action::Create,
            Action::Ingest,
            Action::PolicyManage,
        ]),
    });
    authority
        .put_principal(&actor, actor.revision(), admin)
        .unwrap();
    let actor = authority.authenticate(secret.trim()).unwrap();
    for name in ["replaced", "removed"] {
        db.create_protected_collection_authorized(
            &actor,
            db.catalog_revision_authorized(&actor).unwrap(),
            serde_json::from_value(serde_json::json!({"name": name, "vector_dim": 2})).unwrap(),
        )
        .unwrap();
    }
    drop(actor);
    drop(db);
    let backup = root.join("backup");
    create_offline_protected_backup(&data, &backup, &keyring).unwrap();
    // The backup predates independent transaction authority. Restore must
    // retain the current authority while replaying new catalog incarnations.
    assert!(Db::migrate_transaction_authority_offline(&data).unwrap());

    let db = Db::open(&data).unwrap();
    let actor = db
        .identity_authority()
        .unwrap()
        .authenticate(secret.trim())
        .unwrap();
    for name in ["replaced", "removed"] {
        db.delete_protected_collection_authorized(&actor, name)
            .unwrap();
    }
    for (name, dimension) in [("replaced", 3), ("added", 2)] {
        db.create_protected_collection_authorized(
            &actor,
            db.catalog_revision_authorized(&actor).unwrap(),
            serde_json::from_value(serde_json::json!({
                "name": name,
                "vector_dim": dimension
            }))
            .unwrap(),
        )
        .unwrap();
    }
    assert_eq!(
        db.protected_collection_config_authorized(&actor, "replaced")
            .unwrap()
            .vector_dim,
        3
    );
    let manage = db
        .bind_access(&actor, "replaced", "acme", Action::PolicyManage)
        .unwrap();
    db.replace_collection_policy_authorized(
        &manage,
        RevisionUpdate {
            expected_revision: 1,
            value: CollectionPolicy {
                department_actions: BTreeSet::new(),
                owner_actions: BTreeSet::from([Action::Read]),
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
            },
        },
    )
    .unwrap();
    let create = db
        .bind_access(&actor, "replaced", "acme", Action::Create)
        .unwrap();
    assert!(actor.allows("acme", "replaced", Action::Ingest));
    let ids = db
        .create_points_authorized(
            &create,
            "standard",
            vec![NewPoint {
                vector: vec![1.0, 0.0, 0.0],
                vectors: BTreeMap::new(),
                sparse_vector: None,
                payload: serde_json::json!({"text":"after backup"}),
            }],
            true,
        )
        .unwrap()
        .publish(|ids| ids)
        .unwrap();
    drop(actor);
    drop(db);
    let archive = root.join("archive");
    create_offline_protected_journal_archive(&data, &archive, &keyring).unwrap();
    #[cfg(feature = "fault-injection")]
    {
        for point in [
            "protected_restore.after_replay_index",
            "protected_restore.after_stage_sync",
        ] {
            let interrupted = root.join(format!("interrupted-catalog-restore-{point}"));
            unsafe {
                std::env::set_var("CHIRONDB_FAILPOINT", format!("error:{point}"));
            }
            let result =
                restore_offline_protected_backup(&backup, &archive, &interrupted, &keyring);
            unsafe {
                std::env::remove_var("CHIRONDB_FAILPOINT");
            }
            assert!(result.is_err());
            assert!(!interrupted.exists());
        }
    }
    let restored_path = root.join("restored");
    restore_offline_protected_backup(&backup, &archive, &restored_path, &keyring).unwrap();
    verify_offline_protected_journal_archive(&archive, &keyring).unwrap();
    let restored = Db::open(&restored_path).unwrap();
    let actor = restored
        .identity_authority()
        .unwrap()
        .authenticate(secret.trim())
        .unwrap();
    assert_eq!(
        restored
            .protected_collection_config_authorized(&actor, "replaced")
            .unwrap()
            .vector_dim,
        3
    );
    assert!(
        restored
            .protected_collection_exists_admin(&actor, "added")
            .unwrap()
    );
    assert!(
        !restored
            .protected_collection_exists_admin(&actor, "removed")
            .unwrap()
    );
    let read = restored
        .bind_access(&actor, "replaced", "acme", Action::Read)
        .unwrap();
    let points = restored
        .get_points_authorized(&read, &ids)
        .unwrap()
        .publish(|points| points)
        .unwrap();
    assert_eq!(points.len(), 1);
    assert_eq!(points[0].vector, vec![1.0, 0.0, 0.0]);
    assert_eq!(
        points[0].payload,
        serde_json::json!({"text":"after backup"})
    );
}
