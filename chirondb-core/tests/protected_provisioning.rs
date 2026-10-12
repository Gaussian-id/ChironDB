use chirondb_core::{Db, security::onboarding};

#[test]
fn invalid_security_identity_never_commits_a_catalog_entry() {
    // Exercise the public core API as an embedded caller, independently of the
    // ChironQL parser's stricter identifier limit.
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let data = root.join("data");
    let keyring = root.join("storage.json");
    let key_out = root.join("admin.key");
    onboarding::initialize(&data, "default", "admin", &keyring, &key_out, false).unwrap();
    let secret = std::fs::read_to_string(key_out).unwrap();
    let db = Db::open(&data).unwrap();
    let actor = db
        .identity_authority()
        .unwrap()
        .authenticate(secret.trim())
        .unwrap();
    let before = db.catalog_revision_authorized(&actor).unwrap();
    let invalid = serde_json::from_value(serde_json::json!({
        "name": "a".repeat(129), "vector_dim": 2
    }))
    .unwrap();
    assert!(
        db.create_protected_collection_authorized(&actor, before, invalid)
            .is_err()
    );
    assert_eq!(db.catalog_revision_authorized(&actor).unwrap(), before);
    let valid = serde_json::from_value(serde_json::json!({
        "name": "a".repeat(128), "vector_dim": 2
    }))
    .unwrap();
    db.create_protected_collection_authorized(&actor, before, valid)
        .unwrap();
    drop(actor);
    drop(db);
    let reopened = Db::open(&data).unwrap();
    let actor = reopened
        .identity_authority()
        .unwrap()
        .authenticate(secret.trim())
        .unwrap();
    assert_eq!(
        reopened.catalog_revision_authorized(&actor).unwrap(),
        before + 1
    );
}
