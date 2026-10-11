use super::*;

struct Fixture {
    authority: Arc<IdentityAuthority>,
    key: IssuedCredential,
    directory: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let key = IdentityAuthority::bootstrap(
            directory.path(),
            PrincipalRecord {
                id: "security-admin".into(),
                tenant: "acme".into(),
                enabled: true,
                attributes: SubjectAttributes {
                    department: "Security".into(),
                    clearance: Classification::Restricted,
                },
                grants: vec![],
                installation_actions: BTreeSet::from([Action::IdentityManage, Action::Observe]),
                delegation: vec![ScopeGrant {
                    tenants: BTreeSet::from(["acme".into()]),
                    collections: BTreeSet::from(["docs".into()]),
                    actions: BTreeSet::from([Action::Read, Action::Search]),
                }],
            },
        )
        .unwrap();
        let authority = IdentityAuthority::open(directory.path()).unwrap().unwrap();
        Self {
            authority,
            key,
            directory,
        }
    }
    fn installed() -> Self {
        let f = Self::new();
        let installation_id = Uuid::new_v4();
        {
            let mut current = f.authority.current.write();
            current.state.version = 3;
            current.state.installation = Some(onboarding::Installation {
                id: installation_id,
                tenant: "acme".into(),
                admin_id: "security-admin".into(),
            });
            current.state.validate().unwrap();
            persist(&f.authority.root, &current.state).unwrap();
        }
        onboarding::write_marker(f.directory.path(), installation_id, 1).unwrap();
        f
    }
    fn actor(&self) -> AuthenticatedIdentity {
        self.authority.authenticate(&self.key.secret).unwrap()
    }
    fn edit(
        &self,
        change: impl FnOnce(&IdentityAuthority, &AuthenticatedIdentity, u64) -> Result<u64>,
    ) {
        let actor = self.actor();
        let revision = actor.revision();
        assert_eq!(
            change(&self.authority, &actor, revision).unwrap(),
            revision + 1
        );
        assert!(actor.publication_permit().is_err());
    }
    fn user(&self) {
        self.edit(|authority, actor, revision| {
            authority.create_user(
                actor,
                revision,
                "ana",
                SubjectAttributes {
                    department: "Finance".into(),
                    clearance: Classification::Confidential,
                },
            )
        });
    }
}

fn collection(incarnation: Uuid) -> CollectionAuthority {
    CollectionAuthority::from_verified_checkpoint(SecurityCheckpoint {
        version: SECURITY_VERSION,
        collection: "docs".into(),
        incarnation,
        revision: 1,
        data_generation: 1,
        policy: CollectionPolicy {
            department_actions: BTreeSet::from([Action::Read, Action::Search]),
            owner_actions: BTreeSet::new(),
            templates: BTreeMap::new(),
        },
        resources: vec![],
    })
    .unwrap()
}

#[test]
fn table_grants_require_catalog_id_and_incarnation_and_do_not_grant_vector_access() {
    let f = Fixture::installed();
    f.authority.upgrade_table_authority_offline().unwrap();
    f.edit(|a, actor, revision| a.create_role(actor, revision, "sql_reader"));
    f.user();
    let incarnation = Uuid::new_v4();
    f.edit(|a, actor, revision| {
        a.change_role_table_privileges(
            actor,
            revision,
            "sql_reader",
            RoleTableGrant {
                table: "only_sql".into(),
                table_id: 41,
                incarnation,
                actions: BTreeSet::from([Action::Read]),
            },
            true,
        )
    });
    f.edit(|a, actor, revision| a.assign_role(actor, revision, "sql_reader", "ana", true));
    let user = f.authority.resolve_user(&f.actor(), "ana").unwrap();
    let key = f
        .authority
        .issue_credential(&f.actor(), f.authority.revision(), &user)
        .unwrap();
    let reader = f.authority.authenticate(&key.secret).unwrap();
    assert!(reader.allows_table("acme", "only_sql", 41, incarnation, Action::Read));
    assert!(reader.allows_table("acme", "renamed", 41, incarnation, Action::Read));
    assert!(!reader.allows_table("acme", "only_sql", 41, Uuid::new_v4(), Action::Read));
    assert!(!reader.allows_table("acme", "only_sql", 42, incarnation, Action::Read));
    assert!(!reader.allows_table("other", "only_sql", 41, incarnation, Action::Read));
    assert!(!reader.allows("acme", "only_sql", Action::Read));
    let bound = reader.for_collection("vectors", Uuid::new_v4());
    assert!(bound.allows_table("acme", "only_sql", 41, incarnation, Action::Read));
    assert!(!bound.allows("acme", "only_sql", Action::Read));
    let bytes = crate::encryption::read_persistent(&f.authority.root.join(IDENTITY_FILE)).unwrap();
    assert!(bytes.starts_with(TABLE_IDENTITY_MAGIC));
    assert!(super::super::storage::decode_metadata(SQL_IDENTITY_MAGIC, &bytes).is_err());
}

#[cfg(feature = "fault-injection")]
#[test]
fn interrupted_table_authority_fence_keeps_old_authority_and_resumes() {
    let f = Fixture::installed();
    let before = crate::encryption::read_persistent(&f.authority.root.join(IDENTITY_FILE)).unwrap();
    let failure = crate::failpoint::test_env(
        "error:identity.after_reader_fence",
        &f.directory.path().join("marker"),
        &f.directory.path().join("release"),
    );
    assert!(f.authority.upgrade_table_authority_offline().is_err());
    drop(failure);
    assert_eq!(
        crate::encryption::read_persistent(&f.authority.root.join(IDENTITY_FILE)).unwrap(),
        before
    );
    assert!(
        std::fs::read_to_string(f.directory.path().join(onboarding::MARKER))
            .unwrap()
            .starts_with("CHRNINSTALL4\n")
    );
    let Fixture {
        authority,
        directory,
        key,
    } = f;
    drop(authority);
    let reopened = IdentityAuthority::open(directory.path()).unwrap().unwrap();
    reopened.upgrade_table_authority_offline().unwrap();
    assert!(
        reopened
            .authenticate(&key.secret)
            .unwrap()
            .supports_table_grants()
    );
}

#[test]
fn sql_password_rotation_revocation_and_v4_reopen_preserve_bearer_identity() {
    let f = Fixture::installed();

    let first = f
        .authority
        .issue_sql_credential(&f.actor(), f.authority.revision(), "security-admin")
        .unwrap();
    let installation_id = f.authority.installation_id().unwrap();
    let marker = std::fs::read_to_string(f.directory.path().join(onboarding::MARKER)).unwrap();
    assert_eq!(marker, format!("CHRNINSTALL2\n{installation_id}\n"));
    // Frozen pre-SQL startup validator: rejects before opening any storage.
    assert!(!marker.starts_with("CHRNINSTALL1\n"));
    assert!(!onboarding::write_marker(f.directory.path(), installation_id, 1).unwrap());
    onboarding::validate_ready(f.directory.path()).unwrap();
    assert_eq!(first.username, "security-admin");
    assert_eq!(
        f.authority
            .sql_verifier_for_user(&first.username)
            .unwrap()
            .id,
        first.id
    );
    let sql_identity = f
        .authority
        .authenticate_sql(&first.username, &first.id)
        .unwrap();
    assert_eq!(sql_identity.principal().tenant, "acme");
    assert_eq!(sql_identity.credential_id(), first.id);
    assert!(f.authority.authenticate(&first.password).is_err());

    let second = f
        .authority
        .issue_sql_credential(&f.actor(), f.authority.revision(), "security-admin")
        .unwrap();
    assert!(sql_identity.publication_permit().is_err());
    assert!(
        f.authority
            .authenticate_sql(&first.username, &first.id)
            .is_err()
    );
    assert_eq!(
        f.authority
            .sql_verifier_for_user(&second.username)
            .unwrap()
            .id,
        second.id
    );
    assert!(f.authority.authenticate(&f.key.secret).is_ok());

    let Fixture {
        authority,
        key,
        directory,
    } = f;
    drop(authority);
    let v4 =
        crate::encryption::read_persistent(&directory.path().join("security").join(IDENTITY_FILE))
            .unwrap();
    assert!(v4.starts_with(SQL_IDENTITY_MAGIC));
    assert!(crate::security::storage::decode_metadata(INSTALLATION_IDENTITY_MAGIC, &v4).is_err());
    let reopened = IdentityAuthority::open(directory.path()).unwrap().unwrap();
    assert_eq!(
        reopened.sql_verifier_for_user(&second.username).unwrap().id,
        second.id
    );
    assert!(reopened.authenticate(&key.secret).is_ok());
    reopened
        .revoke_credential(
            &reopened.authenticate(&key.secret).unwrap(),
            reopened.revision(),
            &second.id,
        )
        .unwrap();
    assert!(reopened.sql_verifier_for_user(&second.username).is_none());
    assert!(
        reopened
            .authenticate_sql(&second.username, &second.id)
            .is_err()
    );
}

#[cfg(feature = "fault-injection")]
#[test]
fn interrupted_sql_password_upgrade_preserves_old_identity_and_grants() {
    for (boundary, fenced_before) in [
        ("atomic.before_temp_sync", false),
        ("atomic.after_rename_before_dir_sync", false),
        ("identity.after_reader_fence", false),
        ("atomic.before_temp_sync", true),
        ("atomic.after_rename_before_dir_sync", true),
    ] {
        let f = Fixture::installed();
        if fenced_before {
            onboarding::write_marker(
                f.directory.path(),
                f.authority.installation_id().unwrap(),
                2,
            )
            .unwrap();
        }
        let revision = f.authority.revision();
        let failure = crate::failpoint::test_env(
            &format!("error:{boundary}"),
            &f.directory.path().join("marker"),
            &f.directory.path().join("release"),
        );
        assert!(
            f.authority
                .issue_sql_credential(&f.actor(), revision, "security-admin")
                .is_err()
        );
        drop(failure);
        let Fixture {
            authority,
            directory,
            key,
        } = f;
        drop(authority);
        let recovered = IdentityAuthority::open(directory.path()).unwrap().unwrap();
        let actor = recovered.authenticate(&key.secret).unwrap();
        assert_eq!(actor.principal().tenant, "acme");
        assert_eq!(actor.principal().delegation.len(), 1);
        if fenced_before && boundary == "atomic.after_rename_before_dir_sync" {
            assert_eq!(recovered.revision(), revision + 1);
            assert!(recovered.sql_verifier_for_user("security-admin").is_some());
        } else {
            assert_eq!(recovered.revision(), revision);
            assert!(recovered.sql_verifier_for_user("security-admin").is_none());
        }
    }
}

#[test]
fn rejected_sql_issuance_does_not_advance_reader_fence() {
    let f = Fixture::installed();
    let path = f.directory.path().join(onboarding::MARKER);
    let before = std::fs::read(&path).unwrap();
    assert!(
        f.authority
            .issue_sql_credential(&f.actor(), 0, "security-admin")
            .is_err()
    );
    assert!(
        f.authority
            .issue_sql_credential(&f.actor(), f.authority.revision(), "missing")
            .is_err()
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn startup_rejects_unfenced_sql_identity_before_content_or_audit_mutation() {
    fn files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut result = BTreeMap::new();
        for entry in std::fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                result.extend(files(&path));
            } else {
                result.insert(path.clone(), std::fs::read(path).unwrap());
            }
        }
        result
    }
    let f = Fixture::installed();
    f.authority
        .issue_sql_credential(&f.actor(), f.authority.revision(), "security-admin")
        .unwrap();
    let id = f.authority.installation_id().unwrap();
    std::fs::write(
        f.directory.path().join(onboarding::MARKER),
        format!("CHRNINSTALL1\n{id}\n"),
    )
    .unwrap();
    let Fixture {
        authority,
        directory,
        ..
    } = f;
    drop(authority);
    let before = files(directory.path());
    assert!(crate::Db::open(directory.path()).is_err());
    assert_eq!(files(directory.path()), before);
    assert!(IdentityAuthority::open(directory.path()).is_err());
    assert_eq!(files(directory.path()), before);
    // Offline publication of the reader fence preserves the existing identity.
    onboarding::write_marker(directory.path(), id, 2).unwrap();
    onboarding::validate_ready(directory.path()).unwrap();
    let identity = IdentityAuthority::open(directory.path()).unwrap().unwrap();
    assert!(identity.sql_verifier_for_user("security-admin").is_some());
    drop(identity);
    // Unknown future identity versions also fail before mutable startup.
    let path = directory.path().join("security").join(IDENTITY_FILE);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[..8].copy_from_slice(b"CHRNID99");
    std::fs::write(&path, bytes).unwrap();
    let before = files(directory.path());
    assert!(crate::Db::open(directory.path()).is_err());
    assert_eq!(files(directory.path()), before);
}

#[test]
fn role_membership_is_live_and_bound_to_collection_incarnation() {
    let f = Fixture::new();
    f.user();
    let id = f.authority.resolve_user(&f.actor(), "ana").unwrap();
    let key = f
        .authority
        .issue_credential(&f.actor(), f.authority.revision(), &id)
        .unwrap();
    assert!(
        !f.authority
            .authenticate(&key.secret)
            .unwrap()
            .allows("acme", "docs", Action::Read)
    );
    f.edit(|a, actor, rev| a.create_role(actor, rev, "finance_reader"));
    let incarnation = Uuid::new_v4();
    f.edit(|a, actor, rev| {
        a.change_role_privileges(
            actor,
            rev,
            "finance_reader",
            RolePrivilegeChanges {
                collection: Some(("docs".into(), incarnation)),
                actions: BTreeSet::from([Action::Read, Action::Search]),
                grant: true,
            },
        )
    });
    f.edit(|a, actor, rev| a.assign_role(actor, rev, "finance_reader", "ana", true));
    let reader = f.authority.authenticate(&key.secret).unwrap();
    assert!(
        collection(incarnation)
            .bind(&reader, "acme", Action::Read)
            .is_ok()
    );
    assert!(
        collection(Uuid::new_v4())
            .bind(&reader, "acme", Action::Read)
            .is_err()
    );
    assert!(
        collection(incarnation)
            .bind(&reader, "acme", Action::Delete)
            .is_err()
    );
    assert!(!reader.allows_installation(Action::Observe));
    f.edit(|a, actor, rev| a.assign_role(actor, rev, "finance_reader", "ana", false));
    assert!(reader.publication_permit().is_err());
    let reader = f.authority.authenticate(&key.secret).unwrap();
    assert!(
        collection(incarnation)
            .bind(&reader, "acme", Action::Read)
            .is_err()
    );
}

#[test]
fn names_do_not_rebind_retired_users_or_roles_after_restart() {
    let f = Fixture::new();
    f.user();
    let id = f.authority.resolve_user(&f.actor(), "ana").unwrap();
    let key = f
        .authority
        .issue_credential(&f.actor(), f.authority.revision(), &id)
        .unwrap();
    f.edit(|a, actor, rev| a.create_role(actor, rev, "reader"));
    let role_id = f.authority.list_roles(&f.actor()).unwrap()[0].id;
    f.edit(|a, actor, rev| a.assign_role(actor, rev, "reader", "ana", true));
    f.edit(|a, actor, rev| a.rename_user(actor, rev, "ana", "renamed"));
    assert_eq!(
        f.authority
            .authenticate(&key.secret)
            .unwrap()
            .principal()
            .id,
        id
    );
    f.edit(|a, actor, rev| a.rename_role(actor, rev, "reader", "renamed_role"));
    assert_eq!(f.authority.list_roles(&f.actor()).unwrap()[0].id, role_id);
    f.edit(|a, actor, rev| a.drop_role(actor, rev, "renamed_role"));
    f.edit(|a, actor, rev| a.create_role(actor, rev, "renamed_role"));
    assert_ne!(f.authority.list_roles(&f.actor()).unwrap()[0].id, role_id);
    assert!(
        f.authority
            .authenticate(&key.secret)
            .unwrap()
            .roles()
            .is_empty()
    );
    f.edit(|a, actor, rev| a.drop_user(actor, rev, "renamed"));
    assert!(f.authority.authenticate(&key.secret).is_err());
    let retired = f.authority.current.read().state.principals[&id].clone();
    let mut revived = retired;
    revived.enabled = true;
    assert!(
        f.authority
            .put_principal(&f.actor(), f.authority.revision(), revived)
            .is_err()
    );
    f.user();
    assert_ne!(f.authority.resolve_user(&f.actor(), "ana").unwrap(), id);
    let Fixture {
        authority,
        directory,
        key: admin,
    } = f;
    drop(authority);
    let reopened = IdentityAuthority::open(directory.path()).unwrap().unwrap();
    assert!(reopened.authenticate(&key.secret).is_err());
    assert_eq!(
        reopened
            .list_users(&reopened.authenticate(&admin.secret).unwrap())
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn role_administration_rejects_escalation_and_stale_updates() {
    let f = Fixture::new();
    f.user();
    f.edit(|a, actor, rev| a.create_role(actor, rev, "reader"));
    let old = f.actor();
    for (collection, action) in [
        (None, Action::IdentityManage),
        (None, Action::Read),
        (Some(("docs".into(), Uuid::new_v4())), Action::Delete),
        (Some(("outside".into(), Uuid::new_v4())), Action::Read),
    ] {
        assert!(
            f.authority
                .change_role_privileges(
                    &f.actor(),
                    f.authority.revision(),
                    "reader",
                    RolePrivilegeChanges {
                        collection,
                        actions: BTreeSet::from([action]),
                        grant: true
                    }
                )
                .is_err()
        );
    }
    f.edit(|a, actor, rev| {
        a.alter_user(
            actor,
            rev,
            "ana",
            UserChanges {
                enabled: Some(false),
                ..Default::default()
            },
        )
    });
    assert!(matches!(
        f.authority.create_role(&old, old.revision(), "stale"),
        Err(SecurityError::Forbidden | SecurityError::Conflict)
    ));
    assert!(
        f.authority
            .issue_credential(
                &f.actor(),
                f.authority.revision(),
                &f.authority.resolve_user(&f.actor(), "ana").unwrap()
            )
            .is_err()
    );
    assert!(
        f.authority.list_roles(&f.actor()).unwrap()[0]
            .grants
            .is_empty()
    );
}

#[test]
fn offline_v1_migration_preserves_revocation_and_rejects_old_envelope() {
    let f = Fixture::new();
    f.user();
    let id = f.authority.resolve_user(&f.actor(), "ana").unwrap();
    let issued = f
        .authority
        .issue_credential(&f.actor(), f.authority.revision(), &id)
        .unwrap();
    f.edit(|a, actor, rev| a.revoke_credential(actor, rev, &issued.id));
    let state = f.authority.current.read().state.clone();
    let old = serde_json::json!({ "version":1, "revision":state.revision,
        "principals":state.principals,"credentials":state.credentials,"groups":state.groups });
    assert!(
        IdentityAuthority::migrate_v1(f.directory.path()).is_err(),
        "exclusive directory lock"
    );
    let Fixture {
        authority,
        directory,
        key,
    } = f;
    drop(authority);
    let path = directory.path().join("security").join(IDENTITY_FILE);
    std::fs::write(
        &path,
        super::super::storage::encode_metadata(b"CHRNID01", &serde_json::to_vec(&old).unwrap()),
    )
    .unwrap();
    assert!(
        IdentityAuthority::open(directory.path()).is_err(),
        "no online auto-upgrade"
    );
    assert!(IdentityAuthority::migrate_v1(directory.path()).unwrap());
    assert!(!IdentityAuthority::migrate_v1(directory.path()).unwrap());
    let bytes = std::fs::read(&path).unwrap();
    assert!(super::super::storage::decode_metadata(b"CHRNID01", &bytes).is_err());
    let reopened = IdentityAuthority::open(directory.path()).unwrap().unwrap();
    assert!(reopened.authenticate(&issued.secret).is_err());
    assert!(reopened.authenticate(&key.secret).is_ok());
    assert_eq!(reopened.revision(), state.revision + 1);
}

#[cfg(feature = "fault-injection")]
#[test]
fn failed_identity_audit_or_fsync_never_acknowledges_a_role_change() {
    for boundary in [
        "audit.before_append",
        "audit.before_sync",
        "atomic.before_temp_sync",
        "atomic.after_rename_before_dir_sync",
    ] {
        let f = Fixture::new();
        let actor = f.actor();
        let revision = actor.revision();
        let failure = crate::failpoint::test_env(
            &format!("error:{boundary}"),
            &f.directory.path().join("marker"),
            &f.directory.path().join("release"),
        );
        assert!(
            f.authority
                .create_role(&actor, revision, "candidate")
                .is_err()
        );
        drop(failure);
        assert_eq!(
            f.authority.revision(),
            revision,
            "failed mutation cannot publish a new revision"
        );
        if boundary.starts_with("atomic.") {
            assert!(actor.publication_permit().is_err());
        } else {
            assert!(
                f.authority.create_role(&actor, revision, "second").is_err(),
                "failed audit writer stays closed"
            );
        }
        let Fixture {
            authority,
            directory,
            key,
        } = f;
        drop(authority);
        let recovered = IdentityAuthority::open(directory.path()).unwrap().unwrap();
        let actor = recovered.authenticate(&key.secret).unwrap();
        let roles = recovered.list_roles(&actor).unwrap();
        if boundary == "atomic.after_rename_before_dir_sync" {
            assert_eq!(roles.len(), 1);
            assert_eq!(roles[0].name, "candidate");
            assert_eq!(recovered.revision(), revision + 1);
        } else {
            assert!(roles.is_empty());
            assert_eq!(recovered.revision(), revision);
        }
    }
}

#[cfg(feature = "fault-injection")]
#[test]
fn identity_migration_crash_child() {
    if let Some(directory) = std::env::var_os("CHIRONDB_IDENTITY_MIGRATION_CHILD") {
        IdentityAuthority::migrate_v1(Path::new(&directory)).unwrap();
        panic!("crash injection did not run");
    }
}

#[cfg(feature = "fault-injection")]
#[test]
fn migration_crash_before_and_after_switch_preserves_credentials_and_revocation() {
    for boundary in [
        "identity.before_migration_publish",
        "identity.after_migration_publish",
    ] {
        let f = Fixture::new();
        f.user();
        let id = f.authority.resolve_user(&f.actor(), "ana").unwrap();
        let revoked = f
            .authority
            .issue_credential(&f.actor(), f.authority.revision(), &id)
            .unwrap();
        f.edit(|a, actor, rev| a.revoke_credential(actor, rev, &revoked.id));
        let state = f.authority.current.read().state.clone();
        let old = serde_json::json!({"version":1,"revision":state.revision,"principals":state.principals,"credentials":state.credentials,"groups":state.groups});
        let Fixture {
            authority,
            directory,
            key,
        } = f;
        drop(authority);
        let path = directory.path().join("security").join(IDENTITY_FILE);
        std::fs::write(
            &path,
            super::super::storage::encode_metadata(b"CHRNID01", &serde_json::to_vec(&old).unwrap()),
        )
        .unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "security::identity::administration_tests::identity_migration_crash_child",
                "--exact",
                "--test-threads=1",
            ])
            .env("CHIRONDB_IDENTITY_MIGRATION_CHILD", directory.path())
            .env("CHIRONDB_FAILPOINT", format!("exit:{boundary}"))
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(86),
            "child must exit at the selected boundary"
        );
        let before = boundary == "identity.before_migration_publish";
        assert_eq!(
            std::fs::read(&path).unwrap().starts_with(b"CHRNID01"),
            before
        );
        if before {
            assert!(IdentityAuthority::open(directory.path()).is_err());
        }
        assert_eq!(
            IdentityAuthority::migrate_v1(directory.path()).unwrap(),
            before
        );
        let reopened = IdentityAuthority::open(directory.path()).unwrap().unwrap();
        assert!(reopened.authenticate(&key.secret).is_ok());
        assert!(reopened.authenticate(&revoked.secret).is_err());
        assert_eq!(reopened.revision(), state.revision + 1);
        crate::audit::verify_hash_chain(directory.path()).unwrap();
    }
}

#[test]
#[ignore = "requires CHIRONDB_OLD_AUTHORITY_BINARY supporting identity format 1"]
fn actual_identity_v1_reader_refuses_v2_authority() {
    use std::process::{Command, Stdio};
    let binary =
        std::env::var_os("CHIRONDB_OLD_AUTHORITY_BINARY").expect("pinned identity v1 reader");
    let Fixture {
        authority,
        directory,
        key,
    } = Fixture::new();
    drop(authority);
    let mut child = Command::new(binary)
        .env_clear()
        .current_dir(directory.path())
        .args(["--data-dir"])
        .arg(directory.path())
        .args([
            "--listen-http",
            "127.0.0.1:0",
            "--listen-grpc",
            "127.0.0.1:0",
            "--listen-wire",
            "127.0.0.1:0",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    if child.try_wait().unwrap().is_none() {
        child.kill().unwrap();
        panic!("old identity reader opened authority v2");
    }
    let result = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(!result.status.success());
    assert!(
        stderr.contains("failed to open data dir")
            && stderr.contains("security authority unavailable"),
        "must reject at authority open: {stderr}"
    );
    assert!(
        IdentityAuthority::open(directory.path())
            .unwrap()
            .unwrap()
            .authenticate(&key.secret)
            .is_ok()
    );
}

#[test]
fn strict_sql_scope_conversion_preserves_roles_and_disabled_users_without_name_fallback() {
    let f = Fixture::installed();
    f.authority.upgrade_table_authority_offline().unwrap();
    f.user();
    let user_id = f.authority.resolve_user(&f.actor(), "ana").unwrap();
    let role_id = Uuid::new_v4();
    let table_uuid = Uuid::new_v4();
    let vector_uuid = Uuid::new_v4();
    {
        let mut current = f.authority.current.write();
        let user = current.state.principals.get_mut(&user_id).unwrap();
        user.enabled = false;
        user.grants.push(ScopeGrant {
            tenants: BTreeSet::from(["acme".into()]),
            collections: BTreeSet::from(["docs".into(), "future".into()]),
            actions: BTreeSet::from([Action::Read, Action::Search]),
        });
        current.state.roles.insert(
            role_id,
            RoleRecord {
                id: role_id,
                name: "writer".into(),
                tenant: "acme".into(),
                retired: false,
                grants: vec![RoleCollectionGrant {
                    collection: "docs".into(),
                    incarnation: vector_uuid,
                    actions: BTreeSet::from([Action::Create, Action::GraphWrite]),
                }],
                table_grants: Vec::new(),
                installation_actions: BTreeSet::new(),
            },
        );
        current
            .state
            .memberships
            .insert(user_id.clone(), BTreeSet::from([role_id]));
        current.state.validate().unwrap();
        persist(&f.authority.root, &current.state).unwrap();
    }
    let tables = BTreeMap::from([(("acme".into(), "docs".into()), (19, table_uuid))]);
    assert!(f.authority.migrate_sql_scopes_offline(&tables).unwrap());
    let state = &f.authority.current.read().state;
    assert!(!state.principals[&user_id].enabled);
    let migrated = state
        .roles
        .values()
        .find(|role| role.name.starts_with("sql_migrated_"))
        .unwrap();
    assert_eq!(migrated.table_grants.len(), 1);
    assert_eq!(
        migrated.table_grants[0].actions,
        BTreeSet::from([Action::Read])
    );
    assert!(state.memberships[&user_id].contains(&migrated.id));
    let role = &state.roles[&role_id];
    assert_eq!(role.grants[0].incarnation, vector_uuid);
    assert_eq!(
        role.table_grants[0].actions,
        BTreeSet::from([Action::Create])
    );
    // Construct a current enabled test identity without changing the durable
    // disabled principal; the conversion itself must not enable it.
    let mut identity = f.actor();
    identity.principal = state.principals[&user_id].clone();
    identity.principal.enabled = true;
    identity.roles = vec![migrated.clone(), role.clone()];
    assert!(identity.allows("acme", "future", Action::Read));
    assert!(identity.allows_table("acme", "renamed", 19, table_uuid, Action::Read));
    assert!(identity.allows_table("acme", "renamed", 19, table_uuid, Action::Create));
    assert!(!identity.allows_table("acme", "docs", 19, Uuid::new_v4(), Action::Read));
    assert!(!identity.allows_table("other", "docs", 19, table_uuid, Action::Read));
    assert!(!identity.allows_table("acme", "future", 20, Uuid::new_v4(), Action::Read));
    assert!(!identity.owns_table("other", Some(&user_id)));
    assert!(identity.owns_table("acme", Some(&user_id)));
    identity.principal.enabled = false;
    assert!(!identity.owns_table("acme", Some(&user_id)));
    assert!(!identity.allows_table("acme", "docs", 19, table_uuid, Action::Read));
}

#[test]
fn strict_sql_scope_budget_rejection_precedes_any_persistent_mutation() {
    let f = Fixture::installed();
    f.authority.upgrade_table_authority_offline().unwrap();
    let incarnation = Uuid::new_v4();
    let mut tables = BTreeMap::new();
    {
        let mut current = f.authority.current.write();
        let principal = current.state.principals.get_mut("security-admin").unwrap();
        let mut names = BTreeSet::new();
        for n in 1..=MAX_POLICY_GRANTS {
            let name = format!("table_{n}");
            tables.insert(("acme".into(), name.clone()), (n as u64, incarnation));
            names.insert(name);
        }
        principal.grants.push(ScopeGrant {
            tenants: BTreeSet::from(["acme".into()]),
            collections: names,
            actions: BTreeSet::from([Action::Read]),
        });
        current.state.validate().unwrap();
        persist(&f.authority.root, &current.state).unwrap();
    }
    let authority_before = std::fs::read(f.authority.root.join(IDENTITY_FILE)).unwrap();
    let marker_before = std::fs::read(f.directory.path().join(onboarding::MARKER)).unwrap();
    let audit_path = f.directory.path().join("audit/audit.jsonl");
    let audit_before = std::fs::read(&audit_path).unwrap();
    assert!(matches!(
        f.authority.migrate_sql_scopes_offline(&tables),
        Err(SecurityError::BudgetExceeded)
    ));
    assert_eq!(
        std::fs::read(f.authority.root.join(IDENTITY_FILE)).unwrap(),
        authority_before
    );
    assert_eq!(
        std::fs::read(f.directory.path().join(onboarding::MARKER)).unwrap(),
        marker_before
    );
    assert_eq!(std::fs::read(audit_path).unwrap(), audit_before);
    assert!(f.actor().publication_permit().is_ok());
}

#[test]
fn encrypted_identity_budget_includes_framing_before_the_reader_fence() {
    if std::env::var_os("CHIRONDB_IDENTITY_BUDGET_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "security::identity::administration_tests::encrypted_identity_budget_includes_framing_before_the_reader_fence", "--nocapture"])
            .env("CHIRONDB_IDENTITY_BUDGET_CHILD", "1").output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    // Process isolation is required: installing the keyring is global.
    let f = Fixture::installed();
    f.authority.upgrade_table_authority_offline().unwrap();
    let keyring_path = f.directory.path().join("keyring.json");
    std::fs::write(
        &keyring_path,
        serde_json::to_vec(&serde_json::json!({
            "version":1, "active_key_id":"test", "keys":[{"id":"test",
            "key_base64":base64::engine::general_purpose::STANDARD.encode([9u8; 32])}]
        }))
        .unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&keyring_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    crate::encryption::install_process_keyring(
        crate::encryption::Keyring::load(&keyring_path).unwrap(),
        false,
    )
    .unwrap();
    let mut candidate = f.authority.current.read().state.clone();
    candidate.version = 6;
    candidate.revision += 1;
    let target_json_len = MAX_IDENTITY_BYTES as usize - 52;
    let names = (0..(MAX_IDENTITY_BYTES as usize - 16_384) / 131)
        .map(|n| format!("n{n:0127}"))
        .collect();
    candidate
        .principals
        .get_mut("security-admin")
        .unwrap()
        .grants = vec![ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: names,
        actions: BTreeSet::from([Action::Read]),
    }];
    let mut missing = target_json_len - serde_json::to_vec(&candidate).unwrap().len();
    let principal = candidate.principals.get_mut("security-admin").unwrap();
    let mut n = 0;
    while missing > 120 {
        let name = if missing >= 131 {
            format!("p{n:0127}")
        } else {
            "padding".into()
        };
        missing -= name.len() + 3; // quotes and array delimiter
        assert!(principal.grants[0].collections.insert(name));
        n += 1;
    }
    principal
        .attributes
        .department
        .push_str(&"p".repeat(missing));
    candidate.validate().unwrap();
    let json = serde_json::to_vec(&candidate).unwrap();
    assert_eq!(json.len(), target_json_len);
    assert_eq!(
        super::super::storage::encode_metadata(STRICT_SQL_IDENTITY_MAGIC, &json).len(),
        MAX_IDENTITY_BYTES as usize
    );
    let identity_before = std::fs::read(f.authority.root.join(IDENTITY_FILE)).unwrap();
    let marker_before = std::fs::read(f.directory.path().join(onboarding::MARKER)).unwrap();
    assert!(matches!(
        encode_state(&candidate),
        Err(SecurityError::BudgetExceeded)
    ));
    assert!(matches!(
        persist(&f.authority.root, &candidate),
        Err(SecurityError::BudgetExceeded)
    ));
    assert_eq!(
        std::fs::read(f.authority.root.join(IDENTITY_FILE)).unwrap(),
        identity_before
    );
    assert_eq!(
        std::fs::read(f.directory.path().join(onboarding::MARKER)).unwrap(),
        marker_before
    );
}
