use super::*;
use crate::GaussError;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;
use uuid::Uuid;

fn principal(id: &str) -> PrincipalRecord {
    PrincipalRecord {
        id: id.into(),
        tenant: "acme".into(),
        enabled: true,
        attributes: SubjectAttributes {
            department: "Finance".into(),
            clearance: Classification::Confidential,
        },
        grants: vec![ScopeGrant {
            tenants: BTreeSet::from(["acme".into()]),
            collections: BTreeSet::from(["docs".into()]),
            actions: BTreeSet::from([Action::Read, Action::Search, Action::Update]),
        }],
        installation_actions: BTreeSet::new(),
        delegation: Vec::new(),
    }
}

fn resource() -> ResourceRecord {
    ResourceRecord {
        key: PointKey {
            collection: Uuid::new_v4(),
            tenant: "acme".into(),
            id: "document".into(),
        },
        storage_id: Uuid::new_v4(),
        labels: ResourceLabels {
            owner: "owner".into(),
            department: "HR".into(),
            classification: Classification::Confidential,
            quarantined: false,
        },
        properties: BTreeMap::new(),
        representations: BTreeMap::new(),
        grants: Vec::new(),
        parent: None,
        revision: 1,
        retired: false,
        create_receipt: None,
    }
}

#[test]
fn admitted_projection_preserves_nested_escaped_and_numeric_policy_oracle() {
    let subject = principal("reader");
    let mut record = resource();
    for path in [
        "/visible",
        "/nested/a~1b/~0text",
        "/empty",
        "/number",
        "/zero",
    ] {
        record.properties.insert(
            path.into(),
            PropertyRule {
                classification: Classification::Internal,
                actions: BTreeSet::from([PropertyAction::Read]),
            },
        );
    }
    record.properties.insert(
        "/export".into(),
        PropertyRule {
            classification: Classification::Internal,
            actions: BTreeSet::from([PropertyAction::Export]),
        },
    );
    let payload = serde_json::json!({
        "visible":{"text":"日本語", "array":[true,null,u64::MAX,-0.0]},
        "nested":{"a/b":{"~text":"allowed","hidden":"secret"},"hiddenEmpty":{}},
        "empty":{}, "number":0.8455124082255701, "zero":-0.0,
        "export":"exported", "hidden":"secret".repeat(1024)
    });
    for action in [
        PropertyAction::Read,
        PropertyAction::Export,
        PropertyAction::Query,
    ] {
        let expected = policy::project_payload(&record, &subject.attributes, &payload, action);
        crate::relational::wal_decode::with_test_storage_pool(64 * 1024, |used| {
            let projected =
                projection::copy(&record, &subject.attributes, &payload, action).unwrap();
            assert_eq!(*projected, expected);
            if action == PropertyAction::Read {
                for field in ["number", "zero"] {
                    assert_eq!(
                        projected[field].as_f64().unwrap().to_bits(),
                        payload[field].as_f64().unwrap().to_bits()
                    );
                }
            }
            assert!(used() > 0);
            drop(projected);
            assert_eq!(used(), 0);
        });
    }
}

#[test]
fn admitted_projection_refusal_cancellation_and_hidden_subtree_do_not_leak() {
    let subject = principal("reader");
    let mut record = resource();
    for (path, classification) in [
        ("/visible", Classification::Internal),
        ("/hidden", Classification::Restricted),
    ] {
        record.properties.insert(
            path.into(),
            PropertyRule {
                classification,
                actions: BTreeSet::from([PropertyAction::Read]),
            },
        );
    }
    let hidden = serde_json::json!({"visible":"ok", "hidden":"secret".repeat(65536)});
    crate::relational::wal_decode::with_test_storage_pool(16 * 1024, |used| {
        let projected =
            projection::copy(&record, &subject.attributes, &hidden, PropertyAction::Read).unwrap();
        assert_eq!(*projected, serde_json::json!({"visible":"ok"}));
        assert!(used() < 16 * 1024);
        drop(projected);
        assert_eq!(used(), 0);
    });
    let large = serde_json::json!({"visible":"x".repeat(65536)});
    for capacity in [1, 8192] {
        crate::relational::wal_decode::with_test_storage_pool(capacity, |used| {
            assert!(matches!(
                projection::copy(&record, &subject.attributes, &large, PropertyAction::Read),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
        });
    }
    crate::relational::wal_decode::with_test_storage_pool(256 * 1024, |used| {
        let projected =
            projection::copy(&record, &subject.attributes, &large, PropertyAction::Read).unwrap();
        assert_eq!(*projected, large);
        drop(projected);
        assert_eq!(used(), 0);
        let canceled = crate::relational::with_sql_cancellation(
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            || projection::copy(&record, &subject.attributes, &large, PropertyAction::Read),
        );
        assert!(matches!(canceled, Err(GaussError::InvalidRequest(_))));
        assert_eq!(used(), 0);
    });
}

#[test]
fn admitted_projection_path_growth_refuses_with_typed_error_and_retry() {
    let subject = principal("reader");
    let mut record = resource();
    let key = "~/日本語".repeat(1024);
    record.properties.insert(
        format!("/{}", key.replace('~', "~0").replace('/', "~1")),
        PropertyRule {
            classification: Classification::Internal,
            actions: BTreeSet::from([PropertyAction::Read]),
        },
    );
    let payload = serde_json::json!({key:"allowed"});
    crate::relational::wal_decode::with_test_storage_pool(8192, |used| {
        assert!(matches!(
            projection::copy(&record, &subject.attributes, &payload, PropertyAction::Read),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(used(), 0);
    });
    crate::relational::wal_decode::with_test_storage_pool(256 * 1024, |used| {
        let projected =
            projection::copy(&record, &subject.attributes, &payload, PropertyAction::Read).unwrap();
        assert_eq!(*projected, payload);
        drop(projected);
        assert_eq!(used(), 0);
    });
}

#[test]
fn explicit_share_does_not_bypass_clearance_deny_or_action() {
    let subject = principal("finance-reader");
    let groups = BTreeSet::from(["shared".into()]);
    let mut record = resource();
    let config = CollectionPolicy {
        department_actions: BTreeSet::from([Action::Read]),
        owner_actions: BTreeSet::new(),
        templates: BTreeMap::new(),
    };
    assert!(
        policy::authorize_resource(
            &subject,
            &groups,
            &record,
            Action::Read,
            &config,
            &BTreeMap::new()
        )
        .is_err()
    );
    record.grants.push(ObjectGrant {
        subject: Subject::Group("shared".into()),
        effect: Effect::Permit,
        actions: BTreeSet::from([Action::Read]),
        inherit: false,
    });
    assert!(
        policy::authorize_resource(
            &subject,
            &groups,
            &record,
            Action::Read,
            &config,
            &BTreeMap::new()
        )
        .is_ok()
    );
    assert!(
        policy::authorize_resource(
            &subject,
            &groups,
            &record,
            Action::Update,
            &config,
            &BTreeMap::new()
        )
        .is_err()
    );
    record.labels.classification = Classification::Restricted;
    assert!(
        policy::authorize_resource(
            &subject,
            &groups,
            &record,
            Action::Read,
            &config,
            &BTreeMap::new()
        )
        .is_err()
    );
    record.labels.classification = Classification::Confidential;
    record.grants.push(ObjectGrant {
        subject: Subject::Principal(subject.id.clone()),
        effect: Effect::Deny,
        actions: BTreeSet::from([Action::Read]),
        inherit: false,
    });
    assert!(
        policy::authorize_resource(
            &subject,
            &groups,
            &record,
            Action::Read,
            &config,
            &BTreeMap::new()
        )
        .is_err()
    );
}

#[test]
fn inheritance_is_bounded_and_never_crosses_a_tenant() {
    let subject = principal("reader");
    let config = CollectionPolicy {
        department_actions: BTreeSet::new(),
        owner_actions: BTreeSet::new(),
        templates: BTreeMap::new(),
    };
    let mut child = resource();
    let mut parent = child.clone();
    parent.key.id = "parent".into();
    parent.grants.push(ObjectGrant {
        subject: Subject::Principal(subject.id.clone()),
        effect: Effect::Permit,
        actions: BTreeSet::from([Action::Read]),
        inherit: true,
    });
    child.parent = Some(parent.key.clone());
    let mut records = BTreeMap::from([
        (parent.key.clone(), parent.clone()),
        (child.key.clone(), child.clone()),
    ]);
    assert!(
        policy::authorize_resource(
            &subject,
            &BTreeSet::new(),
            &child,
            Action::Read,
            &config,
            &records
        )
        .is_ok()
    );
    parent.parent = Some(child.key.clone());
    records.insert(parent.key.clone(), parent.clone());
    assert!(
        policy::authorize_resource(
            &subject,
            &BTreeSet::new(),
            &child,
            Action::Read,
            &config,
            &records
        )
        .is_err()
    );
    child.parent.as_mut().unwrap().tenant = "globex".into();
    assert!(
        policy::authorize_resource(
            &subject,
            &BTreeSet::new(),
            &child,
            Action::Read,
            &config,
            &records
        )
        .is_err()
    );
}

#[test]
fn inheritance_stack_preserves_exact_depth_grant_and_cycle_boundaries() {
    let subject = principal("reader");
    let config = CollectionPolicy {
        department_actions: BTreeSet::new(),
        owner_actions: BTreeSet::new(),
        templates: BTreeMap::new(),
    };
    let base = resource();
    let mut chain: Vec<_> = (0..=MAX_INHERITANCE_DEPTH)
        .map(|i| {
            let mut row = base.clone();
            row.key.id = format!("depth-{i}");
            row
        })
        .collect();
    for i in 0..MAX_INHERITANCE_DEPTH {
        chain[i].parent = Some(chain[i + 1].key.clone());
    }
    chain[MAX_INHERITANCE_DEPTH - 1].grants.push(ObjectGrant {
        subject: Subject::Principal(subject.id.clone()),
        effect: Effect::Permit,
        actions: BTreeSet::from([Action::Read]),
        inherit: true,
    });
    let evaluate = |rows: &[ResourceRecord]| {
        let records = rows
            .iter()
            .map(|row| (row.key.clone(), row.clone()))
            .collect();
        policy::authorize_resource(
            &subject,
            &BTreeSet::new(),
            &rows[0],
            Action::Read,
            &config,
            &records,
        )
    };
    assert_eq!(evaluate(&chain), Err(SecurityError::BudgetExceeded));
    chain[MAX_INHERITANCE_DEPTH - 1].parent = None;
    assert_eq!(evaluate(&chain), Ok(()));
    chain[MAX_INHERITANCE_DEPTH - 1].parent = Some(chain[0].key.clone());
    assert!(
        matches!(evaluate(&chain), Err(SecurityError::Invalid(message)) if message == "inheritance cycle")
    );
    chain[MAX_INHERITANCE_DEPTH - 1].parent = None;
    // The grant bound remains independent of the depth bound.
    chain[0].grants =
        vec![chain[MAX_INHERITANCE_DEPTH - 1].grants[0].clone(); MAX_POLICY_GRANTS + 1];
    assert_eq!(evaluate(&chain), Err(SecurityError::BudgetExceeded));
}

#[test]
fn nested_group_validation_prevents_cycles_and_foreign_members() {
    let subject = principal("reader");
    let principals = BTreeMap::from([(subject.id.clone(), subject.clone())]);
    let mut groups = BTreeMap::from([
        (
            "direct".into(),
            GroupRecord {
                id: "direct".into(),
                tenant: "acme".into(),
                members: BTreeSet::from([GroupMember::Principal(subject.id.clone())]),
            },
        ),
        (
            "parent".into(),
            GroupRecord {
                id: "parent".into(),
                tenant: "acme".into(),
                members: BTreeSet::from([GroupMember::Group("direct".into())]),
            },
        ),
    ]);
    policy::validate_groups(&groups, &principals).unwrap();
    assert_eq!(
        policy::expand_groups(&subject, &groups).unwrap(),
        BTreeSet::from(["direct".into(), "parent".into()])
    );
    groups
        .get_mut("direct")
        .unwrap()
        .members
        .insert(GroupMember::Group("parent".into()));
    assert!(policy::validate_groups(&groups, &principals).is_err());
    groups
        .get_mut("direct")
        .unwrap()
        .members
        .remove(&GroupMember::Group("parent".into()));
    groups.get_mut("direct").unwrap().tenant = "globex".into();
    assert!(policy::validate_groups(&groups, &principals).is_err());
}

#[test]
fn property_projection_does_not_grant_filter_or_write_access() {
    let subject = principal("reader");
    let mut record = resource();
    record.properties.insert(
        "/name".into(),
        PropertyRule {
            classification: Classification::Public,
            actions: BTreeSet::from([PropertyAction::Read]),
        },
    );
    record.properties.insert(
        "/budget".into(),
        PropertyRule {
            classification: Classification::Restricted,
            actions: BTreeSet::from([PropertyAction::Read, PropertyAction::Query]),
        },
    );
    let payload = serde_json::json!({"name":"project", "budget":100, "unknown":"secret"});
    assert_eq!(
        policy::project_payload(&record, &subject.attributes, &payload, PropertyAction::Read),
        serde_json::json!({"name":"project"})
    );
    assert!(!policy::field_allowed(
        &record,
        &subject.attributes,
        "/budget",
        PropertyAction::Query
    ));
    assert!(policy::validate_payload_write(&record, &subject.attributes, &payload).is_err());
}

#[test]
fn representation_cannot_be_less_restricted_than_its_input() {
    let mut template = IngestTemplate {
        department: "Finance".into(),
        classification: Classification::Internal,
        properties: BTreeMap::from([(
            "/text".into(),
            PropertyRule {
                classification: Classification::Restricted,
                actions: BTreeSet::from([PropertyAction::Read]),
            },
        )]),
        representations: BTreeMap::from([(
            "dense".into(),
            Representation {
                source_fields: BTreeSet::from(["/text".into()]),
                classification: Classification::Internal,
            },
        )]),
    };
    assert!(policy::validate_template(&template).is_err());
    template
        .representations
        .get_mut("dense")
        .unwrap()
        .classification = Classification::Restricted;
    policy::validate_template(&template).unwrap();
    assert!(
        serde_json::from_str::<ResourceLabels>(
            r#"{"owner":"a","department":"HR","quarantined":false}"#
        )
        .is_err()
    );
}

#[test]
fn revocation_drains_publication_and_survives_reopen_without_secrets() {
    let directory = tempfile::tempdir().unwrap();
    let mut admin = principal("security-admin");
    admin.installation_actions.insert(Action::IdentityManage);
    admin.delegation = admin.grants.clone();
    let bootstrap = IdentityAuthority::bootstrap(directory.path(), admin).unwrap();
    let authority = IdentityAuthority::open(directory.path()).unwrap().unwrap();
    let actor = authority.authenticate(&bootstrap.secret).unwrap();
    authority
        .put_principal(&actor, 1, principal("reader"))
        .unwrap();
    assert!(actor.publication_permit().is_err());
    let actor = authority.authenticate(&bootstrap.secret).unwrap();
    let issued = authority.issue_credential(&actor, 2, "reader").unwrap();
    let reader = authority.authenticate(&issued.secret).unwrap();
    let permit = reader.publication_permit().unwrap();
    let actor = authority.authenticate(&bootstrap.secret).unwrap();
    let cloned = authority.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let credential_id = issued.id.clone();
    let thread = std::thread::spawn(move || {
        tx.send(cloned.revoke_credential(&actor, 3, &credential_id))
            .unwrap();
    });
    let started = std::time::Instant::now();
    while !reader.cancelled().load(Ordering::Acquire) {
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        std::thread::yield_now();
    }
    assert!(reader.publication_permit().is_err());
    assert!(
        rx.try_recv().is_err(),
        "revoke must not acknowledge an outstanding publication"
    );
    drop(permit);
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(2))
            .unwrap()
            .unwrap(),
        4
    );
    thread.join().unwrap();
    assert!(IdentityAuthority::open(directory.path()).is_err());
    drop(authority);
    let reopened = IdentityAuthority::open(directory.path()).unwrap().unwrap();
    assert!(reopened.authenticate(&issued.secret).is_err());
    let bytes = std::fs::read(directory.path().join("security/identity.v1")).unwrap();
    let persisted = String::from_utf8(bytes).unwrap();
    assert!(!persisted.contains(&issued.secret));
    assert!(!persisted.contains(&bootstrap.secret));
    assert!(reopened.authenticate(&bootstrap.secret).is_ok());
}

#[test]
fn payload_replacement_cannot_erase_or_convert_a_protected_field() {
    let subject = principal("writer");
    let mut record = resource();
    record.properties.insert(
        "/name".into(),
        PropertyRule {
            classification: Classification::Public,
            actions: BTreeSet::from([PropertyAction::Write]),
        },
    );
    record.properties.insert(
        "/payroll/salary".into(),
        PropertyRule {
            classification: Classification::Restricted,
            actions: BTreeSet::from([PropertyAction::Write]),
        },
    );
    let old = serde_json::json!({"name":"before", "payroll":{"salary":100}});
    for new in [
        serde_json::json!({"name":"after"}),
        serde_json::json!({"name":"after", "payroll":{}}),
        serde_json::json!({"name":"after", "payroll":null}),
    ] {
        assert!(policy::validate_payload_change(&record, &subject.attributes, &old, &new).is_err());
    }
    let new = serde_json::json!({"name":"after", "payroll":{"salary":100}});
    policy::validate_payload_change(&record, &subject.attributes, &old, &new).unwrap();
}

#[test]
fn context_separates_tenant_namespace_scope_and_object_policy() {
    let directory = tempfile::tempdir().unwrap();
    let mut subject = principal("reader");
    subject.installation_actions.insert(Action::IdentityManage);
    let issued = IdentityAuthority::bootstrap(directory.path(), subject.clone()).unwrap();
    let identities = IdentityAuthority::open(directory.path()).unwrap().unwrap();
    let actor = identities.authenticate(&issued.secret).unwrap();
    let mut own = resource();
    own.labels.department = subject.attributes.department.clone();
    let mut foreign = own.clone();
    foreign.key.tenant = "globex".into();
    foreign.storage_id = Uuid::new_v4();
    let checkpoint = SecurityCheckpoint {
        version: SECURITY_VERSION,
        collection: "docs".into(),
        incarnation: own.key.collection,
        revision: 1,
        data_generation: 1,
        policy: CollectionPolicy {
            department_actions: BTreeSet::from([Action::Read, Action::Update]),
            owner_actions: BTreeSet::new(),
            templates: BTreeMap::new(),
        },
        resources: vec![own.clone(), foreign.clone()],
    };
    let authority = CollectionAuthority::from_verified_checkpoint(checkpoint.clone()).unwrap();
    assert!(authority.bind(&actor, "globex", Action::Read).is_err());
    assert!(authority.bind(&actor, "acme", Action::Export).is_err());
    let context = authority.bind(&actor, "acme", Action::Read).unwrap();
    assert_eq!(
        context.authorize("document").unwrap().storage_id,
        own.storage_id
    );
    assert_eq!(
        context.authorize_physical(foreign.storage_id).unwrap_err(),
        SecurityError::NotFound
    );
    assert_eq!(
        context.authorized_domain().unwrap(),
        BTreeSet::from([own.storage_id])
    );
    let writer = authority.bind(&actor, "acme", Action::Update).unwrap();
    assert!(
        writer
            .project("document", &serde_json::json!({}), false)
            .is_err()
    );
    let mut denied = checkpoint;
    denied.revision = 2;
    denied.data_generation = 2;
    denied.resources[0].grants.push(ObjectGrant {
        subject: Subject::Principal(subject.id),
        effect: Effect::Deny,
        actions: BTreeSet::from([Action::Read]),
        inherit: false,
    });
    authority.install(1, denied, |_| Ok(())).unwrap();
    assert!(context.publication_permit().is_err());
    let context = authority.bind(&actor, "acme", Action::Read).unwrap();
    assert_eq!(
        context.authorize("document").unwrap_err(),
        context.authorize("absent").unwrap_err()
    );
    assert!(context.authorized_domain().unwrap().is_empty());
}

#[test]
fn malformed_security_checkpoint_cannot_enable_dormant_inheritance() {
    let mut record = resource();
    record.parent = Some(record.key.clone());
    let checkpoint = SecurityCheckpoint {
        version: SECURITY_VERSION,
        collection: "docs".into(),
        incarnation: record.key.collection,
        revision: 1,
        data_generation: 1,
        policy: CollectionPolicy {
            department_actions: BTreeSet::new(),
            owner_actions: BTreeSet::new(),
            templates: BTreeMap::new(),
        },
        resources: vec![record],
    };
    assert!(CollectionAuthority::from_verified_checkpoint(checkpoint).is_err());
}

#[test]
fn failed_policy_persistence_keeps_old_epoch_closed() {
    let directory = tempfile::tempdir().unwrap();
    let mut subject = principal("reader");
    subject.installation_actions.insert(Action::IdentityManage);
    let issued = IdentityAuthority::bootstrap(directory.path(), subject).unwrap();
    let identities = IdentityAuthority::open(directory.path()).unwrap().unwrap();
    let actor = identities.authenticate(&issued.secret).unwrap();
    let checkpoint = SecurityCheckpoint {
        version: SECURITY_VERSION,
        collection: "docs".into(),
        incarnation: Uuid::new_v4(),
        revision: 1,
        data_generation: 1,
        policy: CollectionPolicy {
            department_actions: BTreeSet::new(),
            owner_actions: BTreeSet::new(),
            templates: BTreeMap::new(),
        },
        resources: Vec::new(),
    };
    let authority = CollectionAuthority::from_verified_checkpoint(checkpoint.clone()).unwrap();
    let context = authority.bind(&actor, "acme", Action::Read).unwrap();
    let mut next = checkpoint;
    next.revision += 1;
    next.data_generation += 1;
    assert!(
        authority
            .install(1, next, |_| Err(SecurityError::Unavailable))
            .is_err()
    );
    assert!(context.publication_permit().is_err());
    assert!(authority.bind(&actor, "acme", Action::Read).is_err());
}

#[test]
fn identity_cannot_delegate_root_or_raise_clearance_and_rotation_is_atomic() {
    let directory = tempfile::tempdir().unwrap();
    let mut admin = principal("authority");
    admin.installation_actions.insert(Action::IdentityManage);
    admin.delegation = admin.grants.clone();
    let issued = IdentityAuthority::bootstrap(directory.path(), admin).unwrap();
    let authority = IdentityAuthority::open(directory.path()).unwrap().unwrap();
    let actor = authority.authenticate(&issued.secret).unwrap();
    let mut target = principal("reader");
    target.attributes.clearance = Classification::Restricted;
    assert_eq!(
        authority
            .put_principal(&actor, 1, target.clone())
            .unwrap_err(),
        SecurityError::Forbidden
    );
    target.attributes.clearance = Classification::Confidential;
    target.installation_actions.insert(Action::IdentityManage);
    assert_eq!(
        authority
            .put_principal(&actor, 1, target.clone())
            .unwrap_err(),
        SecurityError::Forbidden
    );
    target.installation_actions.clear();
    authority.put_principal(&actor, 1, target).unwrap();
    assert!(
        authority
            .put_principal(&actor, 1, principal("stale"))
            .is_err()
    );
    let actor = authority.authenticate(&issued.secret).unwrap();
    let rotated = authority.rotate_credential(&actor, 2, &issued.id).unwrap();
    assert!(authority.authenticate(&issued.secret).is_err());
    assert_eq!(
        authority
            .authenticate(&rotated.secret)
            .unwrap()
            .principal()
            .id,
        "authority"
    );
    drop(authority);
    let reopened = IdentityAuthority::open(directory.path()).unwrap().unwrap();
    assert!(reopened.authenticate(&issued.secret).is_err());
    assert!(reopened.authenticate(&rotated.secret).is_ok());
    let audit = std::fs::read_to_string(directory.path().join("audit/audit.jsonl")).unwrap();
    assert!(audit.contains("identity.rotate_credential"));
    assert!(!audit.contains(&issued.secret));
    assert!(!audit.contains(&rotated.secret));
}

#[test]
fn group_depth_is_bounded_even_when_a_shared_subtree_was_memoized() {
    let subject = principal("reader");
    let principals = BTreeMap::from([(subject.id.clone(), subject.clone())]);
    let mut groups = BTreeMap::new();
    for depth in 0..8 {
        let id = format!("g{depth}");
        let member = if depth == 0 {
            GroupMember::Principal(subject.id.clone())
        } else {
            GroupMember::Group(format!("g{}", depth - 1))
        };
        groups.insert(
            id.clone(),
            GroupRecord {
                id,
                tenant: "acme".into(),
                members: BTreeSet::from([member]),
            },
        );
    }
    policy::validate_groups(&groups, &principals).unwrap();
    assert_eq!(policy::expand_groups(&subject, &groups).unwrap().len(), 8);
    groups.insert(
        "g8".into(),
        GroupRecord {
            id: "g8".into(),
            tenant: "acme".into(),
            members: BTreeSet::from([GroupMember::Group("g7".into())]),
        },
    );
    assert_eq!(
        policy::validate_groups(&groups, &principals).unwrap_err(),
        SecurityError::BudgetExceeded
    );
}

#[test]
fn database_requires_authority_outside_content_and_refuses_legacy_restore() {
    let directory = tempfile::tempdir().unwrap();
    let snapshot = tempfile::tempdir().unwrap();
    let destination = snapshot.path().join("snapshot");
    let mut admin = principal("authority");
    admin.installation_actions.insert(Action::IdentityManage);
    admin.delegation = admin.grants.clone();
    let issued = IdentityAuthority::bootstrap(directory.path(), admin).unwrap();
    assert!(crate::Db::open(directory.path()).is_err());
    crate::storage_layout::initialize_empty(directory.path()).unwrap();
    let db = crate::Db::open(directory.path()).unwrap();
    let identities = db.identity_authority().unwrap();
    let actor = identities.authenticate(&issued.secret).unwrap();
    let old_key = identities.issue_credential(&actor, 1, "authority").unwrap();
    assert!(matches!(
        db.snapshot(&destination),
        Err(crate::GaussError::Security(SecurityError::Forbidden))
    ));
    assert!(!destination.exists());
    let actor = identities.authenticate(&issued.secret).unwrap();
    identities
        .revoke_credential(&actor, 2, &old_key.id)
        .unwrap();
    assert!(matches!(
        db.restore(&destination),
        Err(crate::GaussError::Security(SecurityError::Forbidden))
    ));
    assert!(
        db.identity_authority()
            .unwrap()
            .authenticate(&old_key.secret)
            .is_err()
    );
    drop(db);
    let reopened = crate::Db::open(directory.path()).unwrap();
    assert!(
        reopened
            .identity_authority()
            .unwrap()
            .authenticate(&old_key.secret)
            .is_err()
    );
    assert!(
        reopened
            .identity_authority()
            .unwrap()
            .authenticate(&issued.secret)
            .is_ok()
    );
}

#[test]
fn create_binding_commit_is_atomic_bounded_and_separate_from_policy_revision() {
    let directory = tempfile::tempdir().unwrap();
    let mut subject = principal("creator");
    subject.grants[0].actions.insert(Action::Create);
    subject.installation_actions.insert(Action::IdentityManage);
    let issued = IdentityAuthority::bootstrap(directory.path(), subject).unwrap();
    let identity = IdentityAuthority::open(directory.path()).unwrap().unwrap();
    let actor = identity.authenticate(&issued.secret).unwrap();
    let checkpoint = SecurityCheckpoint {
        version: SECURITY_VERSION,
        collection: "docs".into(),
        incarnation: Uuid::new_v4(),
        revision: 1,
        data_generation: 1,
        policy: CollectionPolicy {
            department_actions: BTreeSet::new(),
            owner_actions: BTreeSet::from([Action::Read]),
            templates: BTreeMap::from([(
                "standard".into(),
                IngestTemplate {
                    department: "Finance".into(),
                    classification: Classification::Internal,
                    properties: BTreeMap::from([(
                        "/text".into(),
                        PropertyRule {
                            classification: Classification::Internal,
                            actions: BTreeSet::from([PropertyAction::Read, PropertyAction::Write]),
                        },
                    )]),
                    representations: BTreeMap::new(),
                },
            )]),
        },
        resources: Vec::new(),
    };
    let authority = CollectionAuthority::from_verified_checkpoint(checkpoint.clone()).unwrap();
    let reader = authority.bind(&actor, "acme", Action::Read).unwrap();
    let creator = authority.bind(&actor, "acme", Action::Create).unwrap();
    let point = NewPoint {
        vector: Vec::new(),
        vectors: BTreeMap::new(),
        sparse_vector: None,
        payload: serde_json::json!({"text":"permitted"}),
    };
    let mut invalid = point.clone();
    invalid.payload = serde_json::json!({"text":"allowed", "classification":"public"});
    let invoked = std::cell::Cell::new(false);
    assert!(
        authority
            .create_with_commit(
                &creator,
                "standard",
                &[point.clone(), invalid],
                None,
                |_, _| {
                    invoked.set(true);
                    Ok(())
                }
            )
            .is_err()
    );
    assert!(
        !invoked.get(),
        "mixed invalid batch must not reach the WAL callback"
    );
    assert!(reader.authorized_domain().unwrap().is_empty());
    let created = authority
        .create_with_commit(
            &creator,
            "standard",
            &[point.clone(), point.clone()],
            None,
            |bindings, generation| {
                assert_eq!(generation, 2);
                assert_eq!(bindings.len(), 2);
                assert_ne!(bindings[0].key, bindings[1].key);
                assert_ne!(bindings[0].storage_id, bindings[1].storage_id);
                assert!(bindings.iter().all(
                    |binding| binding.key.tenant == "acme" && binding.labels.owner == "creator"
                ));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(reader.policy_revision(), 1);
    assert_eq!(reader.data_generation(), 2);
    assert_eq!(
        reader.authorized_domain().unwrap(),
        created.iter().map(|record| record.storage_id).collect()
    );
    let mut stale = checkpoint;
    stale.revision = 2;
    assert_eq!(
        authority.install(1, stale, |_| Ok(())).unwrap_err(),
        SecurityError::Conflict,
        "policy update must not erase data created after its snapshot"
    );
    let restored = CollectionAuthority::from_verified_checkpoint(authority.checkpoint()).unwrap();
    assert_eq!(
        restored
            .bind(&actor, "acme", Action::Read)
            .unwrap()
            .data_generation(),
        2
    );
    let forged = CollectionAuthority::from_verified_checkpoint(authority.checkpoint()).unwrap();
    let foreign_context = forged.bind(&actor, "acme", Action::Create).unwrap();
    assert!(
        authority
            .create_with_commit(
                &foreign_context,
                "standard",
                std::slice::from_ref(&point),
                None,
                |_, _| panic!("foreign authority")
            )
            .is_err()
    );
    assert!(
        authority
            .create_with_commit(&creator, "standard", &[point], None, |_, _| Err(
                SecurityError::Unavailable.into()
            ))
            .is_err()
    );
    assert!(
        reader.publication_permit().is_err(),
        "uncertain commit must close admission until recovery"
    );
}

#[test]
fn authority_has_one_writer_and_old_contexts_close_on_shutdown() {
    let directory = tempfile::tempdir().unwrap();
    let db = crate::Db::open(directory.path()).unwrap();
    let mut admin = principal("authority");
    admin.installation_actions.insert(Action::IdentityManage);
    assert!(IdentityAuthority::bootstrap(directory.path(), admin.clone()).is_err());
    drop(db);
    let issued = IdentityAuthority::bootstrap(directory.path(), admin).unwrap();
    let authority = IdentityAuthority::open(directory.path()).unwrap().unwrap();
    let actor = authority.authenticate(&issued.secret).unwrap();
    assert!(
        IdentityAuthority::open(directory.path()).is_err(),
        "a second writer could acknowledge revoke while the first still serves old grants"
    );
    assert!(crate::Db::open(directory.path()).is_err());
    let retained = authority.clone();
    drop(authority);
    assert!(IdentityAuthority::open(directory.path()).is_err());
    drop(retained);
    assert!(actor.publication_permit().is_err());
    let reopened = IdentityAuthority::open(directory.path()).unwrap().unwrap();
    assert!(reopened.authenticate(&issued.secret).is_ok());
    assert!(
        actor.publication_permit().is_err(),
        "restart cannot revive an old context"
    );
}

#[test]
fn property_rules_reject_overlapping_paths_and_unknown_empty_objects() {
    let subject = principal("writer");
    let mut record = resource();
    record.properties.insert(
        "/metadata".into(),
        PropertyRule {
            classification: Classification::Internal,
            actions: BTreeSet::from([PropertyAction::Read, PropertyAction::Write]),
        },
    );
    let payload = serde_json::json!({"metadata":{"arbitrary":"value"}});
    policy::validate_payload_write(&record, &subject.attributes, &payload).unwrap();
    assert_eq!(
        policy::project_payload(&record, &subject.attributes, &payload, PropertyAction::Read),
        payload
    );
    let unknown = serde_json::json!({"classification":{}});
    assert!(policy::validate_payload_write(&record, &subject.attributes, &unknown).is_err());
    assert!(
        policy::validate_payload_change(
            &record,
            &subject.attributes,
            &serde_json::json!({}),
            &unknown
        )
        .is_err()
    );
    record.properties.insert(
        "/metadata/payroll".into(),
        PropertyRule {
            classification: Classification::Restricted,
            actions: BTreeSet::from([PropertyAction::Read]),
        },
    );
    let template = IngestTemplate {
        department: "Finance".into(),
        classification: Classification::Internal,
        properties: record.properties,
        representations: BTreeMap::new(),
    };
    assert!(policy::validate_template(&template).is_err());
}

#[test]
fn valid_json_corruption_in_authority_files_fails_integrity() {
    let directory = tempfile::tempdir().unwrap();
    let mut admin = principal("authority");
    admin.installation_actions.insert(Action::IdentityManage);
    IdentityAuthority::bootstrap(directory.path(), admin).unwrap();
    let path = directory.path().join("security/identity.v1");
    let valid = std::fs::read_to_string(&path).unwrap();
    let damaged = valid.replacen("\"revision\":1", "\"revision\":2", 1);
    assert_ne!(valid, damaged);
    std::fs::write(&path, damaged).unwrap();
    assert!(IdentityAuthority::open(directory.path()).is_err());
}
