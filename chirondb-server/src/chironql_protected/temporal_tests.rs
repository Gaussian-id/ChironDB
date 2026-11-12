use super::*;
use std::{collections::BTreeSet, fs, process::Command};

#[test]
fn protected_temporal_reads_bind_scope_and_recheck_at_publication() {
    const CHILD: &str = "CHIRON_TEMP_PROTECTED_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(Command::new(std::env::current_exe().unwrap()).args(["--exact","chironql_protected::temporal_tests::protected_temporal_reads_bind_scope_and_recheck_at_publication","--nocapture"]).env(CHILD,"1").status().unwrap().success());
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = root.join("live");
    let key = root.join("storage.json");
    let token_path = root.join("admin.key");
    chirondb_core::security::onboarding::initialize(
        &path,
        "acme",
        "admin",
        &key,
        &token_path,
        false,
    )
    .unwrap();
    let token = fs::read_to_string(token_path).unwrap();
    let token = token.trim();
    let db = Db::open(&path).unwrap();
    let authority = db.identity_authority().unwrap();
    let actor = authority.authenticate(token).unwrap();
    db.create_protected_collection_authorized(
        &actor,
        db.catalog_revision_authorized(&actor).unwrap(),
        serde_json::from_value(json!({"name":"armada","vector_dim":2})).unwrap(),
    )
    .unwrap();
    let req = |s: &str| ChironQlRequest {
        query: s.into(),
        ..Default::default()
    };
    let latest = "LATEST armada ASSET 'truck' PROPERTY 'temp';";
    assert!(execute(&db, token, &req(latest)).is_err());
    let actor = db
        .management_identity(&authority.authenticate(token).unwrap())
        .unwrap();
    let mut principal = actor.principal().clone();
    principal.grants = vec![ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: BTreeSet::from(["armada".into(), "fleet_assets".into()]),
        actions: BTreeSet::from([
            Action::Read,
            Action::Create,
            Action::Ingest,
            Action::TemporalRead,
            Action::TemporalAppend,
        ]),
    }];
    authority
        .put_principal(&actor, actor.revision(), principal)
        .unwrap();
    let manager = db
        .management_identity(&authority.authenticate(token).unwrap())
        .unwrap();
    let context = db
        .bind_access(&manager, "armada", "acme", Action::PolicyManage)
        .unwrap();
    let property = PropertyRule {
        classification: Classification::Internal,
        actions: BTreeSet::from([
            PropertyAction::Read,
            PropertyAction::Query,
            PropertyAction::Write,
        ]),
    };
    db.replace_collection_policy_authorized(
        &context,
        RevisionUpdate {
            expected_revision: context.policy_revision(),
            value: CollectionPolicy {
                department_actions: BTreeSet::new(),
                owner_actions: BTreeSet::from([
                    Action::Read,
                    Action::TemporalRead,
                    Action::TemporalAppend,
                ]),
                templates: std::collections::BTreeMap::from([(
                    "asset".into(),
                    IngestTemplate {
                        department: "Security".into(),
                        classification: Classification::Internal,
                        properties: std::collections::BTreeMap::from([("/temp".into(), property)]),
                        representations: std::collections::BTreeMap::from([(
                            "dense".into(),
                            Representation {
                                source_fields: BTreeSet::from(["/temp".into()]),
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
        .bind_access(
            &authority.authenticate(token).unwrap(),
            "armada",
            "acme",
            Action::Create,
        )
        .unwrap();
    let asset = db
        .create_points_authorized(
            &create,
            "asset",
            vec![NewPoint {
                vector: vec![1., 0.],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"temp":false}),
            }],
            true,
        )
        .unwrap()
        .publish(|ids| ids[0].clone())
        .unwrap();
    let req = |s: &str| ChironQlRequest {
        query: s.replace("'truck'", &format!("'{asset}'")),
        ..Default::default()
    };
    for sql in [
        "SQL CREATE TABLE fleet_assets (id TEXT PRIMARY KEY);",
        "SQL INSERT INTO fleet_assets VALUES ('truck');",
        "APPEND INTO armada [{asset:'truck',property:'temp',time_ns:'-9223372036854775808',value:true}];",
    ] {
        execute(&db, token, &req(sql))
            .unwrap()
            .publish(|r| r)
            .unwrap();
    }
    let sql = "PIPELINE\nRELATIONAL r { SQL SELECT id FROM fleet_assets LIMIT 1 }\nTEMPORAL t { LATEST armada ASSET r.record_ref PROPERTY 'temp' }\nINNER JOIN t ON t.asset_ref = r.record_ref\nRETURN r.id,t.time_ns,t.value\nLIMIT 1;";
    let expected = json!({"id":asset,"time_ns":"-9223372036854775808","value":true});
    assert_eq!(
        execute(&db, token, &req(sql))
            .unwrap()
            .publish(|r| r.rows)
            .unwrap(),
        std::slice::from_ref(&expected)
    );
    drop(db);
    let db = Db::open(&path).unwrap();
    assert_eq!(
        execute(&db, token, &req(sql))
            .unwrap()
            .publish(|r| r.rows)
            .unwrap(),
        [expected]
    );
    let pending = execute(&db, token, &req(sql)).unwrap();
    execute(
        &db,
        token,
        &req("APPEND INTO armada [{asset:'truck',property:'temp',time_ns:'1',value:false}];"),
    )
    .unwrap()
    .publish(|r| r)
    .unwrap();
    assert!(
        pending
            .publish(|_| panic!("stale snapshot published"))
            .is_err()
    );
    let pending = execute(&db, token, &req(sql)).unwrap();
    let authority = db.identity_authority().unwrap();
    // Every domain is revalidated, including a SQL grant revoked after execution.
    let actor = authority.authenticate(token).unwrap();
    let granted = actor.principal().clone();
    let mut restricted = granted.clone();
    for grant in &mut restricted.grants {
        grant.actions.remove(&Action::Read);
    }
    authority
        .put_principal(&actor, actor.revision(), restricted)
        .unwrap();
    assert!(pending.publish(|_| panic!("revoked SQL output")).is_err());
    assert!(execute(&db, token, &req(sql)).is_err());
    let actor = authority.authenticate(token).unwrap();
    authority
        .put_principal(&actor, actor.revision(), granted)
        .unwrap();
    assert!(
        execute(&db, token, &req(sql))
            .unwrap()
            .publish(|r| r)
            .is_ok()
    );

    let actor = authority.authenticate(token).unwrap();
    let read = db
        .bind_access(&actor, "armada", "acme", Action::TemporalRead)
        .unwrap();
    let append = db
        .bind_access(&actor, "armada", "acme", Action::TemporalAppend)
        .unwrap();
    use chirondb_core::db::temporal::{SensorValue, TemporalAccess, TemporalSample};
    let latest_with = |access| db.latest_temporal("armada", access, &asset, "temp");
    assert!(
        latest_with(TemporalAccess::Authorized(&read))
            .unwrap()
            .is_some()
    );
    assert!(latest_with(TemporalAccess::Authorized(&append)).is_err());
    let untrusted_scope = chirondb_core::tenant::TenantScope::tenant("admin", "acme");
    assert!(latest_with(TemporalAccess::Scoped(&untrusted_scope)).is_err());
    assert!(
        db.bind_access(&actor, "armada", "other-tenant", Action::TemporalRead)
            .is_err()
    );
    assert!(
        db.append_temporal_batch(
            "armada",
            TemporalAccess::Authorized(&read),
            vec![TemporalSample::new(
                "truck",
                "temp",
                2,
                SensorValue::Boolean(true)
            )]
        )
        .is_err()
    );

    let pending = execute(&db, token, &req(sql)).unwrap();
    let actor = authority.authenticate(token).unwrap();
    let mut principal = actor.principal().clone();
    for g in &mut principal.grants {
        g.actions.remove(&Action::TemporalRead);
    }
    authority
        .put_principal(&actor, actor.revision(), principal)
        .unwrap();
    assert!(pending.publish(|_| panic!("revoked output")).is_err());
    assert!(execute(&db, token, &req(sql)).is_err());
    assert!(latest_with(TemporalAccess::Authorized(&read)).is_err());

    let actor = authority.authenticate(token).unwrap();
    let mut principal = actor.principal().clone();
    for grant in &mut principal.grants {
        grant.actions.insert(Action::TemporalRead);
    }
    authority
        .put_principal(&actor, actor.revision(), principal)
        .unwrap();
    let actor = authority.authenticate(token).unwrap();
    let old = db
        .bind_access(&actor, "armada", "acme", Action::TemporalRead)
        .unwrap();
    db.delete_protected_collection_authorized(&actor, "armada")
        .unwrap();
    db.create_protected_collection_authorized(
        &actor,
        db.catalog_revision_authorized(&actor).unwrap(),
        serde_json::from_value(json!({"name":"armada","vector_dim":2})).unwrap(),
    )
    .unwrap();
    assert!(latest_with(TemporalAccess::Authorized(&old)).is_err());
    let fresh = db
        .bind_access(&actor, "armada", "acme", Action::TemporalRead)
        .unwrap();
    assert!(latest_with(TemporalAccess::Authorized(&fresh)).is_err());
}
