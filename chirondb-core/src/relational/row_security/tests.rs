use super::*;
use crate::security::{
    Classification, IdentityAuthority, PrincipalRecord, ScopeGrant, SubjectAttributes,
};

#[test]
fn native_policy_revocation_cancels_buffered_results_and_receipts_through_reopen() {
    let (_old, _authority, identity, _state) = fixture();
    let root = tempfile::tempdir().unwrap();
    let mut principal = identity.principal().clone();
    principal.installation_actions.extend([
        Action::PolicyManage,
        Action::LabelsManage,
        Action::GrantsManage,
    ]);
    principal.delegation = principal.grants.clone();
    principal.delegation[0].actions.extend([
        Action::Search,
        Action::LabelsManage,
        Action::GrantsManage,
    ]);
    crate::storage_layout::initialize_empty(root.path()).unwrap();
    let key = IdentityAuthority::bootstrap(root.path(), principal).unwrap();
    let db = crate::Db::open(root.path()).unwrap();
    let actor = db
        .identity_authority()
        .unwrap()
        .authenticate(&key.secret)
        .unwrap();
    let request = |sql: &str, key: Option<&str>| SqlExecutionRequest {
        statements: vec![crate::SqlStatementRequest {
            sql: sql.into(),
            parameters: vec![],
        }],
        idempotency_key: key.map(str::to_owned),
        retry_id: None,
    };
    let inspect = |db: &crate::Db, actor: &AuthenticatedIdentity| {
        let output = db
            .relational_security_authorized(actor, "docs", 0, 8)
            .unwrap();
        let SqlResult::Rows { rows, .. } = &output.results[0] else {
            panic!()
        };
        let RelationalValue::Json(value) = &rows[0][0] else {
            panic!()
        };
        value.clone()
    };
    let mut creation = request(
        "CREATE TABLE docs(id BIGINT PRIMARY KEY, secret TEXT)",
        None,
    );
    creation.statements.push(crate::SqlStatementRequest {
        sql: "INSERT INTO docs VALUES(1,'before') RETURNING secret".into(),
        parameters: vec![],
    });
    let created = db
        .execute_sql_authorized_owned(&actor, creation, "test")
        .unwrap();
    let insert = request(
        "INSERT INTO docs VALUES(2,'before') RETURNING secret",
        Some("insert-authority"),
    );
    db.execute_sql_authorized(&actor, insert.clone(), "test")
        .unwrap();
    let queued = db
        .execute_sql_authorized_owned(&actor, request("SELECT secret FROM docs", None), "test")
        .unwrap();
    let creation_session = db.begin_sql_transaction_authorized(&actor, "test").unwrap();
    db.execute_sql_transaction_authorized(
        &actor,
        &creation_session.handle,
        request("CREATE TABLE child(id BIGINT PRIMARY KEY)", None),
        "test",
    )
    .unwrap();
    let private_row = db
        .execute_sql_transaction_authorized_owned(
            &actor,
            &creation_session.handle,
            request("INSERT INTO child VALUES(1) RETURNING id", None),
            "test",
        )
        .unwrap();
    assert!(serde_json::to_vec(&private_row).is_ok());
    db.commit_sql_transaction_authorized(&actor, &creation_session.handle, "test")
        .unwrap();
    assert!(
        serde_json::to_vec(&private_row).is_err(),
        "private new-table results expire at commit"
    );
    let session = db.begin_sql_transaction_authorized(&actor, "test").unwrap();
    db.execute_sql_transaction_authorized(
        &actor,
        &session.handle,
        request("SAVEPOINT before_data", None),
        "test",
    )
    .unwrap();
    let mut batch = request("SELECT secret FROM docs", None);
    for sql in ["ROLLBACK TO SAVEPOINT before_data", "SELECT id FROM child"] {
        batch.statements.push(crate::SqlStatementRequest {
            sql: sql.into(),
            parameters: vec![],
        });
    }
    let before_rollback = db
        .execute_sql_transaction_authorized_owned(&actor, &session.handle, batch, "test")
        .unwrap();
    let private_child = db
        .execute_sql_transaction_authorized_owned(
            &actor,
            &session.handle,
            request("SELECT id FROM child", None),
            "test",
        )
        .unwrap();
    let replay = db
        .execute_sql_authorized_owned(&actor, insert.clone(), "test")
        .unwrap();
    let metadata = inspect(&db, &actor);
    assert!(
        !metadata.to_string().contains("before"),
        "control plane never includes SQL values"
    );
    let mut policy: chirondb_types::RelationalRowPolicy =
        serde_json::from_value(metadata["policy"].clone()).unwrap();
    let expected = policy.revision;
    policy.revision += 1;
    let mut record: ResourceRecord =
        serde_json::from_value(metadata["rows"][0]["authority"].clone()).unwrap();
    record
        .properties
        .get_mut("/secret")
        .unwrap()
        .actions
        .remove(&PropertyAction::Read);
    record.revision = policy.revision;
    let delta = chirondb_types::relational::RelationalSecurityDelta {
        table: "docs".into(),
        incarnation: serde_json::from_value(metadata["incarnation"].clone()).unwrap(),
        expected_revision: expected,
        policy,
        records: vec![record],
    };
    db.change_relational_security_authorized(&actor, delta.clone())
        .unwrap()
        .consume(|_| Ok(()))
        .unwrap();
    assert!(
        serde_json::to_vec(&created).is_err(),
        "new table in CREATE+INSERT batch retains its epoch"
    );
    assert!(serde_json::to_vec(&queued).is_err());
    assert!(
        serde_json::to_vec(&before_rollback).is_err(),
        "all result sets retain their authority after savepoint rollback"
    );
    db.rollback_sql_transaction_authorized(&actor, &session.handle, "test")
        .unwrap();
    assert!(
        serde_json::to_vec(&private_child).is_err(),
        "private results expire at rollback"
    );
    assert!(replay.consume(|_| Ok(())).is_err());
    assert!(
        db.change_relational_security_authorized(&actor, delta)
            .is_err(),
        "stale revision cannot apply twice"
    );
    assert!(
        db.execute_sql_authorized(&actor, insert.clone(), "test")
            .is_err()
    );
    assert!(
        db.execute_sql_authorized(&actor, request("SELECT secret FROM docs", None), "test")
            .is_err()
    );
    db.execute_sql_authorized(
        &actor,
        request("SELECT id FROM docs WHERE secret='before'", None),
        "test",
    )
    .unwrap();
    db.execute_sql_authorized(
        &actor,
        request("UPDATE docs SET secret='after' WHERE id=1", None),
        "test",
    )
    .unwrap();
    drop(actor);
    drop(db);
    let db = crate::Db::open(root.path()).unwrap();
    let actor = db
        .identity_authority()
        .unwrap()
        .authenticate(&key.secret)
        .unwrap();
    assert!(db.execute_sql_authorized(&actor, insert, "test").is_err());
    assert!(
        db.execute_sql_authorized(&actor, request("SELECT secret FROM docs", None), "test")
            .is_err()
    );
    let queued = db
        .execute_sql_authorized_owned(&actor, request("SELECT id FROM docs", None), "test")
        .unwrap();
    let delete = request("DELETE FROM docs WHERE id=1", Some("delete-authority"));
    db.execute_sql_authorized(&actor, delete.clone(), "test")
        .unwrap();
    assert!(serde_json::to_vec(&queued).is_err());
    let result = db.execute_sql_authorized(&actor, delete, "test").unwrap();
    assert!(matches!(
        result.results[0],
        SqlResult::Mutation { affected_rows: 1 }
    ));
}

fn fixture() -> (
    tempfile::TempDir,
    Arc<IdentityAuthority>,
    AuthenticatedIdentity,
    RelationalState,
) {
    let root = tempfile::tempdir().unwrap();
    let key = IdentityAuthority::bootstrap(
        root.path(),
        PrincipalRecord {
            id: "alice".into(),
            tenant: "acme".into(),
            enabled: true,
            attributes: SubjectAttributes {
                department: "Security".into(),
                clearance: Classification::Restricted,
            },
            grants: vec![ScopeGrant {
                tenants: BTreeSet::from(["acme".into()]),
                collections: BTreeSet::from(["docs".into(), "child".into()]),
                actions: BTreeSet::from([
                    Action::Read,
                    Action::Create,
                    Action::Update,
                    Action::Delete,
                ]),
            }],
            installation_actions: BTreeSet::from([Action::IdentityManage, Action::Schema]),
            delegation: vec![],
        },
    )
    .unwrap();
    let authority = IdentityAuthority::open(root.path()).unwrap().unwrap();
    let identity = authority.authenticate(&key.secret).unwrap();
    std::fs::create_dir(root.path().join("segments")).unwrap();
    let state = RelationalState::empty(root.path().join("segments")).unwrap();
    (root, authority, identity, state)
}
fn run(
    state: &mut RelationalState,
    identity: &AuthenticatedIdentity,
    sql: &str,
) -> Result<Vec<SqlResult>> {
    let request = SqlExecutionRequest {
        statements: vec![crate::SqlStatementRequest {
            sql: sql.into(),
            parameters: vec![],
        }],
        idempotency_key: None,
        retry_id: None,
    };
    let prepared = prepare_execution(
        state.clone(),
        request,
        false,
        true,
        Some("acme"),
        Some(identity),
        false,
    )?;
    if !prepared.mutations.is_empty() {
        apply_batch(
            state,
            &RelationalBatch {
                sequence: state.sequence + 1,
                mutations: prepared.mutations,
            },
        )?;
    }
    Ok(prepared.results)
}
fn restrict(state: &mut RelationalState, actions: &[PropertyAction]) {
    let table = Arc::make_mut(state.tables.get_mut("docs").unwrap().unwrap());
    let mut versions = table.rows.get(&1).unwrap().unwrap().into_owned().unwrap();
    let mut record = (**versions.last().unwrap().security.as_ref().unwrap()).clone();
    record.properties.get_mut("/secret").unwrap().actions = actions.iter().copied().collect();
    versions.last_mut().unwrap().security = Some(Metadata::adopt(record).unwrap());
    table.rows.insert(1, versions).unwrap();
}
fn denied(state: &mut RelationalState, identity: &AuthenticatedIdentity, sql: &str) {
    let before = state.sequence;
    let result = run(state, identity, sql);
    assert!(
        matches!(result, Err(GaussError::Security(SecurityError::Forbidden))),
        "{sql}: {result:?}"
    );
    assert_eq!(state.sequence, before, "denial cannot publish a mutation");
}

#[test]
fn native_constraint_probes_require_query_authority_even_for_hidden_keys() {
    let (_root, _authority, identity, mut state) = fixture();
    run(
        &mut state,
        &identity,
        "CREATE TABLE docs(id BIGINT PRIMARY KEY, secret TEXT)",
    )
    .unwrap();
    run(&mut state, &identity, "INSERT INTO docs VALUES(1,'hidden')").unwrap();
    let edit = |state: &mut RelationalState, allow: bool| {
        let table = Arc::make_mut(state.tables.get_mut("docs").unwrap().unwrap());
        let mut versions = table.rows.get(&1).unwrap().unwrap().into_owned().unwrap();
        let mut record = (**versions.last().unwrap().security.as_ref().unwrap()).clone();
        record.labels.owner = "other-owner".into();
        record.grants = if allow {
            vec![crate::security::ObjectGrant {
                subject: Subject::Principal("alice".into()),
                effect: crate::security::Effect::Permit,
                actions: BTreeSet::from([Action::Search]),
                inherit: false,
            }]
        } else {
            vec![]
        };
        versions.last_mut().unwrap().security = Some(Metadata::adopt(record).unwrap());
        table.rows.insert(1, versions).unwrap();
    };
    edit(&mut state, false);
    for id in [1, 2] {
        denied(
            &mut state,
            &identity,
            &format!("INSERT INTO docs VALUES({id},'new')"),
        );
        denied(
            &mut state,
            &identity,
            &format!("INSERT INTO docs VALUES({id},'new') ON CONFLICT DO NOTHING"),
        );
    }
    edit(&mut state, true);
    run(&mut state, &identity, "INSERT INTO docs VALUES(2,'own')").unwrap();
    let result = run(&mut state, &identity, "SELECT id FROM docs").unwrap();
    let SqlResult::Rows { rows, .. } = &result[0] else {
        panic!()
    };
    assert_eq!(rows, &vec![vec![RelationalValue::Integer(2)]]);
    assert!(
        run(
            &mut state,
            &identity,
            "INSERT INTO docs VALUES(1,'collision')"
        )
        .is_err()
    );
    // Search exposes only explicitly queryable key membership, never a row
    // representation and never ON CONFLICT access to hidden contents.
    assert!(
        run(
            &mut state,
            &identity,
            "INSERT INTO docs VALUES(1,'collision') ON CONFLICT DO NOTHING"
        )
        .is_err()
    );
    edit(&mut state, false);
    denied(&mut state, &identity, "INSERT INTO docs VALUES(3,'new')");
}

#[test]
fn native_check_constraints_require_query_authority_before_value_validation() {
    let (_root, _authority, identity, mut state) = fixture();
    run(
        &mut state,
        &identity,
        "CREATE TABLE docs(id BIGINT PRIMARY KEY, secret TEXT, guess TEXT, CHECK(guess=secret))",
    )
    .unwrap();
    run(
        &mut state,
        &identity,
        "INSERT INTO docs VALUES(1,'hidden','hidden')",
    )
    .unwrap();
    restrict(&mut state, &[PropertyAction::Read]);
    for guess in ["hidden", "different"] {
        denied(
            &mut state,
            &identity,
            &format!("UPDATE docs SET guess='{guess}' WHERE id=1"),
        );
        denied(
            &mut state,
            &identity,
            &format!(
                "INSERT INTO docs VALUES(1,'input','input') ON CONFLICT(id) DO UPDATE SET guess='{guess}'"
            ),
        );
    }
    restrict(&mut state, &[PropertyAction::Query]);
    denied(&mut state, &identity, "SELECT secret FROM docs");
    run(
        &mut state,
        &identity,
        "UPDATE docs SET guess='hidden' WHERE id=1",
    )
    .unwrap();
    let before = state.sequence;
    assert!(matches!(
        run(&mut state, &identity, "UPDATE docs SET guess='different' WHERE id=1"),
        Err(GaussError::InvalidRequest(message)) if message.contains("check constraint")
    ));
    assert_eq!(state.sequence, before);
}

#[test]
fn native_cascade_check_constraints_require_query_authority() {
    let (_root, _authority, identity, mut state) = fixture();
    for statement in [
        "CREATE TABLE docs(id BIGINT PRIMARY KEY, secret TEXT)",
        "INSERT INTO docs VALUES(1,'parent')",
        "CREATE TABLE child(id BIGINT PRIMARY KEY, parent BIGINT REFERENCES docs(id) ON DELETE SET NULL, secret BIGINT, CHECK(parent IS NOT NULL OR secret=7))",
        "INSERT INTO child VALUES(1,1,7)",
    ] {
        run(&mut state, &identity, statement).unwrap();
    }
    let edit = |state: &mut RelationalState, query: bool| {
        let table = Arc::make_mut(state.tables.get_mut("child").unwrap().unwrap());
        let mut versions = table.rows.get(&1).unwrap().unwrap().into_owned().unwrap();
        let mut record = (**versions.last().unwrap().security.as_ref().unwrap()).clone();
        record.properties.get_mut("/secret").unwrap().actions = if query {
            BTreeSet::from([PropertyAction::Query])
        } else {
            BTreeSet::new()
        };
        versions.last_mut().unwrap().security = Some(Metadata::adopt(record).unwrap());
        table.rows.insert(1, versions).unwrap();
    };
    for secret in [7, 9] {
        let mut candidate = state.clone();
        run(
            &mut candidate,
            &identity,
            &format!("UPDATE child SET secret={secret} WHERE id=1"),
        )
        .unwrap();
        edit(&mut candidate, false);
        denied(&mut candidate, &identity, "DELETE FROM docs WHERE id=1");
        edit(&mut candidate, true);
        let before = candidate.sequence;
        let result = run(&mut candidate, &identity, "DELETE FROM docs WHERE id=1");
        if secret == 7 {
            result.unwrap();
            let rows = run(
                &mut candidate,
                &identity,
                "SELECT parent FROM child WHERE id=1",
            )
            .unwrap();
            assert!(
                matches!(&rows[0], SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Null]])
            );
        } else {
            assert!(
                matches!(result, Err(GaussError::InvalidRequest(message)) if message.contains("check constraint"))
            );
            assert_eq!(
                candidate.sequence, before,
                "failed cascade must not delete the parent"
            );
            let rows = run(&mut candidate, &identity, "SELECT id FROM docs").unwrap();
            assert!(
                matches!(&rows[0], SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Integer(1)]])
            );
        }
        denied(&mut candidate, &identity, "SELECT secret FROM child");
    }
}

#[test]
fn native_column_rename_preserves_rules_and_drop_readd_does_not_revive_them() {
    let (_root, _authority, identity, mut state) = fixture();
    run(
        &mut state,
        &identity,
        "CREATE TABLE docs(id BIGINT PRIMARY KEY, secret TEXT)",
    )
    .unwrap();
    run(&mut state, &identity, "INSERT INTO docs VALUES(1,'hidden')").unwrap();
    restrict(&mut state, &[PropertyAction::Query, PropertyAction::Write]);
    run(
        &mut state,
        &identity,
        "ALTER TABLE docs RENAME COLUMN secret TO renamed",
    )
    .unwrap();
    denied(&mut state, &identity, "SELECT renamed FROM docs");
    run(
        &mut state,
        &identity,
        "SELECT id FROM docs WHERE renamed='hidden'",
    )
    .unwrap();
    run(
        &mut state,
        &identity,
        "ALTER TABLE docs DROP COLUMN renamed",
    )
    .unwrap();
    run(
        &mut state,
        &identity,
        "ALTER TABLE docs ADD COLUMN renamed TEXT DEFAULT 'new'",
    )
    .unwrap();
    denied(&mut state, &identity, "SELECT renamed FROM docs");
    denied(
        &mut state,
        &identity,
        "SELECT id FROM docs WHERE renamed='new'",
    );
    denied(
        &mut state,
        &identity,
        "UPDATE docs SET renamed='changed' WHERE id=1",
    );
    denied(&mut state, &identity, "INSERT INTO docs VALUES(2,'new')");
    let row = state
        .tables
        .get("docs")
        .unwrap()
        .rows
        .visible(1, state.sequence)
        .unwrap()
        .unwrap();
    assert!(!row.security.unwrap().properties.contains_key("/renamed"));
}

#[test]
fn native_foreign_key_probes_and_cascades_cannot_bypass_hidden_row_authority() {
    let (_root, _authority, identity, mut state) = fixture();
    run(
        &mut state,
        &identity,
        "CREATE TABLE docs(id BIGINT PRIMARY KEY)",
    )
    .unwrap();
    run(&mut state, &identity, "CREATE TABLE child(id BIGINT PRIMARY KEY, parent BIGINT REFERENCES docs(id) ON DELETE CASCADE)").unwrap();
    run(&mut state, &identity, "INSERT INTO docs VALUES(1)").unwrap();
    run(&mut state, &identity, "INSERT INTO child VALUES(10,1)").unwrap();
    let hide = |state: &mut RelationalState, name: &str, owner: &str, search: bool| {
        let table = Arc::make_mut(state.tables.get_mut(name).unwrap().unwrap());
        let mut versions = table.rows.get(&1).unwrap().unwrap().into_owned().unwrap();
        let mut record = (**versions.last().unwrap().security.as_ref().unwrap()).clone();
        record.labels.owner = owner.into();
        record.grants = if search {
            vec![crate::security::ObjectGrant {
                subject: Subject::Principal("alice".into()),
                effect: crate::security::Effect::Permit,
                actions: BTreeSet::from([Action::Search]),
                inherit: false,
            }]
        } else {
            vec![]
        };
        versions.last_mut().unwrap().security = Some(Metadata::adopt(record).unwrap());
        table.rows.insert(1, versions).unwrap();
    };
    hide(&mut state, "docs", "other-owner", false);
    denied(&mut state, &identity, "INSERT INTO child VALUES(11,1)");
    denied(&mut state, &identity, "INSERT INTO child VALUES(11,999)");
    hide(&mut state, "docs", "other-owner", true);
    run(&mut state, &identity, "INSERT INTO child VALUES(11,1)").unwrap();
    hide(&mut state, "docs", "alice", false);
    hide(&mut state, "child", "other-owner", true);
    denied(&mut state, &identity, "DELETE FROM docs WHERE id=1");
    let rows = run(&mut state, &identity, "SELECT id FROM docs").unwrap();
    assert!(matches!(&rows[0], SqlResult::Rows { rows, .. } if rows.len() == 1));
    assert_eq!(
        state
            .tables
            .get("child")
            .unwrap()
            .rows
            .visible_rows(state.sequence)
            .count(),
        2
    );
}

#[test]
fn native_authority_preflight_refuses_before_unbudgeted_identity_or_cte_copies() {
    let (_root, _authority, identity, mut state) = fixture();
    run(
        &mut state,
        &identity,
        "CREATE TABLE docs(id BIGINT PRIMARY KEY)",
    )
    .unwrap();
    let before = state.sequence;
    memory::with_storage_pool(1024, |_| {
        assert!(matches!(
            run(&mut state, &identity, "INSERT INTO docs VALUES(1)"),
            Err(GaussError::ResourceExhausted(_))
        ));
    });
    assert_eq!(state.sequence, before);
    state.request_identity = Some(Arc::new(identity));
    let ParsedRelationalStatement::Sql(statement) = parse_relational_statement(
        "WITH a AS (SELECT id FROM docs), b AS (SELECT * FROM a) SELECT * FROM b",
    )
    .unwrap() else {
        panic!()
    };
    memory::with_storage_pool(1024, |_| {
        assert!(matches!(
            preflight(&state, &statement, state.sequence),
            Err(GaussError::ResourceExhausted(_))
        ));
    });
}

#[test]
fn native_legacy_rows_require_explicit_registration_and_keep_it_on_recovery() {
    let (_unused, _authority, identity, _state) = fixture();
    let root = tempfile::tempdir().unwrap();
    let mut principal = identity.principal().clone();
    principal.installation_actions.extend([
        Action::PolicyManage,
        Action::LabelsManage,
        Action::GrantsManage,
    ]);
    principal.delegation = principal.grants.clone();
    principal.delegation[0]
        .actions
        .extend([Action::LabelsManage, Action::GrantsManage]);
    let key = IdentityAuthority::bootstrap(root.path(), principal).unwrap();
    let authority = IdentityAuthority::open(root.path()).unwrap().unwrap();
    let actor = authority.authenticate(&key.secret).unwrap();
    let journal = TransactionJournal::open(root.path()).unwrap();
    let engine = RelationalEngine::open(root.path(), Arc::clone(&journal)).unwrap();
    let audit = AuditContext {
        principal_id: "alice".into(),
        tenant_id: Some("acme".into()),
        transport: "test".into(),
        request_id: None,
    };
    for sql in [
        "CREATE TABLE docs(id BIGINT PRIMARY KEY, secret TEXT)",
        "INSERT INTO docs VALUES(41,'historical')",
    ] {
        engine
            .execute_authorized_with_audit(
                SqlExecutionRequest {
                    statements: vec![crate::SqlStatementRequest {
                        sql: sql.into(),
                        parameters: vec![],
                    }],
                    idempotency_key: None,
                    retry_id: None,
                },
                &audit,
            )
            .unwrap();
    }
    let before = engine.state.read().clone();
    denied(&mut before.clone(), &actor, "SELECT secret FROM docs");
    let mut definition = before
        .tables
        .get("docs")
        .unwrap()
        .definition
        .as_ref()
        .clone();
    assert!(definition.row_policy.is_none());
    let incarnation = uuid::Uuid::new_v4();
    definition.security_incarnation = Some(incarnation);
    definition.row_policy = Some(default_policy(&definition, &actor));
    let record = (*create(&definition, 1, Some(&actor)).unwrap().unwrap()).clone();
    let delta = chirondb_types::relational::RelationalSecurityDelta {
        table: "docs".into(),
        incarnation,
        expected_revision: 0,
        policy: definition.row_policy.unwrap(),
        records: vec![record],
    };
    let registered = engine
        .change_row_security(&actor, &authority, delta.clone(), &audit)
        .unwrap();
    let transaction = registered.committed.as_ref().unwrap();
    assert_eq!(
        transaction.prepare.audit.operation,
        "relational_authority.change"
    );
    assert_eq!(transaction.prepare.audit.details["row_bindings"], 1);
    assert!(
        !serde_json::to_string(&transaction.prepare.audit)
            .unwrap()
            .contains("historical")
    );
    assert!(
        engine
            .change_row_security(&actor, &authority, delta, &audit)
            .is_err()
    );
    drop(registered);
    drop(engine);
    drop(journal);
    let journal = TransactionJournal::open(root.path()).unwrap();
    let reopened = RelationalEngine::open(root.path(), journal).unwrap();
    let mut state = reopened.state.read().clone();
    let result = run(&mut state, &actor, "SELECT secret FROM docs WHERE id=41").unwrap();
    assert!(
        matches!(&result[0], SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Text("historical".into())]])
    );
}

#[cfg(feature = "fault-injection")]
#[test]
fn native_policy_failure_never_reopens_old_results_and_recovery_follows_journal() {
    for (failpoint, committed) in [
        ("error:transaction.before_commit", false),
        ("error:transaction.before_commit_fsync", true),
    ] {
        let (_unused, _authority, identity, _state) = fixture();
        let root = tempfile::tempdir().unwrap();
        let mut principal = identity.principal().clone();
        principal.installation_actions.extend([
            Action::PolicyManage,
            Action::LabelsManage,
            Action::GrantsManage,
        ]);
        principal.delegation = principal.grants.clone();
        principal.delegation[0]
            .actions
            .extend([Action::LabelsManage, Action::GrantsManage]);
        crate::storage_layout::initialize_empty(root.path()).unwrap();
        let key = IdentityAuthority::bootstrap(root.path(), principal).unwrap();
        let db = crate::Db::open(root.path()).unwrap();
        let actor = db
            .identity_authority()
            .unwrap()
            .authenticate(&key.secret)
            .unwrap();
        let request = |sql: &str| SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql: sql.into(),
                parameters: vec![],
            }],
            idempotency_key: None,
            retry_id: None,
        };
        for sql in [
            "CREATE TABLE docs(id BIGINT PRIMARY KEY, secret TEXT)",
            "INSERT INTO docs VALUES(1,'before')",
        ] {
            db.execute_sql_authorized(&actor, request(sql), "test")
                .unwrap();
        }
        let queued = db
            .execute_sql_authorized_owned(&actor, request("SELECT secret FROM docs"), "test")
            .unwrap();
        let view = db
            .relational_security_authorized(&actor, "docs", 0, 8)
            .unwrap();
        let SqlResult::Rows { rows, .. } = &view.results[0] else {
            panic!()
        };
        let RelationalValue::Json(value) = &rows[0][0] else {
            panic!()
        };
        let mut policy: chirondb_types::RelationalRowPolicy =
            serde_json::from_value(value["policy"].clone()).unwrap();
        let expected_revision = policy.revision;
        policy.revision += 1;
        let mut record: ResourceRecord =
            serde_json::from_value(value["rows"][0]["authority"].clone()).unwrap();
        record.revision = policy.revision;
        record
            .properties
            .get_mut("/secret")
            .unwrap()
            .actions
            .remove(&PropertyAction::Read);
        let delta = chirondb_types::relational::RelationalSecurityDelta {
            table: "docs".into(),
            incarnation: record.key.collection,
            expected_revision,
            policy,
            records: vec![record],
        };
        {
            let _fault = crate::failpoint::test_env(
                failpoint,
                &root.path().join("marker"),
                &root.path().join("release"),
            );
            let error = db
                .change_relational_security_authorized(&actor, delta)
                .unwrap_err();
            assert_eq!(
                matches!(error, GaussError::CommitOutcomeUnknown { .. }),
                committed,
                "{error}"
            );
        }
        assert!(serde_json::to_vec(&queued).is_err());
        assert!(serde_json::to_vec(&view).is_err());
        assert!(
            db.execute_sql_authorized(&actor, request("SELECT secret FROM docs"), "test")
                .is_err()
        );
        drop(actor);
        drop(db);
        let db = crate::Db::open(root.path()).unwrap();
        let actor = db
            .identity_authority()
            .unwrap()
            .authenticate(&key.secret)
            .unwrap();
        let recovered =
            db.execute_sql_authorized(&actor, request("SELECT secret FROM docs"), "test");
        assert_eq!(
            recovered.is_err(),
            committed,
            "recovery must follow durable decision"
        );
        assert!(
            serde_json::to_vec(&queued).is_err(),
            "reopening cannot revive an old handle"
        );
    }
}

#[test]
fn native_column_read_query_write_are_separate_before_index_and_cte_evaluation() {
    let (_root, _authority, identity, mut state) = fixture();
    run(
        &mut state,
        &identity,
        "CREATE TABLE docs (id BIGINT PRIMARY KEY, secret TEXT)",
    )
    .unwrap();
    run(
        &mut state,
        &identity,
        "INSERT INTO docs VALUES (1,'hidden')",
    )
    .unwrap();
    run(
        &mut state,
        &identity,
        "CREATE INDEX secret_idx ON docs(secret)",
    )
    .unwrap();
    restrict(&mut state, &[PropertyAction::Read]);
    assert!(run(&mut state, &identity, "SELECT secret FROM docs").is_ok());
    for query in [
        "SELECT id FROM docs WHERE secret='hidden'",
        "SELECT id FROM docs WHERE secret='not-present'",
        "SELECT secret FROM docs ORDER BY secret LIMIT 1",
        "SELECT secret AS s FROM docs ORDER BY s LIMIT 1",
        "SELECT secret AS s FROM docs ORDER BY 1 LIMIT 1",
        "SELECT DISTINCT secret FROM docs",
        "SELECT COUNT(secret) FROM docs",
        "SELECT secret FROM docs GROUP BY secret",
        "WITH a AS (SELECT id,secret AS s FROM docs) SELECT id FROM a WHERE s='hidden'",
        "WITH a(k,s) AS (SELECT id,secret FROM docs), b AS (SELECT k,s FROM a) SELECT k FROM b WHERE s='not-present'",
        "SELECT p.id FROM docs p JOIN docs q ON p.secret=q.secret",
        "UPDATE docs SET id=2 WHERE secret='hidden'",
        "DELETE FROM docs WHERE secret='not-present'",
        "UPDATE docs SET secret='hidden' WHERE id=1",
        "UPDATE docs SET secret='replacement' WHERE id=1",
    ] {
        denied(&mut state, &identity, query);
    }
    restrict(&mut state, &[PropertyAction::Query]);
    let result = run(
        &mut state,
        &identity,
        "SELECT id FROM docs WHERE secret='hidden'",
    )
    .unwrap();
    assert!(matches!(&result[0], SqlResult::Rows { rows, .. } if rows.len() == 1));
    denied(&mut state, &identity, "SELECT secret FROM docs");
    denied(
        &mut state,
        &identity,
        "UPDATE docs SET secret='hidden' WHERE id=1",
    );
    restrict(&mut state, &[PropertyAction::Write]);
    run(
        &mut state,
        &identity,
        "UPDATE docs SET secret='changed' WHERE id=1",
    )
    .unwrap();
    denied(
        &mut state,
        &identity,
        "UPDATE docs SET secret='again' WHERE id=1 RETURNING secret",
    );
    denied(
        &mut state,
        &identity,
        "SELECT id FROM docs WHERE secret='changed'",
    );
    restrict(
        &mut state,
        &[
            PropertyAction::Read,
            PropertyAction::Query,
            PropertyAction::Write,
        ],
    );
    let rows = run(&mut state, &identity, "SELECT secret FROM docs WHERE id=1").unwrap();
    assert!(
        matches!(&rows[0], SqlResult::Rows { rows, .. } if rows[0][0] == RelationalValue::Text("changed".into()))
    );
}

#[test]
fn native_mvcc_rewrite_and_replay_preserve_authority() {
    let (_root, _authority, identity, mut state) = fixture();
    run(
        &mut state,
        &identity,
        "CREATE TABLE docs (id BIGINT PRIMARY KEY, secret TEXT)",
    )
    .unwrap();
    run(&mut state, &identity, "INSERT INTO docs VALUES (1,'a')").unwrap();
    let original = stored(state.tables.get("docs").unwrap(), 1, state.sequence)
        .unwrap()
        .unwrap();
    run(
        &mut state,
        &identity,
        "UPDATE docs SET secret='b' WHERE id=1",
    )
    .unwrap();
    run(
        &mut state,
        &identity,
        "ALTER TABLE docs ALTER COLUMN secret TYPE TEXT",
    )
    .unwrap();
    let table = state.tables.get("docs").unwrap();
    assert_eq!(stored(table, 1, state.sequence).unwrap().unwrap(), original);
    let version = table.rows.visible(1, state.sequence).unwrap().unwrap();
    let serialized = serde_json::to_vec(&version).unwrap();
    let restored: RowVersion = serde_json::from_slice(&serialized).unwrap();
    assert_eq!(restored.security.as_deref(), Some(&original));
    assert_eq!(restored.values[1], RelationalValue::Text("b".into()));
    // An older row without authority remains invisible, even to the table owner.
    let table = Arc::make_mut(state.tables.get_mut("docs").unwrap().unwrap());
    let mut versions = table.rows.get(&1).unwrap().unwrap().into_owned().unwrap();
    versions.last_mut().unwrap().security = None;
    table.rows.insert(1, versions).unwrap();
    let result = run(&mut state, &identity, "SELECT secret FROM docs").unwrap();
    assert!(matches!(&result[0], SqlResult::Rows { rows, .. } if rows.is_empty()));
}

#[test]
fn native_queued_output_and_old_snapshot_fail_after_policy_epoch_closes() {
    let (_root, _authority, identity, mut state) = fixture();
    run(
        &mut state,
        &identity,
        "CREATE TABLE docs (id BIGINT PRIMARY KEY, secret TEXT)",
    )
    .unwrap();
    run(
        &mut state,
        &identity,
        "INSERT INTO docs VALUES (1,'secret')",
    )
    .unwrap();
    let request = SqlExecutionRequest {
        statements: vec![crate::SqlStatementRequest {
            sql: "SELECT secret FROM docs".into(),
            parameters: vec![],
        }],
        idempotency_key: None,
        retry_id: None,
    };
    let prepared = prepare_execution(
        state.clone(),
        request.clone(),
        false,
        true,
        Some("acme"),
        Some(&identity),
        false,
    )
    .unwrap();
    let memory = output::reserve_results(&prepared.results).unwrap();
    let response = SqlResponse::new(
        SqlExecutionResponse {
            transaction_id: None,
            snapshot: state.sequence,
            committed: true,
            outcome: SqlOutcome::Committed,
            commit_sequence: None,
            retryable: false,
            results: prepared.results,
        },
        memory,
    )
    .with_publication(prepared.publication);
    assert!(serde_json::to_vec(&response).is_ok());
    let old_snapshot = state.clone();
    state
        .tables
        .get("docs")
        .unwrap()
        .policy_epoch
        .as_ref()
        .unwrap()
        .close_and_drain()
        .unwrap();
    assert!(serde_json::to_vec(&response).is_err());
    assert!(
        prepare_execution(
            old_snapshot,
            request,
            false,
            true,
            Some("acme"),
            Some(&identity),
            false
        )
        .is_err()
    );
    // Failed revocation can restore service with a fresh epoch, never reopen
    // an epoch retained by an already-computed result.
    Arc::make_mut(state.tables.get_mut("docs").unwrap().unwrap()).policy_epoch =
        Some(crate::security::Epoch::new(1));
    run(&mut state, &identity, "SELECT secret FROM docs").unwrap();
    assert!(response.consume(|_| Ok(())).is_err());
}
