use chirondb::chironql_exec::{ExecContext, Session, execute};
use chirondb::rbac::Role;
use chirondb::tenant::TenantScope;
use chirondb::{CollectionConfig, Db, DistanceMetric, Point, RelationalValue};
use chirondb_types::ConfigureEdgeTypeRequest;
use chirondb_types::chironql::{ChironQlResponse, ExecutionDomain};
use serde_json::json;
use tempfile::TempDir;

fn run(db: &Db, role: Role, query: &str, parameters: Vec<RelationalValue>) -> ChironQlResponse {
    let mut session = Session::default();
    let mut context = ExecContext {
        db,
        session: &mut session,
        role,
        allowed_collections: None,
        want_trace: true,
        confirm: true,
        parameters,
        idempotency_key: None,
        retry_id: None,
        tenant: TenantScope::system(),
    };
    execute(&mut context, query).expect(query)
}

fn fixture() -> (TempDir, Db) {
    let directory = TempDir::new().expect("tempdir");
    let db = Db::open(directory.path()).expect("open");
    db.create_collection(CollectionConfig {
        name: "chunks".into(),
        vector_dim: 2,
        metric: DistanceMetric::L2,
        shards: 1,
        replicas: 1,
        quantization: None,
        payload_schema: Default::default(),
        named_vector_dims: Default::default(),
        hnsw_m: None,
        hnsw_ef_construction: None,
        hnsw_ef_search: None,
        recall_sla: None,
        index_kind: None,
        streamer_max_bytes: 0,
    })
    .expect("collection");
    db.set_graph_lifecycle_scoped("chunks", true, true, &TenantScope::system())
        .expect("graph");
    db.configure_edge_type_scoped(
        "chunks",
        ConfigureEdgeTypeRequest {
            name: "CITES".into(),
            weight_property: None,
        },
        true,
        &TenantScope::system(),
    )
    .expect("edge type");
    db.upsert(
        "chunks",
        vec![
            Point {
                id: "root".into(),
                vector: vec![1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"kind": "root"}),
            },
            Point {
                id: "child".into(),
                vector: vec![0.0, 1.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"kind": "child"}),
            },
        ],
    )
    .expect("points");
    run(
        &db,
        Role::ReadWrite,
        "RELATE chunks root -> CITES -> child;",
        Vec::new(),
    );
    run(
        &db,
        Role::Admin,
        "SQL CREATE TABLE documents (id TEXT PRIMARY KEY, title TEXT NOT NULL, chunk_ref RECORD_REF('chunks') NOT NULL, source_ref RECORD_REF('chunks') NOT NULL);",
        Vec::new(),
    );
    run(
        &db,
        Role::ReadWrite,
        "SQL INSERT INTO documents (id, title, chunk_ref, source_ref) VALUES ('doc-1', 'Root document', RECORD_REF('chunks', 'root'), RECORD_REF('chunks', 'child'));",
        Vec::new(),
    );
    (directory, db)
}

#[test]
fn sql_wrapper_uses_native_executor_and_typed_record_refs() {
    let (_directory, db) = fixture();
    let response = run(
        &db,
        Role::ReadOnly,
        "SQL SELECT id, RECORD_REF('chunks', id) AS entity FROM documents LIMIT 10;",
        Vec::new(),
    );
    assert_eq!(response.domains, vec![ExecutionDomain::Relational]);
    assert_eq!(response.rows[0]["id"], json!("doc-1"));
    assert_eq!(
        response.rows[0]["entity"],
        json!({"namespace": "chunks", "id": "doc-1"})
    );
    assert!(response.snapshot_id.is_some());
}

#[test]
fn pipeline_combines_vector_graph_and_relational_rows() {
    let (_directory, db) = fixture();
    let query = r#"PIPELINE
  VECTOR v { SEARCH chunks NEAR $1 LIMIT 1 }
  GRAPH g { TRAVERSE chunks FROM v.record_ref VIA CITES DEPTH 1 RETURN NODES LIMIT 20 }
  RELATIONAL r { SQL SELECT id, title, chunk_ref, source_ref FROM documents LIMIT 20 }
  INNER JOIN r ON r.chunk_ref = v.record_ref
  LEFT JOIN g ON g.record_ref = r.source_ref
  RETURN r.id, r.title, v.score, g.depth
  ORDER BY v.score DESC
  LIMIT 10;"#;
    let response = run(
        &db,
        Role::ReadOnly,
        query,
        vec![RelationalValue::Vector(vec![1.0, 0.0])],
    );
    assert_eq!(
        response.domains,
        vec![
            ExecutionDomain::Relational,
            ExecutionDomain::Vector,
            ExecutionDomain::Graph,
        ]
    );
    assert_eq!(response.rows.len(), 1);
    assert_eq!(response.rows[0]["id"], json!("doc-1"));
    assert_eq!(response.rows[0]["title"], json!("Root document"));
    assert!(response.rows[0]["score"].is_number());
    assert!(response.rows[0]["depth"].is_number());
}

#[test]
fn pipeline_left_join_returns_null_for_a_missing_record_reference() {
    let (_directory, db) = fixture();
    run(
        &db,
        Role::ReadWrite,
        "SQL UPDATE documents SET source_ref = RECORD_REF('chunks', 'missing') WHERE id = 'doc-1';",
        Vec::new(),
    );
    let response = run(
        &db,
        Role::ReadOnly,
        r#"PIPELINE
  VECTOR v { SEARCH chunks NEAR [1,0] LIMIT 1 }
  GRAPH g { TRAVERSE chunks FROM v.record_ref VIA CITES DEPTH 1 RETURN NODES LIMIT 20 }
  RELATIONAL r { SQL SELECT id, chunk_ref, source_ref FROM documents LIMIT 20 }
  INNER JOIN r ON r.chunk_ref = v.record_ref
  LEFT JOIN g ON g.record_ref = r.source_ref
  RETURN r.id, g.depth
  LIMIT 10;"#,
        Vec::new(),
    );
    assert_eq!(response.rows, vec![json!({"id": "doc-1", "depth": null})]);
}

#[test]
fn pipeline_rejects_mutating_relational_stage_before_execution() {
    let error = chirondb::chironql_parser::parse(
        "PIPELINE VECTOR v { SEARCH chunks NEAR [1,0] LIMIT 1 } RELATIONAL r { SQL DELETE FROM documents WHERE id = 'doc-1' } INNER JOIN r ON r.chunk_ref = v.record_ref RETURN r.id LIMIT 1;",
    )
    .expect_err("write pipeline");
    assert_eq!(error.code, "chironql.pipeline_write");
}

#[test]
fn multimodel_snapshot_detects_a_commit_before_publication() {
    let (_directory, db) = fixture();
    let snapshot = db
        .begin_multimodel_read()
        .expect("snapshot admission")
        .expect("stable frontier");
    db.upsert(
        "chunks",
        vec![Point {
            id: "later".into(),
            vector: vec![0.5, 0.5],
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({"kind": "later"}),
        }],
    )
    .expect("concurrent commit");
    assert!(!snapshot.validate().expect("validate snapshot"));
}

#[test]
fn transaction_block_commits_and_recovers_all_three_models() {
    let (directory, db) = fixture();
    let response = run(
        &db,
        Role::ReadWrite,
        r#"TRANSACTION {
  SQL INSERT INTO documents (id, title, chunk_ref, source_ref)
      VALUES ('doc-2', 'Atomic document', RECORD_REF('chunks', 'chunk-2'), RECORD_REF('chunks', 'source-2'));
  VECTOR UPSERT INTO chunks
      {id: 'chunk-2', vector: [0.8,0.2], payload: {kind: 'chunk'}},
      {id: 'source-2', vector: [0.2,0.8], payload: {kind: 'source'}};
  GRAPH CONNECT chunks 'chunk-2' -> CITES -> 'source-2' SET {kind: 'source'};
};"#,
        Vec::new(),
    );
    assert_eq!(
        response.domains,
        vec![
            ExecutionDomain::Relational,
            ExecutionDomain::Vector,
            ExecutionDomain::Graph,
        ]
    );
    assert_eq!(response.stats.affected, Some(4));
    assert_eq!(response.committed, Some(true));
    assert!(response.transaction_id.is_some());
    assert!(
        response
            .snapshot_id
            .as_deref()
            .unwrap()
            .starts_with("multi-model:")
    );

    let row = run(
        &db,
        Role::ReadOnly,
        "SQL SELECT title FROM documents WHERE id = 'doc-2';",
        Vec::new(),
    );
    assert_eq!(row.rows, vec![json!({"title": "Atomic document"})]);
    let points = run(
        &db,
        Role::ReadOnly,
        "GET chunks POINTS 'chunk-2', 'source-2';",
        Vec::new(),
    );
    assert_eq!(points.rows.len(), 2);
    let traversal = run(
        &db,
        Role::ReadOnly,
        "TRAVERSE chunks FROM 'chunk-2' VIA CITES DEPTH 1 RETURN NODES LIMIT 10;",
        Vec::new(),
    );
    assert_eq!(traversal.rows[0]["id"], json!("source-2"));

    drop(db);
    let reopened = Db::open(directory.path()).expect("reopen");
    let recovered_row = run(
        &reopened,
        Role::ReadOnly,
        "SQL SELECT title FROM documents WHERE id = 'doc-2';",
        Vec::new(),
    );
    assert_eq!(
        recovered_row.rows,
        vec![json!({"title": "Atomic document"})]
    );
    assert_eq!(
        run(
            &reopened,
            Role::ReadOnly,
            "GET chunks POINTS 'chunk-2', 'source-2';",
            Vec::new(),
        )
        .rows
        .len(),
        2
    );
    let recovered_graph = run(
        &reopened,
        Role::ReadOnly,
        "TRAVERSE chunks FROM 'chunk-2' VIA CITES DEPTH 1 RETURN NODES LIMIT 10;",
        Vec::new(),
    );
    assert_eq!(recovered_graph.rows[0]["id"], json!("source-2"));
}

#[test]
fn rejected_transaction_block_leaves_every_domain_unchanged() {
    let (_directory, db) = fixture();
    let mut session = Session::default();
    let mut context = ExecContext {
        db: &db,
        session: &mut session,
        role: Role::ReadWrite,
        allowed_collections: None,
        want_trace: true,
        confirm: true,
        parameters: Vec::new(),
        idempotency_key: None,
        retry_id: Some("rejected-multi-model".into()),
        tenant: TenantScope::system(),
    };
    let error = execute(
        &mut context,
        r#"TRANSACTION {
  SQL INSERT INTO documents (id, title, chunk_ref, source_ref)
      VALUES ('doc-rejected', 'Rejected', RECORD_REF('chunks', 'chunk-rejected'), RECORD_REF('chunks', 'source-rejected'));
  VECTOR UPSERT INTO chunks
      {id: 'chunk-rejected', vector: [1,0]},
      {id: 'source-rejected', vector: [0,1]};
  GRAPH CONNECT chunks 'chunk-rejected' -> MISSING -> 'source-rejected';
};"#,
    )
    .expect_err("missing graph type");
    assert_eq!(error.code, "graph.type_unknown");
    assert!(
        run(
            &db,
            Role::ReadOnly,
            "SQL SELECT id FROM documents WHERE id = 'doc-rejected';",
            Vec::new(),
        )
        .rows
        .is_empty()
    );
    assert!(
        run(
            &db,
            Role::ReadOnly,
            "GET chunks POINTS 'chunk-rejected', 'source-rejected';",
            Vec::new(),
        )
        .rows
        .is_empty()
    );
}

#[test]
fn keyed_transaction_replays_ids_across_races_and_reopen() {
    let (directory, db) = fixture();
    let query = r#"TRANSACTION {
      SQL INSERT INTO documents (id, title, chunk_ref, source_ref)
        VALUES ('receipt', 'once', RECORD_REF('chunks', 'root'), RECORD_REF('chunks', 'child'));
      EXPECT SQL ROWS 1;
      VECTOR UPSERT INTO chunks {id: 'root', vector: [1,0], payload: {kind: 'root'}};
      GRAPH CONNECT chunks 'root' -> CITES -> 'child' SET {kind: 'receipt'};
    };"#;
    let execute_keyed = |db: &Db, query: &str, retry: String| {
        let mut session = Session::default();
        let mut context = ExecContext {
            db,
            session: &mut session,
            role: Role::ReadWrite,
            allowed_collections: None,
            want_trace: false,
            confirm: true,
            parameters: vec![],
            idempotency_key: Some("multi-model-once".into()),
            retry_id: Some(retry),
            tenant: TenantScope::system(),
        };
        execute(&mut context, query)
    };
    let barrier = std::sync::Barrier::new(8);
    let responses = std::thread::scope(|scope| {
        let barrier = &barrier;
        let db = &db;
        (0..8)
            .map(|index| {
                scope.spawn(move || {
                    barrier.wait();
                    execute_keyed(db, query, format!("race-{index}")).unwrap()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    let first = &responses[0];
    assert_eq!(first.rows.len(), 1);
    assert!(first.rows[0]["edge_id"].is_string());
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.stats.replayed == Some(false))
            .count(),
        1
    );
    for response in &responses {
        assert_eq!(response.transaction_id, first.transaction_id);
        assert_eq!(response.rows, first.rows);
        assert_eq!(response.snapshot_id, first.snapshot_id);
        assert_eq!(response.stats.affected, Some(3));
        if response.stats.replayed == Some(true) {
            assert_eq!(response.stats.operation_lsn, None);
        }
    }
    assert!(
        execute_keyed(
            &db,
            &query.replace("'once'", "'different'"),
            "conflict".into()
        )
        .is_err()
    );
    drop(db);
    let db = Db::open(directory.path()).unwrap();
    let replay = execute_keyed(&db, query, "reopen".into()).unwrap();
    assert_eq!(replay.transaction_id, first.transaction_id);
    assert_eq!(replay.rows, first.rows);
    assert_eq!(replay.stats.replayed, Some(true));
    let count = run(
        &db,
        Role::ReadOnly,
        "SQL SELECT COUNT(*) AS n FROM documents WHERE id = 'receipt';",
        vec![],
    );
    assert_eq!(count.rows, vec![json!({"n": 1})]);
}

#[cfg(feature = "fault-injection")]
#[test]
fn keyed_multimodel_recovers_after_sigkill_without_second_allocation() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    const CHILD: &str = "CHIRONDB_MULTIMODEL_KILL_CHILD";
    let query = r#"TRANSACTION {
      SQL INSERT INTO documents (id, title, chunk_ref, source_ref)
        VALUES ('killed', 'once', RECORD_REF('chunks', 'root'), RECORD_REF('chunks', 'child'));
      VECTOR UPSERT INTO chunks {id: 'root', vector: [1,0], payload: {kind: 'committed'}};
      GRAPH CONNECT chunks 'root' -> CITES -> 'child' SET {kind: 'receipt'};
    };"#;
    let keyed = |db: &Db| {
        let mut session = Session::default();
        let mut ctx = ExecContext {
            db,
            session: &mut session,
            role: Role::ReadWrite,
            allowed_collections: None,
            want_trace: false,
            confirm: true,
            parameters: vec![],
            idempotency_key: Some("crash-multi-model".into()),
            retry_id: None,
            tenant: TenantScope::system(),
        };
        execute(&mut ctx, query)
    };
    if let Some(data) = std::env::var_os(CHILD) {
        keyed(&Db::open(data).unwrap()).unwrap();
        panic!("child must be killed at the commit/projection boundary");
    }
    for cut in [
        "transaction.after_prepare",
        "transaction.before_commit_fsync",
        "multi_model.after_collection_wal",
    ] {
        let (directory, db) = fixture();
        drop(db);
        let control = tempfile::tempdir().unwrap();
        let marker = control.path().join("paused");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "keyed_multimodel_recovers_after_sigkill_without_second_allocation",
                "--nocapture",
            ])
            .env(CHILD, directory.path())
            .env("CHIRONDB_FAILPOINT", format!("pause:{cut}"))
            .env("CHIRONDB_FAILPOINT_MARKER", &marker)
            .env(
                "CHIRONDB_FAILPOINT_RELEASE",
                control.path().join("never-release"),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !marker.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                let output = child.wait_with_output().unwrap();
                panic!(
                    "child exited at {cut}: {status}\n{}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("deadline at {cut}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        let output = child.wait_with_output().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(output.status.signal(), Some(9));
        }
        assert!(!output.status.success());
        let db = Db::open(directory.path()).unwrap();
        let identity_path = directory.path().join("graph_identity.gdx");
        let identities = std::fs::read(&identity_path).unwrap();
        let committed = cut != "transaction.after_prepare";
        let mut previous = None;
        for _ in 0..2 {
            let receipt = keyed(&db);
            if committed {
                let receipt = receipt.unwrap();
                assert!(receipt.stats.replayed.unwrap());
                let value = (receipt.transaction_id.clone(), receipt.rows.clone());
                if let Some(previous) = previous {
                    assert_eq!(value, previous);
                }
                previous = Some(value);
                let status = db
                    .transaction_status(receipt.transaction_id.as_deref().unwrap())
                    .unwrap();
                assert!(status.storage_projected && status.audit_projected);
            } else {
                let error = receipt.unwrap_err();
                assert_eq!(error.code, "chironql.transaction_rejected");
                let id = error.error.rsplit(": ").next().unwrap();
                assert_eq!(
                    db.transaction_status(id).unwrap().state,
                    chirondb_core::TransactionState::Rejected
                );
                assert!(error.hint.unwrap().contains(id));
            }
        }
        assert_eq!(
            std::fs::read(&identity_path).unwrap(),
            identities,
            "retry allocated IDs at {cut}"
        );
        let count = run(
            &db,
            Role::ReadOnly,
            "SQL SELECT COUNT(*) AS n FROM documents WHERE id = 'killed';",
            vec![],
        );
        assert_eq!(count.rows, vec![json!({"n": usize::from(committed)})]);
        let point = run(&db, Role::ReadOnly, "GET chunks POINTS 'root';", vec![]);
        assert_eq!(
            point.rows[0]["payload"]["kind"],
            if committed { "committed" } else { "root" }
        );
    }
}

#[test]
fn native_multimodel_fingerprint_ignores_named_vector_map_order() {
    use chirondb::{MultiModelTransactionRequest, SqlExecutionRequest, SqlStatementRequest};
    let directory = tempfile::tempdir().unwrap();
    let db = Db::open(directory.path()).unwrap();
    db.create_collection(
        serde_json::from_value(json!({
            "name":"named", "vector_dim":2, "named_vector_dims":{"a":2,"b":2}
        }))
        .unwrap(),
    )
    .unwrap();
    db.set_graph_lifecycle_scoped("named", true, true, &TenantScope::system())
        .unwrap();
    run(
        &db,
        Role::Admin,
        "SQL CREATE TABLE receipts (id BIGINT PRIMARY KEY);",
        vec![],
    );
    let mut first = None;
    for attempt in 0..16 {
        let mut vectors = std::collections::HashMap::new();
        for name in if attempt % 2 == 0 {
            ["a", "b"]
        } else {
            ["b", "a"]
        } {
            vectors.insert(name.into(), vec![1.0, 0.0]);
        }
        let request = MultiModelTransactionRequest {
            sql: SqlExecutionRequest {
                statements: vec![SqlStatementRequest {
                    sql: "INSERT INTO receipts VALUES (1)".into(),
                    parameters: vec![],
                }],
                idempotency_key: Some("unordered-vector-map".into()),
                retry_id: Some(attempt.to_string()),
            },
            collection: "named".into(),
            points: vec![Point {
                id: "point".into(),
                vector: vec![1.0, 0.0],
                vectors,
                sparse_vector: None,
                payload: json!({}),
            }],
            point_deletes: vec![],
            relations: vec![],
            edge_deletes: vec![],
            edge_updates: vec![],
        };
        let response = db
            .execute_multimodel_transaction(
                request,
                &TenantScope::system(),
                &chirondb_core::audit::AuditContext::embedded(),
            )
            .unwrap();
        assert_eq!(response.graph.replayed, attempt != 0);
        if let Some(first) = &first {
            assert_eq!(&response.sql.transaction_id, first);
        }
        first = Some(response.sql.transaction_id);
    }
}
