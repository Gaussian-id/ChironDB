use super::*;
use std::collections::{BTreeMap, BTreeSet};

const QUERY: &str = r#"TRANSACTION {
 SQL INSERT INTO docs (id, chunk, source) VALUES ('row-1', RECORD_REF('docs', NEW_RECORD('chunk')), RECORD_REF('docs', NEW_RECORD('source')));
 EXPECT SQL ROWS 1;
 VECTOR CREATE POINTS INTO docs USING TEMPLATE standard
   {binding:'chunk',point:{vector:[1,0],payload:{text:'chunk'}}},
   {binding:'source',point:{vector:[0,1],payload:{text:'source'}}};
 GRAPH CONNECT docs NEW chunk -> cites -> NEW source SET {kind:'source'};
};"#;

fn graph_pipeline() -> &'static str {
    "PIPELINE
      VECTOR v { SEARCH docs NEAR [1,0] LIMIT 1 }
      GRAPH g { TRAVERSE docs FROM v.record_ref VIA cites DEPTH 1 WHERE text = 'source' EDGE WHERE kind = 'source' RETURN NODES LIMIT 20 }
      RELATIONAL r { SQL SELECT id, chunk, source FROM docs LIMIT 10 }
      INNER JOIN r ON r.chunk = v.record_ref
      INNER JOIN g ON g.record_ref = r.source
      RETURN r.id, g.depth
      LIMIT 10;"
}

fn retrieval_variants(query: &str) -> [String; 3] {
    [
        query.into(),
        query.replace(
            "SEARCH docs NEAR [1,0]",
            "HYBRID docs TEXT 'chunk' FIELD text",
        ),
        query.replace(
            "SEARCH docs NEAR [1,0]",
            "HYBRID docs NEAR [1,0] TEXT 'chunk' FIELD text",
        ),
    ]
}

fn run(db: &Db, token: &str, query: &str) -> ChironQlResponse {
    execute(
        db,
        token,
        &ChironQlRequest {
            query: query.into(),
            confirm: true,
            ..Default::default()
        },
    )
    .unwrap_or_else(|error| panic!("{query}: {error:?}"))
    .publish(|result| result)
    .unwrap()
}

fn identity_command(db: &Db, token: &str, query: &str) {
    let revision = db
        .identity_authority()
        .unwrap()
        .authenticate(token)
        .unwrap()
        .revision();
    run(db, token, &format!("{query} IF REVISION {revision};"));
}

fn setup(data: &std::path::Path, token: &str) -> Db {
    let db = Db::open(data).unwrap();
    run(
        &db,
        token,
        "CREATE PROTECTED COLLECTION docs DIM 2 IF REVISION 1;",
    );
    identity_command(&db, token, "CREATE ROLE knowledge_writer");
    identity_command(
        &db,
        token,
        "GRANT READ, SEARCH, CREATE, INGEST, UPDATE, DELETE, GRAPH_READ, GRAPH_WRITE ON COLLECTION docs TO ROLE knowledge_writer",
    );
    identity_command(&db, token, "GRANT ROLE knowledge_writer TO USER root");
    let policy = CollectionPolicy {
        department_actions: BTreeSet::new(),
        owner_actions: BTreeSet::from([
            Action::Read,
            Action::Search,
            Action::Update,
            Action::Delete,
            Action::GraphRead,
            Action::GraphWrite,
        ]),
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
    run(
        &db,
        token,
        &format!(
            "ALTER COLLECTION docs SET SECURITY POLICY {} IF REVISION 1;",
            serde_json::to_string(&policy).unwrap().replace('"', "'")
        ),
    );
    run(
        &db,
        token,
        "SQL CREATE TABLE docs (id TEXT PRIMARY KEY, chunk RECORD_REF('docs') NOT NULL, source RECORD_REF('docs') NOT NULL);",
    );
    db
}

#[test]
fn protected_retrieval_receiver_keeps_current_publication_guard() {
    const CHILD: &str = "CHIRON_RETRIEVAL_PUBLICATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact", "chironql_protected::atomic_insert_tests::protected_retrieval_receiver_keeps_current_publication_guard", "--nocapture"]).env(CHILD,"1").status().unwrap().success());
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let data = root.join("data");
    let key_out = root.join("admin.key");
    chirondb_core::security::onboarding::initialize(
        &data,
        "acme",
        "root",
        &root.join("storage.json"),
        &key_out,
        false,
    )
    .unwrap();
    let secret = std::fs::read_to_string(key_out).unwrap();
    let token = secret.trim();
    let db = setup(&data, token);
    run(
        &db,
        token,
        "ALTER COLLECTION docs SET GRAPH ENABLED IF REVISION 2;",
    );
    run(
        &db,
        token,
        "ALTER COLLECTION docs SET EDGE TYPE cites IF REVISION 3;",
    );
    let receipt = run(&db, token, QUERY);
    let chunk = receipt.rows[0]["record_ref"]["id"].as_str().unwrap();
    // Retirement invalidates the input context. Its acknowledgement must use
    // the fresh context returned by the core, for both explicit and filter delete.
    let extra = run(
        &db,
        token,
        "CREATE POINTS INTO docs USING TEMPLATE standard {vector:[0,1],payload:{text:'disposable'}} REQUEST receiver-delete-one;",
    );
    let extra_id = extra.rows[0]["id"].as_str().unwrap();
    let deleted = run(
        &db,
        token,
        &format!("DELETE FROM docs POINTS '{extra_id}';"),
    );
    assert_eq!(deleted.stats.affected, Some(1));
    run(
        &db,
        token,
        "CREATE POINTS INTO docs USING TEMPLATE standard {vector:[0,1],payload:{text:'disposable'}} REQUEST receiver-delete-filter;",
    );
    assert_eq!(
        run(&db, token, "DELETE FROM docs WHERE text = 'disposable';")
            .stats
            .affected,
        Some(1)
    );
    assert_eq!(run(&db, token, "COUNT docs;").rows[0]["count"], json!(2));
    let queries = [
        format!("GET docs POINTS '{chunk}';"),
        "SCROLL docs LIMIT 2;".into(),
        "COUNT docs;".into(),
        "SEARCH docs NEAR [1,0] LIMIT 2;".into(),
        "HYBRID docs TEXT 'chunk' FIELD text LIMIT 2;".into(),
        "HYBRID docs NEAR [1,0] TEXT 'chunk' FIELD text LIMIT 2;".into(),
        format!(
            "TRAVERSE docs FROM '{chunk}' VIA cites DEPTH 1 WITH PAYLOAD RETURN NODES LIMIT 10;"
        ),
        format!(
            "TRAVERSE docs FROM '{chunk}' VIA cites DEPTH 1 WITH PAYLOAD RETURN EDGES LIMIT 10;"
        ),
        format!(
            "TRAVERSE docs FROM '{chunk}' VIA cites DEPTH 1 WITH PAYLOAD RETURN PATHS LIMIT 10;"
        ),
    ];
    let mut queued = Vec::new();
    for query in queries {
        let request = ChironQlRequest {
            query,
            ..Default::default()
        };
        let output = execute(&db, token, &request).unwrap();
        assert!(matches!(
            &output,
            Output::Query(PublicationGuard::Data(_), _)
        ));
        assert!(!output.publish(|value| value.rows).unwrap().is_empty());
        queued.push(execute(&db, token, &request).unwrap());
    }
    let authority = db.identity_authority().unwrap();
    let actor = authority.authenticate(token).unwrap();
    authority
        .revoke_credential(&actor, actor.revision(), actor.credential_id())
        .unwrap();
    for output in queued {
        let mut published = false;
        assert!(output.publish(|_| published = true).is_err());
        assert!(!published);
    }
}

#[test]
fn protected_atomic_insert_from_fresh_encrypted_installation() {
    const CHILD: &str = "CHIRONDB_ATOMIC_INSERT_ENCRYPTED_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "chironql_protected::atomic_insert_tests::protected_atomic_insert_from_fresh_encrypted_installation", "--nocapture"])
            .env(CHILD, "1").status().unwrap();
        assert!(status.success());
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let root_path = directory.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root_path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let data = root_path.join("data");
    let keyring = root_path.join("keyring.json");
    let secret_path = root_path.join("admin.key");
    chirondb_core::security::onboarding::initialize(
        &data,
        "acme",
        "root",
        &keyring,
        &secret_path,
        false,
    )
    .unwrap();
    let secret = std::fs::read_to_string(secret_path).unwrap();
    let token = secret.trim();
    let db = setup(&data, token);
    // Existing protected content must receive graph handles through encrypted backfill.
    let existing = run(
        &db,
        token,
        "CREATE POINTS INTO docs USING TEMPLATE standard {vector:[1,1],payload:{text:'existing'}} REQUEST existing;",
    );
    let first = run(
        &db,
        token,
        "ALTER COLLECTION docs SET GRAPH ENABLED IF REVISION 2;",
    );
    assert_eq!(first.rows[0]["revision"], json!(3));
    let deadline = Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let result = run(
            &db,
            token,
            "ALTER COLLECTION docs SET GRAPH ENABLED IF REVISION 3;",
        );
        assert_eq!(result.rows[0]["revision"], json!(3));
        if result.rows[0]["graph"]["backfill_in_progress"] == false {
            break;
        }
        assert!(Instant::now() < deadline, "protected backfill timed out");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    run(
        &db,
        token,
        "ALTER COLLECTION docs SET EDGE TYPE cites IF REVISION 3;",
    );
    for query in [
        "ALTER COLLECTION docs SET EDGE TYPE cites IF REVISION 3;",
        "ALTER COLLECTION docs SET GRAPH DISABLED IF REVISION 3;",
    ] {
        assert_eq!(
            execute(
                &db,
                token,
                &ChironQlRequest {
                    query: query.into(),
                    confirm: true,
                    ..Default::default()
                }
            )
            .err()
            .unwrap()
            .code,
            "security.conflict"
        );
    }
    let request = ChironQlRequest {
        query: QUERY.into(),
        idempotency_key: Some("protected-insert".into()),
        ..Default::default()
    };
    for query in [
        QUERY.replace("NEW_RECORD('chunk')", "NEW_RECORD('missing')"),
        QUERY.replace("NEW_RECORD('chunk')", "NEW_RECORD(DISTINCT 'chunk')"),
        QUERY.replace("NEW_RECORD('chunk')", "NEW_RECORD('chunk') OVER ()"),
        QUERY.replace("source',point:{", "source',point:{id:'forged',"),
        QUERY.replace("NEW source", "NEW missing"),
    ] {
        assert!(
            execute(
                &db,
                token,
                &ChironQlRequest {
                    query,
                    ..request.clone()
                }
            )
            .is_err()
        );
    }
    let guarded_query = QUERY.replace("EXPECT SQL ROWS 1", "EXPECT SQL ROWS 2");
    for key in [None, Some("rejected-row-count-insert".into())] {
        let frontier = db.multimodel_visibility_frontier().unwrap();
        let failure = execute(
            &db,
            token,
            &ChironQlRequest {
                query: guarded_query.clone(),
                idempotency_key: key,
                ..request.clone()
            },
        )
        .err()
        .unwrap();
        assert_eq!(failure.code, "chironql.sql_row_precondition_failed");
        assert_eq!(db.multimodel_visibility_frontier().unwrap(), frontier);
        assert_eq!(run(&db, token, "COUNT docs;").rows[0]["count"], json!(1));
        assert!(run(&db, token, "SQL SELECT id FROM docs;").rows.is_empty());
    }
    let receipt = execute(&db, token, &request)
        .unwrap()
        .publish(|result| result)
        .unwrap();
    assert_eq!(
        execute(
            &db,
            token,
            &ChironQlRequest {
                query: QUERY.replace("EXPECT SQL ROWS 1", "EXPECT SQL ROWS 2"),
                ..request.clone()
            }
        )
        .err()
        .unwrap()
        .code,
        "security.invalid",
        "a changed guard changes the committed key fingerprint"
    );
    assert_eq!(receipt.rows.len(), 3);
    assert_eq!(receipt.stats.replayed, Some(false));
    let mut public_ids = Vec::new();
    for row in &receipt.rows[..2] {
        let id = row["record_ref"]["id"].as_str().unwrap();
        uuid::Uuid::parse_str(id).unwrap();
        public_ids.push(id.to_string());
        assert_eq!(row["record_ref"]["namespace"], "docs");
        assert_eq!(
            run(&db, token, &format!("GET docs POINTS '{id}';"))
                .rows
                .len(),
            1
        );
    }
    assert_edge(&db, token, &receipt);
    let chunk = receipt
        .rows
        .iter()
        .find(|row| row["binding"] == "chunk")
        .unwrap()["record_ref"]["id"]
        .as_str()
        .unwrap();
    let source = receipt
        .rows
        .iter()
        .find(|row| row["binding"] == "source")
        .unwrap()["record_ref"]["id"]
        .as_str()
        .unwrap();
    for returns in ["NODES", "EDGES", "PATHS"] {
        let query = format!(
            "TRAVERSE docs FROM '{chunk}' VIA cites DEPTH 1 WITH PAYLOAD RETURN {returns} LIMIT 10;"
        );
        let result = run(&db, token, &query);
        assert_eq!(result.domains, vec![ExecutionDomain::Graph]);
        assert_eq!(result.rows.len(), 1);
        match returns {
            "NODES" => {
                assert_eq!(result.rows[0]["id"], source);
                assert_eq!(result.rows[0]["payload"], json!({"text":"source"}));
            }
            "EDGES" => {
                assert_eq!(result.rows[0]["source"], chunk);
                assert_eq!(result.rows[0]["target"], source);
                assert_eq!(result.rows[0]["properties"], json!({"kind":"source"}));
            }
            "PATHS" => {
                assert_eq!(result.rows[0]["nodes"][0]["id"], chunk);
                assert_eq!(result.rows[0]["nodes"][1]["id"], source);
            }
            _ => unreachable!(),
        }
    }
    let rows = run(&db, token, "SQL SELECT chunk, source FROM docs;");
    assert_eq!(rows.rows[0]["chunk"], receipt.rows[0]["record_ref"]);
    assert_eq!(rows.rows[0]["source"], receipt.rows[1]["record_ref"]);
    let replay = execute(&db, token, &request)
        .unwrap()
        .publish(|result| result)
        .unwrap();
    assert_eq!(receipt.rows, replay.rows);
    assert_eq!(receipt.transaction_id, replay.transaction_id);
    assert_eq!(replay.stats.replayed, Some(true));
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(protocol_replays(&db, token, &request, &receipt));
    // Explicit EXISTING endpoint references resolve a server-owned public ID.
    let existing_id = existing.rows[0]["id"].as_str().unwrap();
    let second = QUERY
        .replace("'row-1'", "'row-2'")
        .replace("NEW source SET", &format!("EXISTING '{existing_id}' SET"));
    assert_eq!(run(&db, token, &second).rows.len(), 3);
    drop(db);
    let db = Db::open(&data).unwrap();
    let replay = execute(&db, token, &request)
        .unwrap()
        .publish(|result| result)
        .unwrap();
    assert_eq!(receipt.rows, replay.rows);
    assert_eq!(receipt.transaction_id, replay.transaction_id);
    let queued = execute(&db, token, &request).unwrap();
    identity_command(
        &db,
        token,
        "REVOKE GRAPH_WRITE ON COLLECTION docs FROM ROLE knowledge_writer",
    );
    assert!(queued.publish(|_| ()).is_err());
    assert_eq!(
        execute(&db, token, &request).err().unwrap().code,
        "security.forbidden"
    );
    let graph_queued = retrieval_variants(graph_pipeline()).map(|query| {
        execute(
            &db,
            token,
            &ChironQlRequest {
                query,
                ..Default::default()
            },
        )
        .unwrap()
    });
    identity_command(
        &db,
        token,
        "REVOKE GRAPH_READ ON COLLECTION docs FROM ROLE knowledge_writer",
    );
    for output in graph_queued {
        assert!(output.publish(|_| ()).is_err());
    }
    for query in retrieval_variants(graph_pipeline()) {
        assert_eq!(
            execute(
                &db,
                token,
                &ChironQlRequest {
                    query,
                    ..Default::default()
                }
            )
            .err()
            .unwrap()
            .code,
            "security.forbidden"
        );
    }
    let without_graph = graph_pipeline()
        .lines()
        .filter(|line| !line.trim_start().starts_with("GRAPH ") && !line.contains("INNER JOIN g"))
        .collect::<Vec<_>>()
        .join("\n")
        .replace("r.id, g.depth", "r.id, v.score");
    let mut text_queued = Vec::new();
    for query in retrieval_variants(&without_graph) {
        let request = ChironQlRequest {
            query,
            ..Default::default()
        };
        let result = execute(&db, token, &request)
            .unwrap()
            .publish(|result| result)
            .unwrap();
        assert_eq!(result.rows.len(), 1);
        assert!(result.rows[0]["score"].is_number());
        assert_eq!(
            result.domains,
            vec![ExecutionDomain::Relational, ExecutionDomain::Vector]
        );
        text_queued.push(execute(&db, token, &request).unwrap());
    }
    identity_command(
        &db,
        token,
        "REVOKE SEARCH ON COLLECTION docs FROM ROLE knowledge_writer",
    );
    for output in text_queued {
        assert!(output.publish(|_| ()).is_err());
    }
    // Graph schema cannot pass through legacy bypass APIs, even for this administrator.
    assert!(
        db.set_graph_lifecycle_scoped("docs", false, true, &crate::tenant::TenantScope::system())
            .is_err()
    );
    chirondb_core::audit::verify_hash_chain(&data).unwrap();
    let audit = std::fs::read_to_string(data.join("audit/audit.jsonl")).unwrap();
    assert!(
        !audit.contains("protected-graph-schema"),
        "audit payload must remain encrypted"
    );
}

#[cfg(feature = "fault-injection")]
#[test]
fn protected_atomic_insert_recovers_after_sigkill() {
    use std::process::{Command, Stdio};
    const MODE: &str = "CHIRONDB_PROTECTED_INSERT_CRASH_MODE";
    const TEST: &str =
        "chironql_protected::atomic_insert_tests::protected_atomic_insert_recovers_after_sigkill";
    let mode = std::env::var(MODE).unwrap_or_default();
    if mode.is_empty() {
        assert!(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env(MODE, "supervisor")
                .status()
                .unwrap()
                .success()
        );
        return;
    }
    let request = ChironQlRequest {
        query: QUERY.into(),
        idempotency_key: Some("killed-create".into()),
        ..Default::default()
    };
    if mode == "writer" {
        let keyring = std::env::var_os("CHIRONDB_INSERT_TEST_KEYRING").unwrap();
        chirondb_core::encryption::install_process_keyring(
            chirondb_core::encryption::Keyring::load(std::path::Path::new(&keyring)).unwrap(),
            true,
        )
        .unwrap();
        let token =
            std::fs::read_to_string(std::env::var_os("CHIRONDB_INSERT_TEST_TOKEN").unwrap())
                .unwrap();
        let db = Db::open(std::env::var_os("CHIRONDB_INSERT_TEST_DATA").unwrap()).unwrap();
        execute(&db, token.trim(), &request).expect("writer should reach failpoint");
        panic!("parent must terminate the paused writer");
    }
    let directory = tempfile::tempdir().unwrap();
    let root_path = directory.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root_path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let baseline = root_path.join("baseline");
    let keyring = root_path.join("keyring.json");
    let secret_path = root_path.join("admin.key");
    chirondb_core::security::onboarding::initialize(
        &baseline,
        "acme",
        "root",
        &keyring,
        &secret_path,
        false,
    )
    .unwrap();
    let token = std::fs::read_to_string(&secret_path).unwrap();
    let token = token.trim();
    let db = setup(&baseline, token);
    run(
        &db,
        token,
        "ALTER COLLECTION docs SET GRAPH ENABLED IF REVISION 2;",
    );
    run(
        &db,
        token,
        "ALTER COLLECTION docs SET EDGE TYPE cites IF REVISION 3;",
    );
    drop(db);
    fn copy_tree(source: &std::path::Path, target: &std::path::Path) {
        std::fs::create_dir(target).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let dest = target.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &dest);
            } else {
                std::fs::copy(entry.path(), dest).unwrap();
            }
        }
    }
    for (index, cut) in [
        "transaction.after_prepare",
        "transaction.before_commit_fsync",
        "multi_model.after_relational_wal",
        "multi_model.after_collection_wal",
    ]
    .into_iter()
    .enumerate()
    {
        let data = root_path.join(format!("case-{index}"));
        copy_tree(&baseline, &data);
        let marker = root_path.join(format!("paused-{index}"));
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env(MODE, "writer")
            .env("CHIRONDB_INSERT_TEST_KEYRING", &keyring)
            .env("CHIRONDB_INSERT_TEST_TOKEN", &secret_path)
            .env("CHIRONDB_INSERT_TEST_DATA", &data)
            .env("CHIRONDB_FAILPOINT", format!("pause:{cut}"))
            .env("CHIRONDB_FAILPOINT_MARKER", &marker)
            .env(
                "CHIRONDB_FAILPOINT_RELEASE",
                root_path.join("never-release"),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(30);
        while !marker.exists() {
            if child.try_wait().unwrap().is_some() {
                let output = child.wait_with_output().unwrap();
                panic!(
                    "child exited before {cut}: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("timeout at {cut}");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        child.kill().unwrap();
        let output = child.wait_with_output().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(output.status.signal(), Some(9));
        }
        assert!(!output.status.success());
        let db = Db::open(&data).unwrap();
        let identity_path = data.join("graph_identity.gdx");
        let allocations = std::fs::read(&identity_path).unwrap();
        let committed = cut != "transaction.after_prepare";
        let mut previous: Option<ChironQlResponse> = None;
        for _ in 0..2 {
            let result = execute(&db, token, &request);
            if committed {
                let result = result
                    .expect("committed retry")
                    .publish(|result| result)
                    .unwrap();
                assert_eq!(result.stats.replayed, Some(true));
                assert_eq!(result.rows.len(), 3);
                assert_edge(&db, token, &result);
                for row in &result.rows[..2] {
                    let id = row["record_ref"]["id"].as_str().unwrap();
                    assert_eq!(
                        run(&db, token, &format!("GET docs POINTS '{id}';"))
                            .rows
                            .len(),
                        1
                    );
                }
                if let Some(previous) = &previous {
                    assert_eq!(previous.rows, result.rows);
                    assert_eq!(previous.transaction_id, result.transaction_id);
                }
                let status = db
                    .transaction_status(result.transaction_id.as_deref().unwrap())
                    .unwrap();
                assert!(status.storage_projected && status.audit_projected);
                previous = Some(result);
            } else {
                assert_eq!(result.err().unwrap().code, "chironql.transaction_rejected");
            }
            assert_eq!(
                std::fs::read(&identity_path).unwrap(),
                allocations,
                "retry must not allocate twice: {cut}"
            );
        }
        assert_eq!(
            run(&db, token, "SQL SELECT id FROM docs;").rows.len(),
            usize::from(committed)
        );
        assert_eq!(
            run(&db, token, "COUNT docs;").rows[0]["count"],
            json!(if committed { 2 } else { 0 })
        );
        chirondb_core::audit::verify_hash_chain(&data).unwrap();
        println!(
            "SIGKILL {cut}: committed={committed}, SQL/content/authority agree, receipt stable"
        );
    }
}

async fn protocol_replays(
    db: &Db,
    token: &str,
    request: &ChironQlRequest,
    receipt: &ChironQlResponse,
) {
    use crate::{
        api,
        auth::AuthConfig,
        grpc::{self, chiron_pb, pb},
        wire,
    };
    use tokio::net::TcpListener;
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_address = http.local_addr().unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wire_address = tcp.local_addr().unwrap().to_string();
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grpc_address = probe.local_addr().unwrap();
    drop(probe);
    let router = api::router_with_auth(db.clone(), AuthConfig::disabled());
    let wire_db = db.clone();
    let grpc_db = db.clone();
    let http_task = tokio::spawn(async move { axum::serve(http, router).await.unwrap() });
    let wire_task = tokio::spawn(async move { wire::serve_listener(wire_db, tcp).await.unwrap() });
    let grpc_task = tokio::spawn(async move {
        grpc::serve_with_auth(grpc_db, AuthConfig::disabled(), grpc_address)
            .await
            .unwrap()
    });
    let miss = ChironQlRequest {
        query: request
            .query
            .replace("'row-1'", "'protocol-guard-miss'")
            .replace("EXPECT SQL ROWS 1", "EXPECT SQL ROWS 2"),
        idempotency_key: Some("protocol-precondition-miss".into()),
        ..request.clone()
    };
    let client = reqwest::Client::new();
    for path in ["/v1/chironql", "/chironql"] {
        let response = client
            .post(format!("http://{http_address}{path}"))
            .bearer_auth(token)
            .json(request)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body = response.text().await.unwrap();
        assert!(status.is_success(), "{path}: {status}: {body}");
        let result: ChironQlResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(result.rows, receipt.rows);
        assert_eq!(result.transaction_id, receipt.transaction_id);
        assert_eq!(result.stats.replayed, Some(true));
    }
    for path in ["/v1/chironql", "/chironql"] {
        let response = client
            .post(format!("http://{http_address}{path}"))
            .bearer_auth(token)
            .json(&miss)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
        let error: ChironQlError = response.json().await.unwrap();
        assert_eq!(error.code, "chironql.sql_row_precondition_failed");
    }
    let mut grpc_client = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match chiron_pb::chiron_db_client::ChironDbClient::connect(format!(
                "http://{grpc_address}"
            ))
            .await
            {
                Ok(client) => break client,
                Err(_) if !grpc_task.is_finished() => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await
                }
                Err(error) => panic!("gRPC failed: {error}"),
            }
        }
    })
    .await
    .unwrap();
    let mut grpc_request = tonic::Request::new(chiron_pb::ChironQlRequest {
        query: request.query.clone(),
        idempotency_key: request.idempotency_key.clone(),
        retry_id: Some("grpc-retry".into()),
        ..Default::default()
    });
    grpc_request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    let result = grpc_client
        .execute_query(grpc_request)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(result.transaction_id, receipt.transaction_id);
    assert_eq!(
        result
            .rows_json
            .iter()
            .map(|row| serde_json::from_str::<serde_json::Value>(row).unwrap())
            .collect::<Vec<_>>(),
        receipt.rows
    );
    let mut failure_request = tonic::Request::new(chiron_pb::ChironQlRequest {
        query: miss.query.clone(),
        idempotency_key: miss.idempotency_key.clone(),
        ..Default::default()
    });
    failure_request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    let failure = grpc_client
        .execute_query(failure_request)
        .await
        .unwrap_err();
    assert_eq!(failure.code(), tonic::Code::FailedPrecondition);
    let details: ChironQlError = serde_json::from_slice(failure.details()).unwrap();
    assert_eq!(details.code, "chironql.sql_row_precondition_failed");
    let failure = wire::send_request(
        &wire_address,
        pb::WireRequest {
            request_id: 2,
            api_key: token.into(),
            operation: Some(pb::wire_request::Operation::Chironql(
                pb::WireChironQlRequest {
                    query: miss.query.clone(),
                    idempotency_key: miss.idempotency_key.clone(),
                    ..Default::default()
                },
            )),
        },
    )
    .await
    .unwrap();
    assert_eq!(failure.error_code, "FAILED_PRECONDITION");
    let details: ChironQlError =
        serde_json::from_str(failure.error_details_json.as_deref().unwrap()).unwrap();
    assert_eq!(details.code, "chironql.sql_row_precondition_failed");
    assert_eq!(run(db, token, "COUNT docs;").rows[0]["count"], json!(3));
    assert!(
        run(
            db,
            token,
            "SQL SELECT id FROM docs WHERE id='protocol-guard-miss';"
        )
        .rows
        .is_empty()
    );
    let wire_result = wire::send_request(
        &wire_address,
        pb::WireRequest {
            request_id: 1,
            api_key: token.into(),
            operation: Some(pb::wire_request::Operation::Chironql(
                pb::WireChironQlRequest {
                    query: request.query.clone(),
                    idempotency_key: request.idempotency_key.clone(),
                    retry_id: Some("wire-retry".into()),
                    ..Default::default()
                },
            )),
        },
    )
    .await
    .unwrap();
    assert!(
        wire_result.error_code.is_empty(),
        "{}",
        wire_result.error_message
    );
    let Some(pb::wire_response::Payload::Chironql(result)) = wire_result.payload else {
        panic!("missing wire receipt")
    };
    assert_eq!(result.transaction_id, receipt.transaction_id);
    assert_eq!(
        result
            .rows_json
            .iter()
            .map(|row| serde_json::from_str::<serde_json::Value>(row).unwrap())
            .collect::<Vec<_>>(),
        receipt.rows
    );
    for (query, rows) in [
        (graph_pipeline().to_string(), 1),
        (
            graph_pipeline().replace("text = 'source'", "text = 'absent'"),
            0,
        ),
        (
            graph_pipeline().replace("kind = 'source'", "kind = 'absent'"),
            0,
        ),
        (
            graph_pipeline().replace("RETURN NODES LIMIT 20", "RETURN NODES LIMIT 0"),
            0,
        ),
        (
            graph_pipeline().replace(
                "NEAR [1,0] LIMIT 1",
                "NEAR [1,0] WHERE text = 'absent' LIMIT 1",
            ),
            0,
        ),
        (
            graph_pipeline()
                .replace("text = 'source'", "text = 'absent'")
                .replace("INNER JOIN g", "LEFT JOIN g"),
            1,
        ),
    ]
    .into_iter()
    .flat_map(|(query, rows)| retrieval_variants(&query).map(|query| (query, rows)))
    {
        let expected = run(db, token, &query);
        assert_eq!(expected.rows.len(), rows);
        assert_eq!(expected.columns, ["id", "depth"]);
        if query.contains("LEFT JOIN g") {
            assert_eq!(expected.rows[0].get("depth"), Some(&Value::Null));
        }
        for prefix in ["", "/v1"] {
            let response = client
                .post(format!("http://{http_address}{prefix}/chironql"))
                .bearer_auth(token)
                .json(&ChironQlRequest {
                    query: query.clone(),
                    ..Default::default()
                })
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
            let response: ChironQlResponse = response.json().await.unwrap();
            assert_eq!(response.rows, expected.rows);
        }
        let mut request = tonic::Request::new(chiron_pb::ChironQlRequest {
            query: query.clone(),
            ..Default::default()
        });
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        let response = grpc_client
            .execute_query(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            response
                .rows_json
                .iter()
                .map(|row| serde_json::from_str::<Value>(row).unwrap())
                .collect::<Vec<_>>(),
            expected.rows
        );
        let response = wire::send_request(
            &wire_address,
            pb::WireRequest {
                request_id: 10,
                api_key: token.into(),
                operation: Some(pb::wire_request::Operation::Chironql(
                    pb::WireChironQlRequest {
                        query,
                        ..Default::default()
                    },
                )),
            },
        )
        .await
        .unwrap();
        assert!(response.error_code.is_empty(), "{}", response.error_message);
        let Some(pb::wire_response::Payload::Chironql(response)) = response.payload else {
            panic!("missing pipeline result")
        };
        assert_eq!(
            response
                .rows_json
                .iter()
                .map(|row| serde_json::from_str::<Value>(row).unwrap())
                .collect::<Vec<_>>(),
            expected.rows
        );
    }
    for (query, code) in [
        (
            graph_pipeline().replace("WHERE text =", "WHERE unknown ="),
            "security.forbidden",
        ),
        (
            graph_pipeline().replace("RETURN NODES", "RETURN EDGES"),
            "chironql.protected_unsupported",
        ),
        (
            graph_pipeline().replace("RETURN NODES", "RETURN PATHS"),
            "chironql.protected_unsupported",
        ),
        (
            graph_pipeline().replace("RETURN NODES", "RETURN NODES WITH PAYLOAD"),
            "chironql.protected_unsupported",
        ),
    ]
    .into_iter()
    .flat_map(|(query, code)| retrieval_variants(&query).map(|query| (query, code)))
    {
        assert_eq!(
            execute(
                db,
                token,
                &ChironQlRequest {
                    query,
                    ..Default::default()
                }
            )
            .err()
            .unwrap()
            .code,
            code
        );
    }
    for query in [
        graph_pipeline().to_string(),
        retrieval_variants(graph_pipeline())[2].clone(),
    ] {
        for position in [1, 2] {
            let mut parameters = vec![RelationalValue::Text("unused".into()); position - 1];
            parameters.push(RelationalValue::Vector(vec![1.0, 0.0]));
            let request = ChironQlRequest {
                query: query.replace("NEAR [1,0]", &format!("NEAR ${position}")),
                parameters,
                ..Default::default()
            };
            let result = execute(db, token, &request)
                .unwrap()
                .publish(|result| result)
                .unwrap();
            assert_eq!(result.rows, run(db, token, graph_pipeline()).rows);
            for parameters in [
                Vec::new(),
                vec![RelationalValue::Text("invalid vector".into()); position],
            ] {
                let mut invalid = request.clone();
                invalid.parameters = parameters;
                assert_eq!(
                    execute(db, token, &invalid).err().unwrap().code,
                    "security.invalid"
                );
            }
        }
    }
    let sparse = graph_pipeline().replace(
        "SEARCH docs NEAR [1,0]",
        "HYBRID docs NEAR [1,0] TEXT {1:1}",
    );
    assert_eq!(
        execute(
            db,
            token,
            &ChironQlRequest {
                query: sparse,
                ..Default::default()
            }
        )
        .err()
        .unwrap()
        .code,
        "chironql.protected_unsupported"
    );
    // SQL authorization precedes retrieval even when retrieval would exhaust its budget.
    identity_command(
        db,
        token,
        "REVOKE READ ON COLLECTION docs FROM ROLE knowledge_writer",
    );
    for query in retrieval_variants(graph_pipeline()) {
        let query = query.replace("LIMIT 1 }", "LIMIT 1 BUDGET 0 }");
        assert_eq!(
            execute(
                db,
                token,
                &ChironQlRequest {
                    query,
                    ..Default::default()
                }
            )
            .err()
            .unwrap()
            .code,
            "security.forbidden"
        );
    }
    identity_command(
        db,
        token,
        "GRANT READ ON COLLECTION docs TO ROLE knowledge_writer",
    );
    http_task.abort();
    wire_task.abort();
    grpc_task.abort();
    let _ = tokio::join!(http_task, wire_task, grpc_task);
}

fn assert_edge(db: &Db, token: &str, receipt: &ChironQlResponse) {
    let identity = db
        .identity_authority()
        .unwrap()
        .authenticate(token)
        .unwrap();
    let context = db
        .bind_access(&identity, "docs", "acme", Action::GraphRead)
        .unwrap();
    let source = receipt.rows[0]["record_ref"]["id"].as_str().unwrap();
    let target = receipt.rows[1]["record_ref"]["id"].as_str().unwrap();
    let result = db
        .traverse_authorized(
            &context,
            crate::graph::GraphTraverseRequest {
                anchors: vec![source.into()],
                edge_types: vec!["cites".into()],
                direction: crate::graph::GraphDirection::Outgoing,
                node_filter: None,
                edge_filter: None,
                budget: crate::graph::TraversalBudget {
                    max_depth: 1,
                    ..Default::default()
                },
            },
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap()
        .publish(|result| result)
        .unwrap();
    assert!(result.nodes.iter().any(|node| node.point_id == target));
}
