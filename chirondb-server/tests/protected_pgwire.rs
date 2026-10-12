use base64::{Engine, engine::general_purpose::STANDARD};
use chirondb::{
    Db, SqlExecutionRequest, SqlStatementRequest, api,
    auth::AuthConfig,
    security::{
        Action, Classification, CollectionPolicy, IngestTemplate, PropertyAction, PropertyRule,
        Representation, RevisionUpdate, ScopeGrant, SubjectAttributes, onboarding,
    },
    tls, wire, wire_postgres,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use ring::{digest, hmac, pbkdf2};
use rustls::pki_types::ServerName;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

#[derive(serde::Deserialize)]
struct SqlIssueResponse {
    id: String,
    username: String,
    password: String,
    revision: u64,
}

async fn issue_sql_over_http(
    db: &Db,
    bearer: &str,
    principal: &str,
    revision: u64,
) -> SqlIssueResponse {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = api::router_with_auth(db.clone(), AuthConfig::disabled());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/security/sql-credentials"))
        .bearer_auth(bearer)
        .json(&serde_json::json!({"principal":principal,"expected_revision":revision}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.headers()[reqwest::header::CACHE_CONTROL],
        "no-store"
    );
    let issued: SqlIssueResponse = response.json().await.unwrap();
    let stale_alias = reqwest::Client::new()
        .post(format!("http://{address}/security/sql-credentials"))
        .bearer_auth(bearer)
        .json(&serde_json::json!({"principal":principal,"expected_revision":revision}))
        .send()
        .await
        .unwrap();
    assert_eq!(stale_alias.status(), reqwest::StatusCode::CONFLICT);
    task.abort();
    assert_eq!(issued.username, "admin");
    assert_eq!(issued.revision, revision + 1);
    assert!(issued.password.len() >= 32);
    issued
}

async fn message<S: AsyncRead + Unpin>(stream: &mut S) -> (u8, Vec<u8>) {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await.unwrap();
    let len = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
    assert!((4..=8192).contains(&len));
    let mut body = vec![0; len - 4];
    stream.read_exact(&mut body).await.unwrap();
    (header[0], body)
}

async fn send<S: AsyncWrite + Unpin>(stream: &mut S, kind: u8, body: &[u8]) {
    stream.write_all(&[kind]).await.unwrap();
    stream
        .write_all(&((body.len() + 4) as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(body).await.unwrap();
}

async fn login<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    username: &str,
    password: &str,
) -> bool {
    login_with_backend(stream, username, password)
        .await
        .is_some()
}

async fn login_with_backend<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    username: &str,
    password: &str,
) -> Option<[u8; 8]> {
    let mut startup = Vec::new();
    startup.extend_from_slice(&wire_postgres::PROTOCOL_V3.to_be_bytes());
    startup.extend_from_slice(b"user\0");
    startup.extend_from_slice(username.as_bytes());
    startup.extend_from_slice(b"\0database\0chiron\0\0");
    stream
        .write_all(&((startup.len() + 4) as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&startup).await.unwrap();
    let (kind, methods) = message(stream).await;
    assert_eq!(kind, b'R');
    assert_eq!(&methods[..4], &10u32.to_be_bytes());
    assert_eq!(&methods[4..], b"SCRAM-SHA-256\0\0");
    let client_first_bare = format!("n={username},r=test-nonce");
    let client_first = format!("n,,{client_first_bare}");
    let mut initial = b"SCRAM-SHA-256\0".to_vec();
    initial.extend_from_slice(&(client_first.len() as i32).to_be_bytes());
    initial.extend_from_slice(client_first.as_bytes());
    send(stream, b'p', &initial).await;
    let (kind, challenge) = message(stream).await;
    assert_eq!(kind, b'R');
    assert_eq!(&challenge[..4], &11u32.to_be_bytes());
    let server_first = std::str::from_utf8(&challenge[4..]).unwrap();
    let attrs: Vec<_> = server_first.split(',').collect();
    let nonce = attrs[0].strip_prefix("r=").unwrap();
    let salt = STANDARD
        .decode(attrs[1].strip_prefix("s=").unwrap())
        .unwrap();
    let iterations: u32 = attrs[2].strip_prefix("i=").unwrap().parse().unwrap();
    let final_without_proof = format!("c=biws,r={nonce}");
    let auth_message = format!("{client_first_bare},{server_first},{final_without_proof}");
    let mut salted = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(iterations).unwrap(),
        &salt,
        password.as_bytes(),
        &mut salted,
    );
    let client_key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &salted), b"Client Key");
    let stored_key = digest::digest(&digest::SHA256, client_key.as_ref());
    let signature = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, stored_key.as_ref()),
        auth_message.as_bytes(),
    );
    let proof: Vec<_> = client_key
        .as_ref()
        .iter()
        .zip(signature.as_ref())
        .map(|(left, right)| left ^ right)
        .collect();
    send(
        stream,
        b'p',
        format!("{final_without_proof},p={}", STANDARD.encode(proof)).as_bytes(),
    )
    .await;
    let (kind, _) = message(stream).await;
    if kind == b'E' {
        return None;
    }
    assert_eq!(kind, b'R');
    let mut backend = None;
    loop {
        let (kind, body) = message(stream).await;
        if kind == b'E' {
            panic!("authentication post-proof failed: {body:?}");
        }
        if kind == b'Z' {
            return Some(backend.expect("authenticated session sends BackendKeyData"));
        }
        if kind == b'K' {
            backend = Some(body.try_into().expect("eight-byte backend key"));
        }
    }
}

async fn login_once(db: &Db, username: &str, password: &str) -> bool {
    let (mut client, mut server) = tokio::io::duplex(16 * 1024);
    let db = db.clone();
    let task = tokio::spawn(async move {
        let mut prefix = [0; 8];
        server.read_exact(&mut prefix).await.unwrap();
        wire_postgres::handle_protected_connection(db, server, prefix)
            .await
            .unwrap();
    });
    let result = login(&mut client, username, password).await;
    drop(client);
    task.await.unwrap();
    result
}

#[tokio::test]
async fn scram_sql_password_authenticates_and_rotates_without_changing_bearer() {
    let _ = tracing_subscriber::fmt::try_init();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let data = root.join("data");
    let keyring = root.join("keyring.json");
    let bearer_path = root.join("bearer.key");
    onboarding::initialize(&data, "acme", "admin", &keyring, &bearer_path, false).unwrap();
    let bearer = std::fs::read_to_string(bearer_path).unwrap();
    let mut db = Db::open(&data).unwrap();
    db.migrate_table_authority_offline().unwrap();
    let authority = db.identity_authority().unwrap().clone();
    let actor = authority.authenticate(bearer.trim()).unwrap();
    db.execute_sql_authorized(
        &actor,
        SqlExecutionRequest {
            statements: vec![SqlStatementRequest {
                sql: "CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT NOT NULL)".into(),
                parameters: vec![],
            }],
            idempotency_key: None,
            retry_id: Some(uuid::Uuid::new_v4().to_string()),
        },
        "test",
    )
    .unwrap();
    let revision = db.catalog_revision_authorized(&actor).unwrap();
    db.create_protected_collection_authorized(
        &actor,
        revision,
        serde_json::from_value(serde_json::json!({"name":"vectors","vector_dim":2})).unwrap(),
    )
    .unwrap();
    let managed = db.management_identity(&actor).unwrap();
    let policy_context = db
        .bind_access(&managed, "vectors", "acme", Action::PolicyManage)
        .unwrap();
    let (policy_revision, _) = db
        .collection_policy_authorized(&managed, "vectors")
        .unwrap()
        .publish(|policy| policy)
        .unwrap();
    db.replace_collection_policy_authorized(
        &policy_context,
        RevisionUpdate {
            expected_revision: policy_revision,
            value: CollectionPolicy {
                department_actions: BTreeSet::new(),
                owner_actions: BTreeSet::from([Action::Read, Action::Search, Action::Delete]),
                templates: BTreeMap::from([(
                    "pgvector".into(),
                    IngestTemplate {
                        department: "Security".into(),
                        classification: Classification::Internal,
                        properties: BTreeMap::from([(
                            "/id".into(),
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
                                source_fields: BTreeSet::from(["/id".into()]),
                                classification: Classification::Internal,
                            },
                        )]),
                    },
                )]),
            },
        },
    )
    .unwrap();
    let mut principal = actor.principal().clone();
    principal.grants.push(ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: BTreeSet::from(["vectors".into()]),
        actions: BTreeSet::from([
            Action::Read,
            Action::Search,
            Action::Create,
            Action::Ingest,
            Action::Delete,
        ]),
    });
    authority
        .put_principal(&managed, authority.revision(), principal)
        .unwrap();
    let admin = || authority.authenticate(bearer.trim()).unwrap();
    authority
        .create_role(&admin(), authority.revision(), "sql_reader")
        .unwrap();
    db.change_role_table_privileges_authorized(
        &admin(),
        authority.revision(),
        "sql_reader",
        "records",
        BTreeSet::from([Action::Read, Action::Create]),
        true,
    )
    .unwrap();
    authority
        .assign_role(&admin(), authority.revision(), "sql_reader", "admin", true)
        .unwrap();
    db.migrate_sql_scopes_offline().unwrap();
    let actor = authority.authenticate(bearer.trim()).unwrap();
    let principal_id = authority.resolve_user(&actor, "admin").unwrap();
    let issued = issue_sql_over_http(&db, bearer.trim(), &principal_id, authority.revision()).await;
    let actor = authority.authenticate(bearer.trim()).unwrap();
    authority
        .create_user(
            &actor,
            authority.revision(),
            "reader",
            SubjectAttributes {
                department: "Security".into(),
                clearance: Classification::Internal,
            },
        )
        .unwrap();
    let actor = authority.authenticate(bearer.trim()).unwrap();
    let reader_id = authority.resolve_user(&actor, "reader").unwrap();
    let reader_password = authority
        .issue_sql_credential(&actor, authority.revision(), &reader_id)
        .unwrap();

    for (username, password, expected) in [
        ("admin", issued.password.as_str(), true),
        ("admin", "wrong-password", false),
        ("unknown", "wrong-password", false),
    ] {
        let (mut client, mut server) = tokio::io::duplex(16 * 1024);
        let db = db.clone();
        let task = tokio::spawn(async move {
            let mut prefix = [0; 8];
            server.read_exact(&mut prefix).await.unwrap();
            wire_postgres::handle_protected_connection(db, server, prefix)
                .await
                .unwrap();
        });
        assert_eq!(login(&mut client, username, password).await, expected);
        if expected {
            for statement in ["INSERT INTO records VALUES (1, 'wire')"] {
                let sql = format!("{statement}\0");
                send(&mut client, b'Q', sql.as_bytes()).await;
                let mut replies = Vec::new();
                loop {
                    let (kind, body) = message(&mut client).await;
                    replies.push((kind, body));
                    if kind == b'Z' {
                        break;
                    }
                }
                assert!(
                    !replies.iter().any(|(kind, _)| *kind == b'E'),
                    "{statement}: {replies:?}"
                );
            }
            send(&mut client, b'Q', b"SELECT value FROM records\0").await;
            let mut saw_row = false;
            let mut replies = Vec::new();
            loop {
                let (kind, body) = message(&mut client).await;
                replies.push((kind, body));
                if kind == b'D' {
                    saw_row = true;
                }
                if kind == b'Z' {
                    break;
                }
            }
            assert!(saw_row, "{replies:?}");
            for statement in [
                "BEGIN",
                "SAVEPOINT before_insert",
                "INSERT INTO records VALUES (2, 'transaction')",
                "RELEASE SAVEPOINT before_insert",
                "COMMIT",
                "SELECT value FROM records WHERE id = 2",
            ] {
                send(&mut client, b'Q', format!("{statement}\0").as_bytes()).await;
                let mut replies = Vec::new();
                loop {
                    let (kind, body) = message(&mut client).await;
                    replies.push((kind, body));
                    if kind == b'Z' {
                        break;
                    }
                }
                assert!(
                    !replies.iter().any(|(kind, _)| *kind == b'E'),
                    "{statement}: {replies:?}"
                );
                if statement.starts_with("SELECT") {
                    assert!(replies.iter().any(|(kind, _)| *kind == b'D'));
                }
            }
            for statement in [
                "BEGIN",
                "CREATE TABLE private_records (id BIGINT PRIMARY KEY, value TEXT)",
                "INSERT INTO private_records VALUES (1, 'before')",
                "INSERT INTO private_records VALUES (2, 'remove')",
                "UPDATE private_records SET value = 'after' WHERE id = 1",
                "DELETE FROM private_records WHERE id = 2",
                "SELECT value FROM private_records WHERE id = 1",
                "COMMIT",
                "SELECT value FROM private_records WHERE id = 1",
            ] {
                send(&mut client, b'Q', format!("{statement}\0").as_bytes()).await;
                let mut replies = Vec::new();
                loop {
                    let (kind, body) = message(&mut client).await;
                    replies.push((kind, body));
                    if kind == b'Z' {
                        break;
                    }
                }
                assert!(
                    !replies.iter().any(|(kind, _)| *kind == b'E'),
                    "{statement}: {replies:?}"
                );
                if statement.starts_with("SELECT") {
                    assert!(replies.iter().any(|(kind, _)| *kind == b'D'));
                }
            }
            for statement in [
                "CREATE TABLE deferred_wire_parent (id BIGINT PRIMARY KEY)",
                "CREATE TABLE deferred_wire_child (id BIGINT PRIMARY KEY, parent_id BIGINT, CONSTRAINT deferred_wire_fk FOREIGN KEY (parent_id) REFERENCES deferred_wire_parent (id) DEFERRABLE INITIALLY DEFERRED)",
            ] {
                send(&mut client, b'Q', format!("{statement}\0").as_bytes()).await;
                loop {
                    let (kind, body) = message(&mut client).await;
                    assert_ne!(kind, b'E', "{statement}: {body:?}");
                    if kind == b'Z' {
                        break;
                    }
                }
            }
            // Both query protocols must validate pending rows when constraint
            // modes become immediate, then leave rollback reachable.
            for prepared in [false, true] {
                for statement in ["BEGIN", "INSERT INTO deferred_wire_child VALUES (1, 99)"] {
                    send(&mut client, b'Q', format!("{statement}\0").as_bytes()).await;
                    loop {
                        let (kind, body) = message(&mut client).await;
                        assert_ne!(kind, b'E', "{statement}: {body:?}");
                        if kind == b'Z' {
                            break;
                        }
                    }
                }
                if prepared {
                    send(
                        &mut client,
                        b'P',
                        b"\0SET CONSTRAINTS deferred_wire_fk IMMEDIATE\0\0\0",
                    )
                    .await;
                    send(&mut client, b'B', b"\0\0\0\0\0\0\0\0").await;
                    send(&mut client, b'E', &[0, 0, 0, 0, 0]).await;
                    send(&mut client, b'S', &[]).await;
                } else {
                    send(&mut client, b'Q', b"SET CONSTRAINTS ALL IMMEDIATE\0").await;
                }
                let mut violated = false;
                loop {
                    let (kind, body) = message(&mut client).await;
                    if kind == b'E' {
                        assert!(body.windows(6).any(|field| field == b"C23503"), "{body:?}");
                        violated = true;
                    }
                    if kind == b'Z' {
                        assert_eq!(body, b"E", "constraint failure must abort the transaction");
                        break;
                    }
                }
                assert!(
                    violated,
                    "constraint mode was acknowledged without validation"
                );
                send(&mut client, b'Q', b"ROLLBACK\0").await;
                loop {
                    let (kind, body) = message(&mut client).await;
                    assert_ne!(kind, b'E', "rollback: {body:?}");
                    if kind == b'Z' {
                        assert_eq!(body, b"I");
                        break;
                    }
                }
                send(
                    &mut client,
                    b'Q',
                    b"SELECT COUNT(*) FROM deferred_wire_child\0",
                )
                .await;
                let mut zero_rows = false;
                loop {
                    let (kind, body) = message(&mut client).await;
                    assert_ne!(kind, b'E', "count: {body:?}");
                    if kind == b'D' {
                        assert_eq!(body, [0, 1, 0, 0, 0, 1, b'0']);
                        zero_rows = true;
                    }
                    if kind == b'Z' {
                        break;
                    }
                }
                assert!(zero_rows);
            }
            let mut parse = b"\0SELECT value FROM records WHERE id = $1\0".to_vec();
            parse.extend_from_slice(&1i16.to_be_bytes());
            parse.extend_from_slice(&23u32.to_be_bytes());
            send(&mut client, b'P', &parse).await;
            let mut bind = b"\0\0".to_vec();
            bind.extend_from_slice(&0i16.to_be_bytes());
            bind.extend_from_slice(&1i16.to_be_bytes());
            bind.extend_from_slice(&1i32.to_be_bytes());
            bind.extend_from_slice(b"1");
            bind.extend_from_slice(&0i16.to_be_bytes());
            send(&mut client, b'B', &bind).await;
            send(&mut client, b'D', &[b'P', 0]).await;
            send(&mut client, b'E', &[0, 0, 0, 0, 0]).await;
            send(&mut client, b'S', &[]).await;
            let mut replies = Vec::new();
            loop {
                let (kind, body) = message(&mut client).await;
                replies.push((kind, body));
                if kind == b'Z' {
                    break;
                }
            }
            assert!(
                !replies.iter().any(|(kind, _)| *kind == b'E'),
                "{replies:?}"
            );
            assert!(replies.iter().any(|(kind, _)| *kind == b'D'), "{replies:?}");
            assert_eq!(replies.iter().filter(|(kind, _)| *kind == b'T').count(), 1);

            // A portal described before INSERT ... RETURNING must still send
            // RowDescription before its DataRow during Execute.
            let parse = b"returning\0INSERT INTO records (id,value) VALUES (3,'extended') RETURNING id\0\0\0";
            send(&mut client, b'P', parse).await;
            send(
                &mut client,
                b'B',
                b"returning_portal\0returning\0\0\0\0\0\0\0",
            )
            .await;
            send(&mut client, b'D', b"Preturning_portal\0").await;
            send(&mut client, b'E', b"returning_portal\0\0\0\0\0").await;
            send(&mut client, b'S', &[]).await;
            let mut replies = Vec::new();
            loop {
                let (kind, body) = message(&mut client).await;
                replies.push((kind, body));
                if kind == b'Z' {
                    break;
                }
            }
            assert!(
                !replies.iter().any(|(kind, _)| *kind == b'E'),
                "{replies:?}"
            );
            let kinds: Vec<_> = replies.iter().map(|(kind, _)| *kind).collect();
            let row_description = kinds.iter().position(|kind| *kind == b'T').unwrap();
            let data_row = kinds.iter().position(|kind| *kind == b'D').unwrap();
            assert!(row_description < data_row, "{replies:?}");

            for sql in ["SET TIME ZONE 'UTC'", "SET CLIENT_ENCODING TO 'UTF8'"] {
                let mut parse = b"set_option\0".to_vec();
                parse.extend_from_slice(sql.as_bytes());
                parse.extend_from_slice(b"\0\0\0");
                send(&mut client, b'P', &parse).await;
                send(&mut client, b'B', b"set_portal\0set_option\0\0\0\0\0\0\0").await;
                send(&mut client, b'D', b"Pset_portal\0").await;
                send(&mut client, b'E', b"set_portal\0\0\0\0\0").await;
                send(&mut client, b'S', &[]).await;
                let mut replies = Vec::new();
                loop {
                    let (kind, body) = message(&mut client).await;
                    replies.push((kind, body));
                    if kind == b'Z' {
                        break;
                    }
                }
                assert!(
                    !replies.iter().any(|(kind, _)| *kind == b'E'),
                    "{sql}: {replies:?}"
                );
                assert!(
                    replies.iter().any(|(kind, _)| *kind == b'C'),
                    "{sql}: {replies:?}"
                );
            }

            for statement in [
                "INSERT INTO vectors (id, embedding) VALUES (1, '[1.0, 0.0]'::vector)",
                "SELECT id FROM vectors ORDER BY embedding <-> '[1.0, 0.0]'::vector LIMIT 1",
                "DELETE FROM vectors WHERE id = 1",
                "CREATE TABLE transient_vectors (id INTEGER PRIMARY KEY, embedding vector(2))",
                "DROP TABLE transient_vectors",
            ] {
                send(&mut client, b'Q', format!("{statement}\0").as_bytes()).await;
                let mut replies = Vec::new();
                loop {
                    let (kind, body) = message(&mut client).await;
                    replies.push((kind, body));
                    if kind == b'Z' {
                        break;
                    }
                }
                assert!(
                    !replies.iter().any(|(kind, _)| *kind == b'E'),
                    "{statement}: {replies:?}"
                );
                if statement.starts_with("SELECT") {
                    assert!(replies.iter().any(|(kind, _)| *kind == b'D'), "{replies:?}");
                }
                if statement.starts_with("INSERT INTO vectors") {
                    send(&mut client, b'Q', format!("{statement}\0").as_bytes()).await;
                    let mut duplicate = Vec::new();
                    loop {
                        let (kind, body) = message(&mut client).await;
                        if kind == b'E' {
                            duplicate = body;
                        }
                        if kind == b'Z' {
                            break;
                        }
                    }
                    assert!(
                        duplicate.windows(5).any(|window| window == b"23505"),
                        "{duplicate:?}"
                    );
                }
            }
            send(&mut client, b'Q', b"SELECT * FROM pg_catalog.pg_class\0").await;
            let mut catalog_rows = Vec::new();
            loop {
                let (kind, body) = message(&mut client).await;
                if kind == b'D' {
                    catalog_rows.push(body);
                }
                if kind == b'Z' {
                    break;
                }
            }
            assert!(
                catalog_rows
                    .iter()
                    .any(|body| body.windows(7).any(|window| window == b"vectors"))
            );
            assert!(
                catalog_rows.iter().any(|body| body
                    .windows(11)
                    .any(|window| window == b"\0\0\0\x07records")),
                "ON TABLE grants must make SQL-only tables visible to driver introspection"
            );
        }
        drop(client);
        task.await.unwrap();
    }
    assert!(authority.authenticate(bearer.trim()).is_ok());
    assert_eq!(
        authority.sql_verifier_for_user("admin").unwrap().id,
        issued.id
    );
    assert!(authority.authenticate_sql("admin", &issued.id).is_ok());
    assert!(db.durability_ready(), "drop degraded durability");
    assert!(
        db.management_identity(&authority.authenticate_sql("admin", &issued.id).unwrap())
            .is_ok()
    );
    let (mut reader_client, mut reader_server) = tokio::io::duplex(16 * 1024);
    let reader_db = db.clone();
    let reader_task = tokio::spawn(async move {
        let mut prefix = [0; 8];
        reader_server.read_exact(&mut prefix).await.unwrap();
        wire_postgres::handle_protected_connection(reader_db, reader_server, prefix)
            .await
            .unwrap();
    });
    assert!(login(&mut reader_client, "reader", &reader_password.password).await);
    send(&mut reader_client, b'Q', b"SELECT value FROM records\0").await;
    let mut denied = Vec::new();
    loop {
        let (kind, body) = message(&mut reader_client).await;
        if kind == b'E' {
            denied = body;
        }
        if kind == b'Z' {
            break;
        }
    }
    assert!(
        denied.windows(5).any(|window| window == b"42501"),
        "{denied:?}"
    );
    send(
        &mut reader_client,
        b'Q',
        b"SELECT * FROM pg_catalog.pg_class\0",
    )
    .await;
    let mut hidden_rows = Vec::new();
    loop {
        let (kind, body) = message(&mut reader_client).await;
        if kind == b'D' {
            hidden_rows.push(body);
        }
        if kind == b'Z' {
            break;
        }
    }
    assert!(
        !hidden_rows
            .iter()
            .any(|body| body.windows(7).any(|window| window == b"vectors"))
    );
    assert!(!hidden_rows.iter().any(|body| {
        body.windows(11)
            .any(|window| window == b"\0\0\0\x07records")
    }));
    send(&mut reader_client, b'Q', b"SELECT current_user\0").await;
    let mut current_user = Vec::new();
    loop {
        let (kind, body) = message(&mut reader_client).await;
        if kind == b'D' {
            current_user = body;
        }
        if kind == b'Z' {
            break;
        }
    }
    assert!(current_user.windows(6).any(|window| window == b"reader"));
    drop(reader_client);
    reader_task.await.unwrap();
    // A readable vector collection cannot reveal another user's SQL schema.
    let actor = authority.authenticate(bearer.trim()).unwrap();
    let mut reader = authority
        .authenticate_sql("reader", &reader_password.id)
        .unwrap()
        .principal()
        .clone();
    reader.installation_actions.insert(Action::Schema);
    authority
        .put_principal(&actor, authority.revision(), reader)
        .unwrap();
    let reader = authority
        .authenticate_sql("reader", &reader_password.id)
        .unwrap();
    db.execute_sql_authorized(&reader, serde_json::from_value(serde_json::json!({
        "statements":[{"sql":"CREATE TABLE vectors (id BIGINT PRIMARY KEY, confidential_marker TEXT)"}]
    })).unwrap(), "test").unwrap();
    let (mut catalog_client, mut catalog_server) = tokio::io::duplex(16 * 1024);
    let catalog_db = db.clone();
    let catalog_task = tokio::spawn(async move {
        let mut prefix = [0; 8];
        catalog_server.read_exact(&mut prefix).await.unwrap();
        wire_postgres::handle_protected_connection(catalog_db, catalog_server, prefix)
            .await
            .unwrap();
    });
    assert!(login(&mut catalog_client, "admin", &issued.password).await);
    send(
        &mut catalog_client,
        b'Q',
        b"SELECT table_name, column_name FROM information_schema.columns\0",
    )
    .await;
    let mut visible_columns = 0;
    loop {
        let (kind, body) = message(&mut catalog_client).await;
        assert_ne!(kind, b'E', "catalog query must be supported: {body:?}");
        visible_columns += usize::from(kind == b'D');
        assert!(
            !body
                .windows(b"confidential_marker".len())
                .any(|window| window == b"confidential_marker"),
            "forbidden SQL column leaked"
        );
        if kind == b'Z' {
            break;
        }
    }
    assert!(visible_columns > 0, "granted table columns remain visible");
    drop(catalog_client);
    catalog_task.await.unwrap();
    assert_overload_recovery(&db, &issued.password).await;
    assert_tls_gate(db.clone(), &root, &issued.password).await;
    let (mut stale_client, mut stale_server) = tokio::io::duplex(16 * 1024);
    let stale_db = db.clone();
    let stale_task = tokio::spawn(async move {
        let mut prefix = [0; 8];
        stale_server.read_exact(&mut prefix).await.unwrap();
        wire_postgres::handle_protected_connection(stale_db, stale_server, prefix)
            .await
            .unwrap();
    });
    assert!(login(&mut stale_client, "admin", &issued.password).await);
    let actor = authority.authenticate(bearer.trim()).unwrap();
    let rotated = authority
        .issue_sql_credential(&actor, authority.revision(), &principal_id)
        .unwrap();
    send(&mut stale_client, b'Q', b"SELECT current_user\0").await;
    let (kind, revoked_body) = message(&mut stale_client).await;
    assert_eq!(kind, b'E');
    assert!(revoked_body.windows(5).any(|window| window == b"28000"));
    drop(stale_client);
    stale_task.await.unwrap();
    assert!(!login_once(&db, "admin", &issued.password).await);
    assert!(login_once(&db, "admin", &rotated.password).await);
    let actor = authority.authenticate(bearer.trim()).unwrap();
    authority
        .revoke_credential(&actor, authority.revision(), &rotated.id)
        .unwrap();
    assert!(!login_once(&db, "admin", &rotated.password).await);
    assert!(authority.authenticate(bearer.trim()).is_ok());
    drop(authority);
    drop(db);
    let reopened = Db::open(&data).unwrap();
    assert!(reopened.durability_ready());
    let actor = reopened
        .identity_authority()
        .unwrap()
        .authenticate(bearer.trim())
        .unwrap();
    assert!(
        !reopened
            .protected_collection_exists_admin(&actor, "transient_vectors")
            .unwrap()
    );
    assert!(
        reopened
            .protected_collection_exists_admin(&actor, "vectors")
            .unwrap()
    );
    assert_eq!(
        reopened
            .relational_tables()
            .iter()
            .filter(|table| table.name == "records")
            .count(),
        1
    );
}

async fn assert_overload_recovery(db: &Db, password: &str) {
    use std::time::Duration;
    let authority = db.identity_authority().unwrap();
    let work_pool = authority.work_pool();
    let work_capacity = work_pool.available_permits();
    let frames = authority.frame_pool();
    let frame_capacity = frames.available_permits();
    let (mut client, mut server) = tokio::io::duplex(16 * 1024);
    let server_db = db.clone();
    let task = tokio::spawn(async move {
        let mut prefix = [0; 8];
        server.read_exact(&mut prefix).await.unwrap();
        wire_postgres::handle_protected_connection(server_db, server, prefix)
            .await
            .unwrap();
    });
    assert!(login(&mut client, "admin", password).await);
    async fn query(stream: &mut tokio::io::DuplexStream, sql: &str) -> Vec<(u8, Vec<u8>)> {
        send(stream, b'Q', format!("{sql}\0").as_bytes()).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut replies = Vec::new();
            loop {
                let reply = message(stream).await;
                let done = reply.0 == b'Z';
                replies.push(reply);
                if done {
                    return replies;
                }
            }
        })
        .await
        .expect("overload response must finish with ReadyForQuery")
    }
    fn assert_error(replies: &[(u8, Vec<u8>)], state: &[u8], transaction: u8) {
        assert_eq!(replies.len(), 2, "one error followed by ReadyForQuery");
        assert_eq!(replies[0].0, b'E');
        assert!(
            replies[0]
                .1
                .windows(state.len())
                .any(|value| value == state)
        );
        assert_eq!(replies[1], (b'Z', vec![transaction]));
    }
    let occupied = work_pool
        .clone()
        .acquire_many_owned(work_capacity as u32)
        .await
        .unwrap();
    assert_error(
        &query(&mut client, "CREATE TABLE never_admitted (id BIGINT)").await,
        b"53300",
        b'I',
    );
    assert!(
        !db.relational_tables()
            .iter()
            .any(|table| table.name == "never_admitted")
    );

    let mut parse = b"overloaded\0SELECT current_user\0".to_vec();
    parse.extend_from_slice(&0i16.to_be_bytes());
    send(&mut client, b'P', &parse).await;
    send(&mut client, b'E', b"\0\0\0\0\0").await;
    send(&mut client, b'S', &[]).await;
    let first = tokio::time::timeout(Duration::from_secs(2), message(&mut client))
        .await
        .unwrap();
    let ready = tokio::time::timeout(Duration::from_secs(2), message(&mut client))
        .await
        .unwrap();
    assert_error(&[first, ready], b"53300", b'I');
    drop(occupied);

    for sql in [
        "CREATE TABLE overload_rows (id BIGINT PRIMARY KEY)",
        "BEGIN",
        "INSERT INTO overload_rows VALUES (1)",
    ] {
        assert!(
            query(&mut client, sql)
                .await
                .iter()
                .all(|reply| reply.0 != b'E')
        );
    }
    let occupied = work_pool
        .clone()
        .acquire_many_owned(work_capacity as u32)
        .await
        .unwrap();
    assert_error(
        &query(&mut client, "INSERT INTO overload_rows VALUES (2)").await,
        b"53300",
        b'E',
    );
    let rollback = query(&mut client, "ROLLBACK").await;
    assert_eq!(
        rollback,
        vec![(b'C', b"ROLLBACK\0".to_vec()), (b'Z', vec![b'I'])]
    );
    drop(occupied);
    let rows = query(&mut client, "SELECT id FROM overload_rows").await;
    assert!(
        rows.iter().all(|reply| !matches!(reply.0, b'D' | b'E')),
        "overloaded transaction must not publish rows"
    );
    assert_eq!(work_pool.available_permits(), work_capacity);
    assert_eq!(
        frames.available_permits(),
        frame_capacity,
        "idle session retains no frame"
    );

    async fn extended(
        stream: &mut tokio::io::DuplexStream,
        kind: u8,
        payload: &[u8],
    ) -> Vec<(u8, Vec<u8>)> {
        send(stream, kind, payload).await;
        send(stream, b'S', &[]).await;
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut replies = Vec::new();
            loop {
                let reply = message(stream).await;
                let ready = reply.0 == b'Z';
                replies.push(reply);
                if ready {
                    return replies;
                }
            }
        })
        .await
        .unwrap()
    }
    let mut admitted_before = None;
    assert!(
        !query(
            &mut client,
            "CREATE TABLE memory_rows (id BIGINT PRIMARY KEY, payload JSONB)"
        )
        .await
        .iter()
        .any(|reply| reply.0 == b'E')
    );
    for _ in 0..2 {
        let mut parse = b"memory\0INSERT INTO memory_rows (id, payload) VALUES (1, $1)\0".to_vec();
        parse.extend_from_slice(&1i16.to_be_bytes());
        parse.extend_from_slice(&3802u32.to_be_bytes());
        let replies = extended(&mut client, b'P', &parse).await;
        assert!(replies.iter().any(|reply| reply.0 == b'1'));
        assert!(!replies.iter().any(|reply| reply.0 == b'E'));
        let json = format!("[{}]", vec!["null"; 20000].join(","));
        let mut admitted = 0;
        for index in 0..32 {
            let mut bind = format!("memory_{index}\0memory\0").into_bytes();
            bind.extend_from_slice(&0i16.to_be_bytes());
            bind.extend_from_slice(&1i16.to_be_bytes());
            bind.extend_from_slice(&(json.len() as i32).to_be_bytes());
            bind.extend_from_slice(json.as_bytes());
            bind.extend_from_slice(&0i16.to_be_bytes());
            let replies = extended(&mut client, b'B', &bind).await;
            if replies.iter().any(|reply| reply.0 == b'E') {
                assert_error(&replies, b"53200", b'I');
                break;
            }
            assert!(replies.iter().any(|reply| reply.0 == b'2'));
            admitted += 1;
        }
        assert!(
            (1..32).contains(&admitted),
            "byte admission must reject before the object-count limit"
        );
        assert_eq!(
            *admitted_before.get_or_insert(admitted),
            admitted,
            "cleanup must return the same capacity"
        );
        for index in 1..admitted {
            let replies =
                extended(&mut client, b'C', format!("Pmemory_{index}\0").as_bytes()).await;
            assert!(replies.iter().any(|reply| reply.0 == b'3'));
        }
        let mut execute = b"memory_0\0".to_vec();
        execute.extend_from_slice(&0u32.to_be_bytes());
        let replies = extended(&mut client, b'E', &execute).await;
        assert!(
            !replies.iter().any(|reply| reply.0 == b'E'),
            "an earlier binding survives refusal and executes after cleanup: {:?}",
            replies
                .iter()
                .filter(|reply| reply.0 == b'E')
                .map(|reply| String::from_utf8_lossy(&reply.1))
                .collect::<Vec<_>>()
        );
        assert!(replies.iter().any(|reply| reply.0 == b'C'));
        assert!(
            query(&mut client, "SELECT COUNT(*) FROM memory_rows")
                .await
                .iter()
                .any(|reply| reply.0 == b'D' && reply.1.ends_with(b"1"))
        );
        let cleanup = query(&mut client, "DEALLOCATE ALL").await;
        assert!(!cleanup.iter().any(|reply| reply.0 == b'E'));
        assert!(
            !query(&mut client, "DELETE FROM memory_rows")
                .await
                .iter()
                .any(|reply| reply.0 == b'E')
        );
    }
    println!(
        "protected session byte admission: {} JSONB portals admitted; two capacity/refusal/cleanup cycles passed",
        admitted_before.unwrap()
    );
    assert!(
        !query(&mut client, "DROP TABLE memory_rows")
            .await
            .iter()
            .any(|reply| reply.0 == b'E')
    );

    let occupied = frames
        .clone()
        .acquire_many_owned(frame_capacity as u32)
        .await
        .unwrap();
    // Send only the header: refusal must precede payload allocation or reading.
    client.write_all(b"Q").await.unwrap();
    client
        .write_all(&(8u32 * 1024 * 1024).to_be_bytes())
        .await
        .unwrap();
    let (kind, error) = tokio::time::timeout(Duration::from_secs(2), message(&mut client))
        .await
        .unwrap();
    assert_eq!(kind, b'E');
    assert!(error.windows(5).any(|value| value == b"53300"));
    drop(client);
    task.await.unwrap();
    drop(occupied);
    assert_eq!(frames.available_permits(), frame_capacity);
}

async fn assert_tls_gate(db: Db, root: &std::path::Path, password: &str) {
    let authority = db.identity_authority().unwrap().clone();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca).unwrap();
    let ca_path = root.join("ca.pem");
    std::fs::write(&ca_path, ca.pem()).unwrap();
    let cert_path = root.join("server.pem");
    let key_path = root.join("server.key");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(wire::serve_tls_listener_with_auth(
        db,
        AuthConfig::disabled(),
        listener,
        cert_path.clone(),
        key_path,
        None,
    ));

    let mut tcp = TcpStream::connect(address).await.unwrap();
    tcp.write_all(&8u32.to_be_bytes()).await.unwrap();
    tcp.write_all(&wire_postgres::SSL_REQUEST_MAGIC.to_be_bytes())
        .await
        .unwrap();
    let mut accepted = [0u8; 1];
    tcp.read_exact(&mut accepted).await.unwrap();
    assert_eq!(accepted, [b'S']);
    let mut config = tls::client_config(ca_path, None).await.unwrap();
    config.alpn_protocols = vec![b"postgresql".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let mut tls_stream = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(
        tls_stream.get_ref().1.alpn_protocol(),
        Some(b"postgresql".as_slice())
    );
    let backend = login_with_backend(&mut tls_stream, "admin", password)
        .await
        .unwrap();
    let connections = authority.wire_connection_pool();
    let frames = authority.frame_pool();
    let work = authority.work_pool();
    let controls = authority.wire_control_pool();
    let control_capacity = controls.available_permits();
    let occupied_connections = connections
        .clone()
        .acquire_many_owned(connections.available_permits() as u32)
        .await
        .unwrap();
    let occupied_frames = frames
        .clone()
        .acquire_many_owned(frames.available_permits() as u32)
        .await
        .unwrap();
    let occupied_work = work
        .clone()
        .acquire_many_owned(work.available_permits() as u32)
        .await
        .unwrap();
    // The bounded control lane remains reachable with every ordinary slot held.
    for cancel_request in [true, false] {
        let mut tcp = TcpStream::connect(address).await.unwrap();
        tcp.write_all(&8u32.to_be_bytes()).await.unwrap();
        tcp.write_all(&wire_postgres::SSL_REQUEST_MAGIC.to_be_bytes())
            .await
            .unwrap();
        let mut accepted = [0u8; 1];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tcp.read_exact(&mut accepted),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(accepted, [b'S']);
        let mut control = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        if cancel_request {
            control.write_all(&16u32.to_be_bytes()).await.unwrap();
            control
                .write_all(&wire_postgres::CANCEL_REQUEST_MAGIC.to_be_bytes())
                .await
                .unwrap();
            control.write_all(&backend).await.unwrap();
            control.flush().await.unwrap();
            let mut eof = [0u8; 1];
            assert_eq!(
                tokio::time::timeout(std::time::Duration::from_secs(2), control.read(&mut eof))
                    .await
                    .unwrap()
                    .unwrap(),
                0,
                "cancel receives clean TLS EOF under saturation"
            );
        } else {
            // Extra control slots must never admit ordinary SQL sessions.
            control.write_all(&12u32.to_be_bytes()).await.unwrap();
            control
                .write_all(&wire_postgres::PROTOCOL_V3.to_be_bytes())
                .await
                .unwrap();
            control.write_all(b"\0\0\0\0").await.unwrap();
            control.flush().await.unwrap();
            let (kind, body) =
                tokio::time::timeout(std::time::Duration::from_secs(2), message(&mut control))
                    .await
                    .unwrap();
            assert_eq!(kind, b'E');
            assert!(body.windows(5).any(|value| value == b"53300"));
        }
    }
    let restored_controls = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        controls.clone().acquire_many_owned(control_capacity as u32),
    )
    .await
    .unwrap()
    .unwrap();
    drop(restored_controls);
    drop((occupied_connections, occupied_frames, occupied_work));
    send(&mut tls_stream, b'Q', b"SELECT current_user\0").await;
    loop {
        let (kind, _) = message(&mut tls_stream).await;
        assert_ne!(kind, b'E', "idle cancel must not poison the next query");
        if kind == b'Z' {
            break;
        }
    }
    drop(tls_stream);

    let mut plain = TcpStream::connect(address).await.unwrap();
    plain.write_all(&12u32.to_be_bytes()).await.unwrap();
    plain
        .write_all(&wire_postgres::PROTOCOL_V3.to_be_bytes())
        .await
        .unwrap();
    plain.write_all(b"\0\0\0\0").await.unwrap();
    let mut response = [0u8; 1];
    let plain_result =
        tokio::time::timeout(std::time::Duration::from_secs(3), plain.read(&mut response))
            .await
            .unwrap();
    assert!(matches!(plain_result, Ok(0) | Err(_)) || response[0] != b'R');
    server.abort();
}
