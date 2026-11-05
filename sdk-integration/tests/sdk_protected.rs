//! Application SDK against the actual provisioned TLS server, not a mock authority.
use chirondb_client::{ChironDbClient, NewPoint, Point, ProtectedSearchQuery, ScrollRequest};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tempfile::TempDir;

struct Lab {
    root: TempDir,
    base: String,
    port: u16,
    child: Option<Child>,
    http: reqwest::Client,
    admin: String,
    cert: Vec<u8>,
}

impl Lab {
    async fn start() -> Self {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().canonicalize().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let init = Command::new(qualified_bin("chironctl"))
            .args([
                "security",
                "init",
                "--tenant",
                "acme",
                "--admin",
                "admin",
                "--data-dir",
            ])
            .arg(path.join("data"))
            .arg("--keyring-out")
            .arg(path.join("storage.json"))
            .arg("--admin-key-out")
            .arg(path.join("admin.key"))
            .output()
            .unwrap();
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = cert.pem().into_bytes();
        std::fs::write(path.join("cert.pem"), &cert).unwrap();
        std::fs::write(path.join("key.pem"), signing_key.serialize_pem()).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let http = reqwest::Client::builder()
            .tls_certs_merge([reqwest::Certificate::from_pem(&cert).unwrap()])
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let admin = std::fs::read_to_string(path.join("admin.key"))
            .unwrap()
            .trim()
            .to_string();
        let mut lab = Self {
            root,
            base: format!("https://localhost:{port}"),
            port,
            child: None,
            http,
            admin,
            cert,
        };
        lab.restart().await;
        lab.query("CREATE PROTECTED COLLECTION docs DIM 2 METRIC cosine;");
        lab.query("ALTER COLLECTION docs SET SECURITY POLICY {department_actions:[],owner_actions:['read','search','update','delete'],templates:{finance:{department:'Finance',classification:'internal',properties:{'/text':{classification:'internal',actions:['read','query','write']}},representations:{dense:{source_fields:['/text'],classification:'internal'}}}}};");
        lab
    }

    fn path(&self) -> PathBuf {
        self.root.path().canonicalize().unwrap()
    }

    async fn restart(&mut self) {
        self.stop();
        let path = self.path();
        let mut command = Command::new(qualified_bin("chirondb"));
        for (key, _) in std::env::vars() {
            if key.starts_with("CHIRONDB_")
                || key.starts_with("GAUSSDB_")
                || key.starts_with("OTEL_")
            {
                command.env_remove(key);
            }
        }
        self.child = Some(
            command
                .arg("--data-dir")
                .arg(path.join("data"))
                .arg("--listen-http")
                .arg(format!("127.0.0.1:{}", self.port))
                .args([
                    "--listen-grpc",
                    "127.0.0.1:0",
                    "--listen-wire",
                    "127.0.0.1:0",
                    "--tenant-enforcement",
                    "enforced",
                ])
                .arg("--tls-cert")
                .arg(path.join("cert.pem"))
                .arg("--tls-key")
                .arg(path.join("key.pem"))
                .arg("--encryption-keyring-file")
                .arg(path.join("storage.json"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        for _ in 0..200 {
            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "server exited"
            );
            if self
                .http
                .get(format!("{}/health", self.base))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("server readiness timeout");
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn query(&self, query: &str) {
        let result = Command::new(qualified_bin("chironql"))
            .arg("--url")
            .arg(&self.base)
            .arg("--ca-cert")
            .arg(self.path().join("cert.pem"))
            .arg("--api-key-file")
            .arg(self.path().join("admin.key"))
            .arg("--exec")
            .arg(query)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    async fn raw(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Value {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.admin);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        assert!(
            response.status().is_success(),
            "provisioning status {}",
            response.status()
        );
        response.json().await.unwrap()
    }

    async fn revision(&self) -> u64 {
        self.raw(reqwest::Method::GET, "/security/whoami", None)
            .await["identity_revision"]
            .as_u64()
            .unwrap()
    }

    async fn user(&self, id: &str, actions: &[&str]) -> Value {
        self.raw(reqwest::Method::PUT,"/security/principals",Some(json!({"expected_revision":self.revision().await,
            "value":{"id":id,"tenant":"acme","enabled":true,"attributes":{"department":"Finance","clearance":"restricted"},
                "grants":[{"tenants":["acme"],"collections":["docs"],"actions":actions}],"installation_actions":[],"delegation":[]}}))).await;
        self.raw(
            reqwest::Method::POST,
            "/security/credentials",
            Some(json!({"expected_revision":self.revision().await,"principal":id})),
        )
        .await
    }
}
impl Drop for Lab {
    fn drop(&mut self) {
        self.stop();
    }
}

fn new_point(text: &str) -> NewPoint {
    NewPoint {
        vector: vec![1., 0.],
        vectors: Default::default(),
        sparse_vector: None,
        payload: json!({"text":text}),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protected_model_views_preserve_atomic_allocations_and_table_authority() {
    use chirondb_client::{ChironQlRequest, RelationalValue as V, TransactionState};
    let mut lab = Lab::start().await;
    let writer = lab
        .user(
            "writer",
            &["read", "search", "create", "ingest", "update", "delete"],
        )
        .await;
    lab.query("ALTER COLLECTION docs SET SECURITY POLICY {department_actions:[],owner_actions:['read','search','update','delete','graph_read','graph_write'],templates:{finance:{department:'Finance',classification:'internal',properties:{'/text':{classification:'internal',actions:['read','query','write']}},representations:{dense:{source_fields:['/text'],classification:'internal'}}}}};");
    lab.query("ALTER COLLECTION docs SET GRAPH ENABLED;");
    lab.query("ALTER COLLECTION docs SET EDGE TYPE cites;");
    lab.query("SQL CREATE TABLE documents (id TEXT PRIMARY KEY, title TEXT, chunk RECORD_REF('docs'), source RECORD_REF('docs'));");
    lab.query("CREATE ROLE sdk_editor;");
    lab.stop();
    for migration in ["migrate-table-authority", "migrate-sql-scopes"] {
        let result = Command::new(qualified_bin("chironctl"))
            .args(["security", migration, "--data-dir"])
            .arg(lab.path().join("data"))
            .arg("--keyring")
            .arg(lab.path().join("storage.json"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    lab.restart().await;
    lab.query("GRANT READ, CREATE, UPDATE, DELETE ON TABLE documents TO ROLE sdk_editor;");
    lab.query("GRANT GRAPH_READ, GRAPH_WRITE ON COLLECTION docs TO ROLE sdk_editor;");
    lab.query("GRANT ROLE sdk_editor TO USER writer;");
    let client = ChironDbClient::new(&lab.base)
        .with_api_key(writer["secret"].as_str().unwrap())
        .with_ca_certificate(&lab.cert)
        .unwrap();
    let app = client.protected();
    let request = ChironQlRequest { query: "TRANSACTION { SQL INSERT INTO documents VALUES ('doc',$1,RECORD_REF('docs',NEW_RECORD('chunk')),RECORD_REF('docs',NEW_RECORD('source'))); EXPECT SQL ROWS 1; VECTOR CREATE POINTS INTO docs USING TEMPLATE finance {binding:'chunk',point:{vector:[1,0],payload:{text:'chunk'}}},{binding:'source',point:{vector:[0,1],payload:{text:'source'}}}; GRAPH CONNECT docs NEW chunk -> cites -> NEW source SET {kind:'source'}; };".into(), parameters: vec![V::Text("protected".into())], idempotency_key: Some("rust-protected-three-models".into()), ..Default::default() };
    let result = app.query(&request).await.unwrap();
    let replay = app.query(&request).await.unwrap();
    assert_eq!(result.rows, replay.rows);
    assert_eq!(result.transaction_id, replay.transaction_id);
    let chunk = result
        .rows
        .iter()
        .find(|r| r["binding"] == "chunk")
        .unwrap()["record_ref"]["id"]
        .as_str()
        .unwrap();
    for output in ["NODES", "EDGES", "PATHS"] {
        let traverse = ChironQlRequest {
            query: format!(
                "TRAVERSE docs FROM '{chunk}' VIA cites DEPTH 1 WITH PAYLOAD RETURN {output} LIMIT 10;"
            ),
            ..Default::default()
        };
        let rows = app.graph().query(&traverse).await.unwrap();
        assert!(!rows.rows.is_empty());
        assert!(rows.stats.searched.is_none());
    }
    assert!(
        app.vector()
            .delete("docs", vec![chunk.into()])
            .await
            .is_err()
    );
    let text = app
        .vector()
        .text_hybrid_search(
            "docs",
            chirondb_client::TextHybridQuery {
                vector: vec![],
                query: "chunk".into(),
                text_field: "text".into(),
                k: 10,
                filter: None,
                budget_ms: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(text.hits.len(), 1);
    let tx = app.relational().begin().await.unwrap();
    tx.sql(
        "UPDATE documents SET title=$1",
        vec![V::Text("interactive".into())],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        app.transaction_status(tx.transaction_id.as_deref().unwrap())
            .await
            .unwrap()
            .state,
        TransactionState::Committed
    );
    lab.restart().await;
    assert_eq!(
        app.query(&request).await.unwrap().transaction_id,
        result.transaction_id
    );
    lab.query("REVOKE READ ON TABLE documents FROM ROLE sdk_editor;");
    assert!(
        app.relational()
            .sql("SELECT * FROM documents", vec![])
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protected_sdk_preserves_server_ids_current_authority_and_tls() {
    let mut lab = Lab::start().await;
    let writer = lab
        .user(
            "writer",
            &["read", "search", "create", "ingest", "update", "delete"],
        )
        .await;
    let hidden = lab.user("hidden", &["read", "search"]).await;
    let db = ChironDbClient::new(&lab.base)
        .with_api_key(writer["secret"].as_str().unwrap())
        .with_ca_certificate(&lab.cert)
        .unwrap()
        .with_timeout(Duration::from_secs(10));
    let app = db.protected();
    assert_eq!(app.whoami().await.unwrap().principal, "writer");
    assert!(app.whoami().await.unwrap().identity_revision.is_none());
    let text = "O'Brien 日本語 \\ path\n'; DROP ROLE admin; --";
    let ids = app
        .create_points("docs", "finance", vec![new_point(text)], "request")
        .await
        .unwrap();
    assert_eq!(
        app.create_points("docs", "finance", vec![new_point(text)], "request")
            .await
            .unwrap(),
        ids
    );
    let conflict = app
        .create_points("docs", "finance", vec![new_point("changed")], "request")
        .await
        .unwrap_err();
    assert_eq!(
        conflict.api_details().unwrap().code.as_deref(),
        Some("security.conflict")
    );
    assert_eq!(
        app.get_points("docs", ids.clone()).await.unwrap()[0].payload["text"],
        text
    );
    let nested = json!({"quoted": text, "items": [null, true, 1.25, {"x": "\\'"}]});
    let mut nested_point = new_point(text);
    nested_point.payload = json!({"text": nested});
    let nested_ids = app
        .create_points("docs", "finance", vec![nested_point], "nested")
        .await
        .unwrap();
    assert_eq!(
        app.get_points("docs", nested_ids.clone()).await.unwrap()[0].payload["text"],
        nested
    );
    assert_eq!(app.delete("docs", nested_ids).await.unwrap(), 1);
    assert_eq!(app.count("docs", None).await.unwrap(), 1);
    assert_eq!(
        app.scroll(
            "docs",
            ScrollRequest {
                offset: None,
                limit: 1,
                filter: None
            }
        )
        .await
        .unwrap()
        .points[0]
            .id,
        ids[0]
    );
    let query = ProtectedSearchQuery {
        vector: vec![1., 0.],
        recall_target: Some(0.95),
        ..Default::default()
    };
    assert_eq!(app.search("docs", query).await.unwrap().hits[0].id, ids[0]);
    let other = ChironDbClient::new(&lab.base)
        .with_http_client(lab.http.clone())
        .with_api_key(hidden["secret"].as_str().unwrap());
    assert!(
        other
            .protected()
            .get_points("docs", ids.clone())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(other.protected().count("docs", None).await.unwrap(), 0);
    assert_eq!(
        db.enable_graph("docs", true)
            .await
            .unwrap_err()
            .api_details()
            .unwrap()
            .code
            .as_deref(),
        Some("security.forbidden")
    );
    assert_eq!(
        app.update_points(
            "docs",
            vec![Point {
                id: ids[0].clone(),
                vector: vec![0., 1.],
                payload: json!({"text":"updated"}),
                ..Default::default()
            }],
            true
        )
        .await
        .unwrap(),
        1
    );
    lab.restart().await;
    assert_eq!(
        app.create_points("docs", "finance", vec![new_point(text)], "request")
            .await
            .unwrap(),
        ids
    );
    assert_eq!(
        app.get_points("docs", ids.clone()).await.unwrap()[0].payload["text"],
        "updated"
    );
    assert_eq!(
        app.delete_by_filter("docs", json!({"text":"updated"}))
            .await
            .unwrap(),
        1
    );
    let extra = app
        .create_points("docs", "finance", vec![new_point(text)], "delete-request")
        .await
        .unwrap();
    assert_eq!(app.delete("docs", extra).await.unwrap(), 1);
    lab.raw(
        reqwest::Method::POST,
        &format!(
            "/security/credentials/{}/revoke",
            writer["id"].as_str().unwrap()
        ),
        Some(json!({"expected_revision":lab.revision().await})),
    )
    .await;
    assert_eq!(
        app.count("docs", None)
            .await
            .unwrap_err()
            .api_details()
            .unwrap()
            .code
            .as_deref(),
        Some("security.unauthenticated")
    );
    assert!(ChironDbClient::new(&lab.base).health().await.is_err());
    // The fixture contains secrets, so assert only that outputs remain private.
    assert!(lab.path().join("admin.key").exists());
}

fn qualified_bin(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var_os("CHIRONDB_BIN_DIR").expect("set CHIRONDB_BIN_DIR"))
        .join(name)
}
