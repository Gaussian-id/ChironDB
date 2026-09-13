//! P7 gate — row-level tenant isolation, end to end against a real `Db`.
//!
//! One test per decision, plus the rollout property that makes the whole thing
//! deployable: enforcement is off until an operator turns it on, so a database
//! that predates this keeps working while its rows are backfilled.

use chirondb::chironql_exec::{ExecContext, Session};
use chirondb::rbac::{ApiKeyEntry, Role};
use chirondb::tenant::{TenantCapability, TenantEnforcement, TenantScope};
use chirondb::{CollectionConfig, Db, DistanceMetric, Point};
use chirondb_types::chironql::{ChironQlError, ChironQlResponse};
use serde_json::json;
use tempfile::TempDir;

const COLLECTION: &str = "products";

/// Two tenants and one legacy row that predates tenant stamping.
fn fixture() -> (TempDir, Db) {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    db.create_collection(CollectionConfig {
        name: COLLECTION.to_string(),
        vector_dim: 3,
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
    .expect("create collection");

    db.upsert(
        COLLECTION,
        vec![
            Point {
                id: "acme-1".to_string(),
                vector: vec![1.0, 0.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"tenant_id": "acme", "category": "electronics"}),
            },
            Point {
                id: "acme-2".to_string(),
                vector: vec![0.9, 0.1, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"tenant_id": "acme", "category": "media"}),
            },
            Point {
                id: "globex-1".to_string(),
                vector: vec![1.0, 0.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"tenant_id": "globex", "category": "electronics"}),
            },
            Point {
                id: "legacy-1".to_string(),
                vector: vec![1.0, 0.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"category": "electronics"}),
            },
        ],
    )
    .expect("seed");

    (dir, db)
}

fn acme() -> TenantScope {
    TenantScope::tenant("acme-key", "acme")
}

fn globex() -> TenantScope {
    TenantScope::tenant("globex-key", "globex")
}

fn run(db: &Db, query: &str, scope: &TenantScope) -> Result<ChironQlResponse, ChironQlError> {
    let mut session = Session::default();
    let mut ctx = ExecContext {
        db,
        session: &mut session,
        role: Role::ReadWrite,
        allowed_collections: None,
        want_trace: true,
        confirm: true,
        tenant: scope.clone(),
    };
    chirondb::chironql_exec::execute(&mut ctx, query)
}

fn ids(response: &ChironQlResponse) -> Vec<String> {
    let mut ids: Vec<String> = response
        .rows
        .iter()
        .map(|row| row["id"].as_str().unwrap_or_default().to_string())
        .collect();
    ids.sort();
    ids
}

// ---------------------------------------------------------------------------
// Rollout: off until switched on
// ---------------------------------------------------------------------------

#[test]
fn enforcement_is_off_by_default_so_existing_deployments_are_unchanged() {
    let (_dir, db) = fixture();
    assert_eq!(db.tenant_enforcement(), TenantEnforcement::Disabled);

    // Every row, including the untenanted one, is reachable as before.
    let response = run(&db, "SCROLL products LIMIT 10;", &acme()).expect("scroll");
    assert_eq!(
        ids(&response),
        vec!["acme-1", "acme-2", "globex-1", "legacy-1"]
    );
}

#[test]
fn unscoped_entry_points_deny_once_enforcement_is_on() {
    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    // A surface that has not been taught about tenants calls this. It must
    // fail loudly rather than serve rows with no scope — that is what makes
    // omission safe rather than a silent leak.
    let error = db.count(COLLECTION, None).expect_err("denied");
    assert!(error.to_string().contains("tenant scope"), "{error}");

    // The scoped path works.
    let counted = db
        .count_scoped(COLLECTION, None, &acme())
        .expect("scoped count");
    assert_eq!(counted.count, 2);
}

// ---------------------------------------------------------------------------
// Decision 1: reads are scoped to the caller's own tenant
// ---------------------------------------------------------------------------

#[test]
fn a_tenant_sees_only_its_own_rows() {
    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    let seen = run(&db, "SCROLL products LIMIT 10;", &acme()).expect("scroll");
    assert_eq!(ids(&seen), vec!["acme-1", "acme-2"]);

    let seen = run(&db, "SCROLL products LIMIT 10;", &globex()).expect("scroll");
    assert_eq!(ids(&seen), vec!["globex-1"]);
}

#[test]
fn a_search_cannot_reach_another_tenants_rows() {
    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    // globex-1 and legacy-1 sit at exactly the query vector; only acme's own
    // rows may come back.
    let hits = run(
        &db,
        "SEARCH products NEAR [1,0,0] LIMIT 10 WITH PAYLOAD;",
        &acme(),
    )
    .expect("search");

    assert_eq!(ids(&hits), vec!["acme-1", "acme-2"]);
}

#[test]
fn a_caller_cannot_widen_its_own_scope_with_a_filter() {
    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    // Asking for someone else's tenant is refused rather than quietly
    // answered with the caller's own rows: the same rule writes follow, so a
    // client bug surfaces instead of hiding.
    let error = run(
        &db,
        "SEARCH products NEAR [1,0,0] WHERE tenant_id = 'globex' LIMIT 10;",
        &acme(),
    )
    .expect_err("refused");
    assert!(error.error.contains("cross_read"), "{}", error.error);

    // Naming its own tenant is redundant but harmless.
    let hits = run(
        &db,
        "SEARCH products NEAR [1,0,0] WHERE tenant_id = 'acme' LIMIT 10;",
        &acme(),
    )
    .expect("search");
    assert_eq!(ids(&hits), vec!["acme-1", "acme-2"]);
}

#[test]
fn fetching_another_tenants_point_by_id_returns_nothing() {
    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    // Not "forbidden": telling a caller that an id exists but is not theirs is
    // itself a disclosure.
    let response = run(&db, "GET products POINTS globex-1;", &acme()).expect("get");
    assert!(response.rows.is_empty());

    let response = run(&db, "GET products POINTS acme-1;", &acme()).expect("get");
    assert_eq!(ids(&response), vec!["acme-1"]);
}

#[test]
fn count_reflects_only_the_callers_rows() {
    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    let counted = run(&db, "COUNT products;", &acme()).expect("count");
    assert_eq!(counted.rows[0]["count"], json!(2));

    let counted = run(&db, "COUNT products;", &globex()).expect("count");
    assert_eq!(counted.rows[0]["count"], json!(1));
}

// ---------------------------------------------------------------------------
// Decision 3: a point with no tenant belongs to nobody
// ---------------------------------------------------------------------------

#[test]
fn a_legacy_point_without_a_tenant_is_visible_to_nobody() {
    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    for scope in [acme(), globex()] {
        let seen = run(&db, "SCROLL products LIMIT 10;", &scope).expect("scroll");
        assert!(
            !ids(&seen).contains(&"legacy-1".to_string()),
            "an untenanted row leaked to {:?}",
            scope.tenant_id()
        );

        let fetched = run(&db, "GET products POINTS legacy-1;", &scope).expect("get");
        assert!(fetched.rows.is_empty());
    }
}

#[test]
fn a_legacy_point_is_still_reachable_before_enforcement_so_it_can_be_migrated() {
    let (_dir, db) = fixture();
    // Disabled — the state a deployment is in while it backfills.
    let seen = run(&db, "GET products POINTS legacy-1;", &acme()).expect("get");
    assert_eq!(ids(&seen), vec!["legacy-1"]);
}

// ---------------------------------------------------------------------------
// Decision 1 (writes): the server stamps, the payload is not trusted
// ---------------------------------------------------------------------------

#[test]
fn a_write_is_stamped_with_the_writers_tenant() {
    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    run(
        &db,
        "UPSERT INTO products {id: 'new-1', vector: [0,0,1], payload: {category: 'tools'}};",
        &acme(),
    )
    .expect("upsert");

    let fetched = run(&db, "GET products POINTS new-1;", &acme()).expect("get");
    assert_eq!(fetched.rows[0]["payload"]["tenant_id"], json!("acme"));

    // And the other tenant cannot see it.
    let theirs = run(&db, "GET products POINTS new-1;", &globex()).expect("get");
    assert!(theirs.rows.is_empty());
}

#[test]
fn a_payload_claiming_another_tenant_is_rejected_not_rewritten() {
    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    let error = run(
        &db,
        "UPSERT INTO products {id: 'forged', vector: [0,0,1], \
         payload: {tenant_id: 'globex'}};",
        &acme(),
    )
    .expect_err("rejected");

    assert!(error.error.contains("cross_write"), "{}", error.error);

    // Nothing was written under either tenant.
    let mine = run(&db, "GET products POINTS forged;", &acme()).expect("get");
    assert!(mine.rows.is_empty());
    let theirs = run(&db, "GET products POINTS forged;", &globex()).expect("get");
    assert!(theirs.rows.is_empty());
}

#[test]
fn another_tenants_point_cannot_be_updated_or_deleted() {
    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    run(
        &db,
        "UPDATE products POINT globex-1 SET PAYLOAD {category: 'hijacked'};",
        &acme(),
    )
    .expect_err("refused");

    // A delete by id silently affects nothing rather than reporting that the
    // id exists elsewhere.
    let deleted = run(&db, "DELETE FROM products POINTS globex-1;", &acme()).expect("delete");
    assert_eq!(deleted.stats.affected, Some(0));

    let still_there = run(&db, "GET products POINTS globex-1;", &globex()).expect("get");
    assert_eq!(ids(&still_there), vec!["globex-1"]);
}

#[test]
fn a_filtered_delete_cannot_reach_across_tenants() {
    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    // The filter matches rows in both tenants; only the caller's own go.
    let deleted = run(
        &db,
        "DELETE FROM products WHERE category = 'electronics';",
        &acme(),
    )
    .expect("delete");
    assert_eq!(deleted.stats.affected, Some(1));

    let survivors = run(&db, "SCROLL products LIMIT 10;", &globex()).expect("scroll");
    assert_eq!(survivors.rows.len(), 1, "globex kept its row");
}

// ---------------------------------------------------------------------------
// Decision 2: cross-tenant is a capability, not a role
// ---------------------------------------------------------------------------

#[test]
fn an_admin_role_alone_does_not_cross_tenants() {
    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    let mut session = Session::default();
    let mut ctx = ExecContext {
        db: &db,
        session: &mut session,
        // Admin role, no tenant capability. Administering the cluster is not
        // the same question as reading somebody else's rows.
        role: Role::Admin,
        allowed_collections: None,
        want_trace: false,
        confirm: true,
        tenant: acme(),
    };
    let response =
        chirondb::chironql_exec::execute(&mut ctx, "SCROLL products LIMIT 10;").expect("scroll");

    assert_eq!(ids(&response), vec!["acme-1", "acme-2"]);
}

#[test]
fn cross_read_reaches_every_tenant_including_untenanted_rows() {
    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    let auditor =
        TenantScope::tenant("auditor-key", "acme").with_capability(TenantCapability::CrossRead);
    let seen = run(&db, "SCROLL products LIMIT 10;", &auditor).expect("scroll");

    assert_eq!(
        ids(&seen),
        vec!["acme-1", "acme-2", "globex-1", "legacy-1"],
        "an auditor can see the un-migrated rows too, which is how they get found"
    );
}

#[test]
fn cross_read_alone_does_not_grant_cross_write() {
    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    let reader =
        TenantScope::tenant("auditor-key", "acme").with_capability(TenantCapability::CrossRead);

    let error = run(
        &db,
        "UPSERT INTO products {id: 'x', vector: [0,0,1], payload: {tenant_id: 'globex'}};",
        &reader,
    )
    .expect_err("read does not imply write");
    assert!(error.error.contains("cross_write"), "{}", error.error);
}

#[test]
fn cross_write_is_the_migration_path() {
    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    let migrator = TenantScope::untenanted("migration-job")
        .with_capabilities([TenantCapability::CrossRead, TenantCapability::CrossWrite]);

    // Adopt the legacy row into a tenant — the operation this capability
    // exists for, rather than borrowing ordinary write behaviour.
    run(
        &db,
        "UPSERT INTO products {id: 'legacy-1', vector: [1,0,0], \
         payload: {tenant_id: 'acme', category: 'electronics'}};",
        &migrator,
    )
    .expect("adopted");

    let seen = run(&db, "GET products POINTS legacy-1;", &acme()).expect("get");
    assert_eq!(ids(&seen), vec!["legacy-1"], "now visible to its tenant");

    let theirs = run(&db, "GET products POINTS legacy-1;", &globex()).expect("get");
    assert!(theirs.rows.is_empty(), "and to nobody else");
}

#[test]
fn a_cross_tenant_write_must_name_its_target() {
    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    let migrator =
        TenantScope::untenanted("migration-job").with_capability(TenantCapability::CrossWrite);

    let error = run(
        &db,
        "UPSERT INTO products {id: 'orphan', vector: [0,0,1]};",
        &migrator,
    )
    .expect_err("must say which tenant");
    assert!(error.error.contains("tenant_id"), "{}", error.error);
}

#[test]
fn a_principal_with_neither_tenant_nor_capability_reads_nothing() {
    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    let nobody = TenantScope::untenanted("misconfigured-key");
    let error = run(&db, "COUNT products;", &nobody).expect_err("denied");
    assert!(error.error.contains("cross_read"), "{}", error.error);
}

// ---------------------------------------------------------------------------
// Configuration: capabilities are granted in the RBAC file, not inferred
// ---------------------------------------------------------------------------

#[test]
fn capabilities_come_from_config_and_unknown_names_are_ignored() {
    use chirondb::rbac::Permission;

    let entry = ApiKeyEntry {
        id: Some("acme".to_string()),
        key: "k".to_string(),
        tenant_id: Some("acme".to_string()),
        role: Role::ReadWrite,
        allowed_collections: Vec::new(),
        max_collections: None,
        capabilities: vec![
            "tenant:cross_read".to_string(),
            "tenant:everything".to_string(),
        ],
    };

    let permission = Permission::from_entry(&entry);
    assert!(permission.has_capability(TenantCapability::CrossRead));
    assert!(
        !permission.has_capability(TenantCapability::CrossWrite),
        "an unknown name must never widen anything"
    );

    let scope = permission.tenant_scope("acme");
    assert_eq!(scope.tenant_id(), Some("acme"));
    assert!(scope.can_cross_read());
    assert!(!scope.can_cross_write());
}

#[test]
fn a_key_with_no_capabilities_is_scoped_to_its_own_tenant() {
    use chirondb::rbac::Permission;

    let entry = ApiKeyEntry {
        id: Some("globex".to_string()),
        key: "k".to_string(),
        tenant_id: Some("globex".to_string()),
        role: Role::Admin,
        allowed_collections: Vec::new(),
        max_collections: None,
        capabilities: Vec::new(),
    };

    let scope = Permission::from_entry(&entry).tenant_scope("globex");
    assert!(!scope.can_cross_read(), "admin is not cross-tenant");
    assert!(!scope.can_cross_write());
}

// ---------------------------------------------------------------------------
// The gRPC surface carries a real principal
// ---------------------------------------------------------------------------

/// Serves gRPC with RBAC configured, so the interceptor resolves a principal
/// and the handler can scope by it.
async fn grpc_with_keys(db: Db) -> (String, tokio::task::JoinHandle<()>) {
    use chirondb::auth::AuthConfig;
    use chirondb::rbac::RbacConfig;

    let rbac = RbacConfig {
        keys: vec![
            ApiKeyEntry {
                id: Some("acme".to_string()),
                key: "acme-key".to_string(),
                tenant_id: Some("acme".to_string()),
                role: Role::ReadWrite,
                allowed_collections: Vec::new(),
                max_collections: None,
                capabilities: Vec::new(),
            },
            ApiKeyEntry {
                id: Some("auditor".to_string()),
                key: "auditor-key".to_string(),
                tenant_id: Some("acme".to_string()),
                role: Role::ReadWrite,
                allowed_collections: Vec::new(),
                max_collections: None,
                capabilities: vec!["tenant:cross_read".to_string()],
            },
        ],
    };
    // Key acceptance is not what is under test here — tenant scoping is — so
    // the keyring is left open and the RBAC table supplies the principals the
    // interceptor resolves per request.
    let auth = AuthConfig::disabled().with_rbac(rbac);

    let addr = {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        probe.local_addr().expect("addr")
    };
    let handle = tokio::spawn(async move {
        chirondb::grpc::serve_with_auth(db, auth, addr)
            .await
            .expect("serve");
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    (format!("http://{addr}"), handle)
}

fn grpc_query(
    query: &str,
    key: &str,
) -> tonic::Request<chirondb::grpc::chiron_pb::ChironQlRequest> {
    let mut request = tonic::Request::new(chirondb::grpc::chiron_pb::ChironQlRequest {
        query: query.to_string(),
        collection: None,
        trace: false,
        confirm: true,
    });
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {key}").parse().expect("metadata"),
    );
    request
}

#[tokio::test]
async fn grpc_scopes_by_the_authenticated_key() {
    use chirondb::grpc::chiron_pb::chiron_db_client::ChironDbClient;

    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);
    let (url, handle) = grpc_with_keys(db).await;

    let mut client = ChironDbClient::connect(url).await.expect("connect");
    let response = client
        .execute_query(grpc_query("COUNT products;", "acme-key"))
        .await
        .expect("count")
        .into_inner();

    let row: serde_json::Value = serde_json::from_str(&response.rows_json[0]).expect("row json");
    assert_eq!(
        row["count"],
        json!(2),
        "acme's key sees acme's two rows, not globex's and not the legacy one"
    );

    handle.abort();
}

#[tokio::test]
async fn grpc_honours_the_cross_read_capability() {
    use chirondb::grpc::chiron_pb::chiron_db_client::ChironDbClient;

    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);
    let (url, handle) = grpc_with_keys(db).await;

    let mut client = ChironDbClient::connect(url).await.expect("connect");
    let response = client
        .execute_query(grpc_query("COUNT products;", "auditor-key"))
        .await
        .expect("count")
        .into_inner();

    let row: serde_json::Value = serde_json::from_str(&response.rows_json[0]).expect("row json");
    assert_eq!(
        row["count"],
        json!(4),
        "the same tenant, one capability apart, sees every row"
    );

    handle.abort();
}

#[tokio::test]
async fn grpc_writes_are_stamped_with_the_keys_tenant() {
    use chirondb::grpc::chiron_pb::chiron_db_client::ChironDbClient;

    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);
    let (url, handle) = grpc_with_keys(db.clone()).await;

    let mut client = ChironDbClient::connect(url).await.expect("connect");
    client
        .execute_query(grpc_query(
            "UPSERT INTO products {id: 'grpc-1', vector: [0,0,1]};",
            "acme-key",
        ))
        .await
        .expect("upsert");

    // Stamped as acme, so globex cannot see it.
    let theirs = run(&db, "GET products POINTS grpc-1;", &globex()).expect("get");
    assert!(theirs.rows.is_empty());
    let mine = run(&db, "GET products POINTS grpc-1;", &acme()).expect("get");
    assert_eq!(ids(&mine), vec!["grpc-1"]);

    handle.abort();
}
