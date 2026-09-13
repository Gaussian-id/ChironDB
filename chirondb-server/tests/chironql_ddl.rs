//! Collection DDL — `CREATE COLLECTION` and `DROP COLLECTION`.
//!
//! Three properties matter more than the happy path, so they are asserted
//! first: DDL needs an admin role, `DROP` counts before it destroys, and DDL
//! refuses entirely while tenant enforcement is on because the engine has no
//! tenant-scoped variant of either call.

use chirondb::chironql_exec::{ExecContext, Session};
use chirondb::rbac::Role;
use chirondb::tenant::{TenantEnforcement, TenantScope};
use chirondb::{CollectionConfig, Db, DistanceMetric, Point};
use chirondb_types::chironql::{ChironQlError, ChironQlKind, ChironQlResponse};
use serde_json::json;
use tempfile::TempDir;

const COLLECTION: &str = "products";

/// A database with one three-point collection, as in the write suite.
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
        ["phone", "laptop", "book"]
            .iter()
            .map(|id| Point {
                id: (*id).to_string(),
                vector: vec![1.0, 0.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({}),
            })
            .collect(),
    )
    .expect("upsert");
    (dir, db)
}

fn run_as(
    db: &Db,
    query: &str,
    role: Role,
    confirm: bool,
) -> Result<ChironQlResponse, ChironQlError> {
    let mut session = Session::default();
    let mut ctx = ExecContext {
        db,
        session: &mut session,
        role,
        allowed_collections: None,
        want_trace: true,
        confirm,
        tenant: TenantScope::system(),
    };
    chirondb::chironql_exec::execute(&mut ctx, query)
}

fn admin(db: &Db, query: &str) -> Result<ChironQlResponse, ChironQlError> {
    run_as(db, query, Role::Admin, false)
}

fn confirmed(db: &Db, query: &str) -> Result<ChironQlResponse, ChironQlError> {
    run_as(db, query, Role::Admin, true)
}

fn collection_names(db: &Db) -> Vec<String> {
    db.list_collections()
        .into_iter()
        .map(|config| config.name)
        .collect()
}

fn field(response: &ChironQlResponse, name: &str) -> serde_json::Value {
    response
        .rows
        .iter()
        .find(|row| row["field"] == json!(name))
        .unwrap_or_else(|| panic!("no `{name}` row in {:?}", response.rows))["value"]
        .clone()
}

// ---------------------------------------------------------------------------
// Permission
// ---------------------------------------------------------------------------

#[test]
fn ddl_needs_a_write_role() {
    let (_dir, db) = fixture();

    run_as(&db, "CREATE COLLECTION fresh DIM 3;", Role::ReadWrite, true)
        .expect("read_write may create collections");
    run_as(&db, "DROP COLLECTION products;", Role::ReadWrite, true)
        .expect("read_write may drop collections");

    let error = run_as(&db, "CREATE COLLECTION denied DIM 3;", Role::ReadOnly, true)
        .expect_err("read_only refused");
    assert_eq!(error.code, "chironql.permission_denied");
    assert!(error.hint.as_deref().unwrap_or_default().contains("write"));

    assert_eq!(collection_names(&db), vec!["fresh".to_string()]);
}

/// `create_collection` and `delete_collection` have no `_scoped` twin, so
/// under enforcement there is no rule for who owns a collection. Refusing is
/// the fail-closed answer; guessing an owner would be the leak.
#[test]
fn ddl_is_refused_while_tenant_enforcement_is_on() {
    let (_dir, db) = fixture();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    let error = confirmed(&db, "CREATE COLLECTION fresh DIM 3;").expect_err("refused");
    assert_eq!(error.code, "chironql.tenant_ddl_unsupported");

    let error = confirmed(&db, "DROP COLLECTION products;").expect_err("refused");
    assert_eq!(error.code, "chironql.tenant_ddl_unsupported");

    assert_eq!(collection_names(&db), vec![COLLECTION.to_string()]);
}

// ---------------------------------------------------------------------------
// CREATE
// ---------------------------------------------------------------------------

#[test]
fn create_collection_makes_a_usable_collection() {
    let (_dir, db) = fixture();

    let response = admin(&db, "CREATE COLLECTION fresh DIM 3 METRIC cosine;").expect("create");

    assert_eq!(response.kind, ChironQlKind::Rows);
    assert_eq!(field(&response, "name"), json!("fresh"));
    assert_eq!(field(&response, "vector_dim"), json!(3));
    assert!(collection_names(&db).contains(&"fresh".to_string()));

    // The collection is real, not just catalogued.
    run_as(
        &db,
        "UPSERT INTO fresh {id: 'a', vector: [1,0,0]};",
        Role::ReadWrite,
        false,
    )
    .expect("upsert into the new collection");
}

/// What `CREATE` echoes and what `DESCRIBE` reports are the same rows, so the
/// settings you can type are the settings you can read back.
#[test]
fn create_echoes_what_describe_reports() {
    let (_dir, db) = fixture();

    let created = admin(&db, "CREATE COLLECTION fresh DIM 8 METRIC dot;").expect("create");
    let described = admin(&db, "DESCRIBE fresh;").expect("describe");

    assert_eq!(created.columns, described.columns);
    assert_eq!(created.rows, described.rows);
}

#[test]
fn with_carries_the_settings_that_have_no_keyword() {
    let (_dir, db) = fixture();

    admin(
        &db,
        "CREATE COLLECTION fresh DIM 3 WITH {shards: 2, hnsw_m: 24, \
         payload_schema: {category: 'string'}};",
    )
    .expect("create");

    let described = admin(&db, "DESCRIBE fresh;").expect("describe");
    assert_eq!(field(&described, "shards"), json!(2));
    assert_eq!(field(&described, "payload.category"), json!("string"));
}

/// serde would drop a misspelt key and create a collection that quietly is not
/// what was asked for. The statement is refused instead.
#[test]
fn a_misspelt_setting_is_refused_not_ignored() {
    let (_dir, db) = fixture();

    let error = admin(&db, "CREATE COLLECTION fresh DIM 3 WITH {shardz: 2};").expect_err("refused");

    assert_eq!(error.code, "chironql.unknown_collection_option");
    assert!(
        error.hint.as_deref().unwrap_or_default().contains("shards"),
        "the hint lists the real settings: {:?}",
        error.hint
    );
    assert!(!collection_names(&db).contains(&"fresh".to_string()));
}

#[test]
fn index_kind_is_not_a_setting_anyone_may_choose() {
    let (_dir, db) = fixture();

    let error = admin(
        &db,
        "CREATE COLLECTION fresh DIM 3 WITH {index_kind: 'hnsw'};",
    )
    .expect_err("refused");

    assert_eq!(error.code, "chironql.no_index_family");
}

#[test]
fn creating_a_collection_that_exists_is_the_engines_refusal() {
    let (_dir, db) = fixture();

    let error = admin(&db, "CREATE COLLECTION products DIM 3;").expect_err("refused");

    assert!(
        error.error.contains("products"),
        "the engine's message names the collection: {}",
        error.error
    );
    assert_eq!(collection_names(&db), vec![COLLECTION.to_string()]);
}

// ---------------------------------------------------------------------------
// DROP
// ---------------------------------------------------------------------------

#[test]
fn drop_counts_first_and_destroys_nothing_when_unconfirmed() {
    let (_dir, db) = fixture();

    let error = admin(&db, "DROP COLLECTION products;").expect_err("refused");

    assert_eq!(error.code, "chironql.confirmation_required");
    assert_eq!(
        error.affected_estimate,
        Some(3),
        "the number of points is in front of whoever decides"
    );
    assert_eq!(collection_names(&db), vec![COLLECTION.to_string()]);
}

#[test]
fn a_confirmed_drop_removes_the_collection_and_reports_its_points() {
    let (_dir, db) = fixture();

    let response = confirmed(&db, "DROP COLLECTION products;").expect("drop");

    assert_eq!(response.kind, ChironQlKind::Affected);
    assert_eq!(response.stats.affected, Some(3));
    assert!(collection_names(&db).is_empty());
}

#[test]
fn if_exists_makes_a_missing_collection_a_no_op() {
    let (_dir, db) = fixture();

    let response = confirmed(&db, "DROP COLLECTION IF EXISTS ghost;").expect("no-op");

    assert_eq!(response.stats.affected, Some(0));
}

#[test]
fn without_if_exists_a_missing_collection_is_an_error() {
    let (_dir, db) = fixture();

    let error = confirmed(&db, "DROP COLLECTION ghost;").expect_err("not found");

    assert_eq!(error.code, "chironql.collection_not_found");
}

/// A session left pointing at a dropped collection would fail every later
/// statement with "not found" and no explanation of why.
#[test]
fn dropping_the_session_collection_clears_it() {
    let (_dir, db) = fixture();
    let mut session = Session::default();

    for (query, confirm) in [
        ("USE products;", false),
        ("DROP COLLECTION products;", true),
    ] {
        let mut ctx = ExecContext {
            db: &db,
            session: &mut session,
            role: Role::Admin,
            allowed_collections: None,
            want_trace: false,
            confirm,
            tenant: TenantScope::system(),
        };
        chirondb::chironql_exec::execute(&mut ctx, query).expect(query);
    }

    assert_eq!(session.collection, None);
}
