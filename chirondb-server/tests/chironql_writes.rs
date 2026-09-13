//! ChironQL P4 gate — write statements and the delete guardrail.
//!
//! The guardrail is server-side on purpose: `DELETE ... WHERE` counts what the
//! filter matches and refuses unless the caller confirmed. A prompt is one way
//! to answer that; an SDK flag is another. Neither is required for the
//! protection to hold, which is the point.

use chirondb::chironql_exec::{ExecContext, Session};
use chirondb::chironql_repl::{ExecuteOptions, LocalSink, QuerySink, ReplOptions, run};
use chirondb::rbac::Role;
use chirondb::tenant::TenantScope;
use chirondb::{CollectionConfig, Db, DistanceMetric, Point};
use chirondb_types::chironql::{ChironQlError, ChironQlKind, ChironQlResponse};
use serde_json::json;
use tempfile::TempDir;

const COLLECTION: &str = "products";

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
                id: "phone".to_string(),
                vector: vec![1.0, 0.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"category": "electronics", "price": 699}),
            },
            Point {
                id: "laptop".to_string(),
                vector: vec![0.9, 0.1, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"category": "electronics", "price": 1499}),
            },
            Point {
                id: "book".to_string(),
                vector: vec![0.0, 1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"category": "media", "price": 25}),
            },
        ],
    )
    .expect("upsert");
    (dir, db)
}

fn write(db: &Db, query: &str) -> Result<ChironQlResponse, ChironQlError> {
    run_as(db, query, Role::ReadWrite, false)
}

fn confirmed(db: &Db, query: &str) -> Result<ChironQlResponse, ChironQlError> {
    run_as(db, query, Role::ReadWrite, true)
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

fn count(db: &Db) -> u64 {
    run_as(db, "COUNT products;", Role::ReadOnly, false)
        .expect("count")
        .rows[0]["count"]
        .as_u64()
        .expect("number")
}

fn stage_names(response: &ChironQlResponse) -> Vec<String> {
    response
        .trace
        .as_ref()
        .expect("trace")
        .stages
        .iter()
        .map(|stage| stage.name.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// UPSERT
// ---------------------------------------------------------------------------

#[test]
fn upsert_inserts_a_new_point() {
    let (_dir, db) = fixture();

    let response = write(
        &db,
        "UPSERT INTO products {id: 'tablet', vector: [0.5,0.5,0], \
         payload: {category: 'electronics', price: 399}};",
    )
    .expect("upsert");

    assert_eq!(response.kind, ChironQlKind::Affected);
    assert_eq!(response.stats.affected, Some(1));
    assert_eq!(count(&db), 4);

    let fetched = run_as(&db, "GET products POINTS tablet;", Role::ReadOnly, false).expect("get");
    assert_eq!(fetched.rows[0]["payload"]["price"], json!(399));
}

#[test]
fn upsert_updates_an_existing_point() {
    let (_dir, db) = fixture();

    write(
        &db,
        "UPSERT INTO products {id: 'phone', vector: [1,0,0], payload: {category: 'clearance'}};",
    )
    .expect("upsert");

    assert_eq!(count(&db), 3, "an existing id is replaced, not appended");
    let fetched = run_as(&db, "GET products POINTS phone;", Role::ReadOnly, false).expect("get");
    assert_eq!(fetched.rows[0]["payload"]["category"], json!("clearance"));
}

#[test]
fn upsert_writes_several_points_at_once() {
    let (_dir, db) = fixture();

    let response = write(
        &db,
        "UPSERT INTO products {id: 'a', vector: [1,0,0]}, {id: 'b', vector: [0,1,0]};",
    )
    .expect("upsert");

    assert_eq!(response.stats.affected, Some(2));
    assert_eq!(count(&db), 5);
}

#[test]
fn a_point_with_the_wrong_dimension_is_refused_by_the_engine() {
    let (_dir, db) = fixture();

    let error = write(&db, "UPSERT INTO products {id: 'bad', vector: [1,0]};")
        .expect_err("dimension mismatch");

    // The engine reports this as an invalid request, and its message names the
    // point and both dimensions.
    assert_eq!(error.code, "chironql.invalid_request");
    assert!(error.error.contains("bad"), "{}", error.error);
    assert!(
        error.error.contains('3') && error.error.contains('2'),
        "{}",
        error.error
    );
    assert_eq!(count(&db), 3, "nothing was written");
}

#[test]
fn a_malformed_point_is_named_as_such() {
    let (_dir, db) = fixture();

    // Parses as a point object, but `vector` is not a list of numbers.
    let error =
        write(&db, "UPSERT INTO products {id: 'bad', vector: 'oops'};").expect_err("invalid point");

    assert_eq!(error.code, "chironql.invalid_point");
    assert!(error.hint.expect("hint").contains("vector"));
}

// ---------------------------------------------------------------------------
// UPDATE
// ---------------------------------------------------------------------------

#[test]
fn update_merges_payload_fields_by_default() {
    let (_dir, db) = fixture();

    write(
        &db,
        "UPDATE products POINT phone SET PAYLOAD {featured: true};",
    )
    .expect("update");

    let fetched = run_as(&db, "GET products POINTS phone;", Role::ReadOnly, false).expect("get");
    assert_eq!(fetched.rows[0]["payload"]["featured"], json!(true));
    assert_eq!(
        fetched.rows[0]["payload"]["price"],
        json!(699),
        "existing fields survive a merge"
    );
}

#[test]
fn update_replace_swaps_the_whole_payload() {
    let (_dir, db) = fixture();

    write(
        &db,
        "UPDATE products POINT phone SET PAYLOAD {featured: true} REPLACE;",
    )
    .expect("update");

    let fetched = run_as(&db, "GET products POINTS phone;", Role::ReadOnly, false).expect("get");
    assert_eq!(fetched.rows[0]["payload"]["featured"], json!(true));
    assert!(
        fetched.rows[0]["payload"]["price"].is_null(),
        "REPLACE drops the old fields"
    );
}

#[test]
fn updating_a_point_that_is_not_there_says_so() {
    let (_dir, db) = fixture();
    let error =
        write(&db, "UPDATE products POINT ghost SET PAYLOAD {a: 1};").expect_err("no such point");
    assert_eq!(error.code, "chironql.point_not_found");
}

// ---------------------------------------------------------------------------
// DELETE by id
// ---------------------------------------------------------------------------

#[test]
fn delete_by_id_needs_no_confirmation() {
    let (_dir, db) = fixture();

    let response = write(&db, "DELETE FROM products POINTS phone, book;").expect("delete");

    assert_eq!(response.stats.affected, Some(2));
    assert_eq!(count(&db), 1);
}

// ---------------------------------------------------------------------------
// DELETE by filter — the guardrail
// ---------------------------------------------------------------------------

#[test]
fn a_filtered_delete_counts_first_and_refuses_without_confirmation() {
    let (_dir, db) = fixture();

    let error = write(&db, "DELETE FROM products WHERE category = 'electronics';")
        .expect_err("confirmation required");

    assert_eq!(error.code, "chironql.confirmation_required");
    assert_eq!(
        error.affected_estimate,
        Some(2),
        "the refusal carries a real number, not a guess"
    );
    assert_eq!(count(&db), 3, "nothing was deleted");

    let trace = error.trace.expect("trace");
    let names: Vec<&str> = trace.stages.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"count_matches"), "{names:?}");
    assert_eq!(
        trace.failed_stage().map(|stage| stage.name.as_str()),
        Some("confirm")
    );
}

#[test]
fn a_confirmed_filtered_delete_runs() {
    let (_dir, db) = fixture();

    let response = confirmed(&db, "DELETE FROM products WHERE category = 'electronics';")
        .expect("confirmed delete");

    assert_eq!(response.stats.affected, Some(2));
    assert_eq!(count(&db), 1);

    let stages = stage_names(&response);
    assert!(stages.contains(&"count_matches".to_string()), "{stages:?}");
    assert!(stages.contains(&"confirm".to_string()), "{stages:?}");
    assert!(stages.contains(&"engine_write".to_string()), "{stages:?}");
}

#[test]
fn a_filter_that_matches_nothing_still_asks_before_deleting() {
    let (_dir, db) = fixture();

    let error = write(&db, "DELETE FROM products WHERE category = 'nothing';")
        .expect_err("confirmation required");

    // Zero is a useful answer: it tells the operator the filter is wrong
    // before they confirm something that does nothing.
    assert_eq!(error.affected_estimate, Some(0));
    assert_eq!(count(&db), 3);
}

// ---------------------------------------------------------------------------
// RBAC — still the real enforcement
// ---------------------------------------------------------------------------

#[test]
fn read_only_is_refused_every_write_before_the_engine_is_touched() {
    let (_dir, db) = fixture();

    for statement in [
        "UPSERT INTO products {id: 'x', vector: [1,0,0]};",
        "UPDATE products POINT phone SET PAYLOAD {a: 1};",
        "DELETE FROM products POINTS phone;",
        "DELETE FROM products WHERE category = 'electronics';",
    ] {
        let error =
            run_as(&db, statement, Role::ReadOnly, true).expect_err("read_only cannot write");
        assert_eq!(error.code, "chironql.permission_denied", "{statement}");
        assert_eq!(
            error
                .trace
                .expect("trace")
                .failed_stage()
                .map(|stage| stage.name.clone()),
            Some("authorize".to_string()),
            "{statement}"
        );
    }

    assert_eq!(count(&db), 3, "nothing changed");
}

#[test]
fn confirmation_does_not_bypass_permission() {
    let (_dir, db) = fixture();

    // `confirm` answers "are you sure", never "are you allowed".
    let error = run_as(
        &db,
        "DELETE FROM products WHERE category = 'electronics';",
        Role::ReadOnly,
        true,
    )
    .expect_err("read_only cannot delete");

    assert_eq!(error.code, "chironql.permission_denied");
    assert_eq!(count(&db), 3);
}

// ---------------------------------------------------------------------------
// The REPL side of the guardrail
// ---------------------------------------------------------------------------

#[test]
fn a_piped_session_refuses_a_filtered_delete_and_says_how_to_proceed() {
    let (_dir, db) = fixture();
    let mut sink = LocalSink::new(db.clone(), Role::ReadWrite);
    let mut out = Vec::new();

    let failures = run(
        &mut sink,
        "DELETE FROM products WHERE category = 'electronics';\n".as_bytes(),
        &mut out,
        ReplOptions {
            interactive: false,
            ..Default::default()
        },
    )
    .expect("repl runs");

    let output = String::from_utf8(out).expect("utf8");
    assert_eq!(failures, 1, "{output}");
    assert!(output.contains("would delete 2"), "{output}");
    assert!(output.contains("--yes"), "{output}");
    assert_eq!(count(&db), 3, "nothing was deleted");
}

#[test]
fn a_write_reports_its_count_without_claiming_no_rows() {
    let (_dir, db) = fixture();
    let mut sink = LocalSink::new(db, Role::ReadWrite);
    let mut out = Vec::new();

    run(
        &mut sink,
        "UPSERT INTO products {id: 'new', vector: [0,0,1]};\n".as_bytes(),
        &mut out,
        ReplOptions {
            interactive: false,
            ..Default::default()
        },
    )
    .expect("repl runs");

    let output = String::from_utf8(out).expect("utf8");
    assert!(output.contains("1 affected"), "{output}");
    // A write has no result set. Printing "(no rows)" beside "1 affected" reads
    // as though the write did nothing.
    assert!(!output.contains("no rows"), "{output}");
}

#[test]
fn the_help_text_does_not_call_writes_unimplemented() {
    let (_dir, db) = fixture();
    let mut sink = LocalSink::new(db, Role::ReadWrite);
    let mut out = Vec::new();

    run(
        &mut sink,
        "\\h\n".as_bytes(),
        &mut out,
        ReplOptions {
            interactive: false,
            ..Default::default()
        },
    )
    .expect("repl runs");

    let output = String::from_utf8(out).expect("utf8");
    assert!(output.contains("UPSERT"), "{output}");
    // This said "(not executable yet)" for four commits after the writes
    // shipped, which is how a working feature gets reported as missing.
    assert!(!output.contains("not executable"), "{output}");
}

#[test]
fn a_piped_session_with_yes_deletes() {
    let (_dir, db) = fixture();
    let mut sink = LocalSink::new(db.clone(), Role::ReadWrite);
    let mut out = Vec::new();

    let failures = run(
        &mut sink,
        "DELETE FROM products WHERE category = 'electronics';\n".as_bytes(),
        &mut out,
        ReplOptions {
            interactive: false,
            confirm: true,
            ..Default::default()
        },
    )
    .expect("repl runs");

    let output = String::from_utf8(out).expect("utf8");
    assert_eq!(failures, 0, "{output}");
    assert!(output.contains("2 affected"), "{output}");
    assert_eq!(count(&db), 1);
}

#[test]
fn the_sink_reports_writes_through_the_same_trait_as_reads() {
    let (_dir, db) = fixture();
    let mut sink = LocalSink::new(db.clone(), Role::ReadWrite);

    let response = sink
        .execute(
            "UPSERT INTO products {id: 'z', vector: [0,0,1]};",
            ExecuteOptions {
                trace: true,
                confirm: false,
            },
        )
        .expect("upsert through the sink");

    assert_eq!(response.kind, ChironQlKind::Affected);
    assert_eq!(count(&db), 4);
}
