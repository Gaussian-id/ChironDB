//! ChironQL P1 gate — the executor against a real `Db`.
//!
//! The load-bearing test here is the differential one: every read statement
//! must return the same thing as the `Db` call the REST handler makes for the
//! equivalent request. ChironQL is a translation layer, and this is what keeps
//! it honest.

use chirondb::chironql_exec::{ExecContext, Session};
use chirondb::chironql_repl::{Format, LocalSink, ReplOptions, run};
use chirondb::rbac::Role;
use chirondb::tenant::TenantScope;
use chirondb::{CollectionConfig, Db, DistanceMetric, Filter, Point, SearchRequest};
use chirondb_types::chironql::{ChironQlError, ChironQlKind, ChironQlResponse, StageOutcome};
use serde_json::{Value, json};
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

    let points = vec![
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
    ];
    db.upsert(COLLECTION, points).expect("upsert");

    (dir, db)
}

fn exec(db: &Db, query: &str) -> Result<ChironQlResponse, ChironQlError> {
    exec_as(db, query, Role::ReadOnly, &mut Session::default())
}

fn exec_as(
    db: &Db,
    query: &str,
    role: Role,
    session: &mut Session,
) -> Result<ChironQlResponse, ChironQlError> {
    let mut ctx = ExecContext {
        db,
        session,
        role,
        allowed_collections: None,
        want_trace: true,
        confirm: false,
        tenant: TenantScope::system(),
    };
    chirondb::chironql_exec::execute(&mut ctx, query)
}

fn ids(response: &ChironQlResponse) -> Vec<String> {
    response
        .rows
        .iter()
        .map(|row| row["id"].as_str().unwrap_or_default().to_string())
        .collect()
}

fn stage_names(response: &ChironQlResponse) -> Vec<String> {
    response
        .trace
        .as_ref()
        .expect("trace requested")
        .stages
        .iter()
        .map(|stage| stage.name.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// Differential: ChironQL vs. the Db call the REST handler makes
// ---------------------------------------------------------------------------

#[test]
fn search_matches_the_equivalent_rest_call() {
    let (_dir, db) = fixture();

    let via_chironql =
        exec(&db, "SEARCH products NEAR [1,0,0] LIMIT 2 WITH PAYLOAD;").expect("chironql search");

    // Exactly what `api::search` does for the equivalent request body.
    let via_rest = db
        .search(
            COLLECTION,
            SearchRequest {
                graph: None,
                vector: vec![1.0, 0.0, 0.0],
                vector_name: None,
                k: 2,
                filter: None,
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: Some(true),
            },
        )
        .expect("rest search");

    let rest_ids: Vec<String> = via_rest.hits.iter().map(|hit| hit.id.clone()).collect();
    assert_eq!(ids(&via_chironql), rest_ids);
    assert_eq!(via_chironql.stats.searched, Some(via_rest.searched));
    assert_eq!(via_chironql.stats.degraded, Some(via_rest.degraded));

    for (row, hit) in via_chironql.rows.iter().zip(via_rest.hits.iter()) {
        assert_eq!(row["score"].as_f64().expect("score"), hit.score as f64);
        assert_eq!(row["payload"], hit.payload);
    }
}

#[test]
fn filtered_search_matches_the_equivalent_rest_call() {
    let (_dir, db) = fixture();

    let via_chironql = exec(
        &db,
        "SEARCH products NEAR [1,0,0] WHERE category = 'electronics' LIMIT 5;",
    )
    .expect("chironql search");

    let via_rest = db
        .search(
            COLLECTION,
            SearchRequest {
                graph: None,
                vector: vec![1.0, 0.0, 0.0],
                vector_name: None,
                k: 5,
                filter: Some(Filter(json!({"category": {"eq": "electronics"}}))),
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: None,
            },
        )
        .expect("rest search");

    let rest_ids: Vec<String> = via_rest.hits.iter().map(|hit| hit.id.clone()).collect();
    assert_eq!(ids(&via_chironql), rest_ids);
    assert!(!rest_ids.contains(&"book".to_string()), "filter applied");
}

#[test]
fn count_matches_the_equivalent_rest_call() {
    let (_dir, db) = fixture();

    let via_chironql =
        exec(&db, "COUNT products WHERE category = 'electronics';").expect("chironql count");
    let via_rest = db
        .count(
            COLLECTION,
            Some(Filter(json!({"category": {"eq": "electronics"}}))),
        )
        .expect("rest count");

    assert_eq!(
        via_chironql.rows[0]["count"].as_u64().expect("count"),
        via_rest.count as u64
    );
}

#[test]
fn get_and_scroll_match_the_equivalent_rest_calls() {
    let (_dir, db) = fixture();

    let via_chironql = exec(&db, "GET products POINTS phone, book;").expect("chironql get");
    let via_rest = db
        .get_points(COLLECTION, &["phone".to_string(), "book".to_string()])
        .expect("rest get");
    let rest_ids: Vec<String> = via_rest.iter().map(|point| point.id.clone()).collect();
    assert_eq!(ids(&via_chironql), rest_ids);

    let scrolled = exec(&db, "SCROLL products LIMIT 2;").expect("chironql scroll");
    let via_rest = db.scroll(COLLECTION, None, 2, None).expect("rest scroll");
    let rest_ids: Vec<String> = via_rest
        .points
        .iter()
        .map(|point| point.id.clone())
        .collect();
    assert_eq!(ids(&scrolled), rest_ids);
    assert_eq!(scrolled.next, via_rest.next_offset);
}

// ---------------------------------------------------------------------------
// Language behaviour end to end
// ---------------------------------------------------------------------------

#[test]
fn session_collection_is_used_when_a_statement_omits_it() {
    let (_dir, db) = fixture();
    let mut session = Session::default();

    exec_as(&db, "USE products;", Role::ReadOnly, &mut session).expect("use");
    assert_eq!(session.collection.as_deref(), Some(COLLECTION));

    let response = exec_as(
        &db,
        "SEARCH NEAR [1,0,0] LIMIT 1;",
        Role::ReadOnly,
        &mut session,
    )
    .expect("search without a collection");
    assert_eq!(ids(&response), vec!["phone"]);
}

#[test]
fn point_reference_resolves_a_stored_vector() {
    let (_dir, db) = fixture();

    let response = exec(&db, "SEARCH products NEAR @phone LIMIT 2;").expect("search by @id");
    assert_eq!(ids(&response).first().map(String::as_str), Some("phone"));
    assert!(
        stage_names(&response).contains(&"resolve_vector".to_string()),
        "the extra point fetch is visible in the trace"
    );
}

#[test]
fn recommend_uses_stored_points() {
    let (_dir, db) = fixture();
    let response =
        exec(&db, "RECOMMEND products LIKE phone UNLIKE book LIMIT 2;").expect("recommend");
    assert!(!response.rows.is_empty());
}

#[test]
fn show_collections_and_describe_report_the_real_config() {
    let (_dir, db) = fixture();

    let listed = exec(&db, "SHOW COLLECTIONS;").expect("show");
    assert_eq!(
        listed.rows[0]["name"].as_str(),
        Some(COLLECTION),
        "{:?}",
        listed.rows
    );

    let described = exec(&db, "DESCRIBE products;").expect("describe");
    let dim = described
        .rows
        .iter()
        .find(|row| row["field"] == json!("vector_dim"))
        .expect("vector_dim row");
    assert_eq!(dim["value"], json!(3));
}

#[test]
fn a_recall_target_is_echoed_as_a_request_and_never_as_a_result() {
    let (_dir, db) = fixture();
    let response = exec(&db, "SEARCH products NEAR [1,0,0] LIMIT 2 RECALL 0.99;").expect("search");

    assert_eq!(response.stats.recall_target_requested, Some(0.99));

    // Nothing anywhere in the response claims an achieved recall.
    let serialized = serde_json::to_string(&response).expect("serialize");
    assert!(!serialized.contains("\"recall\":"), "{serialized}");
    assert!(!serialized.contains("ef_search"), "{serialized}");
}

// ---------------------------------------------------------------------------
// Trace
// ---------------------------------------------------------------------------

#[test]
fn a_successful_search_traces_every_stage_it_ran() {
    let (_dir, db) = fixture();
    let response = exec(
        &db,
        "SEARCH products NEAR [1,0,0] WHERE category = 'electronics' LIMIT 2;",
    )
    .expect("search");

    let stages = stage_names(&response);
    assert_eq!(
        stages,
        vec![
            "parse",
            "authorize",
            "resolve_collection",
            "compile_filter",
            "engine_search",
            "render"
        ]
    );

    // A stage that did not run is absent, not present with a zero duration.
    assert!(!stages.contains(&"resolve_vector".to_string()));
    assert!(!stages.contains(&"fuse".to_string()));
}

#[test]
fn a_failure_traces_up_to_and_including_the_stage_that_failed() {
    let (_dir, db) = fixture();
    let error = exec(&db, "SEARCH products NEAR @missing LIMIT 2;").expect_err("point missing");

    assert_eq!(error.code, "chironql.point_not_found");
    let trace = error.trace.expect("failures always carry a trace");
    let names: Vec<&str> = trace.stages.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["parse", "authorize", "resolve_collection", "resolve_vector"]
    );

    let failed = trace.failed_stage().expect("a failed stage");
    assert_eq!(failed.name, "resolve_vector");
    match &failed.outcome {
        StageOutcome::Failed { code, .. } => assert_eq!(code, "chironql.point_not_found"),
        StageOutcome::Ok => panic!("expected a failure"),
    }
}

#[test]
fn a_parse_reject_fails_at_the_parse_stage_with_a_caret_position() {
    let (_dir, db) = fixture();
    let query = "SEARCH products NEAR [1,0,0] WHERE a = 1 OR b = 2;";
    let error = exec(&db, query).expect_err("OR is rejected");

    assert_eq!(error.code, "chironql.no_or_across_fields");
    let position = error.position.expect("a caret position") as usize;
    assert_eq!(&query[position..position + 2], "OR");

    let trace = error.trace.expect("trace");
    assert_eq!(trace.stages.len(), 1);
    assert_eq!(trace.stages[0].name, "parse");
}

#[test]
fn the_footer_and_the_trace_agree_about_what_was_scanned() {
    let (_dir, db) = fixture();
    let response = exec(&db, "SEARCH products NEAR [1,0,0] LIMIT 3;").expect("search");

    let scanned_in_stats = response.stats.searched.expect("searched");
    let engine_stage = response
        .trace
        .as_ref()
        .expect("trace")
        .stages
        .iter()
        .find(|stage| stage.name == "engine_search")
        .expect("engine stage");
    let scanned_in_trace = engine_stage.detail.as_ref().expect("detail")["scanned"]
        .as_u64()
        .expect("scanned");

    assert_eq!(scanned_in_stats as u64, scanned_in_trace);
}

#[test]
fn collection_not_found_names_the_collection_and_fails_at_resolve() {
    let (_dir, db) = fixture();
    let error = exec(&db, "COUNT nonexistent;").expect_err("no such collection");

    assert_eq!(error.code, "chironql.collection_not_found");
    let trace = error.trace.expect("trace");
    assert_eq!(
        trace.failed_stage().map(|stage| stage.name.as_str()),
        Some("resolve_collection")
    );
}

// ---------------------------------------------------------------------------
// RBAC — enforced server-side, before execution
// ---------------------------------------------------------------------------

#[test]
fn a_read_only_session_is_refused_writes_before_anything_executes() {
    let (_dir, db) = fixture();
    let mut session = Session::default();

    let error = exec_as(
        &db,
        "DELETE FROM products POINTS phone;",
        Role::ReadOnly,
        &mut session,
    )
    .expect_err("read_only cannot write");

    assert_eq!(error.code, "chironql.permission_denied");

    let trace = error.trace.expect("trace");
    assert_eq!(
        trace.failed_stage().map(|stage| stage.name.as_str()),
        Some("authorize"),
        "the refusal happens at authorize, before the engine is touched"
    );

    // And the point is still there.
    let still_there = exec(&db, "GET products POINTS phone;").expect("get");
    assert_eq!(ids(&still_there), vec!["phone"]);
}

#[test]
fn reads_are_allowed_for_a_read_only_session() {
    let (_dir, db) = fixture();
    let mut session = Session::default();
    let response = exec_as(&db, "COUNT products;", Role::ReadOnly, &mut session).expect("count");
    assert_eq!(response.rows[0]["count"], json!(3));
}

#[test]
fn an_authorized_delete_by_id_runs() {
    let (_dir, db) = fixture();
    let mut session = Session::default();

    let response = exec_as(
        &db,
        "DELETE FROM products POINTS phone;",
        Role::ReadWrite,
        &mut session,
    )
    .expect("read_write may delete");

    assert_eq!(response.stats.affected, Some(1));
    let remaining = exec(&db, "COUNT products;").expect("count");
    assert_eq!(remaining.rows[0]["count"], json!(2));
}

// ---------------------------------------------------------------------------
// The console loop, driven exactly as a piped session would drive it
// ---------------------------------------------------------------------------

#[test]
fn a_scripted_console_session_produces_a_table() {
    let (_dir, db) = fixture();
    let mut sink = LocalSink::new(db, Role::ReadOnly);
    let mut out = Vec::new();

    let failures = run(
        &mut sink,
        "USE products;\nSEARCH NEAR [1,0,0] LIMIT 2;\n".as_bytes(),
        &mut out,
        ReplOptions {
            interactive: false,
            ..Default::default()
        },
    )
    .expect("repl runs");

    let output = String::from_utf8(out).expect("utf8");
    assert_eq!(failures, 0, "{output}");
    assert!(output.contains("phone"), "{output}");
    assert!(output.contains("score"), "{output}");
    assert!(output.contains("points scanned"), "{output}");
}

#[test]
fn a_scripted_console_session_reports_failures_and_keeps_going() {
    let (_dir, db) = fixture();
    let mut sink = LocalSink::new(db, Role::ReadOnly);
    let mut out = Vec::new();

    let failures = run(
        &mut sink,
        "SELECT * FROM products;\nCOUNT products;\n".as_bytes(),
        &mut out,
        ReplOptions {
            interactive: false,
            ..Default::default()
        },
    )
    .expect("repl runs");

    let output = String::from_utf8(out).expect("utf8");
    assert_eq!(failures, 1, "{output}");
    assert!(output.contains("ChironQL is not SQL"), "{output}");
    // It kept going and ran the next statement.
    assert!(output.contains("count"), "{output}");
}

#[test]
fn a_piped_json_session_stays_machine_readable() {
    let (_dir, db) = fixture();
    let mut sink = LocalSink::new(db, Role::ReadOnly);
    let mut out = Vec::new();

    run(
        &mut sink,
        "COUNT products;\n".as_bytes(),
        &mut out,
        ReplOptions {
            interactive: false,
            format: Format::Json,
            ..Default::default()
        },
    )
    .expect("repl runs");

    let output = String::from_utf8(out).expect("utf8");
    let parsed: Value = serde_json::from_str(&output).expect("valid json");
    assert_eq!(parsed["kind"], json!("rows"));
    assert_eq!(parsed["rows"][0]["count"], json!(3));
}

#[test]
fn use_reports_nothing_to_render() {
    let (_dir, db) = fixture();
    let mut session = Session::default();
    let response = exec_as(&db, "USE products;", Role::ReadOnly, &mut session).expect("use");
    assert_eq!(response.kind, ChironQlKind::Empty);
    assert!(response.rows.is_empty());
}
