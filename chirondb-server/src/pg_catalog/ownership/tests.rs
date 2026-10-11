use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn execute(db: &Db, sql: &str) {
    db.execute_sql(
        serde_json::from_value(serde_json::json!({"statements":[{"sql":sql}]})).unwrap(),
    )
    .unwrap();
}
fn fresh() -> (Db, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    (Db::open(directory.path()).unwrap(), directory)
}
fn rows(value: &QueryResponse) -> &[Vec<Option<String>>] {
    match value {
        QueryResponse::RowSet { rows, .. } => rows,
        _ => panic!("rowset required"),
    }
}
fn retained(value: &QueryResponse) -> usize {
    let QueryResponse::RowSet { columns, rows, tag } = value else {
        return 512;
    };
    columns.capacity() * size_of::<ColumnSpec>()
        + columns.iter().map(|c| c.name.capacity()).sum::<usize>()
        + rows.capacity() * size_of::<Vec<Option<String>>>()
        + rows
            .iter()
            .map(|r| {
                r.capacity() * size_of::<Option<String>>()
                    + r.iter().flatten().map(String::capacity).sum::<usize>()
            })
            .sum::<usize>()
        + tag.capacity()
        + size_of::<QueryResponse>()
}
#[test]
fn catalog_classification_matches_routes_without_building_a_response() {
    let samples = [
        ("SELECT version();", Route::Version),
        ("select pg_catalog.current_database()", Route::Database),
        ("select current_schemas()", Route::Schema),
        ("select current_user()", Route::User),
        ("show transaction isolation level", Route::Isolation),
        ("show server_version", Route::Server),
        (
            "SELECT table_name, table_name FROM information_schema.tables",
            Route::Tables(2),
        ),
        (
            "SELECT column_name FROM information_schema.columns",
            Route::Columns(1),
        ),
        (
            "select pg_catalog.pg_attribute.attname as name, pg_catalog.format_type",
            Route::ReflectionColumns,
        ),
        (
            "select domain_constraints from pg_catalog.pg_type.typtype",
            Route::Domains,
        ),
        (
            "select pg_catalog.pg_enum from pg_catalog.pg_type.typtype",
            Route::Enums,
        ),
        (
            "select array_agg(cast(attr.attname as text) from pg_catalog.pg_constraint.contype",
            Route::Constraints,
        ),
        (
            "select pg_catalog.pg_constraint.confrelid, pg_catalog.pg_get_constraintdef",
            Route::ForeignKeys,
        ),
        (
            "select pg_catalog.pg_class.relname, pg_catalog.pg_constraint.conname, pg_catalog.pg_get_constraintdef",
            Route::Checks,
        ),
        (
            "select pg_catalog.pg_index.indrelid, idx_cols.elements",
            Route::Indexes,
        ),
        (
            "select pg_catalog.pg_class.relname, pg_catalog.pg_description.description, pg_catalog.pg_description.objsubid",
            Route::Comments,
        ),
        ("select pg_catalog.pg_class.relname", Route::Names),
        (
            "select pg_catalog.pg_class.oid, pg_catalog.pg_class.relname",
            Route::Oids,
        ),
        ("select * from pg_catalog.pg_class", Route::Class),
        ("select * from pg_namespace", Route::Namespace),
        ("select * from pg_attribute", Route::Attribute),
        (
            "select * from pg_type where oid = to_regtype($1)",
            Route::TypeLookup,
        ),
        ("select * from pg_type", Route::Type),
        ("select * from pg_index", Route::Index),
    ];
    for (sql, route) in samples {
        assert_eq!(
            CatalogPlan::new(sql).unwrap().unwrap().route,
            route,
            "{sql}"
        );
    }
    let filter_sql = format!(
        "select table_name from information_schema.tables where table_name = '{}'",
        "x".repeat(65536)
    );
    let filter = sql_text_filter(&filter_sql, "table_name").unwrap();
    assert_eq!(filter.len(), 65536);
    assert!(filter.as_ptr() >= filter_sql.as_ptr());
    assert!(filter.as_ptr() < filter_sql.as_ptr().wrapping_add(filter_sql.len()));
    for sql in [
        "",
        ";",
        "select 1",
        "SELECT count(*) FROM information_schema.tables",
        "SELECT table_name AS alias FROM information_schema.tables",
    ] {
        assert!(CatalogPlan::new(sql).unwrap().is_none(), "{sql}");
    }
}
#[test]
fn catalog_rows_preserve_names_oids_and_defaults_with_repeated_projection_bounds() {
    let (db, _directory) = fresh();
    execute(
        &db,
        "CREATE TABLE items (id BIGINT PRIMARY KEY, body TEXT DEFAULT '雪''quoted', amount DECIMAL(8,2) DEFAULT 0)",
    );
    execute(&db, "CREATE INDEX by_body ON items (body)");
    let definition = db.relational_tables().remove(0);
    let table_oid = (100_000 + definition.table_id).to_string();
    let response = intercept_owned(&db, "SELECT * FROM pg_catalog.pg_class", &[], |_| true)
        .unwrap()
        .unwrap();
    let mut expected = vec![vec![
        Some(table_oid.clone()),
        Some("items".into()),
        Some("r".into()),
        Some("2200".into()),
    ]];
    for index in &definition.indexes {
        expected.push(vec![
            Some((200_000 + index.index_id).to_string()),
            Some(index.name.clone()),
            Some("i".into()),
            Some("2200".into()),
        ]);
    }
    assert_eq!(rows(&response), expected);
    drop(response);
    let response = intercept_owned(&db, "SELECT * FROM pg_attribute", &[], |_| true)
        .unwrap()
        .unwrap();
    assert_eq!(
        rows(&response),
        vec![
            vec![
                Some(table_oid.clone()),
                Some("id".into()),
                Some("20".into()),
                Some("t".into())
            ],
            vec![
                Some(table_oid.clone()),
                Some("body".into()),
                Some("25".into()),
                Some("f".into())
            ],
            vec![
                Some(table_oid.clone()),
                Some("amount".into()),
                Some("1700".into()),
                Some("f".into())
            ]
        ]
    );
    drop(response);
    let snapshot = db.relational_catalog_owned().unwrap();
    let names = db.collection_names_owned(None).unwrap();
    for repetitions in [1, 2, 17, 1024] {
        let projection = std::iter::repeat_n("column_default", repetitions)
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("SELECT {projection} FROM information_schema.columns");
        let plan = CatalogPlan::new(&sql).unwrap().unwrap();
        let bound = plan.peak(&snapshot, &names, &|_| true).unwrap();
        let response = plan
            .execute(&snapshot, &names, &[], &|_| true, None)
            .unwrap();
        assert_eq!(rows(&response).len(), 3);
        assert_eq!(
            rows(&response)[1],
            vec![Some("'雪''quoted'".into()); repetitions]
        );
        assert!(retained(&response) <= bound);
    }
    let denied = intercept_owned(&db, "select pg_catalog.pg_class.relname", &[], |_| false)
        .unwrap()
        .unwrap();
    assert!(rows(&denied).is_empty());
}
#[test]
fn catalog_default_and_array_expansion_fit_precharged_peak() {
    let values = [
        crate::RelationalValue::Text("'雪\\\"".repeat(1024)),
        crate::RelationalValue::Float(f64::from_bits(1)),
        crate::RelationalValue::Json(
            serde_json::json!({"'雪":["'\n",0.1,null,{"nested":"value"}]}),
        ),
        crate::RelationalValue::Bytes((0..=255).cycle().take(4096).collect()),
        crate::RelationalValue::Vector(vec![f32::from_bits(1), f32::MAX, -0.0]),
        crate::RelationalValue::RecordRef(crate::RecordRef {
            namespace: "n'雪".into(),
            id: "i'雪".into(),
        }),
    ];
    for value in values {
        let bound = default_text_bound(&value).unwrap();
        let text = relational_default_sql(&value);
        assert!(text.capacity() <= bound * 4, "{value:?}");
        let independent = match &value {
            crate::RelationalValue::Text(v) => Some(format!("'{}'", v.replace('\'', "''"))),
            crate::RelationalValue::Json(v) => Some(format!(
                "'{}'::jsonb",
                serde_json::to_string(v).unwrap().replace('\'', "''")
            )),
            crate::RelationalValue::Bytes(v) => Some(format!(
                "'\\x{}'::bytea",
                v.iter().map(|b| format!("{b:02x}")).collect::<String>()
            )),
            _ => None,
        };
        if let Some(expected) = independent {
            assert_eq!(text, expected);
        }
    }
    assert!(mul(usize::MAX, 2).is_err());
    assert!(add(usize::MAX, 1).is_err());
}
#[tokio::test]
async fn catalog_refuses_before_producer_and_retains_response_until_task_drop() {
    if std::env::var_os("CHIRON_PG_CATALOG_QUOTA_CHILD").is_none() {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact","pg_catalog::ownership::tests::catalog_refuses_before_producer_and_retains_response_until_task_drop","--nocapture"])
            .env("CHIRON_PG_CATALOG_QUOTA_CHILD","1").status().unwrap().success());
        return;
    }
    let mut profile = crate::resource_profile::ResourceProfile::from_limits(1 << 30, 1);
    profile.sql_pool_bytes = 8 * 1024 * 1024;
    profile.sql_request_working_set_bytes = 2 * 1024 * 1024;
    crate::resource_profile::install(profile);
    let (db, _directory) = fresh();
    execute(
        &db,
        &format!(
            "CREATE TABLE items (id INTEGER, body TEXT DEFAULT '{}')",
            "s".repeat(8192)
        ),
    );
    let snapshot = db.relational_catalog_owned().unwrap();
    let names = db.collection_names_owned(None).unwrap();
    let sql = "select pg_catalog.pg_attribute.attname as name, pg_catalog.format_type";
    let calls = Arc::new(AtomicUsize::new(0));
    let allows = |_: &str| {
        calls.fetch_add(1, Ordering::Relaxed);
        true
    };
    let held = ResponseReservation::new(7 * 512 * 1024).unwrap();
    let error = CatalogPlan::new(sql)
        .unwrap()
        .unwrap()
        .execute(&snapshot, &names, &[], &allows, None)
        .unwrap_err();
    assert!(matches!(error, GaussError::ResourceExhausted(_)));
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "only preflight may inspect a visible table before refusal"
    );
    drop(held);
    let response = CatalogPlan::new(sql)
        .unwrap()
        .unwrap()
        .execute(&snapshot, &names, &[], &allows, None)
        .unwrap();
    assert!(ResponseReservation::new(7 * 512 * 1024).is_err());
    let (ready, started) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _response = response;
        ready.send(()).unwrap();
        std::future::pending::<()>().await
    });
    started.await.unwrap();
    assert!(ResponseReservation::new(7 * 512 * 1024).is_err());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let held = ResponseReservation::new(7 * 512 * 1024).unwrap();
    assert!(
        intercept_owned(&db, "SELECT version()", &[], |_| panic!(
            "fixed probe must not scan names"
        ))
        .unwrap()
        .is_some()
    );
    assert!(CatalogPlan::new(&"x".repeat(2 * 1024 * 1024)).is_err());
    drop(held);
    assert!(ResponseReservation::new(7 * 512 * 1024).is_ok());
}
