//! B3 + B4 acceptance — drive the seven pgvector statement shapes through
//! the GaussWire / Postgres-protocol sniff end-to-end.
//!
//! - B3 (search): CREATE TABLE → CREATE INDEX → INSERT → `SELECT … ORDER BY
//!   embedding <-> '[…]'::vector LIMIT k` round-trips and returns the inserted
//!   row id back. Covers L2, Cosine, Dot operators.
//! - B4 (DDL/DML + WHERE): denormalised e-commerce schema works end-to-end —
//!   filter by category, range on price, IN list, then sort by vector.
//!
//! Replays the v3 wire protocol byte-for-byte to avoid taking a CI dependency
//! on `psql` (the conformance harness in B6 wires the real binary).

use chirondb::Db;
use chirondb::auth::AuthConfig;
use chirondb::wire;
use chirondb::wire_postgres::PROTOCOL_V3;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn make_db() -> (Db, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Db::open(dir.path()).unwrap();
    (db, dir)
}

async fn spawn_server(db: Db, auth: AuthConfig) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = wire::serve_listener_with_auth(db, auth, listener).await;
    });
    port
}

async fn connect(port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut body = Vec::new();
    body.extend_from_slice(b"user\0alice\0database\0mydb\0application_name\0pgvector-test\0");
    body.push(0);
    let total = 4 + 4 + body.len();
    let mut hdr = Vec::with_capacity(total);
    hdr.extend_from_slice(&(total as u32).to_be_bytes());
    hdr.extend_from_slice(&PROTOCOL_V3.to_be_bytes());
    hdr.extend_from_slice(&body);
    stream.write_all(&hdr).await.unwrap();
    // Drain until ReadyForQuery.
    loop {
        let (t, _b) = read_message(&mut stream).await;
        if t == b'Z' {
            break;
        }
    }
    stream
}

async fn read_message(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut hdr = [0_u8; 5];
    stream.read_exact(&mut hdr).await.unwrap();
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    let mut payload = vec![0_u8; len - 4];
    stream.read_exact(&mut payload).await.unwrap();
    (hdr[0], payload)
}

#[derive(Debug)]
enum Reply {
    RowDescription(Vec<String>, Vec<u32>),
    DataRow(Vec<Option<String>>),
    CommandComplete(String),
    EmptyQuery,
    Error { sqlstate: String, message: String },
}

async fn run_query(stream: &mut TcpStream, sql: &str) -> Vec<Reply> {
    let mut q = Vec::new();
    q.push(b'Q');
    let body_len = sql.len() + 1; // include trailing NUL
    q.extend_from_slice(&((4 + body_len) as u32).to_be_bytes());
    q.extend_from_slice(sql.as_bytes());
    q.push(0);
    stream.write_all(&q).await.unwrap();
    let mut out = Vec::new();
    loop {
        let (t, body) = read_message(stream).await;
        match t {
            b'T' => {
                let (names, oids) = parse_row_description(&body);
                out.push(Reply::RowDescription(names, oids));
            }
            b'D' => out.push(Reply::DataRow(parse_data_row(&body))),
            b'C' => out.push(Reply::CommandComplete(parse_cstring(&body))),
            b'I' => out.push(Reply::EmptyQuery),
            b'E' => out.push(parse_error_response(&body)),
            b'Z' => break,
            other => panic!("unexpected message 0x{other:02x}"),
        }
    }
    out
}

async fn write_frontend_message(stream: &mut TcpStream, kind: u8, payload: &[u8]) {
    let mut message = Vec::with_capacity(payload.len() + 5);
    message.push(kind);
    message.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    message.extend_from_slice(payload);
    stream.write_all(&message).await.unwrap();
}

#[tokio::test]
async fn native_relational_scalar_sql_uses_postgres_simple_query_protocol() {
    let (db, _guard) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;

    let created = run_query(
        &mut stream,
        "CREATE TABLE owners (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)",
    )
    .await;
    assert!(
        matches!(created.as_slice(), [Reply::CommandComplete(tag)] if tag == "CREATE TABLE"),
        "{created:?}"
    );
    let inserted = run_query(
        &mut stream,
        "INSERT INTO owners VALUES (1, 'Ada'), (2, 'Grace')",
    )
    .await;
    assert!(matches!(inserted.as_slice(), [Reply::CommandComplete(tag)] if tag == "INSERT 0 2"));
    let selected = run_query(&mut stream, "SELECT id, name FROM owners WHERE id = 2").await;
    assert!(matches!(
        selected.as_slice(),
        [Reply::RowDescription(columns, oids), Reply::DataRow(row), Reply::CommandComplete(tag)]
            if columns == &["id", "name"]
            && oids == &[23, 25]
                && row == &[Some("2".into()), Some("Grace".into())]
                && tag == "SELECT 1"
    ));
}

#[tokio::test]
async fn unknown_scalar_table_uses_native_undefined_table_sqlstate() {
    let (db, _guard) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;

    let response = run_query(
        &mut stream,
        "SELECT COUNT(*) FROM relational_table_that_does_not_exist",
    )
    .await;
    assert!(matches!(
        response.as_slice(),
        [Reply::Error { sqlstate, message }]
            if sqlstate == "42P01" && message.contains("does not exist")
    ));
}

#[tokio::test]
async fn native_relational_distinct_uses_postgres_simple_query_protocol() {
    let (db, _guard) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;

    run_query(
        &mut stream,
        "CREATE TABLE distinct_wire (id INTEGER PRIMARY KEY, category TEXT)",
    )
    .await;
    run_query(
        &mut stream,
        "INSERT INTO distinct_wire VALUES (1, 'a'), (2, 'a'), (3, 'b'), (4, NULL)",
    )
    .await;
    let selected = run_query(
        &mut stream,
        "SELECT DISTINCT category FROM distinct_wire ORDER BY category NULLS LAST",
    )
    .await;
    assert!(
        matches!(
            selected.as_slice(),
            [
                Reply::RowDescription(columns, oids),
                Reply::DataRow(first),
                Reply::DataRow(second),
                Reply::DataRow(third),
                Reply::CommandComplete(tag)
            ] if columns == &["category"]
                && oids == &[25]
                && first == &[Some("a".into())]
                && second == &[Some("b".into())]
                && third == &[None]
                && tag == "SELECT 3"
        ),
        "{selected:?}"
    );

    let aggregate = run_query(
        &mut stream,
        "SELECT COUNT(DISTINCT category) AS categories FROM distinct_wire",
    )
    .await;
    assert!(
        matches!(
            aggregate.as_slice(),
            [
                Reply::RowDescription(columns, oids),
                Reply::DataRow(row),
                Reply::CommandComplete(tag)
            ] if columns == &["categories"]
                && oids == &[20]
                && row == &[Some("2".into())]
                && tag == "SELECT 1"
        ),
        "{aggregate:?}"
    );
}

#[tokio::test]
async fn native_relational_schema_changes_run_over_postgres_wire() {
    let (db, _guard) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;

    run_query(
        &mut stream,
        "CREATE TABLE migrations (id INTEGER PRIMARY KEY, keep TEXT, obsolete TEXT)",
    )
    .await;
    run_query(
        &mut stream,
        "INSERT INTO migrations VALUES (1, 'preserved', 'removed')",
    )
    .await;
    let dependent = run_query(&mut stream, "ALTER TABLE migrations DROP COLUMN id").await;
    assert!(
        matches!(
            dependent.as_slice(),
            [Reply::Error { sqlstate, .. }] if sqlstate == "2BP01"
        ),
        "{dependent:?}"
    );
    let altered = run_query(&mut stream, "ALTER TABLE migrations DROP COLUMN obsolete").await;
    assert!(matches!(
        altered.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "ALTER TABLE"
    ));
    let selected = run_query(&mut stream, "SELECT id, keep FROM migrations").await;
    assert!(matches!(
        selected.as_slice(),
        [Reply::RowDescription(columns, oids), Reply::DataRow(row), Reply::CommandComplete(tag)]
            if columns == &["id", "keep"]
                && oids == &[23, 25]
                && row == &[Some("1".into()), Some("preserved".into())]
                && tag == "SELECT 1"
    ));
    let rejected = run_query(&mut stream, "SELECT obsolete FROM migrations").await;
    assert!(
        matches!(
            rejected.as_slice(),
            [Reply::Error { sqlstate, .. }] if sqlstate == "42703"
        ),
        "{rejected:?}"
    );
    let renamed = run_query(
        &mut stream,
        "ALTER TABLE migrations RENAME COLUMN keep TO retained",
    )
    .await;
    assert!(matches!(
        renamed.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "ALTER TABLE"
    ));
    let selected = run_query(&mut stream, "SELECT id, retained FROM migrations").await;
    assert!(matches!(
        selected.as_slice(),
        [Reply::RowDescription(columns, oids), Reply::DataRow(row), Reply::CommandComplete(tag)]
            if columns == &["id", "retained"]
                && oids == &[23, 25]
                && row == &[Some("1".into()), Some("preserved".into())]
                && tag == "SELECT 1"
    ));
    let old_name = run_query(&mut stream, "SELECT keep FROM migrations").await;
    assert!(
        matches!(
            old_name.as_slice(),
            [Reply::Error { sqlstate, .. }] if sqlstate == "42703"
        ),
        "{old_name:?}"
    );
    let duplicate = run_query(
        &mut stream,
        "ALTER TABLE migrations RENAME COLUMN retained TO id",
    )
    .await;
    assert!(
        matches!(
            duplicate.as_slice(),
            [Reply::Error { sqlstate, .. }] if sqlstate == "42701"
        ),
        "{duplicate:?}"
    );
    let altered_type = run_query(
        &mut stream,
        "ALTER TABLE migrations ALTER COLUMN id TYPE BIGINT",
    )
    .await;
    assert!(matches!(
        altered_type.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "ALTER TABLE"
    ));
    let typed = run_query(&mut stream, "SELECT id, retained FROM migrations").await;
    assert!(matches!(
        typed.as_slice(),
        [Reply::RowDescription(columns, oids), Reply::DataRow(row), Reply::CommandComplete(tag)]
            if columns == &["id", "retained"]
                && oids == &[20, 25]
                && row == &[Some("1".into()), Some("preserved".into())]
                && tag == "SELECT 1"
    ));
    for statement in [
        "ALTER TABLE migrations ALTER COLUMN retained SET NOT NULL",
        "ALTER TABLE migrations ALTER COLUMN retained SET DEFAULT 'fallback'",
    ] {
        let reply = run_query(&mut stream, statement).await;
        assert!(matches!(
            reply.as_slice(),
            [Reply::CommandComplete(tag)] if tag == "ALTER TABLE"
        ));
    }
    let null_violation = run_query(
        &mut stream,
        "INSERT INTO migrations (id, retained) VALUES (3, NULL)",
    )
    .await;
    assert!(
        matches!(
            null_violation.as_slice(),
            [Reply::Error { sqlstate, .. }] if sqlstate == "23502"
        ),
        "{null_violation:?}"
    );
    let inserted_default = run_query(&mut stream, "INSERT INTO migrations (id) VALUES (2)").await;
    assert!(matches!(
        inserted_default.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "INSERT 0 1"
    ));
    let defaulted = run_query(&mut stream, "SELECT retained FROM migrations WHERE id = 2").await;
    assert!(matches!(
        defaulted.as_slice(),
        [Reply::RowDescription(columns, oids), Reply::DataRow(row), Reply::CommandComplete(tag)]
            if columns == &["retained"]
                && oids == &[25]
                && row == &[Some("fallback".into())]
                && tag == "SELECT 1"
    ));
    for statement in [
        "ALTER TABLE migrations ALTER COLUMN retained DROP DEFAULT",
        "ALTER TABLE migrations ALTER COLUMN retained DROP NOT NULL",
    ] {
        let reply = run_query(&mut stream, statement).await;
        assert!(matches!(
            reply.as_slice(),
            [Reply::CommandComplete(tag)] if tag == "ALTER TABLE"
        ));
    }
    run_query(&mut stream, "DELETE FROM migrations WHERE id = 2").await;
    run_query(
        &mut stream,
        "ALTER TABLE migrations ADD CONSTRAINT migrations_retained_key UNIQUE (retained)",
    )
    .await;
    let renamed_constraint = run_query(
        &mut stream,
        "ALTER TABLE migrations RENAME CONSTRAINT migrations_retained_key TO migrations_retained_uq",
    )
    .await;
    assert!(matches!(
        renamed_constraint.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "ALTER TABLE"
    ));
    let missing_constraint = run_query(
        &mut stream,
        "ALTER TABLE migrations RENAME CONSTRAINT missing TO replacement",
    )
    .await;
    assert!(
        matches!(
            missing_constraint.as_slice(),
            [Reply::Error { sqlstate, .. }] if sqlstate == "42704"
        ),
        "{missing_constraint:?}"
    );
    let duplicate_constraint = run_query(
        &mut stream,
        "ALTER TABLE migrations RENAME CONSTRAINT migrations_pkey TO migrations_retained_uq",
    )
    .await;
    assert!(
        matches!(
            duplicate_constraint.as_slice(),
            [Reply::Error { sqlstate, .. }] if sqlstate == "42710"
        ),
        "{duplicate_constraint:?}"
    );
    run_query(
        &mut stream,
        "ALTER TABLE migrations RENAME CONSTRAINT migrations_pkey TO migrations_identity_pk",
    )
    .await;
    run_query(
        &mut stream,
        "CREATE TABLE migration_refs (id INTEGER PRIMARY KEY, retained TEXT REFERENCES migrations(retained))",
    )
    .await;
    let cascaded_constraint = run_query(
        &mut stream,
        "ALTER TABLE migrations DROP CONSTRAINT migrations_retained_uq CASCADE",
    )
    .await;
    assert!(matches!(
        cascaded_constraint.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "ALTER TABLE"
    ));
    let orphan_after_cascade = run_query(
        &mut stream,
        "INSERT INTO migration_refs VALUES (1, 'no-longer-referenced')",
    )
    .await;
    assert!(matches!(
        orphan_after_cascade.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "INSERT 0 1"
    ));
    run_query(
        &mut stream,
        "CREATE TABLE occupied_migrations (id INTEGER PRIMARY KEY)",
    )
    .await;
    let renamed_table = run_query(
        &mut stream,
        "ALTER TABLE migrations RENAME TO archived_migrations",
    )
    .await;
    assert!(matches!(
        renamed_table.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "ALTER TABLE"
    ));
    let renamed_table_row =
        run_query(&mut stream, "SELECT id, retained FROM archived_migrations").await;
    assert!(matches!(
        renamed_table_row.as_slice(),
        [Reply::RowDescription(columns, oids), Reply::DataRow(row), Reply::CommandComplete(tag)]
            if columns == &["id", "retained"]
                && oids == &[20, 25]
                && row == &[Some("1".into()), Some("preserved".into())]
                && tag == "SELECT 1"
    ));
    let old_table = run_query(&mut stream, "SELECT id FROM migrations").await;
    assert!(
        matches!(
            old_table.as_slice(),
            [Reply::Error { sqlstate, .. }] if sqlstate == "42P01"
        ),
        "{old_table:?}"
    );
    let duplicate_table = run_query(
        &mut stream,
        "ALTER TABLE archived_migrations RENAME TO occupied_migrations",
    )
    .await;
    assert!(
        matches!(
            duplicate_table.as_slice(),
            [Reply::Error { sqlstate, .. }] if sqlstate == "42P07"
        ),
        "{duplicate_table:?}"
    );
    run_query(
        &mut stream,
        "CREATE TABLE table_drop_parent (id INTEGER PRIMARY KEY)",
    )
    .await;
    run_query(
        &mut stream,
        "CREATE TABLE table_drop_child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES table_drop_parent(id))",
    )
    .await;
    let restricted_table = run_query(&mut stream, "DROP TABLE table_drop_parent").await;
    assert!(
        matches!(
            restricted_table.as_slice(),
            [Reply::Error { sqlstate, .. }] if sqlstate == "2BP01"
        ),
        "{restricted_table:?}"
    );
    let cascaded_table = run_query(&mut stream, "DROP TABLE table_drop_parent CASCADE").await;
    assert!(matches!(
        cascaded_table.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "DROP TABLE"
    ));
    let orphan_after_table_drop =
        run_query(&mut stream, "INSERT INTO table_drop_child VALUES (1, 999)").await;
    assert!(matches!(
        orphan_after_table_drop.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "INSERT 0 1"
    ));
    run_query(
        &mut stream,
        "CREATE TABLE column_drop_parent (id INTEGER PRIMARY KEY, code TEXT UNIQUE, obsolete TEXT, keep TEXT)",
    )
    .await;
    run_query(
        &mut stream,
        "CREATE TABLE column_drop_child (id INTEGER PRIMARY KEY, parent_code TEXT REFERENCES column_drop_parent(code))",
    )
    .await;
    let restricted_column = run_query(
        &mut stream,
        "ALTER TABLE column_drop_parent DROP COLUMN code",
    )
    .await;
    assert!(
        matches!(
            restricted_column.as_slice(),
            [Reply::Error { sqlstate, .. }] if sqlstate == "2BP01"
        ),
        "{restricted_column:?}"
    );
    let cascaded_column = run_query(
        &mut stream,
        "ALTER TABLE column_drop_parent DROP COLUMN code CASCADE, DROP COLUMN obsolete",
    )
    .await;
    assert!(matches!(
        cascaded_column.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "ALTER TABLE"
    ));
    let remaining_columns = run_query(&mut stream, "SELECT id, keep FROM column_drop_parent").await;
    assert!(matches!(
        remaining_columns.as_slice(),
        [Reply::RowDescription(columns, oids), Reply::CommandComplete(tag)]
            if columns == &["id", "keep"] && oids == &[23, 25] && tag == "SELECT 0"
    ));
    let orphan_after_column_drop = run_query(
        &mut stream,
        "INSERT INTO column_drop_child VALUES (1, 'orphan')",
    )
    .await;
    assert!(matches!(
        orphan_after_column_drop.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "INSERT 0 1"
    ));
}

#[tokio::test]
async fn native_relational_cte_uses_postgres_simple_query_protocol() {
    let (db, _guard) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;

    run_query(
        &mut stream,
        "CREATE TABLE cte_items (id INTEGER PRIMARY KEY, label TEXT NOT NULL)",
    )
    .await;
    run_query(
        &mut stream,
        "INSERT INTO cte_items VALUES (1, 'one'), (2, 'two'), (3, 'three')",
    )
    .await;
    let selected = run_query(
        &mut stream,
        "WITH selected(item_id, item_label) AS (SELECT id, label FROM cte_items WHERE id >= 2) SELECT item_id, item_label FROM selected ORDER BY item_id",
    )
    .await;
    assert!(matches!(
        selected.as_slice(),
        [
            Reply::RowDescription(columns, oids),
            Reply::DataRow(first),
            Reply::DataRow(second),
            Reply::CommandComplete(tag)
        ] if columns == &["item_id", "item_label"]
            && oids == &[23, 25]
            && first == &[Some("2".into()), Some("two".into())]
            && second == &[Some("3".into()), Some("three".into())]
            && tag == "SELECT 2"
    ));

    let subqueries = run_query(
        &mut stream,
        "SELECT id, (SELECT label FROM cte_items WHERE id = 1) AS seed FROM cte_items WHERE id IN (SELECT id FROM cte_items WHERE id >= 2) AND EXISTS (SELECT id FROM cte_items WHERE id = 3) ORDER BY id",
    )
    .await;
    assert!(matches!(
        subqueries.as_slice(),
        [
            Reply::RowDescription(columns, oids),
            Reply::DataRow(first),
            Reply::DataRow(second),
            Reply::CommandComplete(tag)
        ] if columns == &["id", "seed"]
            && oids == &[23, 25]
            && first == &[Some("2".into()), Some("one".into())]
            && second == &[Some("3".into()), Some("one".into())]
            && tag == "SELECT 2"
    ));

    let rejected = run_query(
        &mut stream,
        "SELECT id, (SELECT label FROM cte_items) AS seed FROM cte_items WHERE id = 1",
    )
    .await;
    assert!(matches!(
        rejected.as_slice(),
        [Reply::Error { sqlstate, message }]
            if sqlstate == "21000" && message.contains("more than one row")
    ));
}

#[tokio::test]
async fn native_relational_row_description_uses_stable_postgres_type_oids() {
    let (db, _guard) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;
    run_query(
        &mut stream,
        "CREATE TABLE typed_values (amount NUMERIC(10,2), observed TIMESTAMP WITH TIME ZONE, uid UUID)",
    )
    .await;
    run_query(
        &mut stream,
        "INSERT INTO typed_values VALUES ('12.50', '2026-09-17T09:00:00Z', '550e8400-e29b-41d4-a716-446655440000')",
    )
    .await;
    let selected = run_query(
        &mut stream,
        "SELECT amount, observed, uid FROM typed_values",
    )
    .await;
    assert!(matches!(
        selected.as_slice(),
        [Reply::RowDescription(columns, oids), Reply::DataRow(_), Reply::CommandComplete(_)]
            if columns == &["amount", "observed", "uid"]
                && oids == &[1700, 1184, 2950]
    ));
}

#[tokio::test]
async fn native_relational_check_violation_uses_postgres_sqlstate() {
    let (db, _guard) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;
    run_query(
        &mut stream,
        "CREATE TABLE balances (id INTEGER PRIMARY KEY, amount INTEGER CONSTRAINT amount_nonnegative CHECK (amount >= 0))",
    )
    .await;
    let rejected = run_query(&mut stream, "INSERT INTO balances VALUES (1, -1)").await;
    assert!(matches!(
        rejected.as_slice(),
        [Reply::Error { sqlstate, message }]
            if sqlstate == "23514" && message.contains("amount_nonnegative")
    ));
    let accepted = run_query(&mut stream, "INSERT INTO balances VALUES (1, 0)").await;
    assert!(matches!(
        accepted.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "INSERT 0 1"
    ));
}

#[tokio::test]
async fn native_relational_prepared_insert_uses_extended_protocol() {
    let (db, _guard) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;
    run_query(
        &mut stream,
        "CREATE TABLE prepared_items (id BIGINT PRIMARY KEY, label TEXT NOT NULL)",
    )
    .await;

    let mut parse = Vec::new();
    parse.extend_from_slice(b"insert_item\0");
    parse.extend_from_slice(b"INSERT INTO prepared_items VALUES ($1, $2)\0");
    parse.extend_from_slice(&2_u16.to_be_bytes());
    parse.extend_from_slice(&20_u32.to_be_bytes());
    parse.extend_from_slice(&25_u32.to_be_bytes());
    write_frontend_message(&mut stream, b'P', &parse).await;

    let mut bind = Vec::new();
    bind.extend_from_slice(b"item_portal\0insert_item\0");
    bind.extend_from_slice(&0_u16.to_be_bytes());
    bind.extend_from_slice(&2_u16.to_be_bytes());
    bind.extend_from_slice(&1_i32.to_be_bytes());
    bind.extend_from_slice(b"7");
    bind.extend_from_slice(&8_i32.to_be_bytes());
    bind.extend_from_slice(b"prepared");
    bind.extend_from_slice(&0_u16.to_be_bytes());
    write_frontend_message(&mut stream, b'B', &bind).await;

    let mut describe = vec![b'S'];
    describe.extend_from_slice(b"insert_item\0");
    write_frontend_message(&mut stream, b'D', &describe).await;
    let mut execute = Vec::new();
    execute.extend_from_slice(b"item_portal\0");
    execute.extend_from_slice(&0_u32.to_be_bytes());
    write_frontend_message(&mut stream, b'E', &execute).await;
    write_frontend_message(&mut stream, b'S', &[]).await;

    let mut message_types = Vec::new();
    loop {
        let (kind, body) = read_message(&mut stream).await;
        if kind == b'E' {
            panic!("extended protocol error: {:?}", parse_error_response(&body));
        }
        message_types.push(kind);
        if kind == b'Z' {
            break;
        }
    }
    assert_eq!(message_types, [b'1', b'2', b't', b'n', b'C', b'Z']);

    let mut select_parse = Vec::new();
    select_parse.extend_from_slice(b"select_item\0");
    select_parse.extend_from_slice(b"SELECT id, label FROM prepared_items WHERE id = $1\0");
    select_parse.extend_from_slice(&1_u16.to_be_bytes());
    select_parse.extend_from_slice(&20_u32.to_be_bytes());
    write_frontend_message(&mut stream, b'P', &select_parse).await;
    let mut select_bind = Vec::new();
    select_bind.extend_from_slice(b"select_portal\0select_item\0");
    select_bind.extend_from_slice(&0_u16.to_be_bytes());
    select_bind.extend_from_slice(&1_u16.to_be_bytes());
    select_bind.extend_from_slice(&1_i32.to_be_bytes());
    select_bind.extend_from_slice(b"7");
    select_bind.extend_from_slice(&0_u16.to_be_bytes());
    write_frontend_message(&mut stream, b'B', &select_bind).await;
    let mut portal_describe = vec![b'P'];
    portal_describe.extend_from_slice(b"select_portal\0");
    write_frontend_message(&mut stream, b'D', &portal_describe).await;
    let mut select_execute = Vec::new();
    select_execute.extend_from_slice(b"select_portal\0");
    select_execute.extend_from_slice(&0_u32.to_be_bytes());
    write_frontend_message(&mut stream, b'E', &select_execute).await;
    write_frontend_message(&mut stream, b'S', &[]).await;
    let mut selected_types = Vec::new();
    let mut selected_row = None;
    loop {
        let (kind, body) = read_message(&mut stream).await;
        if kind == b'E' {
            panic!("extended SELECT error: {:?}", parse_error_response(&body));
        }
        if kind == b'D' {
            selected_row = Some(parse_data_row(&body));
        }
        selected_types.push(kind);
        if kind == b'Z' {
            break;
        }
    }
    assert_eq!(selected_types, [b'1', b'2', b'T', b'D', b'C', b'Z']);
    assert_eq!(
        selected_row.unwrap(),
        [Some("7".into()), Some("prepared".into())]
    );
}

#[tokio::test]
async fn sql_deallocate_closes_protocol_prepared_statements() {
    let (db, _guard) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;
    run_query(
        &mut stream,
        "CREATE TABLE deallocate_items (id INTEGER PRIMARY KEY)",
    )
    .await;

    for name in ["_pg3_0", "other_statement"] {
        let mut parse = Vec::new();
        parse.extend_from_slice(name.as_bytes());
        parse.push(0);
        parse.extend_from_slice(b"SELECT id FROM deallocate_items\0");
        parse.extend_from_slice(&0_u16.to_be_bytes());
        write_frontend_message(&mut stream, b'P', &parse).await;
    }
    write_frontend_message(&mut stream, b'S', &[]).await;
    let mut prepared = Vec::new();
    loop {
        let (kind, body) = read_message(&mut stream).await;
        if kind == b'E' {
            panic!("prepare error: {:?}", parse_error_response(&body));
        }
        prepared.push(kind);
        if kind == b'Z' {
            break;
        }
    }
    assert_eq!(prepared, [b'1', b'1', b'Z']);

    let deallocated = run_query(&mut stream, "DEALLOCATE \"_pg3_0\"").await;
    assert!(matches!(
        deallocated.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "DEALLOCATE"
    ));

    let mut describe = vec![b'S'];
    describe.extend_from_slice(b"_pg3_0\0");
    write_frontend_message(&mut stream, b'D', &describe).await;
    write_frontend_message(&mut stream, b'S', &[]).await;
    let mut missing = None;
    loop {
        let (kind, body) = read_message(&mut stream).await;
        if kind == b'E' {
            missing = Some(parse_error_response(&body));
        }
        if kind == b'Z' {
            break;
        }
    }
    assert!(matches!(
        missing,
        Some(Reply::Error { sqlstate, .. }) if sqlstate == "26000"
    ));

    let all = run_query(&mut stream, "DEALLOCATE ALL").await;
    assert!(matches!(
        all.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "DEALLOCATE"
    ));
    let missing_again = run_query(&mut stream, "DEALLOCATE other_statement").await;
    assert!(matches!(
        missing_again.as_slice(),
        [Reply::Error { sqlstate, .. }] if sqlstate == "26000"
    ));
}

#[tokio::test]
async fn extended_catalog_query_inside_transaction_uses_catalog_projection() {
    let (db, _guard) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;
    assert!(matches!(
        run_query(&mut stream, "BEGIN").await.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "BEGIN"
    ));

    let mut parse = Vec::new();
    parse.extend_from_slice(b"server_version\0select pg_catalog.version()\0");
    parse.extend_from_slice(&0_u16.to_be_bytes());
    write_frontend_message(&mut stream, b'P', &parse).await;
    let mut bind = Vec::new();
    bind.extend_from_slice(b"version_portal\0server_version\0");
    bind.extend_from_slice(&0_u16.to_be_bytes());
    bind.extend_from_slice(&0_u16.to_be_bytes());
    bind.extend_from_slice(&0_u16.to_be_bytes());
    write_frontend_message(&mut stream, b'B', &bind).await;
    let mut describe = vec![b'P'];
    describe.extend_from_slice(b"version_portal\0");
    write_frontend_message(&mut stream, b'D', &describe).await;
    let mut execute = Vec::new();
    execute.extend_from_slice(b"version_portal\0");
    execute.extend_from_slice(&0_u32.to_be_bytes());
    write_frontend_message(&mut stream, b'E', &execute).await;
    write_frontend_message(&mut stream, b'S', &[]).await;

    let mut message_types = Vec::new();
    let mut row = None;
    loop {
        let (kind, body) = read_message(&mut stream).await;
        if kind == b'E' {
            panic!("extended catalog error: {:?}", parse_error_response(&body));
        }
        if kind == b'D' {
            row = Some(parse_data_row(&body));
        }
        message_types.push(kind);
        if kind == b'Z' {
            break;
        }
    }
    assert_eq!(message_types, [b'1', b'2', b'T', b'D', b'C', b'Z']);
    assert!(row.unwrap()[0].as_deref().unwrap().contains("PostgreSQL"));
}

#[tokio::test]
async fn prepared_insert_sees_table_created_in_same_transaction() {
    let (db, _guard) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;
    run_query(&mut stream, "BEGIN").await;
    run_query(
        &mut stream,
        "CREATE TABLE private_items (id BIGINT PRIMARY KEY, label TEXT NOT NULL)",
    )
    .await;

    let mut parse = Vec::new();
    parse.extend_from_slice(b"private_insert\0");
    parse.extend_from_slice(b"INSERT INTO private_items VALUES ($1, $2) RETURNING id\0");
    parse.extend_from_slice(&2_u16.to_be_bytes());
    parse.extend_from_slice(&20_u32.to_be_bytes());
    parse.extend_from_slice(&25_u32.to_be_bytes());
    write_frontend_message(&mut stream, b'P', &parse).await;
    let mut bind = Vec::new();
    bind.extend_from_slice(b"private_portal\0private_insert\0");
    bind.extend_from_slice(&0_u16.to_be_bytes());
    bind.extend_from_slice(&2_u16.to_be_bytes());
    bind.extend_from_slice(&1_i32.to_be_bytes());
    bind.extend_from_slice(b"1");
    bind.extend_from_slice(&5_i32.to_be_bytes());
    bind.extend_from_slice(b"first");
    bind.extend_from_slice(&0_u16.to_be_bytes());
    write_frontend_message(&mut stream, b'B', &bind).await;
    let mut execute = Vec::new();
    execute.extend_from_slice(b"private_portal\0");
    execute.extend_from_slice(&0_u32.to_be_bytes());
    write_frontend_message(&mut stream, b'E', &execute).await;
    write_frontend_message(&mut stream, b'S', &[]).await;

    let mut row = None;
    loop {
        let (kind, body) = read_message(&mut stream).await;
        if kind == b'E' {
            panic!(
                "transaction-private prepared insert error: {:?}",
                parse_error_response(&body)
            );
        }
        if kind == b'D' {
            row = Some(parse_data_row(&body));
        }
        if kind == b'Z' {
            break;
        }
    }
    assert_eq!(row.unwrap(), [Some("1".into())]);
    assert!(matches!(
        run_query(&mut stream, "COMMIT").await.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "COMMIT"
    ));
    let selected = run_query(&mut stream, "SELECT label FROM private_items WHERE id = 1").await;
    assert!(matches!(
        selected.as_slice(),
        [Reply::RowDescription(_, _), Reply::DataRow(row), Reply::CommandComplete(_)]
            if row == &[Some("first".into())]
    ));
}

#[tokio::test]
async fn extended_protocol_returns_binary_relational_results() {
    let (db, _guard) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;
    run_query(
        &mut stream,
        "CREATE TABLE binary_items (id BIGINT PRIMARY KEY, label TEXT NOT NULL)",
    )
    .await;
    run_query(&mut stream, "INSERT INTO binary_items VALUES (7, 'binary')").await;

    let mut parse = Vec::new();
    parse.extend_from_slice(b"binary_select\0");
    parse.extend_from_slice(b"SELECT id, label FROM binary_items WHERE id = $1\0");
    parse.extend_from_slice(&1_u16.to_be_bytes());
    parse.extend_from_slice(&20_u32.to_be_bytes());
    write_frontend_message(&mut stream, b'P', &parse).await;

    let mut bind = Vec::new();
    bind.extend_from_slice(b"binary_portal\0binary_select\0");
    bind.extend_from_slice(&1_u16.to_be_bytes());
    bind.extend_from_slice(&1_i16.to_be_bytes());
    bind.extend_from_slice(&1_u16.to_be_bytes());
    bind.extend_from_slice(&8_i32.to_be_bytes());
    bind.extend_from_slice(&7_i64.to_be_bytes());
    bind.extend_from_slice(&1_u16.to_be_bytes());
    bind.extend_from_slice(&1_i16.to_be_bytes());
    write_frontend_message(&mut stream, b'B', &bind).await;

    let mut describe = vec![b'P'];
    describe.extend_from_slice(b"binary_portal\0");
    write_frontend_message(&mut stream, b'D', &describe).await;
    let mut execute = Vec::new();
    execute.extend_from_slice(b"binary_portal\0");
    execute.extend_from_slice(&0_u32.to_be_bytes());
    write_frontend_message(&mut stream, b'E', &execute).await;
    write_frontend_message(&mut stream, b'S', &[]).await;

    let mut message_types = Vec::new();
    let mut formats = None;
    let mut row = None;
    loop {
        let (kind, body) = read_message(&mut stream).await;
        if kind == b'E' {
            panic!(
                "binary extended query error: {:?}",
                parse_error_response(&body)
            );
        }
        if kind == b'T' {
            formats = Some(parse_row_formats(&body));
        }
        if kind == b'D' {
            row = Some(parse_binary_data_row(&body));
        }
        message_types.push(kind);
        if kind == b'Z' {
            break;
        }
    }

    assert_eq!(message_types, [b'1', b'2', b'T', b'D', b'C', b'Z']);
    assert_eq!(formats.unwrap(), [1, 1]);
    let row = row.unwrap();
    assert_eq!(
        i64::from_be_bytes(row[0].as_deref().unwrap().try_into().unwrap()),
        7
    );
    assert_eq!(row[1].as_deref(), Some(b"binary".as_slice()));
}

#[tokio::test]
async fn extended_protocol_accepts_driver_session_set_statements() {
    let (db, _guard) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;

    let mut parse = Vec::new();
    parse.extend_from_slice(b"set_timezone\0SET TIME ZONE 'UTC'\0");
    parse.extend_from_slice(&0_u16.to_be_bytes());
    write_frontend_message(&mut stream, b'P', &parse).await;
    let mut bind = Vec::new();
    bind.extend_from_slice(b"set_portal\0set_timezone\0");
    bind.extend_from_slice(&0_u16.to_be_bytes());
    bind.extend_from_slice(&0_u16.to_be_bytes());
    bind.extend_from_slice(&0_u16.to_be_bytes());
    write_frontend_message(&mut stream, b'B', &bind).await;
    let mut execute = Vec::new();
    execute.extend_from_slice(b"set_portal\0");
    execute.extend_from_slice(&0_u32.to_be_bytes());
    write_frontend_message(&mut stream, b'E', &execute).await;
    write_frontend_message(&mut stream, b'S', &[]).await;

    let mut message_types = Vec::new();
    let mut command = None;
    loop {
        let (kind, body) = read_message(&mut stream).await;
        if kind == b'E' {
            panic!("extended SET error: {:?}", parse_error_response(&body));
        }
        if kind == b'C' {
            command = Some(parse_cstring(&body));
        }
        message_types.push(kind);
        if kind == b'Z' {
            break;
        }
    }
    assert_eq!(message_types, [b'1', b'2', b'C', b'Z']);
    assert_eq!(command.as_deref(), Some("SET"));
}

#[tokio::test]
async fn extended_protocol_execution_error_discards_messages_until_sync() {
    let (db, _guard) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;
    run_query(
        &mut stream,
        "CREATE TABLE guarded_items (id INTEGER PRIMARY KEY, amount INTEGER CHECK (amount >= 0))",
    )
    .await;

    let mut parse = Vec::new();
    parse.extend_from_slice(b"bad_insert\0");
    parse.extend_from_slice(b"INSERT INTO guarded_items VALUES ($1, $2)\0");
    parse.extend_from_slice(&2_u16.to_be_bytes());
    parse.extend_from_slice(&23_u32.to_be_bytes());
    parse.extend_from_slice(&23_u32.to_be_bytes());
    write_frontend_message(&mut stream, b'P', &parse).await;

    let mut bind = Vec::new();
    bind.extend_from_slice(b"bad_portal\0bad_insert\0");
    bind.extend_from_slice(&0_u16.to_be_bytes());
    bind.extend_from_slice(&2_u16.to_be_bytes());
    bind.extend_from_slice(&1_i32.to_be_bytes());
    bind.extend_from_slice(b"1");
    bind.extend_from_slice(&2_i32.to_be_bytes());
    bind.extend_from_slice(b"-1");
    bind.extend_from_slice(&0_u16.to_be_bytes());
    write_frontend_message(&mut stream, b'B', &bind).await;

    let mut execute = Vec::new();
    execute.extend_from_slice(b"bad_portal\0");
    execute.extend_from_slice(&0_u32.to_be_bytes());
    write_frontend_message(&mut stream, b'E', &execute).await;

    let mut ignored_parse = Vec::new();
    ignored_parse.extend_from_slice(b"must_be_ignored\0SELECT id FROM guarded_items\0");
    ignored_parse.extend_from_slice(&0_u16.to_be_bytes());
    write_frontend_message(&mut stream, b'P', &ignored_parse).await;
    write_frontend_message(&mut stream, b'S', &[]).await;

    let mut message_types = Vec::new();
    let mut sqlstate = None;
    loop {
        let (kind, body) = read_message(&mut stream).await;
        if kind == b'E'
            && let Reply::Error {
                sqlstate: state, ..
            } = parse_error_response(&body)
        {
            sqlstate = Some(state);
        }
        message_types.push(kind);
        if kind == b'Z' {
            break;
        }
    }
    assert_eq!(message_types, [b'1', b'2', b'E', b'Z']);
    assert_eq!(sqlstate.as_deref(), Some("23514"));

    let accepted = run_query(&mut stream, "INSERT INTO guarded_items VALUES (1, 0)").await;
    assert!(matches!(
        accepted.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "INSERT 0 1"
    ));
}

#[tokio::test]
async fn native_relational_postgres_transaction_and_savepoint_are_isolated() {
    let (db, _guard) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut writer = connect(port).await;
    let mut reader = connect(port).await;
    run_query(
        &mut writer,
        "CREATE TABLE tx_items (id INTEGER PRIMARY KEY)",
    )
    .await;
    assert!(matches!(
        run_query(&mut writer, "BEGIN").await.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "BEGIN"
    ));
    run_query(&mut writer, "INSERT INTO tx_items VALUES (1)").await;
    let outside = run_query(&mut reader, "SELECT COUNT(*) FROM tx_items").await;
    assert!(matches!(
        outside.as_slice(),
        [Reply::RowDescription(_, _), Reply::DataRow(row), Reply::CommandComplete(_)]
            if row == &[Some("0".into())]
    ));
    run_query(&mut writer, "SAVEPOINT before_duplicate").await;
    let duplicate = run_query(&mut writer, "INSERT INTO tx_items VALUES (1)").await;
    assert!(matches!(duplicate.as_slice(), [Reply::Error { sqlstate, .. }] if sqlstate == "23505"));
    assert!(matches!(
        run_query(&mut writer, "ROLLBACK TO SAVEPOINT before_duplicate")
            .await
            .as_slice(),
        [Reply::CommandComplete(tag)] if tag == "ROLLBACK"
    ));
    run_query(&mut writer, "INSERT INTO tx_items VALUES (2)").await;
    assert!(matches!(
        run_query(&mut writer, "COMMIT").await.as_slice(),
        [Reply::CommandComplete(tag)] if tag == "COMMIT"
    ));
    let committed = run_query(&mut reader, "SELECT COUNT(*) FROM tx_items").await;
    assert!(matches!(
        committed.as_slice(),
        [Reply::RowDescription(_, _), Reply::DataRow(row), Reply::CommandComplete(_)]
            if row == &[Some("2".into())]
    ));
}

fn parse_cstring(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn parse_row_description(buf: &[u8]) -> (Vec<String>, Vec<u32>) {
    let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let mut i = 2;
    let mut names = Vec::with_capacity(n);
    let mut oids = Vec::with_capacity(n);
    for _ in 0..n {
        let end = buf[i..].iter().position(|&b| b == 0).unwrap();
        names.push(String::from_utf8_lossy(&buf[i..i + end]).into_owned());
        i += end + 1;
        i += 6; // table OID + attno
        oids.push(u32::from_be_bytes(buf[i..i + 4].try_into().unwrap()));
        i += 12; // type OID + typlen + typmod + format
    }
    (names, oids)
}

fn parse_data_row(buf: &[u8]) -> Vec<Option<String>> {
    let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let mut i = 2;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let len = i32::from_be_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        i += 4;
        if len < 0 {
            out.push(None);
        } else {
            let s = String::from_utf8_lossy(&buf[i..i + len as usize]).into_owned();
            i += len as usize;
            out.push(Some(s));
        }
    }
    out
}

fn parse_row_formats(buf: &[u8]) -> Vec<i16> {
    let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let mut offset = 2;
    let mut formats = Vec::with_capacity(n);
    for _ in 0..n {
        let end = buf[offset..].iter().position(|&byte| byte == 0).unwrap();
        offset += end + 1 + 16;
        formats.push(i16::from_be_bytes(
            buf[offset..offset + 2].try_into().unwrap(),
        ));
        offset += 2;
    }
    formats
}

fn parse_binary_data_row(buf: &[u8]) -> Vec<Option<Vec<u8>>> {
    let count = u16::from_be_bytes(buf[0..2].try_into().unwrap()) as usize;
    let mut offset = 2;
    let mut row = Vec::with_capacity(count);
    for _ in 0..count {
        let length = i32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap());
        offset += 4;
        if length == -1 {
            row.push(None);
        } else {
            let length = usize::try_from(length).unwrap();
            row.push(Some(buf[offset..offset + length].to_vec()));
            offset += length;
        }
    }
    assert_eq!(offset, buf.len());
    row
}

fn parse_error_response(buf: &[u8]) -> Reply {
    let mut sqlstate = String::new();
    let mut message = String::new();
    let mut i = 0;
    while i < buf.len() && buf[i] != 0 {
        let code = buf[i];
        i += 1;
        let end = buf[i..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(buf.len() - i);
        let value = String::from_utf8_lossy(&buf[i..i + end]).into_owned();
        i += end + 1;
        match code {
            b'C' => sqlstate = value,
            b'M' => message = value,
            _ => {}
        }
    }
    Reply::Error { sqlstate, message }
}

#[tokio::test]
async fn select_round_trip_l2() {
    let (db, _g) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;

    let setup = [
        "CREATE EXTENSION IF NOT EXISTS vector;",
        "CREATE TABLE items (id INTEGER PRIMARY KEY, embedding vector(4));",
        "INSERT INTO items (id, embedding) VALUES (1, '[1.0, 0.0, 0.0, 0.0]'::vector);",
        "INSERT INTO items (id, embedding) VALUES (2, '[0.0, 1.0, 0.0, 0.0]'::vector);",
    ];
    for s in setup {
        let replies = run_query(&mut stream, s).await;
        assert!(
            replies.iter().all(|r| !matches!(r, Reply::Error { .. })),
            "{s} failed: {replies:?}"
        );
    }

    let replies = run_query(
        &mut stream,
        "SELECT id, embedding <-> '[1.0, 0.0, 0.0, 0.0]'::vector AS d FROM items ORDER BY embedding <-> '[1.0, 0.0, 0.0, 0.0]'::vector LIMIT 1;",
    )
    .await;

    let cols = replies
        .iter()
        .find_map(|r| match r {
            Reply::RowDescription(c, _) => Some(c.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(cols, vec!["id".to_string(), "d".to_string()]);
    let row = replies
        .iter()
        .find_map(|r| match r {
            Reply::DataRow(r) => Some(r.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(row[0].as_deref(), Some("1"));
    let distance: f64 = row[1].as_deref().unwrap().parse().unwrap();
    assert!(distance.abs() < 1e-5);
    let tag = replies
        .iter()
        .find_map(|r| match r {
            Reply::CommandComplete(t) => Some(t.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(tag, "SELECT 1");
}

#[tokio::test]
async fn create_index_hnsw_rejects_and_keeps_connection_live() {
    let (db, _g) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;
    let _ = run_query(
        &mut stream,
        "CREATE TABLE c (id INTEGER PRIMARY KEY, embedding vector(2));",
    )
    .await;
    let r = run_query(
        &mut stream,
        "CREATE INDEX ON c USING hnsw (embedding vector_cosine_ops);",
    )
    .await;
    let error = r
        .iter()
        .find_map(|m| match m {
            Reply::Error { sqlstate, message } => Some((sqlstate, message)),
            _ => None,
        })
        .unwrap();
    assert_eq!(error.0, "0A000");
    assert!(error.1.contains("LS-VEC is automatic"));

    let live = run_query(
        &mut stream,
        "INSERT INTO c (id, embedding) VALUES (1, '[1.0, 0.0]'::vector);",
    )
    .await;
    assert!(live.iter().all(|m| !matches!(m, Reply::Error { .. })));
}

#[tokio::test]
async fn ecommerce_schema_filter_and_search() {
    let (db, _g) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;
    let setup = [
        "CREATE TABLE products (id INTEGER PRIMARY KEY, embedding vector(2), category TEXT, price INTEGER, in_stock BOOLEAN);",
        "INSERT INTO products (id, embedding, category, price, in_stock) VALUES (1, '[0.0, 0.0]'::vector, 'red', 50, true);",
        "INSERT INTO products (id, embedding, category, price, in_stock) VALUES (2, '[1.0, 0.0]'::vector, 'blue', 200, true);",
        "INSERT INTO products (id, embedding, category, price, in_stock) VALUES (3, '[0.0, 1.0]'::vector, 'red', 80, false);",
        "INSERT INTO products (id, embedding, category, price, in_stock) VALUES (4, '[1.0, 1.0]'::vector, 'green', 150, true);",
    ];
    for s in setup {
        let r = run_query(&mut stream, s).await;
        assert!(
            r.iter().all(|m| !matches!(m, Reply::Error { .. })),
            "{s}: {r:?}"
        );
    }

    // 1. AND + range filter + L2 search.
    let r = run_query(
        &mut stream,
        "SELECT id FROM products WHERE category = 'red' AND price < 100 ORDER BY embedding <-> '[0.0, 0.0]'::vector LIMIT 5;",
    )
    .await;
    let rows: Vec<_> = r
        .iter()
        .filter_map(|m| match m {
            Reply::DataRow(rr) => Some(rr.clone()),
            _ => None,
        })
        .collect();
    let ids: Vec<&str> = rows.iter().map(|row| row[0].as_deref().unwrap()).collect();
    assert_eq!(ids, vec!["1", "3"]);

    // 2. IN list filter.
    let r = run_query(
        &mut stream,
        "SELECT id FROM products WHERE category IN ('blue', 'green') ORDER BY embedding <-> '[1.0, 1.0]'::vector LIMIT 5;",
    )
    .await;
    let rows: Vec<_> = r
        .iter()
        .filter_map(|m| match m {
            Reply::DataRow(rr) => Some(rr.clone()),
            _ => None,
        })
        .collect();
    let ids: Vec<&str> = rows.iter().map(|row| row[0].as_deref().unwrap()).collect();
    // Closest to [1,1] within {blue, green} -> 4 (green at [1,1]) then 2 (blue at [1,0]).
    assert_eq!(ids, vec!["4", "2"]);

    // 3. DELETE by predicate.
    let r = run_query(&mut stream, "DELETE FROM products WHERE id = 2;").await;
    assert!(matches!(
        r.iter().find(|m| matches!(m, Reply::CommandComplete(_))),
        Some(Reply::CommandComplete(t)) if t == "DELETE 1"
    ));

    // 4. DROP TABLE.
    let r = run_query(&mut stream, "DROP TABLE products;").await;
    assert!(matches!(
        r.iter().find(|m| matches!(m, Reply::CommandComplete(_))),
        Some(Reply::CommandComplete(t)) if t == "DROP TABLE"
    ));
}

#[tokio::test]
async fn parser_reject_join_propagates_0a000_with_hint() {
    let (db, _g) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;
    let _ = run_query(
        &mut stream,
        "CREATE TABLE a (id INTEGER PRIMARY KEY, embedding vector(2));",
    )
    .await;
    let r = run_query(&mut stream, "SELECT a.id FROM a JOIN b ON a.id = b.id;").await;
    let err = r
        .iter()
        .find_map(|m| match m {
            Reply::Error { sqlstate, message } => Some((sqlstate.clone(), message.clone())),
            _ => None,
        })
        .unwrap();
    assert_eq!(err.0, "0A000");
    assert!(err.1.to_lowercase().contains("join"));
}
