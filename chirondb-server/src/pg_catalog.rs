//! `pg_catalog` shim — minimum surface so libpq / psycopg3 / JDBC connect
//! probes and `psql \d` don't blow up on the unsupported-JOIN reject path.
//!
//! B5 of `.SPEC/gaussdb-vector_cleaned.md`. Spec: `.SPEC/gaussdb-vector_cleaned.md` §7 — "minimum:
//! pg_class, pg_attribute, pg_type, pg_index, hand-stubbed."
//!
//! The pgvector parser rejects every JOIN with SQLSTATE `0A000`, but psql's
//! introspection queries are JOIN-heavy. Rather than break the parser
//! contract, we intercept catalog SQL *before* parsing and serve it from a
//! pinned set of canned responses derived from the live `Db` state.
//!
//! Pattern matched here:
//!
//! | Trigger substring (case-insensitive)              | Response |
//! |----------------------------------------------------|----------|
//! | `select version()`                                 | server_version |
//! | `select current_database()`                        | "gaussdb" (or startup db) |
//! | `select current_schema()` / `current_schemas`      | "public" |
//! | `from pg_catalog.pg_class` w/ `relname`           | list collections |
//! | `from pg_catalog.pg_attribute`                     | list columns of a collection |
//! | `from pg_catalog.pg_type`                          | minimal type stub |
//! | `from pg_catalog.pg_index`                         | minimal index stub |
//!
//! Anything else falls through to the regular parser. Out of scope: full
//! catalog fidelity, OID stability across restarts, statistic columns.

use crate::Db;
use crate::pgvector_exec::{ColumnSpec, PgType, QueryResponse};

/// Returns `Some(response)` when the SQL is a recognised catalog probe and
/// should bypass the parser. Otherwise `None` — caller proceeds with normal
/// parse+execute.
pub fn intercept(db: &Db, sql: &str) -> Option<QueryResponse> {
    intercept_scoped(db, sql, |_| true)
}

pub fn intercept_scoped(
    db: &Db,
    sql: &str,
    allows_collection: impl Fn(&str) -> bool,
) -> Option<QueryResponse> {
    let normalised = sql.trim().trim_end_matches(';').trim().to_ascii_lowercase();
    if normalised.is_empty() {
        return None;
    }
    if matches_select_function(&normalised, "version") {
        return Some(single_text_row("version", &server_version_string()));
    }
    if matches_select_function(&normalised, "current_database") {
        return Some(single_text_row("current_database", "gaussdb"));
    }
    if matches_select_function(&normalised, "current_schema")
        || matches_select_function(&normalised, "current_schemas")
    {
        return Some(single_text_row("current_schema", "public"));
    }
    if matches_select_function(&normalised, "current_user") {
        return Some(single_text_row("current_user", "gaussdb"));
    }
    if matches_select_function(&normalised, "current_setting") {
        return Some(single_text_row("current_setting", ""));
    }

    // Catalog-table routing. We match by substring rather than by parsed AST
    // because the SQL involves JOINs the parser intentionally rejects.
    if normalised.contains("pg_catalog.pg_class") || normalised.contains(" pg_class") {
        return Some(list_pg_class(db, &allows_collection));
    }
    if normalised.contains("pg_catalog.pg_namespace") || normalised.contains(" pg_namespace") {
        return Some(list_pg_namespace());
    }
    if normalised.contains("pg_catalog.pg_attribute") || normalised.contains(" pg_attribute") {
        return Some(list_pg_attribute(db, &allows_collection));
    }
    if normalised.contains("pg_catalog.pg_type") || normalised.contains(" pg_type") {
        return Some(list_pg_type());
    }
    if normalised.contains("pg_catalog.pg_index") || normalised.contains(" pg_index") {
        return Some(list_pg_index(db, &allows_collection));
    }

    None
}

fn matches_select_function(sql_lower: &str, func: &str) -> bool {
    // Accept `select <func>()`, `select <func>();`, optional whitespace.
    let patterns = [
        format!("select {func}()"),
        format!("select pg_catalog.{func}()"),
    ];
    patterns.iter().any(|p| sql_lower.starts_with(p))
}

fn server_version_string() -> String {
    format!("PostgreSQL {}", crate::wire_postgres::SERVER_VERSION_STRING)
}

fn single_text_row(name: &str, value: &str) -> QueryResponse {
    QueryResponse::RowSet {
        columns: vec![ColumnSpec {
            name: name.to_string(),
            pg_type: PgType::Text,
        }],
        rows: vec![vec![Some(value.to_string())]],
        tag: "SELECT 1".to_string(),
    }
}

fn list_pg_class(db: &Db, allows_collection: &impl Fn(&str) -> bool) -> QueryResponse {
    let columns = vec![
        ColumnSpec {
            name: "oid".to_string(),
            pg_type: PgType::Int4,
        },
        ColumnSpec {
            name: "relname".to_string(),
            pg_type: PgType::Text,
        },
        ColumnSpec {
            name: "relkind".to_string(),
            pg_type: PgType::Text,
        },
        ColumnSpec {
            name: "relnamespace".to_string(),
            pg_type: PgType::Int4,
        },
    ];
    let rows: Vec<Vec<Option<String>>> = db
        .list_collections()
        .into_iter()
        .filter(|config| allows_collection(&config.name))
        .enumerate()
        .map(|(idx, cfg)| {
            vec![
                Some((1000 + idx as u32).to_string()), // synthetic OID
                Some(cfg.name),
                Some("r".to_string()),    // ordinary table
                Some("2200".to_string()), // 'public' namespace OID
            ]
        })
        .collect();
    let n = rows.len();
    QueryResponse::RowSet {
        columns,
        rows,
        tag: format!("SELECT {n}"),
    }
}

fn list_pg_namespace() -> QueryResponse {
    QueryResponse::RowSet {
        columns: vec![
            ColumnSpec {
                name: "oid".to_string(),
                pg_type: PgType::Int4,
            },
            ColumnSpec {
                name: "nspname".to_string(),
                pg_type: PgType::Text,
            },
        ],
        rows: vec![
            vec![Some("11".to_string()), Some("pg_catalog".to_string())],
            vec![Some("2200".to_string()), Some("public".to_string())],
        ],
        tag: "SELECT 2".to_string(),
    }
}

fn list_pg_attribute(db: &Db, allows_collection: &impl Fn(&str) -> bool) -> QueryResponse {
    let columns = vec![
        ColumnSpec {
            name: "attrelid".to_string(),
            pg_type: PgType::Int4,
        },
        ColumnSpec {
            name: "attname".to_string(),
            pg_type: PgType::Text,
        },
        ColumnSpec {
            name: "atttypid".to_string(),
            pg_type: PgType::Int4,
        },
        ColumnSpec {
            name: "attnotnull".to_string(),
            pg_type: PgType::Bool,
        },
    ];
    let mut rows = Vec::new();
    for (idx, cfg) in db
        .list_collections()
        .into_iter()
        .filter(|config| allows_collection(&config.name))
        .enumerate()
    {
        let oid = 1000 + idx as u32;
        rows.push(vec![
            Some(oid.to_string()),
            Some("id".to_string()),
            Some("25".to_string()),
            Some("t".to_string()),
        ]);
        rows.push(vec![
            Some(oid.to_string()),
            Some("embedding".to_string()),
            // pgvector vector type uses dynamic OID, no canonical value.
            // Surface as text-oid (25) for compatibility with text-format clients.
            Some("16385".to_string()),
            Some("t".to_string()),
        ]);
        let _ = cfg;
    }
    let n = rows.len();
    QueryResponse::RowSet {
        columns,
        rows,
        tag: format!("SELECT {n}"),
    }
}

fn list_pg_type() -> QueryResponse {
    let columns = vec![
        ColumnSpec {
            name: "oid".to_string(),
            pg_type: PgType::Int4,
        },
        ColumnSpec {
            name: "typname".to_string(),
            pg_type: PgType::Text,
        },
    ];
    let rows = vec![
        vec![Some("23".to_string()), Some("int4".to_string())],
        vec![Some("25".to_string()), Some("text".to_string())],
        vec![Some("701".to_string()), Some("float8".to_string())],
        vec![Some("16".to_string()), Some("bool".to_string())],
        vec![Some("16385".to_string()), Some("vector".to_string())],
    ];
    let n = rows.len();
    QueryResponse::RowSet {
        columns,
        rows,
        tag: format!("SELECT {n}"),
    }
}

fn list_pg_index(db: &Db, allows_collection: &impl Fn(&str) -> bool) -> QueryResponse {
    let columns = vec![
        ColumnSpec {
            name: "indexrelid".to_string(),
            pg_type: PgType::Int4,
        },
        ColumnSpec {
            name: "indrelid".to_string(),
            pg_type: PgType::Int4,
        },
        ColumnSpec {
            name: "indisunique".to_string(),
            pg_type: PgType::Bool,
        },
    ];
    let mut rows = Vec::new();
    for (idx, _cfg) in db
        .list_collections()
        .into_iter()
        .filter(|config| allows_collection(&config.name))
        .enumerate()
    {
        rows.push(vec![
            Some((9000 + idx as u32).to_string()),
            Some((1000 + idx as u32).to_string()),
            Some("f".to_string()),
        ]);
    }
    let n = rows.len();
    QueryResponse::RowSet {
        columns,
        rows,
        tag: format!("SELECT {n}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_db() -> (Db, TempDir) {
        let dir = TempDir::new().unwrap();
        (Db::open(dir.path()).unwrap(), dir)
    }

    #[test]
    fn version_intercepted() {
        let (db, _g) = fresh_db();
        let resp = intercept(&db, "SELECT version();").unwrap();
        match resp {
            QueryResponse::RowSet { rows, .. } => {
                assert!(rows[0][0].as_deref().unwrap().contains("PostgreSQL"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn pg_class_lists_collections() {
        let (db, _g) = fresh_db();
        db.create_collection(crate::CollectionConfig {
            name: "items".into(),
            vector_dim: 4,
            metric: crate::DistanceMetric::L2,
            shards: 1,
            replicas: 1,
            quantization: None,
            payload_schema: std::collections::HashMap::new(),
            named_vector_dims: std::collections::HashMap::new(),
            hnsw_m: None,
            hnsw_ef_construction: None,
            hnsw_ef_search: None,
            recall_sla: None,
            index_kind: None,
            streamer_max_bytes: 0,
        })
        .unwrap();
        let resp = intercept(
            &db,
            "SELECT c.oid, c.relname, c.relkind FROM pg_catalog.pg_class c;",
        )
        .unwrap();
        match resp {
            QueryResponse::RowSet { rows, .. } => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0][1].as_deref(), Some("items"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn pg_namespace_returns_public() {
        let (db, _g) = fresh_db();
        let resp = intercept(&db, "SELECT nspname FROM pg_catalog.pg_namespace;").unwrap();
        match resp {
            QueryResponse::RowSet { rows, .. } => {
                assert!(rows.iter().any(|r| r[1].as_deref() == Some("public")));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn falls_through_when_no_pattern_matches() {
        let (db, _g) = fresh_db();
        assert!(intercept(&db, "SELECT 1;").is_none());
        assert!(intercept(&db, "INSERT INTO t VALUES (1);").is_none());
    }
}
