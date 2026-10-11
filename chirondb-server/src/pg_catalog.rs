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
//! | `show transaction isolation level`                | "repeatable read" |
//! | `show standard_conforming_strings`                | "on" |
//! | `show server_version`                              | compatibility version |
//! | `from pg_catalog.pg_class` w/ `relname`           | list collections and native tables |
//! | `from pg_catalog.pg_attribute`                     | list collection/native table columns |
//! | `from pg_catalog.pg_type`                          | minimal type stub |
//! | `from pg_catalog.pg_index`                         | minimal index stub |
//!
//! Anything else falls through to the regular parser. Out of scope: full
//! catalog fidelity or statistic columns. Native relational table/index OIDs
//! are derived from their persistent catalog IDs and therefore survive restart.

use crate::Db;
use crate::pgvector_exec::{ColumnSpec, PgType, QueryResponse};

const RELATIONAL_TABLE_OID_BASE: u64 = 100_000;
const RELATIONAL_INDEX_OID_BASE: u64 = 200_000;
mod ownership;
pub(crate) use ownership::{CatalogPlan, CatalogResponse};

/// Legacy DTO adapters transfer output ownership to the embedded caller.
/// PostgreSQL transports use the fallible owned variants below.
pub fn intercept(db: &Db, sql: &str) -> Option<QueryResponse> {
    intercept_scoped_with_parameters(db, sql, &[], |_| true)
}
pub fn intercept_scoped(
    db: &Db,
    sql: &str,
    allows: impl Fn(&str) -> bool,
) -> Option<QueryResponse> {
    intercept_scoped_with_parameters(db, sql, &[], allows)
}
pub fn intercept_scoped_with_parameters(
    db: &Db,
    sql: &str,
    parameters: &[crate::RelationalValue],
    allows: impl Fn(&str) -> bool,
) -> Option<QueryResponse> {
    intercept_owned(db, sql, parameters, allows)
        .ok()
        .flatten()
        .map(CatalogResponse::into_dto)
}
pub fn intercept_protected_with_parameters(
    db: &Db,
    sql: &str,
    parameters: &[crate::RelationalValue],
    collections: &[crate::CollectionConfig],
    allows: impl Fn(&str) -> bool,
) -> Option<QueryResponse> {
    let plan = CatalogPlan::new(sql).ok()??;
    if plan.fixed() {
        return plan.execute_fixed(None).ok().map(CatalogResponse::into_dto);
    }
    let tables = db.relational_catalog_owned().ok()?;
    let bytes = collections.iter().try_fold(512usize, |n, c| {
        n.checked_add(c.name.len())?
            .checked_add(std::mem::size_of::<String>())
    })?;
    let _memory = crate::response_buffer::ResponseReservation::new(bytes as u64).ok()?;
    let mut names = Vec::new();
    names.try_reserve_exact(collections.len()).ok()?;
    for collection in collections {
        names.push(collection.name.clone());
    }
    plan.execute(&tables, &names, parameters, &allows, None)
        .ok()
        .map(CatalogResponse::into_dto)
}
pub(crate) fn recognizes(sql: &str) -> crate::Result<bool> {
    Ok(CatalogPlan::new(sql)?.is_some())
}
pub(crate) fn intercept_owned(
    db: &Db,
    sql: &str,
    parameters: &[crate::RelationalValue],
    allows: impl Fn(&str) -> bool,
) -> crate::Result<Option<CatalogResponse>> {
    let Some(plan) = CatalogPlan::new(sql)? else {
        return Ok(None);
    };
    if plan.fixed() {
        return plan.execute_fixed(None).map(Some);
    }
    let tables = db.relational_catalog_owned()?;
    let collections = db.collection_names_owned(None)?;
    plan.execute(&tables, &collections, parameters, &allows, None)
        .map(Some)
}
pub(crate) fn intercept_authorized_owned(
    db: &Db,
    identity: &crate::security::AuthenticatedIdentity,
    sql: &str,
    parameters: &[crate::RelationalValue],
) -> crate::Result<Option<CatalogResponse>> {
    let Some(plan) = CatalogPlan::new(sql)? else {
        return Ok(None);
    };
    if plan.fixed() {
        let _permit = db.catalog_publication_permit(identity)?;
        return plan.execute_fixed(Some(identity.user_name())).map(Some);
    }
    let tables = db.relational_catalog_owned()?;
    let collections = db.collection_names_owned(Some(identity))?;
    let _permit = db.catalog_publication_permit(identity)?;
    let allows = |name: &str| {
        tables
            .permits_read(name, identity)
            .unwrap_or_else(|| collections.iter().any(|collection| collection == name))
    };
    plan.execute(
        &tables,
        &collections,
        parameters,
        &allows,
        Some(identity.user_name()),
    )
    .map(Some)
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

fn information_schema_tables(
    tables: &chirondb_core::relational::RelationalCatalogSnapshot,
    collections: &[String],
    sql: &str,
    allows_collection: &impl Fn(&str) -> bool,
) -> Option<QueryResponse> {
    let projection = information_schema_projection(
        sql,
        "tables",
        &["table_catalog", "table_schema", "table_name", "table_type"],
    )?;
    if sql_text_filter(sql, "table_schema").is_some_and(|schema| schema != "public") {
        return Some(information_schema_response(&projection, Vec::new()));
    }
    let table_filter = sql_text_filter(sql, "table_name");
    let mut tables = tables
        .iter()
        .filter(|table| allows_collection(&table.name))
        .filter(|table| {
            table_filter
                .as_ref()
                .is_none_or(|name| *name == table.name.as_str())
        })
        .collect::<Vec<_>>();
    tables.sort_by(|left, right| left.name.cmp(&right.name));
    let mut rows: Vec<Vec<Option<String>>> = tables
        .into_iter()
        .map(|table| {
            projection
                .iter()
                .map(|column| match column.as_str() {
                    "table_catalog" => Some("gaussdb".to_string()),
                    "table_schema" => Some("public".to_string()),
                    "table_name" => Some(table.name.clone()),
                    "table_type" => Some("BASE TABLE".to_string()),
                    _ => unreachable!("projection validated"),
                })
                .collect()
        })
        .collect();
    for collection in collections
        .iter()
        .filter(|collection| allows_collection(collection))
        .filter(|collection| {
            table_filter
                .as_ref()
                .is_none_or(|name| *name == collection.as_str())
        })
    {
        rows.push(
            projection
                .iter()
                .map(|column| match column.as_str() {
                    "table_catalog" => Some("gaussdb".to_string()),
                    "table_schema" => Some("public".to_string()),
                    "table_name" => Some(collection.clone()),
                    "table_type" => Some("BASE TABLE".to_string()),
                    _ => unreachable!("projection validated"),
                })
                .collect(),
        );
    }
    Some(information_schema_response(&projection, rows))
}

fn information_schema_columns(
    tables: &chirondb_core::relational::RelationalCatalogSnapshot,
    collections: &[String],
    sql: &str,
    allows_collection: &impl Fn(&str) -> bool,
) -> Option<QueryResponse> {
    const ALLOWED: &[&str] = &[
        "table_catalog",
        "table_schema",
        "table_name",
        "column_name",
        "ordinal_position",
        "column_default",
        "is_nullable",
        "data_type",
        "character_maximum_length",
        "numeric_precision",
        "numeric_scale",
        "is_identity",
        "identity_generation",
    ];
    let projection = information_schema_projection(sql, "columns", ALLOWED)?;
    if sql_text_filter(sql, "table_schema").is_some_and(|schema| schema != "public") {
        return Some(information_schema_response(&projection, Vec::new()));
    }
    let table_filter = sql_text_filter(sql, "table_name");
    let mut tables = tables
        .iter()
        .filter(|table| allows_collection(&table.name))
        .filter(|table| {
            table_filter
                .as_ref()
                .is_none_or(|name| *name == table.name.as_str())
        })
        .collect::<Vec<_>>();
    tables.sort_by(|left, right| left.name.cmp(&right.name));
    let mut rows = Vec::new();
    for table in tables {
        for (ordinal, column) in table.columns.iter().enumerate() {
            rows.push(
                projection
                    .iter()
                    .map(|projected| match projected.as_str() {
                        "table_catalog" => Some("gaussdb".to_string()),
                        "table_schema" => Some("public".to_string()),
                        "table_name" => Some(table.name.clone()),
                        "column_name" => Some(column.name.clone()),
                        "ordinal_position" => Some((ordinal + 1).to_string()),
                        "column_default" => column.default.as_ref().map(relational_default_sql),
                        "is_nullable" => {
                            Some(if column.nullable { "YES" } else { "NO" }.to_string())
                        }
                        "data_type" => Some(information_schema_data_type(&column.data_type)),
                        "character_maximum_length" => match &column.data_type {
                            crate::RelationalType::Varchar { length } => Some(length.to_string()),
                            _ => None,
                        },
                        "numeric_precision" => match &column.data_type {
                            crate::RelationalType::SmallInt => Some("16".to_string()),
                            crate::RelationalType::Integer => Some("32".to_string()),
                            crate::RelationalType::BigInt => Some("64".to_string()),
                            crate::RelationalType::Decimal { precision, .. } => {
                                Some(precision.to_string())
                            }
                            _ => None,
                        },
                        "numeric_scale" => match &column.data_type {
                            crate::RelationalType::SmallInt
                            | crate::RelationalType::Integer
                            | crate::RelationalType::BigInt => Some("0".to_string()),
                            crate::RelationalType::Decimal { scale, .. } => Some(scale.to_string()),
                            _ => None,
                        },
                        "is_identity" => Some(
                            if column.identity.is_some() {
                                "YES"
                            } else {
                                "NO"
                            }
                            .to_string(),
                        ),
                        "identity_generation" => column.identity.map(|identity| match identity {
                            crate::IdentityGeneration::Always => "ALWAYS".to_string(),
                            crate::IdentityGeneration::ByDefault => "BY DEFAULT".to_string(),
                        }),
                        _ => unreachable!("projection validated"),
                    })
                    .collect(),
            );
        }
    }
    for collection in collections
        .iter()
        .filter(|collection| allows_collection(collection))
        .filter(|collection| {
            table_filter
                .as_ref()
                .is_none_or(|name| *name == collection.as_str())
        })
    {
        for (ordinal, name, data_type) in [(1, "id", "text"), (2, "embedding", "USER-DEFINED")] {
            rows.push(
                projection
                    .iter()
                    .map(|column| match column.as_str() {
                        "table_catalog" => Some("gaussdb".to_string()),
                        "table_schema" => Some("public".to_string()),
                        "table_name" => Some(collection.clone()),
                        "column_name" => Some(name.to_string()),
                        "ordinal_position" => Some(ordinal.to_string()),
                        "column_default"
                        | "character_maximum_length"
                        | "numeric_precision"
                        | "numeric_scale"
                        | "identity_generation" => None,
                        "is_nullable" => Some("NO".to_string()),
                        "data_type" => Some(data_type.to_string()),
                        "is_identity" => Some("NO".to_string()),
                        _ => unreachable!("projection validated"),
                    })
                    .collect(),
            );
        }
    }
    Some(information_schema_response(&projection, rows))
}

fn information_schema_projection(
    sql: &str,
    relation: &str,
    allowed: &[&str],
) -> Option<Vec<String>> {
    let from = format!(" from information_schema.{relation}");
    let select = sql.strip_prefix("select ")?.split_once(&from)?.0;
    let mut projection = Vec::new();
    for expression in select.split(',') {
        let expression = expression.trim();
        if expression.split_ascii_whitespace().count() != 1 {
            return None;
        }
        let unqualified = expression.rsplit('.').next()?.trim_matches('"');
        if !allowed.contains(&unqualified) {
            return None;
        }
        projection.push(unqualified.to_string());
    }
    (!projection.is_empty()).then_some(projection)
}

fn sql_text_filter<'a>(sql: &'a str, column: &str) -> Option<&'a str> {
    let mut offset = 0;
    while let Some(found) = sql[offset..].find(column) {
        let after_name = offset + found + column.len();
        let rest = sql[after_name..].trim_start();
        if let Some(rest) = rest.strip_prefix('=') {
            let rest = rest.trim_start();
            if let Some(value) = rest.strip_prefix('\'') {
                return value.find('\'').map(|end| &value[..end]);
            }
        }
        offset = after_name;
    }
    None
}

fn information_schema_response(
    projection: &[String],
    rows: Vec<Vec<Option<String>>>,
) -> QueryResponse {
    let columns = projection
        .iter()
        .map(|name| ColumnSpec {
            name: name.clone(),
            pg_type: if name == "ordinal_position"
                || name == "character_maximum_length"
                || name == "numeric_precision"
                || name == "numeric_scale"
            {
                PgType::Int4
            } else {
                PgType::Text
            },
        })
        .collect();
    QueryResponse::RowSet {
        tag: format!("SELECT {}", rows.len()),
        columns,
        rows,
    }
}

fn information_schema_data_type(data_type: &crate::RelationalType) -> String {
    match data_type {
        crate::RelationalType::Varchar { .. } => "character varying".to_string(),
        crate::RelationalType::Decimal { .. } => "numeric".to_string(),
        crate::RelationalType::Vector { .. } | crate::RelationalType::RecordRef { .. } => {
            "USER-DEFINED".to_string()
        }
        other => relational_format_type(other),
    }
}

fn sqlalchemy_table_names(
    tables: &chirondb_core::relational::RelationalCatalogSnapshot,
    collections: &[String],
    allows_collection: &impl Fn(&str) -> bool,
) -> QueryResponse {
    let mut names = collections
        .iter()
        .filter(|name| allows_collection(name))
        .cloned()
        .chain(
            tables
                .iter()
                .filter(|table| allows_collection(&table.name))
                .map(|table| table.name.clone()),
        )
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    let rows = names
        .into_iter()
        .map(|name| vec![Some(name)])
        .collect::<Vec<_>>();
    QueryResponse::RowSet {
        columns: vec![ColumnSpec {
            name: "relname".to_string(),
            pg_type: PgType::Text,
        }],
        tag: format!("SELECT {}", rows.len()),
        rows,
    }
}

fn sqlalchemy_table_comments(
    tables: &chirondb_core::relational::RelationalCatalogSnapshot,
    allows_collection: &impl Fn(&str) -> bool,
) -> QueryResponse {
    let rows = tables
        .iter()
        .filter(|table| allows_collection(&table.name))
        .map(|table| vec![Some(table.name.clone()), None])
        .collect::<Vec<_>>();
    QueryResponse::RowSet {
        columns: vec![
            ColumnSpec {
                name: "relname".to_string(),
                pg_type: PgType::Text,
            },
            ColumnSpec {
                name: "description".to_string(),
                pg_type: PgType::Text,
            },
        ],
        tag: format!("SELECT {}", rows.len()),
        rows,
    }
}

fn sqlalchemy_table_oids(
    tables: &chirondb_core::relational::RelationalCatalogSnapshot,
    allows_collection: &impl Fn(&str) -> bool,
) -> QueryResponse {
    let mut rows = tables
        .iter()
        .filter(|table| allows_collection(&table.name))
        .filter_map(|table| {
            relational_table_oid(table.table_id)
                .map(|oid| vec![Some(oid.to_string()), Some(table.name.clone())])
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| left[1].cmp(&right[1]));
    QueryResponse::RowSet {
        columns: vec![
            ColumnSpec {
                name: "oid".to_string(),
                pg_type: PgType::Int4,
            },
            ColumnSpec {
                name: "relname".to_string(),
                pg_type: PgType::Text,
            },
        ],
        tag: format!("SELECT {}", rows.len()),
        rows,
    }
}

fn sqlalchemy_columns(
    tables: &chirondb_core::relational::RelationalCatalogSnapshot,
    allows_collection: &impl Fn(&str) -> bool,
) -> QueryResponse {
    let columns = vec![
        ("name", PgType::Text),
        ("format_type", PgType::Text),
        ("default", PgType::Text),
        ("not_null", PgType::Bool),
        ("table_name", PgType::Text),
        ("comment", PgType::Text),
        ("generated", PgType::Text),
        ("identity_options", PgType::Jsonb),
        ("collation", PgType::Text),
    ]
    .into_iter()
    .map(|(name, pg_type)| ColumnSpec {
        name: name.to_string(),
        pg_type,
    })
    .collect();
    let mut rows = Vec::new();
    for table in tables.iter().filter(|table| allows_collection(&table.name)) {
        for column in &table.columns {
            let identity = column.identity.map(|generation| {
                format!(
                    "{{\"always\":{},\"start\":1,\"increment\":1,\"minvalue\":1,\"maxvalue\":9223372036854775807,\"cache\":1,\"cycle\":false}}",
                    matches!(generation, crate::IdentityGeneration::Always)
                )
            });
            rows.push(vec![
                Some(column.name.clone()),
                Some(relational_format_type(&column.data_type)),
                column.default.as_ref().map(relational_default_sql),
                Some(if column.nullable { "f" } else { "t" }.to_string()),
                Some(table.name.clone()),
                None,
                Some(String::new()),
                identity,
                None,
            ]);
        }
    }
    QueryResponse::RowSet {
        tag: format!("SELECT {}", rows.len()),
        columns,
        rows,
    }
}

fn sqlalchemy_constraints(
    tables: &chirondb_core::relational::RelationalCatalogSnapshot,
    parameters: &[crate::RelationalValue],
    allows_collection: &impl Fn(&str) -> bool,
) -> QueryResponse {
    let constraint_type = parameters.iter().find_map(|parameter| match parameter {
        crate::RelationalValue::Text(value) if value == "p" || value == "u" => Some(value.as_str()),
        _ => None,
    });
    let columns = vec![
        ("conrelid", PgType::Int4),
        ("cols", PgType::TextArray),
        ("conname", PgType::Text),
        ("description", PgType::Text),
        ("indnkeyatts", PgType::Int4),
        ("indnullsnotdistinct", PgType::Bool),
    ]
    .into_iter()
    .map(|(name, pg_type)| ColumnSpec {
        name: name.to_string(),
        pg_type,
    })
    .collect();
    let mut rows = Vec::new();
    for table in tables.iter().filter(|table| allows_collection(&table.name)) {
        let Some(table_oid) = relational_table_oid(table.table_id) else {
            continue;
        };
        if constraint_type == Some("p") && !table.primary_key.is_empty() {
            let name = table
                .primary_key_name
                .clone()
                .unwrap_or_else(|| format!("{}_pkey", table.name));
            rows.push(constraint_reflection_row(
                table_oid,
                &table.primary_key,
                &name,
                false,
            ));
        }
        if constraint_type == Some("u") {
            for constraint in &table.unique_constraints {
                let name = constraint.name.clone().unwrap_or_else(|| {
                    format!("{}_{}_key", table.name, constraint.columns.join("_"))
                });
                rows.push(constraint_reflection_row(
                    table_oid,
                    &constraint.columns,
                    &name,
                    false,
                ));
            }
        }
    }
    QueryResponse::RowSet {
        tag: format!("SELECT {}", rows.len()),
        columns,
        rows,
    }
}

fn sqlalchemy_foreign_keys(
    tables: &chirondb_core::relational::RelationalCatalogSnapshot,
    allows_collection: &impl Fn(&str) -> bool,
) -> QueryResponse {
    let columns = vec![
        ("relname", PgType::Text),
        ("conname", PgType::Text),
        ("condef", PgType::Text),
        ("nspname", PgType::Text),
        ("description", PgType::Text),
    ]
    .into_iter()
    .map(|(name, pg_type)| ColumnSpec {
        name: name.to_string(),
        pg_type,
    })
    .collect();
    let mut rows = Vec::new();
    for table in tables.iter().filter(|table| allows_collection(&table.name)) {
        if table.foreign_keys.is_empty() {
            rows.push(vec![Some(table.name.clone()), None, None, None, None]);
            continue;
        }
        for foreign_key in &table.foreign_keys {
            let name = foreign_key.name.clone().unwrap_or_else(|| {
                format!("{}_{}_fkey", table.name, foreign_key.columns.join("_"))
            });
            let child_columns = foreign_key
                .columns
                .iter()
                .map(|column| quote_pg_identifier(column))
                .collect::<Vec<_>>()
                .join(", ");
            let parent_columns = foreign_key
                .referenced_columns
                .iter()
                .map(|column| quote_pg_identifier(column))
                .collect::<Vec<_>>()
                .join(", ");
            let match_kind = match foreign_key.match_kind {
                crate::ForeignKeyMatch::Simple => "SIMPLE",
                crate::ForeignKeyMatch::Full => "FULL",
            };
            let deferrability = if foreign_key.deferrable {
                if foreign_key.initially_deferred {
                    "DEFERRABLE INITIALLY DEFERRED"
                } else {
                    "DEFERRABLE INITIALLY IMMEDIATE"
                }
            } else {
                "NOT DEFERRABLE"
            };
            let definition = format!(
                "FOREIGN KEY ({child_columns}) REFERENCES {}({parent_columns}) MATCH {match_kind} ON UPDATE {} ON DELETE {} {deferrability}",
                quote_pg_identifier(&foreign_key.referenced_table),
                foreign_key_action_sql(foreign_key.on_update),
                foreign_key_action_sql(foreign_key.on_delete),
            );
            rows.push(vec![
                Some(table.name.clone()),
                Some(name),
                Some(definition),
                Some("public".to_string()),
                None,
            ]);
        }
    }
    QueryResponse::RowSet {
        tag: format!("SELECT {}", rows.len()),
        columns,
        rows,
    }
}

fn sqlalchemy_indexes(
    tables: &chirondb_core::relational::RelationalCatalogSnapshot,
    allows_collection: &impl Fn(&str) -> bool,
) -> QueryResponse {
    let columns = vec![
        ("indrelid", PgType::Int4),
        ("relname", PgType::Text),
        ("indisunique", PgType::Bool),
        ("has_constraint", PgType::Bool),
        ("indoption", PgType::Int2Array),
        ("reloptions", PgType::TextArray),
        ("amname", PgType::Text),
        ("filter_definition", PgType::Text),
        ("indnkeyatts", PgType::Int4),
        ("indnullsnotdistinct", PgType::Bool),
        ("elements", PgType::TextArray),
        ("elements_is_expr", PgType::BoolArray),
        ("elements_opclass", PgType::TextArray),
        ("elements_opdefault", PgType::BoolArray),
    ]
    .into_iter()
    .map(|(name, pg_type)| ColumnSpec {
        name: name.to_string(),
        pg_type,
    })
    .collect();
    let mut rows = Vec::new();
    for table in tables.iter().filter(|table| allows_collection(&table.name)) {
        let Some(table_oid) = relational_table_oid(table.table_id) else {
            continue;
        };
        for index in &table.indexes {
            if table.primary_key_index_id == Some(index.index_id) {
                continue;
            }
            let has_constraint = table
                .unique_constraints
                .iter()
                .any(|constraint| constraint.index_id == index.index_id);
            let length = index.columns.len();
            let elements = pg_array(index.columns.iter().map(String::as_str));
            let false_values = pg_array(std::iter::repeat_n("f", length));
            let true_values = pg_array(std::iter::repeat_n("t", length));
            let zero_values = pg_array(std::iter::repeat_n("0", length));
            let opclasses = pg_array(std::iter::repeat_n("text_ops", length));
            rows.push(vec![
                Some(table_oid.to_string()),
                Some(index.name.clone()),
                Some(if index.unique { "t" } else { "f" }.to_string()),
                Some(if has_constraint { "t" } else { "f" }.to_string()),
                Some(zero_values),
                None,
                Some("btree".to_string()),
                None,
                Some(length.to_string()),
                Some("f".to_string()),
                Some(elements),
                Some(false_values),
                Some(opclasses),
                Some(true_values),
            ]);
        }
    }
    QueryResponse::RowSet {
        tag: format!("SELECT {}", rows.len()),
        columns,
        rows,
    }
}

fn sqlalchemy_check_constraints(
    tables: &chirondb_core::relational::RelationalCatalogSnapshot,
    allows_collection: &impl Fn(&str) -> bool,
) -> QueryResponse {
    let columns = vec![
        ("relname", PgType::Text),
        ("conname", PgType::Text),
        ("condef", PgType::Text),
        ("description", PgType::Text),
    ]
    .into_iter()
    .map(|(name, pg_type)| ColumnSpec {
        name: name.to_string(),
        pg_type,
    })
    .collect();
    let mut rows = Vec::new();
    for table in tables.iter().filter(|table| allows_collection(&table.name)) {
        if table.check_constraints.is_empty() {
            rows.push(vec![Some(table.name.clone()), None, None, None]);
            continue;
        }
        for (position, constraint) in table.check_constraints.iter().enumerate() {
            let name = constraint
                .name
                .clone()
                .unwrap_or_else(|| format!("{}_check_{}", table.name, position + 1));
            rows.push(vec![
                Some(table.name.clone()),
                Some(name),
                Some(format!("CHECK ({})", constraint.expression)),
                None,
            ]);
        }
    }
    QueryResponse::RowSet {
        tag: format!("SELECT {}", rows.len()),
        columns,
        rows,
    }
}

fn pg_array<'a>(values: impl IntoIterator<Item = &'a str>) -> String {
    format!(
        "{{{}}}",
        values
            .into_iter()
            .map(|value| {
                if value
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
                {
                    value.to_string()
                } else {
                    format!("\"{}\"", value.replace('"', "\\\""))
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn quote_pg_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn foreign_key_action_sql(action: crate::ForeignKeyAction) -> &'static str {
    match action {
        crate::ForeignKeyAction::NoAction => "NO ACTION",
        crate::ForeignKeyAction::Restrict => "RESTRICT",
        crate::ForeignKeyAction::Cascade => "CASCADE",
        crate::ForeignKeyAction::SetNull => "SET NULL",
        crate::ForeignKeyAction::SetDefault => "SET DEFAULT",
    }
}

fn constraint_reflection_row(
    table_oid: u32,
    columns: &[String],
    name: &str,
    nulls_not_distinct: bool,
) -> Vec<Option<String>> {
    let array = format!(
        "{{{}}}",
        columns
            .iter()
            .map(|column| column.replace('"', "\\\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    vec![
        Some(table_oid.to_string()),
        Some(array),
        Some(name.to_string()),
        None,
        Some(columns.len().to_string()),
        Some(if nulls_not_distinct { "t" } else { "f" }.to_string()),
    ]
}

fn empty_domains() -> QueryResponse {
    empty_named_rowset(&[
        ("name", PgType::Text),
        ("attype", PgType::Text),
        ("nullable", PgType::Bool),
        ("default", PgType::Text),
        ("visible", PgType::Bool),
        ("schema", PgType::Text),
        ("condefs", PgType::Text),
        ("connames", PgType::Text),
        ("collname", PgType::Text),
    ])
}

fn empty_enums() -> QueryResponse {
    empty_named_rowset(&[
        ("name", PgType::Text),
        ("visible", PgType::Bool),
        ("schema", PgType::Text),
        ("labels", PgType::Text),
    ])
}

fn empty_named_rowset(columns: &[(&str, PgType)]) -> QueryResponse {
    QueryResponse::RowSet {
        columns: columns
            .iter()
            .map(|(name, pg_type)| ColumnSpec {
                name: (*name).to_string(),
                pg_type: *pg_type,
            })
            .collect(),
        rows: Vec::new(),
        tag: "SELECT 0".to_string(),
    }
}

fn relational_format_type(data_type: &crate::RelationalType) -> String {
    match data_type {
        crate::RelationalType::Boolean => "boolean".to_string(),
        crate::RelationalType::SmallInt => "smallint".to_string(),
        crate::RelationalType::Integer => "integer".to_string(),
        crate::RelationalType::BigInt => "bigint".to_string(),
        crate::RelationalType::Real => "real".to_string(),
        crate::RelationalType::Float => "double precision".to_string(),
        crate::RelationalType::Decimal { precision, scale } => {
            format!("numeric({precision},{scale})")
        }
        crate::RelationalType::Text => "text".to_string(),
        crate::RelationalType::Varchar { length } => format!("character varying({length})"),
        crate::RelationalType::Bytea => "bytea".to_string(),
        crate::RelationalType::Date => "date".to_string(),
        crate::RelationalType::TimestampUtc => "timestamp with time zone".to_string(),
        crate::RelationalType::Uuid => "uuid".to_string(),
        crate::RelationalType::Jsonb | crate::RelationalType::RecordRef { .. } => {
            "jsonb".to_string()
        }
        crate::RelationalType::Vector { dimension } => format!("vector({dimension})"),
    }
}

fn relational_default_sql(value: &crate::RelationalValue) -> String {
    match value {
        crate::RelationalValue::Null => "NULL".to_string(),
        crate::RelationalValue::Boolean(value) => value.to_string(),
        crate::RelationalValue::Integer(value) => value.to_string(),
        crate::RelationalValue::Float(value) => value.to_string(),
        crate::RelationalValue::Decimal(value) => value.clone(),
        crate::RelationalValue::Text(value)
        | crate::RelationalValue::Date(value)
        | crate::RelationalValue::TimestampUtc(value) => {
            format!("'{}'", value.replace('\'', "''"))
        }
        crate::RelationalValue::Uuid(value) => format!("'{value}'::uuid"),
        crate::RelationalValue::Bytes(value) => {
            let encoded = value
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!("'\\x{encoded}'::bytea")
        }
        crate::RelationalValue::Json(value) => {
            format!("'{}'::jsonb", value.to_string().replace('\'', "''"))
        }
        crate::RelationalValue::Vector(value) => {
            let text = value
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            format!("'[{text}]'::vector")
        }
        crate::RelationalValue::RecordRef(value) => format!(
            "'{{\"namespace\":\"{}\",\"id\":\"{}\"}}'::jsonb",
            value.namespace.replace('\'', "''"),
            value.id.replace('\'', "''")
        ),
    }
}

fn empty_type_lookup() -> QueryResponse {
    QueryResponse::RowSet {
        columns: vec![
            ColumnSpec {
                name: "name".to_string(),
                pg_type: PgType::Text,
            },
            ColumnSpec {
                name: "oid".to_string(),
                pg_type: PgType::Int4,
            },
            ColumnSpec {
                name: "array_oid".to_string(),
                pg_type: PgType::Int4,
            },
            ColumnSpec {
                name: "regtype".to_string(),
                pg_type: PgType::Text,
            },
            ColumnSpec {
                name: "delimiter".to_string(),
                pg_type: PgType::Text,
            },
        ],
        rows: Vec::new(),
        tag: "SELECT 0".to_string(),
    }
}

fn list_pg_class(
    tables: &chirondb_core::relational::RelationalCatalogSnapshot,
    collections: &[String],
    allows_collection: &impl Fn(&str) -> bool,
) -> QueryResponse {
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
    let mut rows: Vec<Vec<Option<String>>> = collections
        .iter()
        .filter(|config| allows_collection(config))
        .cloned()
        .enumerate()
        .map(|(idx, cfg)| {
            vec![
                Some((1000 + idx as u32).to_string()), // synthetic OID
                Some(cfg),
                Some("r".to_string()),    // ordinary table
                Some("2200".to_string()), // 'public' namespace OID
            ]
        })
        .collect();
    for table in tables.iter().filter(|table| allows_collection(&table.name)) {
        let Some(table_oid) = relational_table_oid(table.table_id) else {
            continue;
        };
        rows.push(vec![
            Some(table_oid.to_string()),
            Some(table.name.clone()),
            Some("r".to_string()),
            Some("2200".to_string()),
        ]);
        for index in &table.indexes {
            let Some(index_oid) = relational_index_oid(index.index_id) else {
                continue;
            };
            rows.push(vec![
                Some(index_oid.to_string()),
                Some(index.name.clone()),
                Some("i".to_string()),
                Some("2200".to_string()),
            ]);
        }
    }
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

fn list_pg_attribute(
    tables: &chirondb_core::relational::RelationalCatalogSnapshot,
    collections: &[String],
    allows_collection: &impl Fn(&str) -> bool,
) -> QueryResponse {
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
    for (idx, cfg) in collections
        .iter()
        .filter(|config| allows_collection(config))
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
    for table in tables.iter().filter(|table| allows_collection(&table.name)) {
        let Some(oid) = relational_table_oid(table.table_id) else {
            continue;
        };
        for column in &table.columns {
            rows.push(vec![
                Some(oid.to_string()),
                Some(column.name.clone()),
                Some(relational_type_oid(&column.data_type).to_string()),
                Some(if column.nullable { "f" } else { "t" }.to_string()),
            ]);
        }
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
        vec![Some("17".to_string()), Some("bytea".to_string())],
        vec![Some("20".to_string()), Some("int8".to_string())],
        vec![Some("21".to_string()), Some("int2".to_string())],
        vec![Some("700".to_string()), Some("float4".to_string())],
        vec![Some("1043".to_string()), Some("varchar".to_string())],
        vec![Some("1082".to_string()), Some("date".to_string())],
        vec![Some("1184".to_string()), Some("timestamptz".to_string())],
        vec![Some("1700".to_string()), Some("numeric".to_string())],
        vec![Some("2950".to_string()), Some("uuid".to_string())],
        vec![Some("3802".to_string()), Some("jsonb".to_string())],
        vec![Some("16385".to_string()), Some("vector".to_string())],
    ];
    let n = rows.len();
    QueryResponse::RowSet {
        columns,
        rows,
        tag: format!("SELECT {n}"),
    }
}

fn list_pg_index(
    tables: &chirondb_core::relational::RelationalCatalogSnapshot,
    collections: &[String],
    allows_collection: &impl Fn(&str) -> bool,
) -> QueryResponse {
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
    for (idx, _cfg) in collections
        .iter()
        .filter(|config| allows_collection(config))
        .enumerate()
    {
        rows.push(vec![
            Some((9000 + idx as u32).to_string()),
            Some((1000 + idx as u32).to_string()),
            Some("f".to_string()),
        ]);
    }
    for table in tables.iter().filter(|table| allows_collection(&table.name)) {
        let Some(table_oid) = relational_table_oid(table.table_id) else {
            continue;
        };
        for index in &table.indexes {
            let Some(index_oid) = relational_index_oid(index.index_id) else {
                continue;
            };
            rows.push(vec![
                Some(index_oid.to_string()),
                Some(table_oid.to_string()),
                Some(if index.unique { "t" } else { "f" }.to_string()),
            ]);
        }
    }
    let n = rows.len();
    QueryResponse::RowSet {
        columns,
        rows,
        tag: format!("SELECT {n}"),
    }
}

fn relational_table_oid(table_id: u64) -> Option<u32> {
    RELATIONAL_TABLE_OID_BASE
        .checked_add(table_id)
        .and_then(|oid| oid.try_into().ok())
}

fn relational_index_oid(index_id: u64) -> Option<u32> {
    RELATIONAL_INDEX_OID_BASE
        .checked_add(index_id)
        .and_then(|oid| oid.try_into().ok())
}

fn relational_type_oid(data_type: &crate::RelationalType) -> u32 {
    match data_type {
        crate::RelationalType::Boolean => PgType::Bool.oid(),
        crate::RelationalType::SmallInt => PgType::Int2.oid(),
        crate::RelationalType::Integer => PgType::Int4.oid(),
        crate::RelationalType::BigInt => PgType::Int8.oid(),
        crate::RelationalType::Real => PgType::Float4.oid(),
        crate::RelationalType::Float => PgType::Float8.oid(),
        crate::RelationalType::Decimal { .. } => PgType::Numeric.oid(),
        crate::RelationalType::Text => PgType::Text.oid(),
        crate::RelationalType::Varchar { .. } => PgType::Varchar.oid(),
        crate::RelationalType::Bytea => PgType::Bytea.oid(),
        crate::RelationalType::Date => PgType::Date.oid(),
        crate::RelationalType::TimestampUtc => PgType::TimestampTz.oid(),
        crate::RelationalType::Uuid => PgType::Uuid.oid(),
        crate::RelationalType::Jsonb | crate::RelationalType::RecordRef { .. } => {
            PgType::Jsonb.oid()
        }
        crate::RelationalType::Vector { .. } => 16_385,
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

    fn sql(sql: &str) -> crate::SqlExecutionRequest {
        crate::SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql: sql.to_string(),
                parameters: Vec::new(),
            }],
            idempotency_key: None,
            retry_id: None,
        }
    }

    fn catalog_rows(db: &Db, relation: &str) -> Vec<Vec<Option<String>>> {
        match intercept(db, &format!("SELECT * FROM pg_catalog.{relation};")).unwrap() {
            QueryResponse::RowSet { rows, .. } => rows,
            _ => panic!("catalog probes must return rows"),
        }
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
    fn sqlalchemy_connection_settings_are_intercepted() {
        let (db, _g) = fresh_db();
        for (sql, expected) in [
            ("SELECT pg_catalog.version()", "PostgreSQL 16.0"),
            ("SHOW transaction isolation level", "repeatable read"),
            ("SHOW standard_conforming_strings", "on"),
            ("SHOW server_version", "16.0"),
        ] {
            let response = intercept(&db, sql).unwrap_or_else(|| panic!("not intercepted: {sql}"));
            let QueryResponse::RowSet { rows, .. } = response else {
                panic!("catalog setting did not return a row: {sql}");
            };
            assert!(rows[0][0].as_deref().unwrap().contains(expected), "{sql}");
        }
    }

    #[test]
    fn information_schema_projects_relational_tables_and_columns() {
        let (db, _g) = fresh_db();
        db.execute_sql(sql("CREATE TABLE info_accounts (\
             id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, \
             email VARCHAR(128) NOT NULL, \
             balance NUMERIC(38,2) DEFAULT 0)"))
            .unwrap();

        let response = intercept(
            &db,
            "SELECT table_schema, table_name, table_type \
             FROM information_schema.tables \
             WHERE table_schema = 'public' AND table_name = 'info_accounts' \
             ORDER BY table_name",
        )
        .unwrap();
        let QueryResponse::RowSet { columns, rows, .. } = response else {
            panic!("information_schema.tables must return rows");
        };
        assert_eq!(
            columns
                .iter()
                .map(|column| column.name.as_str())
                .collect::<Vec<_>>(),
            ["table_schema", "table_name", "table_type"]
        );
        assert_eq!(
            rows,
            [[
                Some("public".to_string()),
                Some("info_accounts".to_string()),
                Some("BASE TABLE".to_string()),
            ]]
        );

        let response = intercept(
            &db,
            "SELECT column_name, data_type, is_nullable, column_default, \
                    ordinal_position, character_maximum_length, numeric_precision, \
                    numeric_scale, is_identity, identity_generation \
             FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = 'info_accounts' \
             ORDER BY ordinal_position",
        )
        .unwrap();
        let QueryResponse::RowSet { columns, rows, .. } = response else {
            panic!("information_schema.columns must return rows");
        };
        assert_eq!(columns[4].pg_type, PgType::Int4);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0][0].as_deref(), Some("id"));
        assert_eq!(rows[0][1].as_deref(), Some("bigint"));
        assert_eq!(rows[0][2].as_deref(), Some("NO"));
        assert_eq!(rows[0][4].as_deref(), Some("1"));
        assert_eq!(rows[0][8].as_deref(), Some("YES"));
        assert_eq!(rows[0][9].as_deref(), Some("ALWAYS"));
        assert_eq!(rows[1][0].as_deref(), Some("email"));
        assert_eq!(rows[1][1].as_deref(), Some("character varying"));
        assert_eq!(rows[1][5].as_deref(), Some("128"));
        assert_eq!(rows[2][0].as_deref(), Some("balance"));
        assert_eq!(rows[2][1].as_deref(), Some("numeric"));
        assert_eq!(rows[2][3].as_deref(), Some("0"));
        assert_eq!(rows[2][6].as_deref(), Some("38"));
        assert_eq!(rows[2][7].as_deref(), Some("2"));
        assert_eq!(rows[2][8].as_deref(), Some("NO"));

        let denied = intercept(
            &db,
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'private'",
        )
        .unwrap();
        let QueryResponse::RowSet { rows, .. } = denied else {
            panic!("non-public schema must return an empty typed rowset");
        };
        assert!(rows.is_empty());
        assert!(intercept(&db, "SELECT count(*) FROM information_schema.tables").is_none());
        assert!(
            intercept(
                &db,
                "SELECT table_name AS name FROM information_schema.tables"
            )
            .is_none()
        );
    }

    #[test]
    fn optional_extension_type_lookup_returns_no_false_match() {
        let (db, _g) = fresh_db();
        let response = intercept(
            &db,
            "SELECT typname AS name, oid, typarray AS array_oid, oid::regtype::text AS regtype, typdelim AS delimiter FROM pg_type t WHERE t.oid = to_regtype($1) ORDER BY t.oid",
        )
        .unwrap();
        let QueryResponse::RowSet { columns, rows, tag } = response else {
            panic!("type lookup must return a rowset");
        };
        assert_eq!(columns.len(), 5);
        assert!(rows.is_empty());
        assert_eq!(tag, "SELECT 0");
    }

    #[test]
    fn sqlalchemy_reflection_projects_tables_columns_and_constraints() {
        let (db, _g) = fresh_db();
        db.execute_sql(sql(
            "CREATE TABLE accounts (id BIGINT PRIMARY KEY, email VARCHAR(128) NOT NULL UNIQUE, note TEXT)",
        ))
        .unwrap();

        let QueryResponse::RowSet { columns, rows, .. } = intercept(
            &db,
            "SELECT pg_catalog.pg_class.relname FROM pg_catalog.pg_class JOIN pg_catalog.pg_namespace ON true",
        )
        .unwrap()
        else {
            panic!("table names must be rows");
        };
        assert_eq!(columns[0].name, "relname");
        assert_eq!(rows, vec![vec![Some("accounts".to_string())]]);

        let QueryResponse::RowSet { columns, rows, .. } = intercept(
            &db,
            "SELECT pg_catalog.pg_attribute.attname AS name, pg_catalog.format_type(pg_catalog.pg_attribute.atttypid, pg_catalog.pg_attribute.atttypmod) AS format_type FROM pg_catalog.pg_class JOIN pg_catalog.pg_attribute ON true",
        )
        .unwrap()
        else {
            panic!("column reflection must be rows");
        };
        assert_eq!(columns[0].name, "name");
        assert_eq!(columns[1].name, "format_type");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[1][0].as_deref(), Some("email"));
        assert_eq!(rows[1][1].as_deref(), Some("character varying(128)"));

        let constraint_sql = "SELECT attr.conrelid, array_agg(CAST(attr.attname AS TEXT) ORDER BY attr.ord) AS cols FROM pg_catalog.pg_attribute JOIN pg_catalog.pg_constraint ON true WHERE pg_catalog.pg_constraint.contype = $1";
        let QueryResponse::RowSet { columns, rows, .. } = intercept_scoped_with_parameters(
            &db,
            constraint_sql,
            &[crate::RelationalValue::Text("p".to_string())],
            |_| true,
        )
        .unwrap() else {
            panic!("primary key reflection must be rows");
        };
        assert_eq!(columns[1].pg_type, PgType::TextArray);
        assert_eq!(rows[0][1].as_deref(), Some("{id}"));
        assert_eq!(rows[0][2].as_deref(), Some("accounts_pkey"));

        let QueryResponse::RowSet { rows, .. } = intercept_scoped_with_parameters(
            &db,
            constraint_sql,
            &[crate::RelationalValue::Text("u".to_string())],
            |_| true,
        )
        .unwrap() else {
            panic!("unique reflection must be rows");
        };
        assert_eq!(rows[0][1].as_deref(), Some("{email}"));
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
    fn relational_catalog_uses_persistent_table_index_and_type_identity() {
        let directory = TempDir::new().unwrap();
        let db = Db::open(directory.path()).unwrap();
        db.execute_sql(sql(
            "CREATE TABLE accounts (id BIGINT PRIMARY KEY, email VARCHAR(128) NOT NULL UNIQUE, payload JSONB, created_at TIMESTAMP WITH TIME ZONE NOT NULL)",
        ))
        .unwrap();
        db.execute_sql(sql(
            "CREATE INDEX accounts_created_idx ON accounts(created_at)",
        ))
        .unwrap();
        let definition = db
            .relational_tables()
            .into_iter()
            .find(|table| table.name == "accounts")
            .unwrap();
        let table_oid = relational_table_oid(definition.table_id)
            .unwrap()
            .to_string();
        let index_oids = definition
            .indexes
            .iter()
            .map(|index| relational_index_oid(index.index_id).unwrap().to_string())
            .collect::<Vec<_>>();

        let before = (
            catalog_rows(&db, "pg_class"),
            catalog_rows(&db, "pg_attribute"),
            catalog_rows(&db, "pg_index"),
        );
        assert!(before.0.iter().any(|row| {
            row[0].as_deref() == Some(table_oid.as_str()) && row[1].as_deref() == Some("accounts")
        }));
        for index_oid in &index_oids {
            assert!(before.0.iter().any(|row| {
                row[0].as_deref() == Some(index_oid.as_str()) && row[2].as_deref() == Some("i")
            }));
            assert!(before.2.iter().any(|row| {
                row[0].as_deref() == Some(index_oid.as_str())
                    && row[1].as_deref() == Some(table_oid.as_str())
            }));
        }
        assert!(before.1.iter().any(|row| {
            row[0].as_deref() == Some(table_oid.as_str())
                && row[1].as_deref() == Some("id")
                && row[2].as_deref() == Some("20")
                && row[3].as_deref() == Some("t")
        }));
        assert!(before.1.iter().any(|row| {
            row[0].as_deref() == Some(table_oid.as_str())
                && row[1].as_deref() == Some("payload")
                && row[2].as_deref() == Some("3802")
                && row[3].as_deref() == Some("f")
        }));

        drop(db);
        let reopened = Db::open(directory.path()).unwrap();
        let after = (
            catalog_rows(&reopened, "pg_class"),
            catalog_rows(&reopened, "pg_attribute"),
            catalog_rows(&reopened, "pg_index"),
        );
        assert_eq!(after, before);
    }

    #[test]
    fn falls_through_when_no_pattern_matches() {
        let (db, _g) = fresh_db();
        assert!(intercept(&db, "SELECT 1;").is_none());
        assert!(intercept(&db, "INSERT INTO t VALUES (1);").is_none());
    }
}
