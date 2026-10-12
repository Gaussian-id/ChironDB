//! Admit catalog classification and producer peak before copying displayed data.
use super::*;
use crate::{GaussError, Result, response_buffer::ResponseReservation};
use chirondb_core::relational::RelationalCatalogSnapshot;
use std::{io, mem::size_of};

#[cfg(test)]
mod tests;

fn full() -> GaussError {
    GaussError::ResourceExhausted("PostgreSQL catalog memory limit exceeded".into())
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or_else(full)
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or_else(full)
}

#[derive(Debug)]
pub(crate) struct CatalogResponse {
    response: QueryResponse,
    _memory: ResponseReservation,
}
impl std::ops::Deref for CatalogResponse {
    type Target = QueryResponse;
    fn deref(&self) -> &Self::Target {
        &self.response
    }
}
impl CatalogResponse {
    // Explicit embedded DTO transfer. Wire paths retain CatalogResponse instead.
    pub(super) fn into_dto(self) -> QueryResponse {
        self.response
    }
    // Session SET/SHOW constructs its source separately. Only retention is
    // covered by this adapter; it does not certify initial session parsing.
    pub(crate) fn retain_existing(response: QueryResponse) -> Result<Self> {
        let mut bytes = 512usize;
        match &response {
            QueryResponse::RowSet { columns, rows, tag } => {
                bytes = add(bytes, mul(columns.capacity(), size_of::<ColumnSpec>())?)?;
                bytes = add(bytes, tag.capacity())?;
                for column in columns {
                    bytes = add(bytes, column.name.capacity())?;
                }
                bytes = add(
                    bytes,
                    mul(rows.capacity(), size_of::<Vec<Option<String>>>())?,
                )?;
                for row in rows {
                    bytes = add(bytes, mul(row.capacity(), size_of::<Option<String>>())?)?;
                    for value in row.iter().flatten() {
                        bytes = add(bytes, value.capacity())?;
                    }
                }
            }
            QueryResponse::CommandTag(tag) => bytes = add(bytes, tag.capacity())?,
            QueryResponse::Empty => {}
        }
        let memory = ResponseReservation::new(bytes as u64)?;
        Ok(Self {
            response,
            _memory: memory,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Version,
    Database,
    Schema,
    User,
    Setting,
    Isolation,
    Standard,
    Server,
    Tables(usize),
    Columns(usize),
    ReflectionColumns,
    Domains,
    Enums,
    Constraints,
    ForeignKeys,
    Checks,
    Indexes,
    Comments,
    Names,
    Oids,
    Class,
    Namespace,
    Attribute,
    TypeLookup,
    Type,
    Index,
}
pub(crate) struct CatalogPlan {
    normalized: String,
    route: Route,
    _memory: ResponseReservation,
}
impl CatalogPlan {
    pub(crate) fn new(sql: &str) -> Result<Option<Self>> {
        let sql = sql.trim().trim_end_matches(';').trim();
        let memory = ResponseReservation::new(add(sql.len(), 512)? as u64)?;
        let mut normalized = String::new();
        normalized
            .try_reserve_exact(sql.len())
            .map_err(|_| full())?;
        normalized.push_str(sql);
        normalized.make_ascii_lowercase();
        let Some(route) = classify(&normalized) else {
            return Ok(None);
        };
        Ok(Some(Self {
            normalized,
            route,
            _memory: memory,
        }))
    }
    pub(crate) fn fixed(&self) -> bool {
        matches!(
            self.route,
            Route::Version
                | Route::Database
                | Route::Schema
                | Route::User
                | Route::Setting
                | Route::Isolation
                | Route::Standard
                | Route::Server
                | Route::Domains
                | Route::Enums
                | Route::Namespace
                | Route::TypeLookup
                | Route::Type
        )
    }
    pub(crate) fn execute_fixed(self, user: Option<&str>) -> Result<CatalogResponse> {
        let memory = ResponseReservation::new(add(8192, user.map_or(0, str::len))? as u64)?;
        let response = match self.route {
            Route::Version => single_text_row("version", &server_version_string()),
            Route::Database => single_text_row("current_database", "gaussdb"),
            Route::Schema => single_text_row("current_schema", "public"),
            Route::User => single_text_row("current_user", user.unwrap_or("gaussdb")),
            Route::Setting => single_text_row("current_setting", ""),
            Route::Isolation => single_text_row("transaction_isolation", "repeatable read"),
            Route::Standard => single_text_row("standard_conforming_strings", "on"),
            Route::Server => single_text_row(
                "server_version",
                crate::wire_postgres::SERVER_VERSION_STRING,
            ),
            Route::Domains => empty_domains(),
            Route::Enums => empty_enums(),
            Route::Namespace => list_pg_namespace(),
            Route::TypeLookup => empty_type_lookup(),
            Route::Type => list_pg_type(),
            _ => {
                return Err(GaussError::InvalidRequest(
                    "catalog route requires a schema snapshot".into(),
                ));
            }
        };
        Ok(CatalogResponse {
            response,
            _memory: memory,
        })
    }
    pub(crate) fn execute(
        self,
        tables: &RelationalCatalogSnapshot,
        collections: &[String],
        parameters: &[crate::RelationalValue],
        allows: &impl Fn(&str) -> bool,
        user: Option<&str>,
    ) -> Result<CatalogResponse> {
        if self.fixed() {
            return self.execute_fixed(user);
        }
        let memory = ResponseReservation::new(self.peak(tables, collections, allows)? as u64)?;
        let sql = &self.normalized;
        let response = match self.route {
            Route::Tables(_) => information_schema_tables(tables, collections, sql, allows),
            Route::Columns(_) => information_schema_columns(tables, collections, sql, allows),
            Route::ReflectionColumns => Some(sqlalchemy_columns(tables, allows)),
            Route::Constraints => Some(sqlalchemy_constraints(tables, parameters, allows)),
            Route::ForeignKeys => Some(sqlalchemy_foreign_keys(tables, allows)),
            Route::Checks => Some(sqlalchemy_check_constraints(tables, allows)),
            Route::Indexes => Some(sqlalchemy_indexes(tables, allows)),
            Route::Comments => Some(sqlalchemy_table_comments(tables, allows)),
            Route::Names => Some(sqlalchemy_table_names(tables, collections, allows)),
            Route::Oids => Some(sqlalchemy_table_oids(tables, allows)),
            Route::Class => Some(list_pg_class(tables, collections, allows)),
            Route::Attribute => Some(list_pg_attribute(tables, collections, allows)),
            Route::Index => Some(list_pg_index(tables, collections, allows)),
            _ => unreachable!("fixed routes returned above"),
        }
        .ok_or_else(|| GaussError::InvalidRequest("catalog projection is unsupported".into()))?;
        Ok(CatalogResponse {
            response,
            _memory: memory,
        })
    }
    fn peak(
        &self,
        tables: &RelationalCatalogSnapshot,
        collections: &[String],
        allows: &impl Fn(&str) -> bool,
    ) -> Result<usize> {
        let width = match self.route {
            Route::Tables(n) | Route::Columns(n) => n,
            _ => 14,
        };
        let mut rows = 0usize;
        let mut text = 0usize;
        for table in tables.iter().filter(|table| allows(&table.name)) {
            let count = match self.route {
                Route::ReflectionColumns | Route::Columns(_) | Route::Attribute => {
                    table.columns.len()
                }
                Route::Class => add(1, table.indexes.len())?,
                Route::Constraints => add(1, table.unique_constraints.len())?,
                Route::ForeignKeys => table.foreign_keys.len().max(1),
                Route::Checks => table.check_constraints.len().max(1),
                Route::Indexes | Route::Index => table.indexes.len(),
                _ => 1,
            };
            rows = add(rows, count)?;
            text = add(text, mul(table.name.len(), count)?)?;
            match self.route {
                Route::ReflectionColumns | Route::Columns(_) => {
                    for column in &table.columns {
                        text = add(text, column.name.len())?;
                        if let Some(value) = &column.default {
                            text = add(text, default_text_bound(value)?)?;
                        }
                    }
                }
                Route::Attribute => {
                    for column in &table.columns {
                        text = add(text, column.name.len())?;
                    }
                }
                Route::Class => {
                    for index in &table.indexes {
                        text = add(text, index.name.len())?;
                    }
                }
                Route::Constraints => {
                    text = add(text, table.primary_key_name.as_ref().map_or(0, String::len))?;
                    text = add(text, names_bound(&table.primary_key)?)?;
                    for constraint in &table.unique_constraints {
                        text = add(text, constraint.name.as_ref().map_or(0, String::len))?;
                        text = add(text, names_bound(&constraint.columns)?)?;
                    }
                }
                Route::ForeignKeys => {
                    for foreign in &table.foreign_keys {
                        text = add(text, foreign.name.as_ref().map_or(0, String::len))?;
                        text = add(text, names_bound(&foreign.columns)?)?;
                        text = add(text, names_bound(&foreign.referenced_columns)?)?;
                        text = add(text, add(foreign.referenced_table.len(), 64)?)?;
                    }
                }
                Route::Checks => {
                    for constraint in &table.check_constraints {
                        text = add(text, constraint.name.as_ref().map_or(0, String::len))?;
                        text = add(text, constraint.expression.len())?;
                    }
                }
                Route::Indexes => {
                    for index in &table.indexes {
                        text = add(text, index.name.len())?;
                        text = add(text, names_bound(&index.columns)?)?;
                    }
                }
                _ => {}
            }
        }
        for name in collections.iter().filter(|name| allows(name)) {
            let count = match self.route {
                Route::Columns(_) | Route::Attribute => 2,
                Route::Tables(_) | Route::Names | Route::Class | Route::Index => 1,
                _ => 0,
            };
            rows = add(rows, count)?;
            text = add(text, mul(name.len(), count)?)?;
        }
        // Each static cell is <=256 bytes (integers/types/identity options).
        // 4x covers formatting growth/temporaries. String slots and row backing
        // allow doubling; borrowed schema/filter/name vectors and sort scratch
        // fit in the additional per-row controller allowance. Dynamic bytes
        // allow 2x escaping, 2x geometric growth and simultaneous source/temp/
        // output backing. Width multiplies repeated information_schema fields.
        let cell = add(1024, mul(2, size_of::<Option<String>>())?)?;
        let row = add(128, mul(width, cell)?)?;
        add(
            add(8192, mul(width, 1024)?)?,
            add(mul(rows, row)?, mul(mul(text, 8)?, width.max(1))?)?,
        )
    }
}
fn names_bound(names: &[String]) -> Result<usize> {
    names
        .iter()
        .try_fold(0, |bytes, name| add(bytes, add(name.len(), 64)?))
}
fn default_text_bound(value: &crate::RelationalValue) -> Result<usize> {
    use crate::RelationalValue as V;
    match value {
        V::Text(v) | V::Date(v) | V::TimestampUtc(v) | V::Decimal(v) => add(v.len(), 64),
        V::Bytes(v) => add(mul(v.len(), 2)?, 64),
        V::Vector(v) => mul(v.len(), 128), // f32 Display, separators and temporary String slots.
        V::RecordRef(v) => add(add(v.namespace.len(), v.id.len())?, 64),
        V::Json(v) => {
            struct Count(usize);
            impl io::Write for Count {
                fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                    self.0 = self
                        .0
                        .checked_add(bytes.len())
                        .ok_or_else(|| io::Error::other("catalog size overflow"))?;
                    Ok(bytes.len())
                }
                fn flush(&mut self) -> io::Result<()> {
                    Ok(())
                }
            }
            let mut count = Count(0);
            serde_json::to_writer(&mut count, v).map_err(|_| full())?;
            add(count.0, 64)
        }
        _ => Ok(512), // f64 Display includes subnormal fixed-point decimal expansion.
    }
}
fn projection_count(sql: &str, relation: &str, allowed: &[&str]) -> Option<usize> {
    let marker = match relation {
        "tables" => " from information_schema.tables",
        _ => " from information_schema.columns",
    };
    let selected = sql.strip_prefix("select ")?.split_once(marker)?.0;
    let mut count = 0;
    for expression in selected.split(',') {
        let expression = expression.trim();
        if expression.split_ascii_whitespace().count() != 1 {
            return None;
        }
        if !allowed.contains(&expression.rsplit('.').next()?.trim_matches('"')) {
            return None;
        }
        count += 1;
    }
    (count != 0).then_some(count)
}
fn classify(sql: &str) -> Option<Route> {
    if sql.is_empty() {
        return None;
    }
    for (function, route) in [
        ("version", Route::Version),
        ("current_database", Route::Database),
        ("current_schema", Route::Schema),
        ("current_schemas", Route::Schema),
        ("current_user", Route::User),
        ("current_setting", Route::Setting),
    ] {
        // Match former starts_with semantics, without allocating format strings.
        if sql.strip_prefix("select ").is_some_and(|rest| {
            let rest = rest.strip_prefix("pg_catalog.").unwrap_or(rest);
            rest.strip_prefix(function)
                .is_some_and(|tail| tail.starts_with("()"))
        }) {
            return Some(route);
        }
    }
    match sql {
        "select current_user" | "select pg_catalog.current_user" => return Some(Route::User),
        "show transaction isolation level" => return Some(Route::Isolation),
        "show standard_conforming_strings" => return Some(Route::Standard),
        "show server_version" => return Some(Route::Server),
        _ => {}
    }
    if sql.contains(" from information_schema.tables")
        && let Some(n) = projection_count(
            sql,
            "tables",
            &["table_catalog", "table_schema", "table_name", "table_type"],
        )
    {
        return Some(Route::Tables(n));
    }
    if sql.contains(" from information_schema.columns")
        && let Some(n) = projection_count(
            sql,
            "columns",
            &[
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
            ],
        )
    {
        return Some(Route::Columns(n));
    }
    if sql.contains("pg_catalog.pg_attribute.attname as name")
        && sql.contains("pg_catalog.format_type")
    {
        return Some(Route::ReflectionColumns);
    }
    if sql.contains("domain_constraints") && sql.contains("pg_catalog.pg_type.typtype") {
        return Some(Route::Domains);
    }
    if sql.contains("pg_catalog.pg_enum") && sql.contains("pg_catalog.pg_type.typtype") {
        return Some(Route::Enums);
    }
    if sql.contains("array_agg(cast(attr.attname as text)")
        && sql.contains("pg_catalog.pg_constraint.contype")
    {
        return Some(Route::Constraints);
    }
    if sql.contains("pg_catalog.pg_constraint.confrelid")
        && sql.contains("pg_catalog.pg_get_constraintdef")
    {
        return Some(Route::ForeignKeys);
    }
    if sql.starts_with("select pg_catalog.pg_class.relname, pg_catalog.pg_constraint.conname")
        && sql.contains("pg_catalog.pg_get_constraintdef")
    {
        return Some(Route::Checks);
    }
    if sql.contains("pg_catalog.pg_index.indrelid") && sql.contains("idx_cols.elements") {
        return Some(Route::Indexes);
    }
    if sql.starts_with("select pg_catalog.pg_class.relname, pg_catalog.pg_description.description")
        && sql.contains("pg_catalog.pg_description.objsubid")
    {
        return Some(Route::Comments);
    }
    if sql.starts_with("select pg_catalog.pg_class.relname") {
        return Some(Route::Names);
    }
    if sql.starts_with("select pg_catalog.pg_class.oid, pg_catalog.pg_class.relname") {
        return Some(Route::Oids);
    }
    if sql.contains("pg_catalog.pg_class") || sql.contains(" pg_class") {
        return Some(Route::Class);
    }
    if sql.contains("pg_catalog.pg_namespace") || sql.contains(" pg_namespace") {
        return Some(Route::Namespace);
    }
    if sql.contains("pg_catalog.pg_attribute") || sql.contains(" pg_attribute") {
        return Some(Route::Attribute);
    }
    if (sql.contains("from pg_type") || sql.contains("from pg_catalog.pg_type"))
        && (sql.contains("to_regtype(") || sql.contains("::regtype"))
    {
        return Some(Route::TypeLookup);
    }
    if sql.contains("pg_catalog.pg_type") || sql.contains(" pg_type") {
        return Some(Route::Type);
    }
    if sql.contains("pg_catalog.pg_index") || sql.contains(" pg_index") {
        return Some(Route::Index);
    }
    None
}
