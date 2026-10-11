//! Catalog probes share immutable admitted schemas, without retaining row roots.
use super::*;
use crate::response_buffer::ResponseReservation;

/// Immutable schema view with independent admission for its handle vector.
/// Schema backing keeps its original reservation after DDL replaces a table.
#[derive(Debug)]
pub struct RelationalCatalogSnapshot {
    schemas: Vec<Schema>,
    _memory: ResponseReservation,
}
impl RelationalCatalogSnapshot {
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &TableDefinition> {
        self.schemas.iter().map(AsRef::as_ref)
    }
    pub fn has_table(&self, name: &str) -> bool {
        self.iter().any(|table| table.name == name)
    }
    pub fn has_index(&self, name: &str) -> bool {
        self.iter()
            .any(|table| table.indexes.iter().any(|index| index.name == name))
    }
    /// SQL namespace wins over any vector collection with the same name.
    pub fn permits_read(&self, name: &str, identity: &AuthenticatedIdentity) -> Option<bool> {
        self.iter().find(|table| table.name == name).map(|table| {
            let tenant = &identity.principal().tenant;
            if table.tenant_id.as_deref() != Some(tenant) {
                return false;
            }
            let roles = || {
                identity
                    .roles()
                    .iter()
                    .filter(|role| role.tenant == *tenant)
            };
            let has_grants = roles().any(|role| !role.table_grants.is_empty());
            let exact = table.security_incarnation.is_some_and(|incarnation| {
                roles().flat_map(|role| &role.table_grants).any(|grant| {
                    grant.table_id == table.table_id
                        && grant.incarnation == incarnation
                        && grant.actions.contains(&SecurityAction::Read)
                })
            });
            exact
                || ((has_grants || identity.has_strict_sql_scopes())
                    && identity.owns_table(tenant, table.creator_principal_id.as_deref()))
                || (!identity.has_strict_sql_scopes()
                    && identity.allows(tenant, name, SecurityAction::Read))
        })
    }
}
impl RelationalEngine {
    pub(crate) fn catalog_snapshot(&self) -> Result<RelationalCatalogSnapshot> {
        check_sql_cancelled()?;
        let state = self.state.read();
        let bytes = state
            .tables
            .len()
            .checked_mul(std::mem::size_of::<Schema>())
            .and_then(|bytes| bytes.checked_add(512))
            .ok_or_else(sql_overloaded)?;
        let memory = ResponseReservation::new(bytes as u64)?;
        let mut schemas = Vec::new();
        schemas
            .try_reserve_exact(state.tables.len())
            .map_err(|_| sql_overloaded())?;
        for table in state.tables.values() {
            check_sql_cancelled()?;
            schemas.push(table.definition.clone());
        }
        Ok(RelationalCatalogSnapshot {
            schemas,
            _memory: memory,
        })
    }
    pub(crate) fn catalog_membership(&self, analysis: &SqlStatementAnalysis) -> (bool, bool) {
        let state = self.state.read();
        (
            analysis
                .tables
                .iter()
                .any(|name| state.tables.contains_key(name)),
            analysis.indexes.iter().any(|name| {
                state.tables.values().any(|table| {
                    table
                        .definition
                        .indexes
                        .iter()
                        .any(|index| &index.name == name)
                })
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(sql: &str) -> SqlExecutionRequest {
        serde_json::from_value(serde_json::json!({"statements":[{"sql":sql}]})).unwrap()
    }
    #[test]
    fn schema_view_shares_admitted_backing_and_never_pins_a_row_root() {
        let directory = tempfile::tempdir().unwrap();
        let (pool, snapshot) = memory::with_storage_pool(8 * 1024 * 1024, |pool| {
            let engine = RelationalEngine::open(
                directory.path(),
                TransactionJournal::open(directory.path()).unwrap(),
            )
            .unwrap();
            engine
                .execute(request(
                    "CREATE TABLE items (id INTEGER, body TEXT DEFAULT 'old')",
                ))
                .unwrap();
            engine
                .execute(request("INSERT INTO items VALUES (1, 'row')"))
                .unwrap();
            let table = engine.state.read().tables["items"].clone();
            let roots = Arc::strong_count(&table);
            let snapshot = engine.catalog_snapshot().unwrap();
            assert_eq!(
                Arc::strong_count(&table),
                roots,
                "catalog view must not keep row generations"
            );
            assert!(std::ptr::eq(
                snapshot.iter().next().unwrap(),
                table.definition.as_ref()
            ));
            drop(table);
            engine
                .execute(request(
                    "ALTER TABLE items ALTER COLUMN body SET DEFAULT 'new'",
                ))
                .unwrap();
            assert_eq!(
                snapshot.iter().next().unwrap().columns[1].default,
                Some(RelationalValue::Text("old".into()))
            );
            assert!(!std::ptr::eq(
                snapshot.iter().next().unwrap(),
                engine.state.read().tables["items"].definition.as_ref()
            ));
            drop(engine);
            assert!(pool.used() > 0);
            (pool, snapshot)
        });
        assert!(snapshot.has_table("items"));
        assert!(!snapshot.has_index("missing"));
        drop(snapshot);
        assert_eq!(pool.used(), 0);
    }
    #[test]
    fn schema_view_refuses_before_handle_copy_and_keeps_the_live_catalog() {
        let directory = tempfile::tempdir().unwrap();
        let engine = RelationalEngine::open(
            directory.path(),
            TransactionJournal::open(directory.path()).unwrap(),
        )
        .unwrap();
        engine
            .execute(request("CREATE TABLE items (id INTEGER PRIMARY KEY)"))
            .unwrap();
        engine
            .execute(request("CREATE INDEX by_id ON items (id)"))
            .unwrap();
        let before = engine.table_definitions();
        memory::with_storage_pool(1, |pool| {
            assert!(matches!(
                engine.catalog_snapshot(),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(pool.used(), 0);
        });
        let mut analysis = RelationalEngine::analyze_statement("SELECT id FROM items").unwrap();
        assert_eq!(engine.catalog_membership(&analysis), (true, false));
        analysis.tables[0] = "absent".into();
        assert_eq!(engine.catalog_membership(&analysis), (false, false));
        analysis.indexes.push(before[0].indexes[0].name.clone());
        assert_eq!(engine.catalog_membership(&analysis), (false, true));
        assert_eq!(engine.table_definitions(), before);
    }
}
