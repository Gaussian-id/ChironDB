//! Small catalog views and allocation-free PostgreSQL namespace resolution.
use super::*;
use crate::{relational::RelationalCatalogSnapshot, response_buffer::ResponseReservation};

#[derive(Debug)]
pub struct CollectionNameSnapshot {
    names: Vec<String>,
    _memory: ResponseReservation,
}
impl std::ops::Deref for CollectionNameSnapshot {
    type Target = [String];
    fn deref(&self) -> &Self::Target {
        &self.names
    }
}
impl Db {
    /// Validate the database authority and keep it current during catalog work.
    pub fn catalog_publication_permit(
        &self,
        identity: &crate::security::AuthenticatedIdentity,
    ) -> Result<crate::security::PublicationPermit> {
        self.ensure_current_identity(identity)?;
        identity.publication_permit().map_err(Into::into)
    }
    pub fn relational_catalog_owned(&self) -> Result<RelationalCatalogSnapshot> {
        self.relational.read().catalog_snapshot()
    }
    /// Returns (relational table mentioned, relational index mentioned,
    /// vector collection mentioned without a relational table mention).
    /// No schema/config/row copy or temporary name set is built.
    pub fn sql_catalog_membership(
        &self,
        analysis: &crate::SqlStatementAnalysis,
    ) -> (bool, bool, bool) {
        let (table, index) = self.relational.read().catalog_membership(analysis);
        let inner = self.inner.read();
        let vector = analysis.tables.iter().any(|name| {
            inner
                .collections
                .get(name)
                .is_some_and(|collection| collection.read().security.is_none())
        });
        (table, index, vector && !table)
    }
    /// Copy only visible collection names; configuration maps are not hydrated.
    /// A protected caller must reacquire publication permission before sending.
    pub fn collection_names_owned(
        &self,
        identity: Option<&crate::security::AuthenticatedIdentity>,
    ) -> Result<CollectionNameSnapshot> {
        let _lifecycle = self.lifecycle_gate.read();
        let _permit = if let Some(identity) = identity {
            self.ensure_current_identity(identity)?;
            Some(identity.publication_permit()?)
        } else {
            None
        };
        let inner = self.inner.read();
        let allows = |name: &str, collection: &Collection| match identity {
            Some(identity) => {
                collection.security.is_some()
                    && identity.allows(
                        &identity.principal().tenant,
                        name,
                        crate::security::Action::Read,
                    )
            }
            None => collection.security.is_none(),
        };
        let mut count = 0usize;
        let mut bytes = 512usize;
        for (name, collection) in &inner.collections {
            if allows(name, &collection.read()) {
                count = count.checked_add(1).ok_or_else(catalog_full)?;
                bytes = bytes
                    .checked_add(name.len())
                    .and_then(|n| n.checked_add(std::mem::size_of::<String>()))
                    .ok_or_else(catalog_full)?;
            }
        }
        let memory = ResponseReservation::new(bytes as u64)?;
        let mut names = Vec::new();
        names.try_reserve_exact(count).map_err(|_| catalog_full())?;
        for (name, collection) in &inner.collections {
            if allows(name, &collection.read()) {
                let mut value = String::new();
                value
                    .try_reserve_exact(name.len())
                    .map_err(|_| catalog_full())?;
                value.push_str(name);
                names.push(value);
            }
        }
        names.sort_unstable();
        Ok(CollectionNameSnapshot {
            names,
            _memory: memory,
        })
    }
}
fn catalog_full() -> GaussError {
    GaussError::ResourceExhausted("catalog memory limit exceeded".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn name_only_catalog_admission_does_not_copy_configuration_maps() {
        let directory = tempfile::tempdir().unwrap();
        let db = Db::open(directory.path()).unwrap();
        let config: CollectionConfig = serde_json::from_value(serde_json::json!({
            "name":"catalog_vectors","vector_dim":3,"metric":"cosine"
        }))
        .unwrap();
        db.create_collection(config).unwrap();
        // The view must not copy unrelated nested configuration, even when it
        // is larger than the receiving pool used for this name-only operation.
        db.inner.read().collections["catalog_vectors"]
            .write()
            .config
            .named_vector_dims
            .insert("large_".to_string() + &"x".repeat(16384), 3);
        crate::relational::wal_decode::with_test_storage_pool(1, |used| {
            assert!(matches!(
                db.collection_names_owned(None),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
        });
        crate::relational::wal_decode::with_test_storage_pool(2048, |used| {
            let names = db.collection_names_owned(None).unwrap();
            assert_eq!(&*names, &["catalog_vectors"]);
            assert!(used() > 0);
            drop(names);
            assert_eq!(used(), 0);
        });
        let vector =
            crate::RelationalEngine::analyze_statement("SELECT id FROM catalog_vectors").unwrap();
        assert_eq!(db.sql_catalog_membership(&vector), (false, false, true));
        db.execute_sql(serde_json::from_value(serde_json::json!({"statements":[{"sql":"CREATE TABLE catalog_vectors (id INTEGER)"}]})).unwrap()).unwrap();
        assert_eq!(db.sql_catalog_membership(&vector), (true, false, false));
    }
}
