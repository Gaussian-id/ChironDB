//! Offline catalog identity backfill. Row and index keys do not change.
use super::*;

impl RelationalEngine {
    /// The caller holds the exclusive database lifecycle gate, so no session
    /// can start between this check and the metadata-only migration.
    pub(crate) fn ensure_table_authority_migration_idle(&self) -> Result<()> {
        if !self.interactive.is_empty()? {
            return Err(invalid(
                "offline table authority migration requires all SQL transactions to end",
            ));
        }
        Ok(())
    }

    pub(crate) fn current_table_privileges(
        &self,
        identity: &AuthenticatedIdentity,
    ) -> Result<BTreeSet<(String, SecurityAction)>> {
        let mut grants = BTreeMap::<_, BTreeSet<_>>::new();
        for role in identity
            .roles()
            .iter()
            .filter(|role| role.tenant == identity.principal().tenant)
        {
            for grant in &role.table_grants {
                grants
                    .entry((grant.table_id, grant.incarnation))
                    .or_default()
                    .extend(&grant.actions);
            }
        }
        let mut privileges = BTreeSet::new();
        if !grants.is_empty() || identity.has_strict_sql_scopes() {
            for table in self.state.read().tables.values() {
                if table.definition.tenant_id.as_deref()
                    != Some(identity.principal().tenant.as_str())
                {
                    continue;
                }
                if let Some(incarnation) = table.definition.security_incarnation
                    && let Some(actions) = grants.get(&(table.definition.table_id, incarnation))
                {
                    privileges.extend(
                        actions
                            .iter()
                            .map(|action| (table.definition.name.clone(), *action)),
                    );
                }
                if identity.owns_table(
                    &identity.principal().tenant,
                    table.definition.creator_principal_id.as_deref(),
                ) {
                    privileges.extend(
                        [
                            SecurityAction::Read,
                            SecurityAction::Create,
                            SecurityAction::Update,
                            SecurityAction::Delete,
                        ]
                        .map(|action| (table.definition.name.clone(), action)),
                    );
                }
                if privileges.len() > 4 * crate::security::MAX_POLICY_GRANTS {
                    return Err(SecurityError::BudgetExceeded.into());
                }
            }
        }
        Ok(privileges)
    }

    /// Only catalog identity is needed to convert name capabilities. Bound
    /// this offline working set independently of row data and table schemas.
    pub(crate) fn sql_scope_migration_bindings(
        &self,
    ) -> Result<BTreeMap<(String, String), (u64, uuid::Uuid)>> {
        let mut bindings = BTreeMap::new();
        let mut bytes = 0usize;
        for table in self.state.read().tables.values() {
            let definition = &table.definition;
            let Some(tenant) = &definition.tenant_id else {
                continue;
            };
            let incarnation = definition.security_incarnation.ok_or_else(|| {
                invalid("complete offline migrate-table-authority before migrate-sql-scopes")
            })?;
            bytes = bytes.saturating_add(tenant.len() + definition.name.len() + 256);
            if bytes > 16 * 1024 * 1024 {
                return Err(SecurityError::BudgetExceeded.into());
            }
            bindings.insert(
                (tenant.clone(), definition.name.clone()),
                (definition.table_id, incarnation),
            );
        }
        Ok(bindings)
    }

    pub(crate) fn table_grant_binding(
        &self,
        tenant: &str,
        name: &str,
    ) -> Result<(u64, uuid::Uuid)> {
        let state = self.state.read();
        let table = state.tables.get(name).ok_or(SecurityError::NotFound)?;
        if table.definition.tenant_id.as_deref() != Some(tenant) {
            return Err(SecurityError::NotFound.into());
        }
        let incarnation = table.definition.security_incarnation.ok_or_else(|| {
            invalid("run offline chironctl security migrate-table-authority first")
        })?;
        Ok((table.definition.table_id, incarnation))
    }

    /// The caller has durably fenced old readers before reaching this method.
    /// One manifest replacement adds every missing identity, preserving all
    /// existing row/index runs and SQL sequence numbers.
    pub(crate) fn migrate_table_authority_offline(&self) -> Result<usize> {
        self.checkpoint()?;
        let _checkpoint = self.checkpoint.lock().map_err(|_| {
            GaussError::WalUnavailable("relational checkpoint lock poisoned".into())
        })?;
        let mut state = self.state.write();
        let mut manifest = read_relational_checkpoint(&self.checkpoint_path)?
            .ok_or_else(|| invalid("missing relational checkpoint after offline flush"))?;
        if manifest.sequence != state.sequence {
            return Err(invalid(
                "offline table migration observed a concurrent SQL change",
            ));
        }
        let mut candidate = state.clone();
        let mut count = 0;
        for table in &mut manifest.tables {
            if table.definition.tenant_id.is_some()
                && table.definition.security_incarnation.is_none()
            {
                let incarnation = uuid::Uuid::new_v4();
                table.definition.security_incarnation = Some(incarnation);
                let current = candidate
                    .tables
                    .get_mut(&table.definition.name)?
                    .ok_or_else(|| invalid("offline table migration catalog mismatch"))?;
                Arc::make_mut(current).definition = Schema::copy(&table.definition)?;
                count += 1;
            }
        }
        if count != 0 {
            crate::failpoint::check("table_authority.before_manifest")?;
            write_relational_checkpoint(&self.checkpoint_path, &manifest)?;
            crate::failpoint::check("table_authority.after_manifest")?;
            *state = candidate;
        }
        Ok(count)
    }
}

#[cfg(all(test, feature = "fault-injection"))]
mod tests {
    use super::*;

    fn request(sql: &str) -> SqlExecutionRequest {
        serde_json::from_value(serde_json::json!({"statements":[{"sql":sql}]})).unwrap()
    }

    #[test]
    fn table_identity_migration_publishes_all_or_none_and_preserves_rows() {
        for point in [
            "table_authority.before_manifest",
            "table_authority.after_manifest",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let journal = TransactionJournal::open(directory.path()).unwrap();
            let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
            let audit = AuditContext {
                principal_id: "admin".into(),
                tenant_id: Some("acme".into()),
                transport: "test".into(),
                request_id: None,
            };
            for table in ["first", "second"] {
                for sql in [
                    format!("CREATE TABLE {table} (id BIGINT PRIMARY KEY, value TEXT)"),
                    format!("INSERT INTO {table} VALUES (1, 'retained')"),
                ] {
                    engine
                        .execute_scoped_with_audit(request(&sql), &audit, Some("acme"), None)
                        .unwrap();
                }
            }
            engine.checkpoint().unwrap();
            let before = read_relational_checkpoint(&engine.checkpoint_path)
                .unwrap()
                .unwrap();
            let failure = crate::failpoint::test_env(
                &format!("error:{point}"),
                &directory.path().join("marker"),
                &directory.path().join("release"),
            );
            assert!(engine.migrate_table_authority_offline().is_err());
            drop(failure);
            drop(engine);
            drop(journal);
            let journal = TransactionJournal::open(directory.path()).unwrap();
            let engine = RelationalEngine::open(directory.path(), journal).unwrap();
            let after = read_relational_checkpoint(&engine.checkpoint_path)
                .unwrap()
                .unwrap();
            assert_eq!(after.sequence, before.sequence);
            let published = point.ends_with("after_manifest");
            assert_eq!(
                after
                    .tables
                    .iter()
                    .filter(|table| table.definition.security_incarnation.is_some())
                    .count(),
                if published { 2 } else { 0 }
            );
            for (old, new) in before.tables.iter().zip(&after.tables) {
                assert_eq!(old.definition.table_id, new.definition.table_id);
                assert_eq!(old.row_segments, new.row_segments);
                assert_eq!(old.index_segments, new.index_segments);
                let result = engine
                    .execute_scoped_with_audit(
                        request(&format!(
                            "SELECT value FROM {} WHERE id=1",
                            new.definition.name
                        )),
                        &audit,
                        Some("acme"),
                        None,
                    )
                    .unwrap();
                assert!(
                    matches!(&result.response.results[0], SqlResult::Rows { rows, .. }
                    if rows == &vec![vec![RelationalValue::Text("retained".into())]])
                );
            }
            assert_eq!(
                engine.migrate_table_authority_offline().unwrap(),
                if published { 0 } else { 2 }
            );
        }
    }
}

#[cfg(test)]
mod creator_tests {
    use super::*;

    #[test]
    fn persisted_creator_requires_a_protected_table_identity() {
        let Statement::CreateTable(create) =
            Parser::parse_sql(&PostgreSqlDialect {}, "CREATE TABLE documents (id BIGINT)")
                .unwrap()
                .pop()
                .unwrap()
        else {
            panic!("CREATE expected")
        };
        let mut definition = table_definition(create).unwrap();
        definition.table_id = 1;
        definition.tenant_id = Some("acme".into());
        definition.security_incarnation = Some(uuid::Uuid::new_v4());
        definition.creator_principal_id = Some("immutable-principal".into());
        validate_definition(&definition).unwrap();
        for invalid_creator in [String::new(), "x".repeat(129)] {
            let mut invalid_definition = definition.clone();
            invalid_definition.creator_principal_id = Some(invalid_creator);
            assert!(validate_definition(&invalid_definition).is_err());
        }
        let mut missing_tenant = definition.clone();
        missing_tenant.tenant_id = None;
        assert!(validate_definition(&missing_tenant).is_err());
        definition.security_incarnation = None;
        assert!(validate_definition(&definition).is_err());
    }
}
