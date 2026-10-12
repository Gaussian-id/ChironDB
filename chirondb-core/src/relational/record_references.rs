//! Protected atomic data commits validate new SQL references and point retirement
//! against their final relational candidate. Legacy SQL values are not global FKs.
use super::*;

pub(super) fn result_references(results: &[SqlResult]) -> BTreeSet<crate::RecordRef> {
    let mut references = BTreeSet::new();
    for result in results {
        if let SqlResult::Rows { rows, .. } = result {
            for row in rows {
                for value in row {
                    if let RelationalValue::RecordRef(reference) = value {
                        references.insert(reference.clone());
                    }
                }
            }
        }
    }
    references
}

/// Reconstruct live reference dependencies from an authenticated journal
/// PREPARE. This also works for receipts written before references were stored
/// in the response, without reading today's (possibly changed) table state.
pub(super) fn replay_references<'a>(
    mutation: Option<&WalEntry>,
    response: &SqlExecutionResponse,
    additional: impl Iterator<Item = &'a crate::RecordRef>,
) -> Result<wal_decode::Owned<BTreeSet<crate::RecordRef>>> {
    let Some(WalEntry::RelationalBatch { batch }) = mutation else {
        return Err(invalid("SQL receipt has no relational PREPARE mutation"));
    };
    let mut memory = wal_decode::MetadataCharge::default();
    let mut bytes = 4096_u64;
    memory.prepare(bytes)?;
    // Borrowed row/table keys allocate only BTree nodes. Cumulative slots cover
    // replacement/rewrite overlap; maps die before the returned set's lease.
    let mut node = |count: usize| -> Result<()> {
        bytes = bytes
            .checked_add(
                (count as u64)
                    .checked_mul(1024)
                    .ok_or_else(sql_overloaded)?,
            )
            .ok_or_else(sql_overloaded)?;
        memory.prepare(bytes)
    };
    let mut rows: BTreeMap<&str, BTreeMap<u64, &StoredRow>> = BTreeMap::new();
    for change in &batch.mutations {
        check_sql_cancelled()?;
        match change {
            RelationalMutation::CreateTable { definition } => {
                rows.remove(definition.name.as_str());
            }
            RelationalMutation::DropTable { name } => {
                rows.remove(name.as_str());
            }
            RelationalMutation::RenameTable {
                old_name,
                definition,
            } => {
                if let Some(existing) = rows.remove(old_name.as_str()) {
                    node(1)?;
                    rows.insert(definition.name.as_str(), existing);
                }
            }
            RelationalMutation::RewriteTable {
                definition,
                rows: rewritten,
            } => {
                node(rewritten.len().checked_add(1).ok_or_else(sql_overloaded)?)?;
                rows.insert(
                    definition.name.as_str(),
                    rewritten.iter().map(|row| (row.row_id, row)).collect(),
                );
            }
            RelationalMutation::Insert {
                table,
                rows: changed,
            }
            | RelationalMutation::Update {
                table,
                rows: changed,
            } => {
                if !rows.contains_key(table.as_str()) {
                    node(1)?;
                }
                let table_rows = rows.entry(table).or_default();
                for row in changed {
                    if !table_rows.contains_key(&row.row_id) {
                        node(1)?;
                    }
                    table_rows.insert(row.row_id, row);
                }
            }
            RelationalMutation::Delete { table, row_ids } => {
                if let Some(table_rows) = rows.get_mut(table.as_str()) {
                    for id in row_ids {
                        table_rows.remove(id);
                    }
                }
            }
            RelationalMutation::AlterTable { .. } => {}
        }
    }
    let mut references = BTreeSet::new();
    let mut insert = |reference: &crate::RecordRef| -> Result<()> {
        check_sql_cancelled()?;
        if !references.contains(reference) {
            bytes = bytes
                .checked_add(1024)
                .and_then(|n| n.checked_add(reference.namespace.len() as u64))
                .and_then(|n| n.checked_add(reference.id.len() as u64))
                .ok_or_else(sql_overloaded)?;
            memory.prepare(bytes)?;
            references.insert(reference.clone());
        }
        Ok(())
    };
    for reference in additional {
        insert(reference)?;
    }
    for result in &response.results {
        if let SqlResult::Rows { rows, .. } = result {
            for row in rows {
                for value in row {
                    if let RelationalValue::RecordRef(reference) = value {
                        insert(reference)?;
                    }
                }
            }
        }
    }
    for table_rows in rows.values() {
        for row in table_rows.values() {
            for value in &row.values {
                if let RelationalValue::RecordRef(reference) = value {
                    insert(reference)?;
                }
            }
        }
    }
    Ok(wal_decode::Owned::from_parts(
        references,
        memory.into_reservation(),
    ))
}

pub(super) fn changed(
    base: &RelationalState,
    candidate: &RelationalState,
    mutations: &[RelationalMutation],
    sequence: u64,
) -> Result<BTreeSet<crate::RecordRef>> {
    let mut references = BTreeSet::new();
    for mutation in mutations {
        let (name, rows) = match mutation {
            RelationalMutation::Insert { table, rows }
            | RelationalMutation::Update { table, rows } => (table, rows),
            RelationalMutation::RewriteTable { definition, rows } => (&definition.name, rows),
            _ => continue,
        };
        let table = candidate
            .tables
            .get(name)
            .ok_or_else(|| invalid("missing table"))?;
        for row in rows {
            check_sql_cancelled()?;
            // A later statement may have replaced or deleted this row. Only
            // the final candidate can create a live reference.
            let Some(final_row) = table.rows.visible(row.row_id, sequence)? else {
                continue;
            };
            let old = base
                .tables
                .get(name)
                .map(|table| table.rows.visible(row.row_id, base.sequence))
                .transpose()?
                .flatten();
            for (column, value) in final_row.values.iter().enumerate() {
                if let RelationalValue::RecordRef(reference) = value
                    && old.as_ref().and_then(|row| row.values.get(column)) != Some(value)
                {
                    references.insert(reference.clone());
                }
            }
        }
    }
    Ok(references)
}

pub(super) fn ensure_unreferenced(
    state: &RelationalState,
    tenant: &str,
    collection: &str,
    ids: &BTreeSet<String>,
) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let namespace = collection.to_ascii_lowercase();
    for table in state.tables.values() {
        if table.definition.tenant_id.as_deref() != Some(tenant) {
            continue;
        }
        let mut legacy_columns = Vec::new();
        for (position, column) in table.definition.columns.iter().enumerate() {
            if !matches!(&column.data_type, RelationalType::RecordRef { namespace: name } if name == &namespace)
            {
                continue;
            }
            let columns = vec![column.name.clone()];
            if let Some(index) = table.indexes.get(&columns) {
                for id in ids {
                    check_sql_cancelled()?;
                    let value = RelationalValue::RecordRef(crate::RecordRef {
                        namespace: namespace.clone(),
                        id: id.clone(),
                    });
                    let Some(key) = index.key(&[&value])? else {
                        return Err(invalid("non-null reference has no index key"));
                    };
                    if index
                        .entries(&table.index_segments, table.index_snapshot, Some(&key))?
                        .next()
                        .transpose()?
                        .is_some()
                    {
                        return Err(crate::security::SecurityError::Conflict.into());
                    }
                }
            } else {
                // A pre-index catalog remains readable until its offline
                // migration; it must retain the safe streaming scan.
                legacy_columns.push(position);
            }
        }
        if !legacy_columns.is_empty() {
            for row in table.rows.visible_rows(state.sequence) {
                check_sql_cancelled()?;
                let (_, values) = row?;
                if legacy_columns.iter().any(|position| {
                    matches!(&values[*position], RelationalValue::RecordRef(reference)
                        if reference.namespace == namespace && ids.contains(&reference.id))
                }) {
                    return Err(crate::security::SecurityError::Conflict.into());
                }
            }
        }
    }
    Ok(())
}

pub(super) fn validate(
    base: &RelationalState,
    candidate: &RelationalState,
    batch: &RelationalBatch,
    access: &crate::security::DataReferenceAuthorization<'_>,
    reads: &mut BTreeSet<(String, uuid::Uuid)>,
    retired: &BTreeSet<String>,
) -> Result<()> {
    if batch.mutations.iter().any(|mutation| {
        !matches!(
            mutation,
            RelationalMutation::Insert { .. }
                | RelationalMutation::Update { .. }
                | RelationalMutation::Delete { .. }
        )
    }) {
        return Err(invalid("protected atomic data commit requires DML"));
    }
    for reference in changed(base, candidate, &batch.mutations, candidate.sequence)? {
        if retired.contains(&reference.id) && access.matches_collection(&reference) {
            return Err(crate::security::SecurityError::Conflict.into());
        }
        let record = access.authorize(&reference)?;
        reads.insert((record.key.id, record.storage_id));
    }
    if retired.is_empty() {
        return Ok(());
    }
    // The final candidate includes SQL unlink operations in this same atomic
    // commit, so a retiring point is tested against its post-mutation index.
    ensure_unreferenced(candidate, access.tenant(), access.collection(), retired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_reference_union_retains_admitted_final_images_and_releases_on_refusal() {
        let reference = |id: &str| crate::RecordRef {
            namespace: "chunks".into(),
            id: id.into(),
        };
        let mutation = WalEntry::RelationalBatch {
            batch: RelationalBatch {
                sequence: 7,
                mutations: vec![
                    RelationalMutation::Insert {
                        table: "docs".into(),
                        rows: vec![
                            StoredRow {
                                row_id: 1,
                                values: vec![RelationalValue::RecordRef(reference("replaced"))],
                            },
                            StoredRow {
                                row_id: 2,
                                values: vec![RelationalValue::RecordRef(reference("deleted"))],
                            },
                        ],
                    },
                    RelationalMutation::Update {
                        table: "docs".into(),
                        rows: vec![StoredRow {
                            row_id: 1,
                            values: vec![RelationalValue::RecordRef(reference("live"))],
                        }],
                    },
                    RelationalMutation::Delete {
                        table: "docs".into(),
                        row_ids: vec![2],
                    },
                ],
            },
        };
        let response = SqlExecutionResponse {
            transaction_id: None,
            snapshot: 7,
            committed: true,
            outcome: SqlOutcome::Committed,
            commit_sequence: Some(7),
            retryable: false,
            results: vec![SqlResult::Rows {
                columns: vec!["ref".into()],
                column_types: vec![RelationalType::RecordRef {
                    namespace: "chunks".into(),
                }],
                rows: vec![vec![RelationalValue::RecordRef(reference("returned"))]; 512],
            }],
        };
        let saved = BTreeSet::from([reference("saved"), reference("live")]);
        let before = serde_json::to_vec(&mutation).unwrap();
        for capacity in [1, 4096, 8192] {
            wal_decode::with_test_storage_pool(capacity, |used| {
                assert!(matches!(
                    replay_references(Some(&mutation), &response, saved.iter()),
                    Err(GaussError::ResourceExhausted(_))
                ));
                assert_eq!(used(), 0);
            });
        }
        wal_decode::with_test_storage_pool(1024 * 1024, |used| {
            let result = replay_references(Some(&mutation), &response, saved.iter()).unwrap();
            assert_eq!(
                &*result,
                &BTreeSet::from([reference("live"), reference("returned"), reference("saved")])
            );
            assert!(used() > 0);
            result
                .consume(|refs| {
                    assert!(used() > 0);
                    assert_eq!(refs.len(), 3);
                    Ok(())
                })
                .unwrap();
            assert_eq!(used(), 0);
            assert!(
                with_sql_cancellation(Arc::new(AtomicBool::new(true)), || replay_references(
                    Some(&mutation),
                    &response,
                    saved.iter()
                ))
                .is_err()
            );
            assert_eq!(used(), 0);
        });
        assert_eq!(serde_json::to_vec(&mutation).unwrap(), before);
    }

    #[test]
    fn replay_uses_final_journal_row_images_and_returned_values() {
        let reference = |id: &str| crate::RecordRef {
            namespace: "chunks".into(),
            id: id.into(),
        };
        let row = |row_id, id: &str| StoredRow {
            row_id,
            values: vec![RelationalValue::RecordRef(reference(id))],
        };
        let mutation = WalEntry::RelationalBatch {
            batch: RelationalBatch {
                sequence: 7,
                mutations: vec![
                    RelationalMutation::Insert {
                        table: "docs".into(),
                        rows: vec![row(1, "replaced"), row(2, "deleted")],
                    },
                    RelationalMutation::Update {
                        table: "docs".into(),
                        rows: vec![row(1, "live")],
                    },
                    RelationalMutation::Delete {
                        table: "docs".into(),
                        row_ids: vec![2],
                    },
                ],
            },
        };
        let response = SqlExecutionResponse {
            transaction_id: None,
            snapshot: 7,
            committed: true,
            outcome: SqlOutcome::Committed,
            commit_sequence: Some(7),
            retryable: false,
            results: vec![SqlResult::Rows {
                columns: vec!["chunk_ref".into()],
                column_types: vec![RelationalType::RecordRef {
                    namespace: "chunks".into(),
                }],
                rows: vec![vec![RelationalValue::RecordRef(reference("returned"))]],
            }],
        };
        assert_eq!(
            &*replay_references(Some(&mutation), &response, std::iter::empty()).unwrap(),
            &BTreeSet::from([reference("live"), reference("returned")])
        );
        assert!(replay_references(None, &response, std::iter::empty()).is_err());
    }
}
