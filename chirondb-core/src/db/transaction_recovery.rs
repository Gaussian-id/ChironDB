//! Startup repairs only unfinished/missing projections after inspecting compact
//! authoritative routing. Catalog incarnation history spills to accounted
//! encrypted runs instead of retaining every historical collection name.
use super::*;
use crate::relational::{
    disk_map::DiskMap,
    wal_decode::{MetadataCharge, Owned},
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Incarnation {
    sequence: u64,
    created: bool,
}
struct Incarnations {
    disk: DiskMap,
}
impl Incarnations {
    fn new(parent: &Path) -> Result<Self> {
        Ok(Self {
            disk: DiskMap::new(parent)?,
        })
    }
    fn retired(&self, name: &str, sequence: u64) -> Result<bool> {
        let prefix = incarnation_key(name, None)?;
        let mut cursor = self.disk.prefix_cursor(&prefix)?;
        let Some(record) = cursor.next().transpose()? else {
            return Ok(false);
        };
        let incarnation = record.decode::<Incarnation>()?;
        if record.key() != incarnation_key(name, Some(incarnation.sequence))?.as_slice() {
            return Err(GaussError::WalCorruption {
                path: "transactions/journal".into(),
                message: "catalog incarnation binding changed".into(),
            });
        }
        Ok(!incarnation.created || sequence < incarnation.sequence)
    }
}
fn incarnation_key(name: &str, sequence: Option<u64>) -> Result<Owned<Vec<u8>>> {
    let length = 8_usize
        .checked_add(name.len())
        .and_then(|n| n.checked_add(8))
        .ok_or_else(|| GaussError::ResourceExhausted("catalog recovery key is too large".into()))?;
    let mut memory = MetadataCharge::default();
    memory.prepare(length as u64 + 256)?;
    let mut key = Vec::new();
    key.try_reserve_exact(length)
        .map_err(|_| GaussError::ResourceExhausted("catalog recovery key memory is full".into()))?;
    key.extend_from_slice(&(name.len() as u64).to_be_bytes());
    key.extend_from_slice(name.as_bytes());
    if let Some(sequence) = sequence {
        key.extend_from_slice(&(!sequence).to_be_bytes());
    }
    Ok(Owned::from_parts(key, memory.into_reservation()))
}

#[cfg(test)]
pub(super) fn recover_transaction_storage_projections(
    journal: &Arc<TransactionJournal>,
    root: &Path,
) -> Result<()> {
    recover_transaction_storage_projections_after(journal, root, 0)
}

pub(super) fn recover_transaction_storage_projections_after(
    journal: &Arc<TransactionJournal>,
    root: &Path,
    frontier: u64,
) -> Result<()> {
    let mut incarnations = Incarnations::new(journal.dir())?;
    incarnations.disk.insert_batch(|batch| {
        journal.for_each_recovery_after(
            frontier,
            |decision| {
                if let Some(change) = decision.catalog {
                    let key = incarnation_key(change.name(), Some(decision.commit_sequence))?;
                    batch.insert(
                        &key,
                        &Incarnation {
                            sequence: decision.commit_sequence,
                            created: matches!(
                                change,
                                crate::transaction_journal::CatalogChange::Create { .. }
                            ),
                        },
                    )?;
                }
                Ok(false)
            },
            |_| unreachable!("metadata pass never selects a body"),
        )
    })?;

    journal.for_each_recovery_after(
        frontier,
        |decision| {
            if let TransactionTarget::Collection { name } = decision.target
                && incarnations.retired(name, decision.commit_sequence)?
            {
                if !decision.storage_projected {
                    journal.mark_projected(decision.transaction_id, ProjectionKind::Storage)?;
                }
                return Ok(false);
            }
            // Preserve the existing missing-store check, even for a completed
            // decision. Multi-model completed decisions were already skipped.
            let target = match decision.target {
                TransactionTarget::Collection { name } => collection_dir(root, name).join("wal"),
                TransactionTarget::Catalog => root.join(CATALOG_WAL_DIR),
                TransactionTarget::Relational => root.join("relational/wal"),
                TransactionTarget::MultiModel { .. } => return Ok(!decision.storage_projected),
            };
            if !target.exists() {
                return Err(GaussError::WalCorruption {
                    path: target.display().to_string(),
                    message: format!(
                        "committed transaction {} targets missing storage",
                        decision.transaction_id
                    ),
                });
            }
            Ok(!decision.storage_projected)
        },
        |transaction| {
            if let TransactionTarget::MultiModel { .. } = &transaction.prepare.target {
                let WalEntry::MultiModelBatch { batch } = transaction.prepare.mutation.as_ref()
                else {
                    return Err(GaussError::WalCorruption {
                        path: journal.dir().display().to_string(),
                        message: format!(
                            "multi-model transaction {} has a non-multi-model mutation",
                            transaction.prepare.transaction_id
                        ),
                    });
                };
                if !transaction.storage_projected {
                    recover_transaction_entry_projection(
                        journal,
                        crate::transaction_journal::StorageTarget::Relational,
                        &root.join("relational/wal"),
                        transaction.prepare.transaction_id,
                        WalEntry::RelationalBatch {
                            batch: batch.relational.clone(),
                        },
                    )?;
                    for projection in &batch.collections {
                        let entry = projection
                            .security
                            .clone()
                            .map(|security| WalEntry::ProtectedBatch {
                                batch: crate::security::ProtectedBatch {
                                    version: crate::security::SECURITY_VERSION,
                                    security,
                                    content: crate::security::ProtectedContent::Graph {
                                        batch: projection.batch.clone(),
                                    },
                                },
                            })
                            .unwrap_or_else(|| WalEntry::GraphBatch {
                                batch: projection.batch.clone(),
                            });
                        recover_transaction_entry_projection(
                            journal,
                            crate::transaction_journal::StorageTarget::Collection(
                                &projection.collection,
                            ),
                            &collection_dir(root, &projection.collection).join("wal"),
                            transaction.prepare.transaction_id,
                            entry,
                        )?;
                    }
                    journal.mark_projected(
                        transaction.prepare.transaction_id,
                        ProjectionKind::Storage,
                    )?;
                }
                return Ok(());
            }
            let target_dir = match &transaction.prepare.target {
                TransactionTarget::Collection { name } => collection_dir(root, name).join("wal"),
                TransactionTarget::Catalog => root.join(CATALOG_WAL_DIR),
                TransactionTarget::Relational => root.join("relational/wal"),
                TransactionTarget::MultiModel { .. } => unreachable!("handled above"),
            };
            if !target_dir.exists() {
                return Err(GaussError::WalCorruption {
                    path: target_dir.display().to_string(),
                    message: format!(
                        "committed transaction {} targets missing storage",
                        transaction.prepare.transaction_id
                    ),
                });
            }
            let transaction_id = transaction.prepare.transaction_id;
            let mut already_projected = transaction.storage_projected;
            if !already_projected {
                Wal::recover_from(&target_dir, 0, |record| {
                    if let WalEntry::TransactionApply {
                        transaction_id: existing,
                        entry,
                    } = &record.entry
                        && *existing == transaction_id
                    {
                        let target = match &transaction.prepare.target {
                            TransactionTarget::Catalog => {
                                crate::transaction_journal::StorageTarget::Catalog
                            }
                            TransactionTarget::Collection { name } => {
                                crate::transaction_journal::StorageTarget::Collection(name)
                            }
                            TransactionTarget::Relational => {
                                crate::transaction_journal::StorageTarget::Relational
                            }
                            TransactionTarget::MultiModel { .. } => unreachable!("handled above"),
                        };
                        journal.validate_storage_projection(transaction_id, target, entry)?;
                        already_projected = true;
                    }
                    Ok(())
                })?;
            }
            if !already_projected {
                let mut wal = Wal::open(&target_dir)?;
                wal.append(&WalEntry::TransactionApply {
                    transaction_id,
                    entry: transaction.prepare.mutation.clone(),
                })?;
            }
            if !transaction.storage_projected
                && matches!(transaction.prepare.target, TransactionTarget::Catalog)
            {
                match transaction.prepare.mutation.as_ref() {
                    WalEntry::CreateCollection { config }
                    | WalEntry::CreateProtectedCollection { config, .. } => {
                        let staging = collection_create_staging_dir(root, &config.name);
                        let installed = collection_dir(root, &config.name);
                        if !installed.exists() && staging.exists() {
                            durable_rename(&staging, &installed)?;
                        }
                    }
                    WalEntry::DropCollection { name }
                    | WalEntry::DropProtectedCollection { name, .. } => {
                        let installed = collection_dir(root, name);
                        let trash = collection_drop_trash_dir(root, name);
                        if installed.exists() && !trash.exists() {
                            durable_rename(&installed, &trash)?;
                        }
                        if trash.exists() {
                            durable_remove_dir_all(&trash)?;
                        }
                    }
                    _ => {}
                }
            }
            journal.mark_projected(transaction_id, ProjectionKind::Storage)?;
            Ok(())
        },
    )
}

fn recover_transaction_entry_projection(
    journal: &TransactionJournal,
    target: crate::transaction_journal::StorageTarget<'_>,
    target_dir: &Path,
    transaction_id: TransactionId,
    entry: WalEntry,
) -> Result<()> {
    if !target_dir.exists() {
        return Err(GaussError::WalCorruption {
            path: target_dir.display().to_string(),
            message: format!("committed transaction {transaction_id} targets missing storage"),
        });
    }
    let mut already_projected = false;
    Wal::recover_from(target_dir, 0, |record| {
        if let WalEntry::TransactionApply {
            transaction_id: existing,
            entry,
        } = &record.entry
            && *existing == transaction_id
        {
            journal.validate_storage_projection(transaction_id, target, entry)?;
            already_projected = true;
        }
        Ok(())
    })?;
    if !already_projected {
        let mut wal = Wal::open(target_dir)?;
        wal.append(&WalEntry::TransactionApply {
            transaction_id,
            entry: Box::new(entry),
        })?;
    }
    Ok(())
}

pub(super) fn recover_transaction_audit_projections(
    journal: &Arc<TransactionJournal>,
    audit_writer: &Arc<audit::AuditWriter>,
) -> Result<()> {
    recover_transaction_audit_projections_after(journal, audit_writer, 0)
}

pub(super) fn recover_transaction_audit_projections_after(
    journal: &Arc<TransactionJournal>,
    audit_writer: &Arc<audit::AuditWriter>,
    frontier: u64,
) -> Result<()> {
    journal.for_each_recovery_after(
        frontier,
        |decision| {
            Ok(!decision.audit_projected
                || !audit_writer.has_durable_transaction_projection(decision.transaction_id)?)
        },
        |transaction| {
            audit_writer.project_committed_transaction(
                transaction.prepare.transaction_id,
                &transaction.prepare.audit,
            )?;
            if !transaction.audit_projected {
                journal
                    .mark_projected(transaction.prepare.transaction_id, ProjectionKind::Audit)?;
            }
            Ok(())
        },
    )
}

/// Reconstruct only the suffix in private content staging. Installation
/// authority and consumed keys never move backward with a content root.
pub(super) fn materialize_suffix(
    journal: &Arc<TransactionJournal>,
    root: &Path,
    frontier: u64,
) -> Result<()> {
    let mut incarnations = Incarnations::new(journal.dir())?;
    incarnations.disk.insert_batch(|batch| {
        journal.for_each_recovery_after(
            frontier,
            |decision| {
                if let Some(change) = decision.catalog {
                    batch.insert(
                        &incarnation_key(change.name(), Some(decision.commit_sequence))?,
                        &Incarnation {
                            sequence: decision.commit_sequence,
                            created: matches!(
                                change,
                                crate::transaction_journal::CatalogChange::Create { .. }
                            ),
                        },
                    )?;
                }
                Ok(matches!(decision.target, TransactionTarget::Catalog))
            },
            |transaction| {
                let prepare = &transaction.prepare;
                crate::relational::wal_decode::copy(prepare.mutation.as_ref())?.consume(
                    |entry| {
                        let mut wal = Wal::open(&root.join(CATALOG_WAL_DIR))?;
                        wal.append_no_sync(&WalEntry::TransactionApply {
                            transaction_id: prepare.transaction_id,
                            entry: Box::new(entry),
                        })?;
                        Ok(())
                    },
                )?;
                // Only the last incarnation is installed in the second pass.
                Ok(())
            },
        )
    })?;
    journal.for_each_recovery_after(
        frontier,
        |decision| Ok(matches!(decision.target, TransactionTarget::Catalog)),
        |transaction| {
            let prepare = &transaction.prepare;
            let name = match prepare.mutation.as_ref() {
                WalEntry::CreateCollection { config }
                | WalEntry::CreateProtectedCollection { config, .. } => &config.name,
                WalEntry::DropCollection { name }
                | WalEntry::DropProtectedCollection { name, .. } => name,
                _ => {
                    return Err(GaussError::InvalidRequest(
                        "invalid common frontier catalog suffix".into(),
                    ));
                }
            };
            // Drops can always remove the old base. A later create installs
            // its own checkpoint, and older creates must not overwrite it.
            if matches!(
                prepare.mutation.as_ref(),
                WalEntry::DropCollection { .. } | WalEntry::DropProtectedCollection { .. }
            ) || !incarnations.retired(name, prepare.commit_sequence)?
            {
                super::protected_backup::replay::install_collection(root, prepare)?;
            }
            Ok(())
        },
    )?;
    journal.for_each_recovery_after(
        frontier,
        |decision| Ok(!matches!(decision.target, TransactionTarget::Catalog)),
        |transaction| {
            let prepare = &transaction.prepare;
            let project = |target, path: PathBuf, entry: &WalEntry| {
                crate::relational::wal_decode::copy(entry)?.consume(|entry| {
                    // A freshly copied base ends at F and every selected
                    // decision is > F. There is no live projection to deduplicate.
                    // Validate its authority proof, append once, and synchronize
                    // the whole private root before publication.
                    journal.validate_storage_projection(prepare.transaction_id, target, &entry)?;
                    let mut wal = Wal::open(&path)?;
                    wal.append_no_sync(&WalEntry::TransactionApply {
                        transaction_id: prepare.transaction_id,
                        entry: Box::new(entry),
                    })?;
                    Ok(())
                })
            };
            match &prepare.target {
                TransactionTarget::Collection { name } => {
                    if !incarnations.retired(name, prepare.commit_sequence)? {
                        project(
                            crate::transaction_journal::StorageTarget::Collection(name),
                            collection_dir(root, name).join("wal"),
                            prepare.mutation.as_ref(),
                        )?;
                    }
                }
                TransactionTarget::Relational => project(
                    crate::transaction_journal::StorageTarget::Relational,
                    root.join("relational/wal"),
                    prepare.mutation.as_ref(),
                )?,
                TransactionTarget::MultiModel { .. } => {
                    let WalEntry::MultiModelBatch { batch } = prepare.mutation.as_ref() else {
                        return Err(GaussError::InvalidRequest(
                            "invalid common frontier multi-model suffix".into(),
                        ));
                    };
                    crate::relational::wal_decode::copy(&batch.relational)?.consume(
                        |relational| {
                            project(
                                crate::transaction_journal::StorageTarget::Relational,
                                root.join("relational/wal"),
                                &WalEntry::RelationalBatch { batch: relational },
                            )
                        },
                    )?;
                    for projection in &batch.collections {
                        if incarnations.retired(&projection.collection, prepare.commit_sequence)? {
                            continue;
                        }
                        let target = crate::transaction_journal::StorageTarget::Collection(
                            &projection.collection,
                        );
                        crate::relational::wal_decode::copy(projection)?.consume(|projection| {
                            let entry = if let Some(security) = projection.security {
                                WalEntry::ProtectedBatch {
                                    batch: crate::security::ProtectedBatch {
                                        version: crate::security::SECURITY_VERSION,
                                        security,
                                        content: crate::security::ProtectedContent::Graph {
                                            batch: projection.batch,
                                        },
                                    },
                                }
                            } else {
                                WalEntry::GraphBatch {
                                    batch: projection.batch,
                                }
                            };
                            project(
                                target,
                                collection_dir(root, &projection.collection).join("wal"),
                                &entry,
                            )
                        })?;
                    }
                }
                TransactionTarget::Catalog => unreachable!("catalog pass above"),
            }
            Ok(())
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relational::wal_decode::with_test_storage_pool;

    #[test]
    fn incarnation_history_spills_and_keeps_latest_drop_create_with_prefix_neighbors() {
        let directory = tempfile::tempdir().unwrap();
        with_test_storage_pool(2 * 1024 * 1024, |used| {
            let mut incarnations = Incarnations::new(directory.path()).unwrap();
            incarnations
                .disk
                .insert_batch(|batch| {
                    for n in 0..2050 {
                        let name = format!("retired-{n}");
                        batch.insert(
                            &incarnation_key(&name, Some(n + 10))?,
                            &Incarnation {
                                sequence: n + 10,
                                created: false,
                            },
                        )?;
                    }
                    for (name, sequence, created) in [
                        ("doc", 1, false),
                        ("docs", 2, true),
                        ("docs", 3, false),
                        ("docs", 4, true),
                        ("docs-long", 5, false),
                    ] {
                        batch.insert(
                            &incarnation_key(name, Some(sequence))?,
                            &Incarnation { sequence, created },
                        )?;
                    }
                    Ok(())
                })
                .unwrap();
            assert!(used() > 0 && used() < 2 * 1024 * 1024);
            assert!(incarnations.retired("docs", 2).unwrap());
            assert!(!incarnations.retired("docs", 4).unwrap());
            assert!(!incarnations.retired("docs", 6).unwrap());
            assert!(incarnations.retired("doc", 6).unwrap());
            assert!(incarnations.retired("docs-long", 6).unwrap());
            assert!(incarnations.retired("retired-2049", 9000).unwrap());
            assert!(!incarnations.retired("missing", 1).unwrap());
            drop(incarnations);
            assert_eq!(used(), 0);
        });
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn incarnation_admission_and_cancelled_fill_leave_no_installed_state_or_owner_leak() {
        let directory = tempfile::tempdir().unwrap();
        with_test_storage_pool(1, |used| {
            assert!(matches!(
                Incarnations::new(directory.path()),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
        });
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
        with_test_storage_pool(2 * 1024 * 1024, |used| {
            let mut incarnations = Incarnations::new(directory.path()).unwrap();
            let cancellation = Arc::new(AtomicBool::new(false));
            let result =
                crate::relational::with_sql_cancellation(Arc::clone(&cancellation), || {
                    incarnations.disk.insert_batch(|batch| {
                        batch.insert(
                            &incarnation_key("docs", Some(1))?,
                            &Incarnation {
                                sequence: 1,
                                created: true,
                            },
                        )?;
                        cancellation.store(true, Ordering::Release);
                        batch.insert(
                            &incarnation_key("docs", Some(2))?,
                            &Incarnation {
                                sequence: 2,
                                created: false,
                            },
                        )
                    })
                });
            assert!(result.is_err());
            assert!(!incarnations.retired("docs", 0).unwrap());
            drop(incarnations);
            assert_eq!(used(), 0);
        });
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }
}
