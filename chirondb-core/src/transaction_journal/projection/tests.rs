use super::*;

fn audit() -> TransactionAudit {
    TransactionAudit::mutation("projection", None, &AuditContext::embedded(), Value::Null)
}
fn commit(
    journal: &TransactionJournal,
    target: TransactionTarget,
    entry: WalEntry,
) -> TransactionId {
    let transaction = journal.commit(target, entry, audit()).unwrap();
    let id = transaction.prepare.transaction_id;
    for kind in [ProjectionKind::Storage, ProjectionKind::Audit] {
        journal.mark_projected(id, kind).unwrap();
    }
    id
}
fn delete() -> WalEntry {
    WalEntry::DeleteBatch {
        ids: vec!["ack".into()],
    }
}

fn graph_projection(protected: bool) -> crate::wal::MultiModelCollectionBatch {
    crate::wal::MultiModelCollectionBatch {
        collection: if protected { "restricted" } else { "docs" }.into(),
        batch: crate::wal::GraphBatch {
            type_configurations: vec![crate::wal::GraphTypeConfiguration {
                type_id: crate::graph::TypeId::from_raw(1),
                name: "cites".into(),
                weight_property: Some("confidence\"λ".into()),
            }],
            ..Default::default()
        },
        security: protected.then(|| crate::security::SecurityDelta {
            incarnation: uuid::Uuid::new_v4(),
            expected_revision: 1,
            revision: 1,
            expected_generation: 1,
            generation: 2,
            policy: None,
            bindings: vec![],
        }),
    }
}
fn storage_entry(projection: &crate::wal::MultiModelCollectionBatch) -> WalEntry {
    match &projection.security {
        Some(security) => WalEntry::ProtectedBatch {
            batch: crate::security::ProtectedBatch {
                version: crate::security::SECURITY_VERSION,
                security: security.clone(),
                content: crate::security::ProtectedContent::Graph {
                    batch: projection.batch.clone(),
                },
            },
        },
        None => WalEntry::GraphBatch {
            batch: projection.batch.clone(),
        },
    }
}

#[test]
fn legacy_hot_and_reopened_projections_require_exact_commit_target_and_body() {
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    assert!(journal.storage_projection_authority().unwrap().is_none());
    let id = commit(
        &journal,
        TransactionTarget::Collection {
            name: "docs".into(),
        },
        delete(),
    );
    for journal in [journal, TransactionJournal::open(directory.path()).unwrap()] {
        journal
            .validate_storage_projection(id, StorageTarget::Collection("docs"), &delete())
            .unwrap();
        for (target, entry) in [
            (StorageTarget::Collection("other"), delete()),
            (StorageTarget::Catalog, delete()),
            (
                StorageTarget::Collection("docs"),
                WalEntry::DeleteBatch {
                    ids: vec!["changed".into()],
                },
            ),
        ] {
            assert!(
                journal
                    .validate_storage_projection(id, target, &entry)
                    .is_err()
            );
        }
        assert!(
            journal
                .validate_storage_projection(
                    TransactionId::default(),
                    StorageTarget::Collection("docs"),
                    &delete()
                )
                .is_err()
        );
    }
}

#[test]
fn rejected_prepare_cannot_authorize_storage_with_the_same_identity_and_body() {
    let directory = tempfile::tempdir().unwrap();
    drop(TransactionJournal::open(directory.path()).unwrap());
    let id = TransactionId::default();
    let mut wal = Wal::open(&directory.path().join(TRANSACTION_JOURNAL_DIR)).unwrap();
    wal.append(&WalEntry::TransactionPrepare {
        prepare: TransactionPrepare {
            version: TRANSACTION_JOURNAL_VERSION,
            transaction_id: id,
            commit_sequence: 1,
            target: TransactionTarget::Collection {
                name: "docs".into(),
            },
            mutation: Box::new(delete()),
            audit: audit(),
            idempotency: None,
        },
    })
    .unwrap();
    drop(wal);
    let journal = TransactionJournal::open(directory.path()).unwrap();
    assert_eq!(journal.status(id).state, TransactionState::Rejected);
    assert!(matches!(
        journal.validate_storage_projection(id, StorageTarget::Collection("docs"), &delete()),
        Err(GaussError::WalCorruption { .. })
    ));
}

#[test]
fn cold_catalog_and_collection_proofs_survive_real_journal_prefix_retirement() {
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let catalog = WalEntry::DropCollection {
        name: "retired".into(),
    };
    let catalog_id = commit(&journal, TransactionTarget::Catalog, catalog.clone());
    let collection_id = commit(
        &journal,
        TransactionTarget::Collection {
            name: "docs".into(),
        },
        delete(),
    );
    authority::tests::activate(&journal);
    assert!(journal.storage_projection_authority().unwrap().is_some());
    {
        let mut inner = journal.inner.lock().unwrap();
        let end = inner.wal.len().unwrap();
        inner.wal.drop_prefix(end).unwrap();
    }
    drop(journal);
    let journal = TransactionJournal::open(directory.path()).unwrap();
    journal
        .validate_storage_projection(catalog_id, StorageTarget::Catalog, &catalog)
        .unwrap();
    journal
        .validate_storage_projection(collection_id, StorageTarget::Collection("docs"), &delete())
        .unwrap();
    assert!(
        journal
            .validate_storage_projection(catalog_id, StorageTarget::Collection("docs"), &catalog)
            .is_err()
    );
    assert!(
        journal
            .validate_storage_projection(
                collection_id,
                StorageTarget::Collection("docs"),
                &WalEntry::Delete { id: "ack".into() }
            )
            .is_err()
    );
    assert_eq!(
        journal.inner.lock().unwrap().state.recovery_decoded_records,
        0
    );
}

#[test]
fn borrowed_multi_model_graph_encoding_matches_plain_and_protected_storage() {
    for protected in [false, true] {
        let projection = graph_projection(protected);
        let owned = storage_entry(&projection);
        assert_eq!(
            serde_json::to_vec(&graph_entry(&projection)).unwrap(),
            serde_json::to_vec(&owned).unwrap()
        );
        assert_eq!(
            fingerprint(&graph_entry(&projection)).unwrap(),
            fingerprint(&owned).unwrap()
        );
    }
}

#[test]
fn multi_model_proofs_bind_each_plain_and_protected_projection_after_prefix_retirement() {
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let batch = crate::wal::MultiModelBatch {
        version: crate::wal::MULTI_MODEL_BATCH_VERSION,
        relational: crate::relational::RelationalBatch {
            sequence: 1,
            mutations: vec![crate::relational::RelationalMutation::DropTable {
                name: "documents".into(),
            }],
        },
        collections: vec![graph_projection(false), graph_projection(true)],
    };
    let id = commit(
        &journal,
        TransactionTarget::MultiModel {
            collections: vec!["docs".into(), "restricted".into()],
        },
        WalEntry::MultiModelBatch {
            batch: batch.clone(),
        },
    );
    for projection in &batch.collections {
        journal
            .validate_storage_projection(
                id,
                StorageTarget::Collection(&projection.collection),
                &storage_entry(projection),
            )
            .unwrap();
    }
    authority::tests::activate(&journal);
    {
        let mut inner = journal.inner.lock().unwrap();
        let end = inner.wal.len().unwrap();
        inner.wal.drop_prefix(end).unwrap();
    }
    drop(journal);
    let journal = TransactionJournal::open(directory.path()).unwrap();
    journal
        .validate_storage_projection(
            id,
            StorageTarget::Relational,
            &WalEntry::RelationalBatch {
                batch: batch.relational,
            },
        )
        .unwrap();
    for projection in &batch.collections {
        let entry = storage_entry(projection);
        journal
            .validate_storage_projection(
                id,
                StorageTarget::Collection(&projection.collection),
                &entry,
            )
            .unwrap();
        let mut changed = projection.clone();
        changed.batch.type_configurations[0].name = "different".into();
        assert!(
            journal
                .validate_storage_projection(
                    id,
                    StorageTarget::Collection(&projection.collection),
                    &storage_entry(&changed)
                )
                .is_err()
        );
        if let Some(security) = &mut changed.security {
            security.incarnation = uuid::Uuid::new_v4();
            changed.batch = projection.batch.clone();
            assert!(
                journal
                    .validate_storage_projection(
                        id,
                        StorageTarget::Collection(&projection.collection),
                        &storage_entry(&changed)
                    )
                    .is_err()
            );
        }
        assert!(
            journal
                .validate_storage_projection(id, StorageTarget::Collection("foreign"), &entry)
                .is_err()
        );
        assert!(
            journal
                .validate_storage_projection(id, StorageTarget::Catalog, &entry)
                .is_err()
        );
    }
    assert_eq!(
        journal.inner.lock().unwrap().state.recovery_decoded_records,
        0
    );
}

#[test]
fn authority_without_additive_proofs_keeps_legacy_wal_validation() {
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let id = commit(
        &journal,
        TransactionTarget::Collection {
            name: "docs".into(),
        },
        delete(),
    );
    authority::tests::activate(&journal);
    // Simulate the supported prior authority record shape. Its optional marker
    // is absent; the complete original WAL must still bind the projection.
    {
        let mut inner = journal.inner.lock().unwrap();
        let mut reference: PreparedRef = {
            let reference = inner.state.prepare(id).unwrap().unwrap();
            serde_json::from_value(serde_json::to_value(&*reference).unwrap()).unwrap()
        };
        reference.storage_proof_version = None;
        let disk = inner.state.decisions.as_mut().unwrap();
        disk.retain(|record| Ok(record.key().first() != Some(&1)))
            .unwrap();
        let mut decision_key = [1; 17];
        decision_key[1..].copy_from_slice(id.0.as_bytes());
        #[derive(Serialize)]
        struct Decision<'a> {
            prepare: &'a PreparedRef,
            committed: bool,
        }
        disk.insert_batch(|batch| {
            batch.insert(
                &decision_key,
                &Decision {
                    prepare: &reference,
                    committed: true,
                },
            )
        })
        .unwrap();
        inner.state.authority_checkpointed = false;
        let end = inner.wal.len().unwrap();
        authority::publish(journal.dir(), &mut inner.state, end).unwrap();
    }
    drop(journal);
    let journal = TransactionJournal::open(directory.path()).unwrap();
    journal
        .validate_storage_projection(id, StorageTarget::Collection("docs"), &delete())
        .unwrap();
    assert!(
        journal
            .validate_storage_projection(id, StorageTarget::Collection("other"), &delete())
            .is_err()
    );
}

#[test]
fn missing_or_future_proof_never_falls_back_to_retained_original_wal() {
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let id = commit(
        &journal,
        TransactionTarget::Collection {
            name: "docs".into(),
        },
        delete(),
    );
    authority::tests::activate(&journal);
    {
        let mut inner = journal.inner.lock().unwrap();
        inner
            .state
            .decisions
            .as_mut()
            .unwrap()
            .retain(|record| Ok(record.key().first() != Some(&PREFIX)))
            .unwrap();
    }
    assert!(
        journal
            .validate_storage_projection(id, StorageTarget::Collection("docs"), &delete())
            .is_err()
    );
    {
        let mut inner = journal.inner.lock().unwrap();
        inner
            .state
            .decisions
            .as_mut()
            .unwrap()
            .insert_batch(|batch| {
                batch.insert(
                    &key(id, StorageTarget::Collection("docs"))?,
                    &ProofView {
                        version: VERSION + 1,
                        transaction_id: id,
                        collection: Some("docs"),
                        digest: fingerprint(&delete())?,
                    },
                )
            })
            .unwrap();
    }
    assert!(
        journal
            .validate_storage_projection(id, StorageTarget::Collection("docs"), &delete())
            .is_err()
    );
}

#[test]
fn corrupt_proof_identity_scope_or_digest_is_rejected() {
    for field in ["transaction_id", "collection", "digest"] {
        let directory = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let id = commit(
            &journal,
            TransactionTarget::Collection {
                name: "docs".into(),
            },
            delete(),
        );
        authority::tests::activate(&journal);
        {
            let mut inner = journal.inner.lock().unwrap();
            inner
                .state
                .decisions
                .as_mut()
                .unwrap()
                .retain(|record| Ok(record.key().first() != Some(&PREFIX)))
                .unwrap();
            let proof = ProofView {
                version: VERSION,
                transaction_id: if field == "transaction_id" {
                    TransactionId::default()
                } else {
                    id
                },
                collection: Some(if field == "collection" {
                    "foreign"
                } else {
                    "docs"
                }),
                digest: if field == "digest" {
                    [0; 32]
                } else {
                    fingerprint(&delete()).unwrap()
                },
            };
            inner
                .state
                .decisions
                .as_mut()
                .unwrap()
                .insert_batch(|batch| {
                    batch.insert(&key(id, StorageTarget::Collection("docs"))?, &proof)
                })
                .unwrap();
        }
        assert!(
            matches!(
                journal.validate_storage_projection(
                    id,
                    StorageTarget::Collection("docs"),
                    &delete()
                ),
                Err(GaussError::WalCorruption { .. })
            ),
            "accepted changed {field}"
        );
    }
}

#[test]
fn pending_live_validation_borrows_prepare_with_only_hash_scratch_capacity() {
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let entry = WalEntry::UpsertBatch {
        points: vec![crate::model::Point {
            id: "ack".into(),
            vector: vec![0.1, -0.0, 1.0e-8],
            vectors: Default::default(),
            sparse_vector: None,
            payload: serde_json::json!({"escaped\"λ": "x".repeat(32768), "number": 0.123456789}),
        }],
    };
    let committed = journal
        .commit(
            TransactionTarget::Collection {
                name: "docs".into(),
            },
            entry.clone(),
            audit(),
        )
        .unwrap();
    crate::relational::wal_decode::with_test_storage_pool(
        512 + crate::relational::wal_decode::lease_root_bytes(),
        |used| {
            journal
                .validate_storage_projection(
                    committed.prepare.transaction_id,
                    StorageTarget::Collection("docs"),
                    &entry,
                )
                .unwrap();
            assert_eq!(used(), 0);
        },
    );
    assert!(
        !journal
            .status(committed.prepare.transaction_id)
            .storage_projected
    );
}

#[test]
fn streaming_fingerprint_respects_pressure_and_midstream_cancellation_without_leaks() {
    crate::relational::wal_decode::with_test_storage_pool(511, |used| {
        assert!(matches!(
            fingerprint(&delete()),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(used(), 0);
    });
    crate::relational::wal_decode::with_test_storage_pool(
        512 + crate::relational::wal_decode::lease_root_bytes(),
        |used| {
            let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
            struct CancelDuringSerialization(Arc<std::sync::atomic::AtomicBool>);
            impl Serialize for CancelDuringSerialization {
                fn serialize<S: serde::Serializer>(
                    &self,
                    serializer: S,
                ) -> std::result::Result<S::Ok, S::Error> {
                    self.0.store(true, std::sync::atomic::Ordering::Release);
                    serializer.serialize_str("cancelled before hashing bytes")
                }
            }
            assert!(
                crate::relational::with_sql_cancellation(flag.clone(), || fingerprint(
                    &CancelDuringSerialization(flag.clone())
                ))
                .is_err()
            );
            assert_eq!(used(), 0);
            fingerprint(&delete()).unwrap();
            assert_eq!(used(), 0);
        },
    );
}
