use super::*;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Proof {
    version: u16,
    digest: [u8; 32],
}
impl Proof {
    pub(super) fn new(prepare: &TransactionPrepare) -> Result<Self> {
        Ok(Self {
            version: 1,
            digest: crate::audit::binding::expected(&prepare.audit)?,
        })
    }
}
impl TransactionJournal {
    /// Generic audit operations have their own UUIDs. Recognized canonical IDs
    /// must bind to a durable COMMIT and its success semantics. A marked future
    /// proof never falls back to an older retained PREPARE.
    pub(crate) fn validate_audit_projection(
        &self,
        id: TransactionId,
        digest: [u8; 32],
    ) -> Result<()> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| GaussError::WalUnavailable("transaction journal lock poisoned".into()))?;
        let Some(reference) = inner.state.prepare(id)? else {
            return Ok(());
        };
        let corrupt = |message: &str| GaussError::WalCorruption {
            path: TRANSACTION_JOURNAL_DIR.into(),
            message: message.into(),
        };
        if inner.state.checked_status(id)?.state != TransactionState::Committed {
            return Err(corrupt("audit projection has no committed decision"));
        }
        let expected = if let Some(proof) = &reference.audit_proof {
            if proof.version != 1 {
                return Err(corrupt("unsupported audit projection proof version"));
            }
            proof.digest
        } else if let Some(prepare) = reference.hot.as_deref() {
            crate::audit::binding::expected(&prepare.audit)?
        } else {
            let prepare = reference.load(&self.dir, id)?;
            crate::audit::binding::expected(&prepare.audit)?
        };
        if digest != expected {
            return Err(corrupt(
                "audit projection differs from its committed semantics",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn committed(journal: &TransactionJournal) -> CommittedTransaction {
        journal
            .commit(
                TransactionTarget::Collection {
                    name: "docs".into(),
                },
                WalEntry::Delete { id: "one".into() },
                TransactionAudit::mutation(
                    "delete",
                    Some("docs"),
                    &AuditContext::embedded(),
                    serde_json::json!({"rows": 1}),
                ),
            )
            .unwrap()
    }
    #[test]
    fn compact_audit_proof_validates_after_original_prepare_prefix_is_physically_retired() {
        let root = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(root.path()).unwrap();
        let transaction = committed(&journal);
        let id = transaction.prepare.transaction_id;
        let expected = crate::audit::binding::expected(&transaction.prepare.audit).unwrap();
        for kind in [ProjectionKind::Storage, ProjectionKind::Audit] {
            journal.mark_projected(id, kind).unwrap();
        }
        authority::tests::activate(&journal);
        {
            let mut inner = journal.inner.lock().unwrap();
            let end = inner.wal.len().unwrap();
            inner.wal.drop_prefix(end).unwrap();
        }
        drop(transaction);
        drop(journal);
        let journal = TransactionJournal::open(root.path()).unwrap();
        journal.validate_audit_projection(id, expected).unwrap();
        let mut altered = expected;
        altered[0] ^= 1;
        assert!(journal.validate_audit_projection(id, altered).is_err());
    }
    #[test]
    fn marked_future_audit_proof_refuses_even_when_original_prepare_is_retained() {
        let root = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(root.path()).unwrap();
        authority::tests::activate(&journal);
        let transaction = committed(&journal);
        let id = transaction.prepare.transaction_id;
        let expected = crate::audit::binding::expected(&transaction.prepare.audit).unwrap();
        journal
            .inner
            .lock()
            .unwrap()
            .state
            .prepares
            .get_mut(&id)
            .unwrap()
            .audit_proof
            .as_mut()
            .unwrap()
            .version = 2;
        assert!(matches!(
            journal.validate_audit_projection(id, expected),
            Err(GaussError::WalCorruption { .. })
        ));
    }
    #[test]
    fn retained_legacy_prepare_binds_audit_and_rejected_prepare_cannot_authorize_success() {
        let root = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(root.path()).unwrap();
        let transaction = committed(&journal);
        let id = transaction.prepare.transaction_id;
        let expected = crate::audit::binding::expected(&transaction.prepare.audit).unwrap();
        journal.validate_audit_projection(id, expected).unwrap();
        drop(transaction);
        drop(journal);
        let rejected = TransactionId::new();
        let mut wal = Wal::open(&root.path().join(TRANSACTION_JOURNAL_DIR)).unwrap();
        let audit =
            TransactionAudit::mutation("delete", None, &AuditContext::embedded(), Value::Null);
        wal.append(&WalEntry::TransactionPrepare {
            prepare: TransactionPrepare {
                version: TRANSACTION_JOURNAL_VERSION,
                transaction_id: rejected,
                commit_sequence: 2,
                target: TransactionTarget::Collection {
                    name: "docs".into(),
                },
                mutation: Box::new(WalEntry::Delete { id: "none".into() }),
                audit: audit.clone(),
                idempotency: None,
            },
        })
        .unwrap();
        drop(wal);
        let journal = TransactionJournal::open(root.path()).unwrap();
        journal.validate_audit_projection(id, expected).unwrap();
        let mut changed = expected;
        changed[0] ^= 1;
        assert!(journal.validate_audit_projection(id, changed).is_err());
        assert!(
            journal
                .validate_audit_projection(
                    rejected,
                    crate::audit::binding::expected(&audit).unwrap()
                )
                .is_err()
        );
        journal
            .validate_audit_projection(TransactionId::new(), changed)
            .unwrap(); // Generic audit operation.
    }
}
