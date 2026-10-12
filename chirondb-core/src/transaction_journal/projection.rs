//! Versioned catalog/collection bindings. Legacy references without these
//! additive proofs validate against retained PREPAREs; they cannot authorize
//! a future history cut without a fenced common materialized frontier.
use super::*;
use crate::relational::{disk_map::Batch, wal_decode::MetadataCharge};
use sha2::{Digest, Sha256};

pub(super) const VERSION: u16 = 1;
const PREFIX: u8 = 5;

#[derive(Clone, Copy)]
pub(crate) enum StorageTarget<'a> {
    Catalog,
    Collection(&'a str),
    Relational,
}
impl<'a> StorageTarget<'a> {
    fn collection(self) -> Option<&'a str> {
        match self {
            Self::Catalog | Self::Relational => None,
            Self::Collection(name) => Some(name),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    version: u16,
    transaction_id: TransactionId,
    collection: Option<String>,
    digest: [u8; 32],
}
#[derive(Serialize)]
struct ProofView<'a> {
    version: u16,
    transaction_id: TransactionId,
    collection: Option<&'a str>,
    digest: [u8; 32],
}

fn fingerprint(value: &impl Serialize) -> Result<[u8; 32]> {
    struct Output(Sha256);
    impl std::io::Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            crate::relational::check_sql_cancelled().map_err(std::io::Error::other)?;
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut memory = MetadataCharge::default();
    memory.prepare(512)?;
    let mut out = Output(Sha256::new());
    serde_json::to_writer(&mut out, value)?;
    Ok(out.0.finalize().into())
}
fn key(id: TransactionId, target: StorageTarget<'_>) -> Result<[u8; 33]> {
    let mut key = [PREFIX; 33];
    key[1..].copy_from_slice(&fingerprint(&(id, target.collection()))?);
    Ok(key)
}

// Preserve the existing externally tagged WalEntry and protected graph JSON
// shapes without cloning a batch, its points, or its security bindings.
#[derive(Serialize)]
enum GraphEntry<'a> {
    GraphBatch { batch: &'a crate::wal::GraphBatch },
    ProtectedBatch { batch: ProtectedGraph<'a> },
}
#[derive(Serialize)]
struct ProtectedGraph<'a> {
    version: u32,
    security: &'a crate::security::SecurityDelta,
    content: GraphContent<'a>,
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum GraphContent<'a> {
    Graph { batch: &'a crate::wal::GraphBatch },
}
fn graph_entry(batch: &crate::wal::MultiModelCollectionBatch) -> GraphEntry<'_> {
    match &batch.security {
        Some(security) => GraphEntry::ProtectedBatch {
            batch: ProtectedGraph {
                version: crate::security::SECURITY_VERSION,
                security,
                content: GraphContent::Graph {
                    batch: &batch.batch,
                },
            },
        },
        None => GraphEntry::GraphBatch {
            batch: &batch.batch,
        },
    }
}

fn expected(prepare: &TransactionPrepare, target: StorageTarget<'_>) -> Result<[u8; 32]> {
    match (&prepare.target, target, prepare.mutation.as_ref()) {
        (TransactionTarget::Catalog, StorageTarget::Catalog, entry) => fingerprint(entry),
        (TransactionTarget::Collection { name }, StorageTarget::Collection(found), entry)
            if name == found =>
        {
            fingerprint(entry)
        }
        (
            TransactionTarget::MultiModel { .. },
            StorageTarget::Collection(name),
            WalEntry::MultiModelBatch { batch },
        ) => {
            let projected = batch
                .collections
                .iter()
                .find(|batch| batch.collection == name)
                .ok_or_else(|| corrupt("transaction has no projection for this collection"))?;
            fingerprint(&graph_entry(projected))
        }
        _ => Err(corrupt(
            "storage projection targets another transaction domain",
        )),
    }
}
pub(super) fn insert(batch: &mut Batch, prepare: &TransactionPrepare) -> Result<()> {
    let mut add = |target| {
        batch.insert(
            &key(prepare.transaction_id, target)?,
            &ProofView {
                version: VERSION,
                transaction_id: prepare.transaction_id,
                collection: target.collection(),
                digest: expected(prepare, target)?,
            },
        )
    };
    match &prepare.target {
        TransactionTarget::Catalog => add(StorageTarget::Catalog),
        TransactionTarget::Collection { name } => add(StorageTarget::Collection(name)),
        TransactionTarget::MultiModel { collections } => {
            for name in collections {
                add(StorageTarget::Collection(name))?;
            }
            Ok(())
        }
        TransactionTarget::Relational => Ok(()),
    }
}

impl TransactionJournal {
    /// Legacy unprotected collection archives may import projections without
    /// an installation journal. Preserve that import contract; protected roots
    /// and explicitly activated authority require the original COMMIT binding.
    pub(crate) fn storage_projection_authority(&self) -> Result<Option<&Self>> {
        if crate::security::onboarding::requires_protected_startup(&self.data_dir) {
            return Ok(Some(self));
        }
        let inner = self
            .inner
            .lock()
            .map_err(|_| GaussError::WalUnavailable("transaction journal lock poisoned".into()))?;
        Ok(inner.state.authoritative.then_some(self))
    }

    pub(crate) fn validate_storage_projection(
        &self,
        id: TransactionId,
        target: StorageTarget<'_>,
        entry: &WalEntry,
    ) -> Result<()> {
        if matches!(target, StorageTarget::Relational) {
            return match entry {
                WalEntry::RelationalBatch { batch } => {
                    self.validate_relational_projection(id, batch)
                }
                _ => Err(corrupt("non-relational projection in relational storage")),
            };
        }
        let inner = self
            .inner
            .lock()
            .map_err(|_| GaussError::WalUnavailable("transaction journal lock poisoned".into()))?;
        if inner.state.checked_status(id)?.state != TransactionState::Committed {
            return Err(corrupt("storage projection has no committed decision"));
        }
        let reference = inner
            .state
            .prepare(id)?
            .ok_or_else(|| corrupt("storage projection lost its PREPARE"))?;
        let digest = if inner.state.authoritative
            && reference.hot.is_none()
            && !inner.state.prepares.contains_key(&id)
            && reference.storage_proof_version.is_some()
        {
            if reference.storage_proof_version != Some(VERSION) {
                return Err(corrupt("unsupported storage projection proof version"));
            }
            let proof = inner
                .state
                .decisions
                .as_ref()
                .expect("decision map")
                .get_owned::<Proof>(&key(id, target)?)?
                .ok_or_else(|| corrupt("storage projection proof is missing"))?;
            if proof.version != VERSION
                || proof.transaction_id != id
                || proof.collection.as_deref() != target.collection()
            {
                return Err(corrupt("storage projection proof binding changed"));
            }
            proof.digest
        } else if let Some(prepare) = reference.hot.as_deref() {
            expected(prepare, target)?
        } else {
            let prepare = reference.load(&self.dir, id)?;
            expected(&prepare, target)?
        };
        if digest != fingerprint(entry)? {
            return Err(corrupt(
                "storage projection differs from its committed mutation",
            ));
        }
        Ok(())
    }
}
fn corrupt(message: &str) -> GaussError {
    GaussError::WalCorruption {
        path: TRANSACTION_JOURNAL_DIR.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests;
