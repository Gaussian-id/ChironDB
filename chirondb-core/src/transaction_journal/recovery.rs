//! Compact recovery routing accompanies authoritative terminal decisions.
//! It contains no row, vector, graph, security delta or audit body. Legacy
//! references without it still require the original retained PREPARE.
use super::*;
use crate::relational::wal_decode;

const VERSION: u16 = 1;

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CatalogChange {
    Create { name: String },
    Drop { name: String },
}
impl CatalogChange {
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Create { name } | Self::Drop { name } => name,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryDescriptor {
    version: u16,
    pub(super) target: TransactionTarget,
    pub(super) catalog: Option<CatalogChange>,
}

fn catalog(prepare: &TransactionPrepare) -> Option<(&str, bool)> {
    if !matches!(prepare.target, TransactionTarget::Catalog) {
        return None;
    }
    match prepare.mutation.as_ref() {
        WalEntry::CreateCollection { config }
        | WalEntry::CreateProtectedCollection { config, .. } => Some((&config.name, true)),
        WalEntry::DropCollection { name } | WalEntry::DropProtectedCollection { name, .. } => {
            Some((name, false))
        }
        _ => None,
    }
}
impl RecoveryDescriptor {
    pub(super) fn from_prepare(prepare: &TransactionPrepare) -> Result<Self> {
        // The receiving journal metadata lease is reserved before adoption.
        Self::owned(prepare)?.consume(Ok)
    }
    pub(super) fn owned(prepare: &TransactionPrepare) -> Result<wal_decode::Owned<Self>> {
        let mut memory = wal_decode::MetadataCharge::default();
        memory.prepare(prepare_heap(prepare) + std::mem::size_of::<Self>() as u64 + 4096)?;
        let catalog = catalog(prepare).map(|(name, created)| {
            if created {
                CatalogChange::Create {
                    name: name.to_owned(),
                }
            } else {
                CatalogChange::Drop {
                    name: name.to_owned(),
                }
            }
        });
        Ok(wal_decode::Owned::from_parts(
            Self {
                version: VERSION,
                target: prepare.target.clone(),
                catalog,
            },
            memory.into_reservation(),
        ))
    }
    pub(super) fn validate(&self) -> Result<()> {
        if self.version != VERSION
            || self.catalog.is_some() && !matches!(self.target, TransactionTarget::Catalog)
        {
            return Err(corrupt(
                "invalid recovery descriptor version or catalog target",
            ));
        }
        Ok(())
    }
    pub(super) fn validate_prepare(&self, prepare: &TransactionPrepare) -> Result<()> {
        self.validate()?;
        if self.target != prepare.target
            || self.catalog.as_ref().map(|change| {
                (
                    change.name(),
                    matches!(change, CatalogChange::Create { .. }),
                )
            }) != catalog(prepare)
        {
            return Err(corrupt("recovery descriptor differs from its PREPARE"));
        }
        Ok(())
    }
    pub(super) fn heap_bytes(&self) -> u64 {
        target_heap(&self.target, true)
            + self.catalog.as_ref().map_or(0, |change| match change {
                CatalogChange::Create { name } | CatalogChange::Drop { name } => {
                    name.capacity() as u64
                }
            })
    }
}
pub(super) fn prepare_heap(prepare: &TransactionPrepare) -> u64 {
    target_heap(&prepare.target, false) + catalog(prepare).map_or(0, |(name, _)| name.len() as u64)
}

fn target_heap(target: &TransactionTarget, allocated: bool) -> u64 {
    match target {
        TransactionTarget::Collection { name } => {
            if allocated {
                name.capacity() as u64
            } else {
                name.len() as u64
            }
        }
        TransactionTarget::MultiModel { collections } => {
            (if allocated {
                collections.capacity()
            } else {
                collections.len()
            }) as u64
                * std::mem::size_of::<String>() as u64
                + collections
                    .iter()
                    .map(|name| {
                        if allocated {
                            name.capacity() as u64
                        } else {
                            name.len() as u64
                        }
                    })
                    .sum::<u64>()
        }
        TransactionTarget::Catalog | TransactionTarget::Relational => 0,
    }
}

pub(crate) struct RecoveryDecision<'a> {
    pub(crate) transaction_id: TransactionId,
    pub(crate) commit_sequence: u64,
    pub(crate) storage_projected: bool,
    pub(crate) audit_projected: bool,
    pub(crate) target: &'a TransactionTarget,
    pub(crate) catalog: Option<&'a CatalogChange>,
}
impl<'a> RecoveryDecision<'a> {
    pub(super) fn new(
        reference: decisions::CommittedRef,
        status: &TransactionStatus,
        descriptor: &'a RecoveryDescriptor,
    ) -> Self {
        Self {
            transaction_id: reference.transaction_id,
            commit_sequence: reference.commit_sequence,
            storage_projected: status.storage_projected,
            audit_projected: status.audit_projected,
            target: &descriptor.target,
            catalog: descriptor.catalog.as_ref(),
        }
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
