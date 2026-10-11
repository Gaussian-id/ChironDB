//! Relational projection replay is authorized by the installation journal.
//! The committed logical prefix replaces an ever-growing in-memory ID set.
use super::*;
use serde::de::{SeqAccess, Visitor};
use sha2::{Digest, Sha256};
use std::fmt;

#[cfg(test)]
mod tests;

pub(super) const LEGACY_HISTORY: &str = "ChironRelationalDiscardedReplayHistory";

/// Preserve the legacy array/UUID validation without retaining its elements.
/// Checkpoint decoding recognizes this exact allocation-free visitor; its
/// ordinary typed-container accounting remains enabled for all other fields.
pub(super) fn discard_legacy_ids<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<Vec<TransactionId>, D::Error> {
    struct History;
    impl<'de> Visitor<'de> for History {
        type Value = Vec<TransactionId>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("an array of legacy transaction UUIDs")
        }
        fn visit_newtype_struct<D: serde::Deserializer<'de>>(
            self,
            decoder: D,
        ) -> std::result::Result<Self::Value, D::Error> {
            decoder.deserialize_seq(self)
        }
        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut items: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            loop {
                check_sql_cancelled().map_err(serde::de::Error::custom)?;
                if items.next_element::<TransactionId>()?.is_none() {
                    break;
                }
            }
            Ok(Vec::new())
        }
    }
    decoder.deserialize_newtype_struct(LEGACY_HISTORY, History)
}

pub(super) fn fingerprint(batch: &RelationalBatch) -> Result<[u8; 32]> {
    struct Output(Sha256);
    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            check_sql_cancelled().map_err(std::io::Error::other)?;
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    check_sql_cancelled()?;
    // Streaming serde writes and digest state do not create another batch or
    // encoded JSON buffer. Keep a fixed bookkeeping reservation for the proof.
    let mut memory = memory::Charge::storage();
    memory.prepare(256)?;
    let mut out = Output(Sha256::new());
    serde_json::to_writer(&mut out, batch)?;
    Ok(out.0.finalize().into())
}

pub(super) fn validate_prepare(
    prepare: &crate::transaction_journal::TransactionPrepare,
    batch: &RelationalBatch,
) -> Result<()> {
    let expected = match (&prepare.target, prepare.mutation.as_ref()) {
        (TransactionTarget::Relational, WalEntry::RelationalBatch { batch }) => batch,
        (TransactionTarget::MultiModel { .. }, WalEntry::MultiModelBatch { batch }) => {
            &batch.relational
        }
        _ => return Err(corrupt("projection has no relational journal target")),
    };
    if fingerprint(expected)? != fingerprint(batch)? {
        return Err(corrupt(
            "relational projection differs from its committed PREPARE",
        ));
    }
    Ok(())
}

pub(super) fn check_frontier(state: &RelationalState, batch: &RelationalBatch) -> Result<bool> {
    if batch.sequence == 0 {
        return Err(corrupt("relational projection has a zero logical sequence"));
    }
    if batch.sequence <= state.sequence {
        return Ok(false);
    }
    if state.sequence.checked_add(1) != Some(batch.sequence) {
        return Err(corrupt(
            "relational projection skips a committed logical sequence",
        ));
    }
    Ok(true)
}
fn corrupt(message: &str) -> GaussError {
    GaussError::WalCorruption {
        path: RELATIONAL_WAL_DIR.into(),
        message: message.into(),
    }
}
