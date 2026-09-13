//! Mutable existence is exactly the unacknowledged tail of a pinned ledger.

use super::*;

impl MutableGraphState {
    pub(crate) fn contains_edge_id(&self, id: EdgeId) -> Result<bool> {
        if self.edge_ids.contains(id.raw()) {
            return Ok(true);
        }
        self.sealed_ledger.contains(id)
    }

    pub(super) fn attach_sealed_ledger(
        &mut self,
        pin: crate::graph_generation::ledger::SealedLedger,
    ) {
        // These are creation LSNs. A property update or pending promotion does
        // not recreate a key already covered by the published cut.
        self.edge_ids = self
            .persist_changes
            .ledger
            .keys()
            .map(|id| id.raw())
            .collect();
        self.sealed_ledger = pin;
    }

    #[cfg(test)]
    pub(crate) fn unsealed_ledger_keys(&self) -> u64 {
        self.edge_ids.len()
    }
}
