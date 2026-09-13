//! Snapshot binding to the selected graph generation and the replayed WAL cut.

use super::Collection;
use crate::{
    Result,
    snapshot::{SnapshotCollection, SnapshotGraph},
};

impl Collection {
    pub(super) fn snapshot_graph(&self) -> Result<Option<SnapshotGraph>> {
        self.graph_lifecycle
            .epoch()
            .map(|epoch| {
                SnapshotGraph::capture(
                    epoch,
                    self.graph_lifecycle.is_enabled(),
                    self.graph_generation
                        .as_ref()
                        .map(|generation| generation.manifest.as_ref()),
                )
            })
            .transpose()
    }

    pub(super) fn snapshot_collection(&self) -> Result<SnapshotCollection> {
        let mut marked = SnapshotCollection::new(
            &self.config,
            self.schema_epoch,
            self.wal.len()?,
            self.live_points(),
            self.last_segment_id.clone(),
        )?;
        marked.graph = self.snapshot_graph()?;
        Ok(marked)
    }
}
