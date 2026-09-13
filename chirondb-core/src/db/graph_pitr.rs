//! Select a complete graph/vector restore baseline before truncating staged WAL.

use crate::{
    GaussError, Result,
    checkpoint::{self, SegmentsManifest},
    fs_util,
    wal::Wal,
};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GraphPitrBase {
    Checkpoint,
    WalOrigin,
    Snapshot,
}

pub(super) fn prepare(
    directory: &Path,
    target_lsn: u64,
    timestamp_target: bool,
    graph_history: bool,
    snapshot_lsn: u64,
) -> Result<Option<GraphPitrBase>> {
    if !graph_history && target_lsn < snapshot_lsn {
        return Ok(None);
    }
    let wal = directory.join("wal");
    let retained = Wal::retained_base_lsn(&wal)?;
    if target_lsn < retained {
        return Err(unavailable("target precedes retained WAL"));
    }
    // Non-mutating boundary/CRC validation, including an exclusive end cut.
    Wal::scan_from(&wal, target_lsn, |_| Ok(()))?;
    if graph_history && timestamp_target && retained != 0 && target_lsn == retained {
        return Err(unavailable(
            "timestamp cannot identify the missing prefix's cut",
        ));
    }
    // At/after the validated source snapshot, no source state is future state.
    // Preserve its visibility and replay the contiguous archive suffix, even
    // when that suffix enables graph for the first time over a pruned vector base.
    if target_lsn >= snapshot_lsn {
        return Ok(Some(GraphPitrBase::Snapshot));
    }
    if let Some(manifest) = checkpoint::read_segments_manifest(directory)?
        && let Some(graph) = manifest.graph
        && graph.graph_batch_watermark <= target_lsn
    {
        if graph.recovery.is_none() || retained > graph.graph_batch_watermark {
            return Err(unavailable(
                "selected graph checkpoint lacks complete replay authority",
            ));
        }
        return Ok(Some(GraphPitrBase::Checkpoint));
    }
    if retained == 0 {
        Ok(Some(GraphPitrBase::WalOrigin))
    } else {
        Err(unavailable(
            "target requires history before the selected graph checkpoint",
        ))
    }
}

/// This is called ONLY on an uninstalled restore copy, after checked WAL
/// truncation. Normal publishers must never clear graph descriptors this way.
pub(super) fn apply_staged(directory: &Path, base: Option<GraphPitrBase>) -> Result<()> {
    if base != Some(GraphPitrBase::WalOrigin) {
        return Ok(());
    }
    let previous = checkpoint::read_segments_manifest(directory)?;
    let empty = SegmentsManifest {
        // Do not recycle names of copied, now-unselected graph peer files.
        generation: previous.as_ref().map_or(0, |manifest| manifest.generation),
        segments: Vec::new(),
        graph: None,
    };
    // Retire future authority only in staging; the live downgrade guard remains.
    if previous.is_some() {
        fs_util::durable_remove_file(&directory.join(checkpoint::SEGMENTS_MANIFEST_FILE))?;
    }
    checkpoint::write_segments_manifest(directory, &empty)?;
    if let Some(mut checkpoint) = checkpoint::read_checkpoint(directory)? {
        checkpoint.wal_watermark = 0;
        checkpoint.last_applied_lsn = 0;
        checkpoint.points = 0;
        checkpoint.segment_id = None;
        checkpoint.segments = Some(Vec::new());
        checkpoint::write_checkpoint(directory, &checkpoint)?;
    }
    Ok(())
}

fn unavailable(reason: &str) -> GaussError {
    GaussError::InvalidRequest(format!(
        "graph PITR unavailable: {reason}; use an older complete snapshot and retained WAL"
    ))
}
