//! Size-tiered temporal run merging. The durable collection checkpoint, rather
//! than an in-memory merge, decides when an old run can be reclaimed.
use super::*;

impl TemporalState {
    pub(super) fn compact_runs(&mut self, force: bool) -> Result<()> {
        let mut metadata = MetadataCharge::default();
        metadata.prepare(self.runs.len() as u64 * 256 + 4096)?;
        loop {
            let mut order: Vec<_> = (0..self.runs.len()).collect();
            order.sort_unstable_by_key(|&i| self.runs[i].1.len());
            // Geometric tiers bound rewrite amplification without rewriting a
            // large historical run on every one-event checkpoint.
            let tier = |i: usize| self.runs[i].1.len().max(1).ilog2();
            let pair = order.windows(2).find(|pair| tier(pair[0]) == tier(pair[1]));
            let pair = pair.or_else(|| (force && self.runs.len() >= MAX_RUNS).then(|| &order[..2]));
            let Some(pair) = pair else {
                break;
            };
            let (a, b) = (pair[0].min(pair[1]), pair[0].max(pair[1]));
            let indexes = (self.runs[a].1.len() as u64 + self.runs[b].1.len() as u64)
                .saturating_mul(4)
                .saturating_add(262144);
            let mut scratch = MetadataCharge::default();
            let required = force && self.runs.len() >= MAX_RUNS;
            match scratch.prepare(indexes) {
                Ok(()) => {}
                Err(GaussError::ResourceExhausted(_)) if !required => break,
                Err(error) => return Err(error),
            }
            let left = Segment::open(RunCursor {
                file: &self.runs[a].1,
                pos: 0,
            })?;
            let right = Segment::open(RunCursor {
                file: &self.runs[b].1,
                pos: 0,
            })?;
            match scratch.prepare(indexes.saturating_add(left.merge_memory_bound(&right))) {
                Ok(()) => {}
                // Existing runs remain valid checkpoint inputs. Defer an
                // optional merge instead of creating a new write/flush limit
                // when a large history no longer fits the available budget.
                Err(GaussError::ResourceExhausted(_)) if !required => break,
                Err(error) => return Err(error),
            }
            let bytes = left.merge(right)?;
            let id = crate::encryption::hex_digest(&Sha256::digest(&bytes));
            let path = self.dir.join(format!("{id}.ctsg"));
            crate::failpoint::check("temporal.before_merge_publish")?;
            atomic_write_persistent(&path, FileType::Segment, &bytes)?;
            let file = PersistentFile::open(&path)?;
            crate::failpoint::check("temporal.after_merge_publish")?;
            // Readers hold the collection lock. Original files stay on disk
            // until a later checkpoint proves they are no longer referenced.
            self.runs.remove(b);
            self.runs.remove(a);
            if !self.runs.iter().any(|(existing, _)| existing == &id) {
                self.runs.push((id, file));
            }
            metrics::counter!("chirondb_temporal_run_merges_total").increment(1);
        }
        Ok(())
    }

    pub(super) fn reclaim_obsolete_runs(&self) -> Result<()> {
        let mut metadata = MetadataCharge::default();
        metadata.prepare(MAX_RUNS as u64 * 256 + 4096)?;
        let Some(checkpoint) = read_checkpoint(self.dir.parent().expect("collection directory"))?
        else {
            return Ok(());
        };
        let Some(durable) = checkpoint.temporal_runs else {
            return Ok(());
        };
        // Also finish a prior publication that returned an error after rename.
        // Never unlink the old generation based on an unsynced directory entry.
        let parent = self.dir.parent().expect("collection directory");
        fs::File::open(crate::checkpoint::checkpoint_path(parent))?.sync_all()?;
        crate::fs_util::sync_directory(parent)?;
        let keep: BTreeSet<_> = durable
            .iter()
            .chain(self.runs.iter().map(|(id, _)| id))
            .collect();
        if !self.dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(id) = name.to_str().and_then(|name| name.strip_suffix(".ctsg")) else {
                continue;
            };
            if id.len() == 64
                && id
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                && !keep.iter().any(|kept| kept.as_str() == id)
            {
                crate::fs_util::durable_remove_file(&entry.path())?;
            }
        }
        Ok(())
    }
}
