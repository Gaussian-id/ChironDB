//! Immutable row values stay in pinned run files. Snapshots share the locator
//! directory and persistent overlay branches; private writes replace only the
//! affected row chains. Row values never clone merely to create a snapshot.

use super::*;

mod locator;

#[cfg(test)]
pub(super) use locator::ORDERED_SEEKS;

type RowChain<'a> = (u64, ChainRead<'a>);

#[cfg(test)]
thread_local! {
    pub(super) static VISIBLE_ROW_SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Clone, Debug, Default)]
pub(super) struct RowStore {
    base: Option<Arc<locator::DiskRows>>,
    delta: imbl::OrdMap<u64, Arc<VersionChain>>,
    /// Ended overlay versions awaiting durable projection. Logical GC may
    /// hide them, but the next delta must close their old physical versions.
    retired: imbl::OrdMap<u64, Arc<VersionChain>>,
    memory: memory::Charge,
    reclaimed_before: u64,
    modified_at: u64,
    disk_base: bool,
    base_sequence: u64,
}

pub(super) struct OrderedRowReader<'a> {
    store: &'a RowStore,
    disk: Option<locator::OrderedReader<'a>>,
}

impl OrderedRowReader<'_> {
    pub(super) fn visible(&mut self, id: u64, snapshot: u64) -> Result<Option<RowVersion>> {
        if let Some(versions) = self.store.delta.get(&id) {
            return Ok(visible_version(versions, snapshot).cloned());
        }
        self.disk.as_mut().map_or(Ok(None), |disk| {
            disk.visible(id, self.store.reclaimed_before, snapshot)
        })
    }
}

impl RowStore {
    fn from_legacy(delta: &BTreeMap<u64, Vec<RowVersion>>) -> Result<Self> {
        let mut rows = Self::default();
        for (id, versions) in delta {
            rows.insert(*id, VersionChain::copy(versions)?)?;
        }
        Ok(rows)
    }

    pub(super) fn ordered_reader(&self) -> OrderedRowReader<'_> {
        OrderedRowReader {
            store: self,
            disk: self
                .base
                .as_ref()
                .map(|base| locator::OrderedReader::new(base)),
        }
    }

    pub(super) fn insert(&mut self, id: u64, versions: VersionChain) -> Result<()> {
        let old = self.delta.get(&id);
        let bytes = self
            .memory
            .bytes()
            .saturating_sub(memory::tree_bytes(self.delta.len()))
            .saturating_sub(old.map_or(0, |versions| memory::row_chain_bytes(versions)))
            .saturating_add(memory::tree_bytes(
                self.delta.len() + usize::from(old.is_none()),
            ))
            .saturating_add(memory::row_chain_bytes(&versions));
        self.memory.prepare(bytes.max(self.memory.bytes()))?;
        for version in versions.iter() {
            self.modified_at = self
                .modified_at
                .max(version.begin)
                .max(version.end.unwrap_or(0));
        }
        self.delta.insert(id, Arc::new(versions));
        self.memory.prepare(bytes)?;
        Ok(())
    }

    pub(super) fn retained_bytes(&self) -> u64 {
        self.memory.bytes()
    }

    pub(super) fn mark_modified(&mut self, sequence: u64) {
        self.modified_at = self.modified_at.max(sequence);
    }

    pub(super) fn can_install_base(&self, sequence: u64) -> bool {
        self.modified_at <= sequence
    }

    pub(super) fn has_disk_base(&self) -> bool {
        self.disk_base
    }

    pub(super) fn installed_sequence(&self) -> Option<u64> {
        self.disk_base.then_some(self.base_sequence)
    }

    pub(super) fn replay_base_frontier(&mut self, committed_sequence: u64) {
        // Further edits within the same staged WAL batch must still project
        // their begin/end changes even though a private disk run has that batch's
        // sequence already. Final publication installs the real commit frontier.
        self.base_sequence = self.base_sequence.min(committed_sequence);
        self.reclaimed_before = self.reclaimed_before.max(committed_sequence);
    }

    pub(super) fn changed_row_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.delta.keys().chain(self.retired.keys()).copied()
    }

    pub(super) fn checkpoint_delta(&self) -> impl Iterator<Item = (u64, &RowVersion)> {
        self.delta
            .iter()
            .chain(&self.retired)
            .flat_map(|(id, versions)| versions.iter().map(move |version| (*id, version)))
            .filter(|(_, version)| {
                version.begin > self.base_sequence
                    || version.end.is_some_and(|end| end > self.base_sequence)
            })
    }

    pub(super) fn retention_frontier(&self) -> u64 {
        self.reclaimed_before
    }

    pub(super) fn install_base(&mut self, mut restored: Self, sequence: u64) {
        // A checkpoint captured before a concurrent table mutation cannot
        // discard that mutation's overlay. A later checkpoint will drain it.
        if !self.can_install_base(sequence) {
            return;
        }
        restored.reclaimed_before = restored.reclaimed_before.max(self.reclaimed_before);
        *self = restored;
    }

    pub(super) fn get(&self, id: &u64) -> Result<Option<ChainRead<'_>>> {
        if let Some(versions) = self.delta.get(id) {
            return Ok((!versions.is_empty()).then_some(ChainRead::Borrowed(&versions[..])));
        }
        let Some(base) = &self.base else {
            return Ok(None);
        };
        let versions = base.get(*id, self.reclaimed_before)?;
        Ok((!versions.is_empty()).then_some(ChainRead::Owned(versions)))
    }

    pub(super) fn visible(&self, id: u64, snapshot: u64) -> Result<Option<RowVersion>> {
        if let Some(versions) = self.delta.get(&id) {
            return Ok(visible_version(versions, snapshot).cloned());
        }
        self.base.as_ref().map_or(Ok(None), |base| {
            base.visible(id, self.reclaimed_before, snapshot)
        })
    }

    pub(super) fn contains_key(&self, id: &u64) -> Result<bool> {
        if let Some(versions) = self.delta.get(id) {
            return Ok(!versions.is_empty());
        }
        self.base
            .as_ref()
            .map_or(Ok(false), |base| base.contains(*id, self.reclaimed_before))
    }

    fn scan(&self, snapshot: Option<u64>) -> impl Iterator<Item = Result<(u64, ChainRead<'_>)>> {
        let base: Box<dyn Iterator<Item = Result<RowChain<'_>>> + '_> = match &self.base {
            Some(base) => Box::new(base.scan(self.reclaimed_before, snapshot, &self.delta)),
            None => Box::new(std::iter::empty()),
        };
        let mut base = base.peekable();
        let mut delta = self
            .delta
            .iter()
            .filter_map(move |(id, versions)| {
                let versions = match snapshot {
                    Some(snapshot) => std::slice::from_ref(visible_version(versions, snapshot)?),
                    None => &versions[..],
                };
                (!versions.is_empty()).then_some((*id, ChainRead::Borrowed(versions)))
            })
            .peekable();
        let mut finished = false;
        std::iter::from_fn(move || {
            if finished {
                return None;
            }
            match (base.peek(), delta.peek()) {
                (Some(Err(_)), _) => {
                    finished = true;
                    base.next()
                }
                (Some(Ok((left, _))), Some((right, _))) if left < right => base.next(),
                (Some(_), Some(_)) | (None, Some(_)) => delta.next().map(Ok),
                (Some(_), None) => base.next(),
                (None, None) => None,
            }
        })
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = Result<(u64, ChainRead<'_>)>> {
        self.scan(None)
    }

    pub(super) fn visible_rows(
        &self,
        snapshot: u64,
    ) -> impl Iterator<Item = Result<(u64, RowValues)>> {
        #[cfg(test)]
        VISIBLE_ROW_SCANS.with(|scans| scans.set(scans.get() + 1));
        self.scan(Some(snapshot)).map(|row| {
            let (id, versions) = row?;
            Ok((
                id,
                versions
                    .last()
                    .expect("visible scan emits one version")
                    .values
                    .clone(),
            ))
        })
    }

    pub(super) fn reclaimable(&self, frontier: u64) -> Result<usize> {
        let base = self.base.as_ref().map_or(Ok(0), |base| {
            base.reclaimable(self.reclaimed_before, frontier, &self.delta)
        })?;
        let delta = self
            .delta
            .values()
            .flat_map(|versions| versions.iter())
            .filter(|version| version.end.is_some_and(|end| end <= frontier))
            .count();
        base.checked_add(delta).ok_or_else(sql_overloaded)
    }

    pub(super) fn reclaim(&mut self, frontier: u64) -> Result<()> {
        if self.delta.is_empty() {
            self.reclaimed_before = self.reclaimed_before.max(frontier);
            return Ok(());
        }
        // GC may copy ended chains and grow their pending-closure vectors.
        // Reserve its conservative peak before touching the live generation;
        // admission failure leaves every row and retention frontier unchanged.
        let mut candidate = self.clone();
        candidate
            .memory
            .prepare(self.memory.bytes().saturating_mul(3))?;
        candidate.reclaim_reserved(frontier)?;
        let bytes = candidate
            .delta
            .values()
            .chain(candidate.retired.values())
            .fold(
                memory::tree_bytes(candidate.delta.len())
                    .saturating_add(memory::tree_bytes(candidate.retired.len())),
                |total, versions| total.saturating_add(memory::row_chain_bytes(versions)),
            );
        candidate.memory.prepare(bytes)?;
        *self = candidate;
        Ok(())
    }

    fn reclaim_reserved(&mut self, frontier: u64) -> Result<()> {
        self.reclaimed_before = self.reclaimed_before.max(frontier);
        // Iterating a shared root lets us edit only affected paths, without a
        // table-sized key list or a mutable traversal that copies every chain.
        let previous = self.delta.clone();
        for (id, versions) in &previous {
            if !versions
                .iter()
                .any(|version| version.end.is_some_and(|end| end <= frontier))
            {
                continue;
            }
            let mut kept = VersionChain::default();
            let mut retired = self
                .retired
                .get(id)
                .map(|chain| VersionChain::copy(chain))
                .transpose()?
                .unwrap_or_default();
            for version in versions.iter() {
                if version.end.is_some_and(|end| end <= frontier) {
                    if version.end.is_some_and(|end| end > self.base_sequence) {
                        retired.push(version.clone())?;
                    }
                } else {
                    kept.push(version.clone())?;
                }
            }
            if !retired.is_empty() {
                self.retired.insert(*id, Arc::new(retired));
            }
            let shared = Arc::new(kept);
            // Empty overlays must continue to shadow a historical base row.
            if shared.is_empty()
                && !self
                    .base
                    .as_ref()
                    .map_or(Ok(false), |base| base.contains(*id, 0))?
            {
                self.delta.remove(id);
            } else {
                self.delta.insert(*id, shared);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.iter()
            .try_fold(0, |count, row| row.map(|_| count + 1))
            .expect("test row scan")
    }
}

pub(super) fn restore_rows(
    table: &RelationalCheckpointTable,
    sequence: u64,
    directory: &Path,
) -> Result<RowStore> {
    let references = checkpoint_row_references(table);
    if references.is_empty() {
        let mut rows = RowStore::from_legacy(&table.rows)?;
        rows.modified_at = sequence;
        return Ok(rows);
    }
    if !table.rows.is_empty()
        || references
            .iter()
            .any(|reference| reference.sequence > sequence)
    {
        return Err(invalid(
            "relational checkpoint contains mixed or future row storage",
        ));
    }
    let base = locator::build(table, sequence, directory)?;
    Ok(RowStore {
        base: Some(Arc::new(base)),
        modified_at: sequence,
        disk_base: true,
        base_sequence: sequence,
        ..RowStore::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn overlay_forks_share_unmodified_payloads_and_release_retired_generations() {
        let mut current = RowStore::default();
        for id in 1..=4096 {
            current
                .insert(
                    id,
                    VersionChain::single(RowVersion {
                        begin: 1,
                        end: None,
                        values: RowValues::adopt(vec![RelationalValue::Text(format!(
                            "{id}:{}",
                            "x".repeat(8192)
                        ))])
                        .unwrap(),
                    })
                    .unwrap(),
                )
                .unwrap();
        }
        let frozen = current.clone();
        assert!(current.delta.ptr_eq(&frozen.delta));
        let original = Arc::downgrade(&frozen.delta[&1]);
        let mut versions = current.get(&1).unwrap().unwrap().into_owned().unwrap();
        versions[0].end = Some(2);
        versions
            .push(RowVersion {
                begin: 2,
                end: None,
                values: RowValues::adopt(vec![RelationalValue::Text("replacement".into())])
                    .unwrap(),
            })
            .unwrap();
        current.insert(1, versions).unwrap();
        assert!(!current.delta.ptr_eq(&frozen.delta));
        current.reclaim(2).unwrap();
        assert_eq!(current.retired[&1].len(), 1);
        assert_eq!(current.retired[&1][0].end, Some(2));
        assert_eq!(current.delta[&1].len(), 1);
        for id in 2..=4096 {
            assert!(Arc::ptr_eq(&current.delta[&id], &frozen.delta[&id]));
        }
        assert_eq!(
            frozen.visible(1, 1).unwrap().unwrap().values,
            vec![RelationalValue::Text(format!("1:{}", "x".repeat(8192)))]
        );
        assert_eq!(
            current.visible(1, 2).unwrap().unwrap().values,
            vec![RelationalValue::Text("replacement".into())]
        );
        let mut fork = current.clone();
        assert!(fork.retired.ptr_eq(&current.retired));
        let closure = Arc::downgrade(&current.retired[&1]);
        let mut deleted = fork.get(&2).unwrap().unwrap().into_owned().unwrap();
        deleted[0].end = Some(3);
        fork.insert(2, deleted).unwrap();
        fork.reclaim(3).unwrap();
        assert!(fork.visible(2, 3).unwrap().is_none());
        assert!(current.visible(2, 3).unwrap().is_some());
        assert!(Arc::ptr_eq(&current.retired[&1], &fork.retired[&1]));
        assert_eq!(current.retired.len(), 1);
        assert_eq!(fork.retired.len(), 2);
        drop(current);
        assert!(closure.upgrade().is_some());
        drop(fork);
        assert!(closure.upgrade().is_none());
        assert!(original.upgrade().is_some());
        drop(frozen);
        assert!(original.upgrade().is_none());
    }

    fn request(sql: &str) -> SqlExecutionRequest {
        SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql: sql.into(),
                parameters: vec![],
            }],
            idempotency_key: None,
            retry_id: None,
        }
    }

    fn value(engine: &RelationalEngine, row: u64) -> String {
        let state = engine.state.read();
        let values = state.tables["documents"]
            .rows
            .visible(row, state.sequence)
            .unwrap()
            .unwrap()
            .values;
        match &values[1] {
            RelationalValue::Text(value) => value.clone(),
            _ => panic!("text expected"),
        }
    }

    #[test]
    fn checkpoint_and_reopen_keep_values_on_disk_and_mutate_only_one_overlay_row() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE documents (id INTEGER PRIMARY KEY, body TEXT)",
            ))
            .unwrap();
        // Reverse primary keys deliberately disagree with hidden row identity.
        let body = "x".repeat(2048);
        for batch in 0..8 {
            let values = (0..64)
                .map(|item| format!("({}, '{body}')", 512 - (batch * 64 + item)))
                .collect::<Vec<_>>()
                .join(",");
            engine
                .execute(request(&format!("INSERT INTO documents VALUES {values}")))
                .unwrap();
        }
        engine.checkpoint().unwrap();
        let old = engine.state.read().clone();
        let original = &old.tables["documents"].rows;
        let old_index = Arc::downgrade(&old.tables["documents"].index_segments[0].reader);
        assert_eq!(original.base.as_ref().unwrap().version_count(), 512);
        assert!(original.delta.is_empty());
        let checkpoint = capture_relational_checkpoint(&old, 0).unwrap();
        assert!(checkpoint.manifest.tables[0].rows.is_empty());
        assert!(Arc::ptr_eq(&checkpoint.tables[0], &old.tables["documents"]));
        drop(checkpoint);
        let first = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        let path = directory
            .path()
            .join(RELATIONAL_SEGMENT_DIR)
            .join(&first.tables[0].row_segments[0].file_name);
        engine.execute(request("INSERT INTO documents VALUES (512, 'changed') ON CONFLICT (id) DO UPDATE SET body = EXCLUDED.body")).unwrap();
        {
            let state = engine.state.read();
            let current = &state.tables["documents"].rows;
            assert!(Arc::ptr_eq(
                original.base.as_ref().unwrap(),
                current.base.as_ref().unwrap()
            ));
            assert_eq!(current.delta.len(), 1);
            assert_eq!(
                current.visible(1, state.sequence).unwrap().unwrap().values[1],
                RelationalValue::Text("changed".into())
            );
            assert_eq!(
                original.visible(1, old.sequence).unwrap().unwrap().values[1],
                RelationalValue::Text(body.clone())
            );
        }
        engine.checkpoint().unwrap();
        assert!(
            engine.state.read().tables["documents"]
                .rows
                .delta
                .is_empty()
        );
        // Small updates append deltas. Reach the existing run bound to force
        // physical compaction before asserting old mapping lifetime.
        for _ in 0..3 {
            engine
                .execute(request(
                    "UPDATE documents SET body = 'changed' WHERE id = 512",
                ))
                .unwrap();
            engine.checkpoint().unwrap();
        }
        #[cfg(unix)]
        assert!(
            !path.exists(),
            "compaction can unlink an old run while its mapping is pinned"
        );
        #[cfg(not(unix))]
        let _ = path;
        assert_eq!(
            original.visible(1, old.sequence).unwrap().unwrap().values[1],
            RelationalValue::Text(body)
        );
        let Statement::Query(query) = Parser::parse_sql(
            &PostgreSqlDialect {},
            "SELECT body FROM documents WHERE id = 512",
        )
        .unwrap()
        .remove(0) else {
            unreachable!()
        };
        let old_result = execute_query(&old, old.sequence, &query, &[]).unwrap();
        assert!(
            matches!(old_result, SqlResult::Rows { rows, .. } if rows == vec![vec![RelationalValue::Text("x".repeat(2048))]])
        );
        assert!(old_index.upgrade().is_some());
        drop(old);
        assert!(
            old_index.upgrade().is_none(),
            "dropping the final snapshot must release its index mapping"
        );
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        assert!(
            engine.state.read().tables["documents"]
                .rows
                .delta
                .is_empty()
        );
        assert_eq!(value(&engine, 1), "changed");
        let selected = engine
            .execute(request("SELECT id, body FROM documents WHERE id = 512"))
            .unwrap()
            .response;
        assert!(
            matches!(&selected.results[0], SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Integer(512), RelationalValue::Text("changed".into())]])
        );
    }

    #[test]
    fn stale_checkpoint_install_cannot_drop_a_newer_overlay_or_empty_rewrite() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE documents (id INTEGER PRIMARY KEY, body TEXT)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO documents VALUES (1, 'old')"))
            .unwrap();
        engine.checkpoint().unwrap();
        let captured = capture_relational_checkpoint(
            &engine.state.read(),
            engine.wal.lock().unwrap().len().unwrap(),
        )
        .unwrap();
        engine
            .execute(request("UPDATE documents SET body = 'new' WHERE id = 1"))
            .unwrap();
        engine.publish_checkpoint(&captured).unwrap();
        assert_eq!(value(&engine, 1), "new");
        assert_eq!(engine.state.read().tables["documents"].rows.delta.len(), 1);
        let manifest = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        let mut rewritten = engine.state.read().clone();
        let definition = rewritten.tables["documents"].definition.as_ref().clone();
        let sequence = rewritten.sequence + 1;
        rewrite_table_state(&mut rewritten, definition, sequence, &[]).unwrap();
        let bases =
            prepare_checkpoint_backings(&manifest, &directory.path().join(RELATIONAL_SEGMENT_DIR))
                .unwrap();
        let permit = rewritten.tables.prepare_install().unwrap();
        assert!(install_checkpoint_backings(
            &mut rewritten,
            &manifest,
            bases,
            permit
        ));
        assert!(rewritten.tables["documents"].rows.is_empty());
        engine.checkpoint().unwrap();
        assert!(
            engine.state.read().tables["documents"]
                .rows
                .delta
                .is_empty()
        );
        assert_eq!(value(&engine, 1), "new");
    }

    #[test]
    fn disk_version_reclamation_retains_snapshot_and_deleted_overlay_shadow() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE documents (id INTEGER PRIMARY KEY, body TEXT)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO documents VALUES (1, 'old')"))
            .unwrap();
        engine.checkpoint().unwrap();
        let owner = AuditContext::embedded();
        let handle = engine.begin_interactive(&owner).unwrap();
        for value in ["new", "new2", "new3", "new4"] {
            engine
                .execute(request(&format!(
                    "UPDATE documents SET body = '{value}' WHERE id = 1"
                )))
                .unwrap();
            engine.checkpoint().unwrap();
        }
        let old_read = engine
            .execute_interactive(
                &handle.handle,
                request("SELECT body FROM documents WHERE id = 1"),
                &owner,
            )
            .unwrap();
        assert!(matches!(&old_read.results[0], SqlResult::Rows { rows, .. }
            if rows == &vec![vec![RelationalValue::Text("old".into())]]));
        let snapshot = engine.state.read().clone();
        assert_eq!(
            snapshot.tables["documents"]
                .rows
                .base
                .as_ref()
                .unwrap()
                .get(1, 0)
                .unwrap()
                .len(),
            5
        );
        assert!(snapshot.tables["documents"].rows.delta.is_empty());
        engine.rollback_interactive(&handle.handle, &owner).unwrap();
        assert_eq!(
            engine.state.read().tables["documents"]
                .rows
                .get(&1)
                .unwrap()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            snapshot.tables["documents"]
                .rows
                .get(&1)
                .unwrap()
                .unwrap()
                .len(),
            5
        );
        engine
            .execute(request("DELETE FROM documents WHERE id = 1"))
            .unwrap();
        let state = engine.state.read();
        assert!(
            state.tables["documents"]
                .rows
                .visible(1, state.sequence)
                .unwrap()
                .is_none()
        );
        assert!(state.tables["documents"].rows.delta[&1].is_empty());
        drop(state);
        engine.checkpoint().unwrap();
        assert!(
            engine.state.read().tables["documents"]
                .rows
                .base
                .as_ref()
                .unwrap()
                .version_count()
                == 0
        );
    }

    #[test]
    fn on_demand_frame_corruption_propagates_to_query_and_checkpoint() {
        use std::io::{Seek, SeekFrom, Write};
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE documents (id INTEGER PRIMARY KEY, body TEXT)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO documents VALUES (1, 'old')"))
            .unwrap();
        engine.checkpoint().unwrap();
        let manifest_bytes = fs::read(&engine.checkpoint_path).unwrap();
        let manifest = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        let path = directory
            .path()
            .join(RELATIONAL_SEGMENT_DIR)
            .join(&manifest.tables[0].row_segments[0].file_name);
        let bytes = fs::read(&path).unwrap();
        let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&[bytes[bytes.len() - 1] ^ 1]).unwrap();
        file.sync_all().unwrap();
        // Do not resize a mapped file: this models a corrupted existing sector.
        assert!(
            engine
                .execute(request("SELECT body FROM documents WHERE id = 1"))
                .is_err()
        );
        assert!(engine.checkpoint().is_err());
        assert_eq!(fs::read(&engine.checkpoint_path).unwrap(), manifest_bytes);
    }

    #[test]
    fn disk_restore_rejects_semantic_corruption_with_valid_frame_checksums() {
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request(
                "CREATE TABLE documents (id INTEGER PRIMARY KEY, body TEXT)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO documents VALUES (1, 'value')"))
            .unwrap();
        engine.checkpoint().unwrap();
        let manifest = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        let segment_dir = directory.path().join(RELATIONAL_SEGMENT_DIR);
        for case in 0..6 {
            let mut table = manifest.tables[0].clone();
            let mut row = PersistedRowVersion {
                row_id: 1,
                version: RowVersion {
                    begin: 2,
                    end: None,
                    values: RowValues::adopt(vec![
                        RelationalValue::Integer(1),
                        RelationalValue::Text("value".into()),
                    ])
                    .unwrap(),
                },
            };
            match case {
                1 => row.version.end = Some(2),
                2 => table.next_row_id = 1,
                3 => {
                    let mut values = row.version.values.to_vec();
                    values.pop();
                    row.version.values = RowValues::adopt(values).unwrap();
                }
                _ => {}
            }
            let valid_key = row_segment_key(
                &table.definition,
                1,
                &RowVersion {
                    begin: 2,
                    end: None,
                    values: RowValues::adopt(vec![
                        RelationalValue::Integer(1),
                        RelationalValue::Text("value".into()),
                    ])
                    .unwrap(),
                },
            )
            .unwrap();
            let mut records = vec![SegmentRecord {
                key: (valid_key).into(),
                value: (serde_json::to_vec(&row).unwrap()).into(),
            }];
            if case == 0 {
                records[0].key =
                    encode_row_key_v1(table.definition.table_id, RowIdentityKey::Hidden(1), 2)
                        .unwrap()
                        .into();
            }
            if case == 4 {
                row.version.begin = 3;
                records.push(SegmentRecord {
                    key: (row_segment_key(&table.definition, 1, &row.version).unwrap()).into(),
                    value: (serde_json::to_vec(&row).unwrap()).into(),
                });
                records.sort_by(|left, right| left.key.cmp(&right.key));
            }
            if case == 5 {
                records[0].value = records[0].value.test_edit(|value| value.insert(0, b' '));
            }
            let name = format!("invalid-{case}.rseg");
            let metadata =
                write_segment(&segment_dir.join(&name), SegmentKind::Row, 10, &records).unwrap();
            table.row_segments = vec![segment_reference(name, &metadata)];
            assert!(
                restore_rows(&table, 10, &segment_dir).is_err(),
                "case {case}"
            );
        }
    }

    #[test]
    fn encrypted_disk_rows_survive_checkpoint_reopen_and_primary_key_change() {
        const CHILD: &str = "CHIRONDB_DISK_ROW_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "relational::rows::tests::encrypted_disk_rows_survive_checkpoint_reopen_and_primary_key_change", "--nocapture"])
                .env(CHILD, "1").output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        use base64::Engine as _;
        let mut key = tempfile::NamedTempFile::new().unwrap();
        serde_json::to_writer(&mut key, &serde_json::json!({"version":1,"active_key_id":"test","keys":[{"id":"test","key_base64":base64::engine::general_purpose::STANDARD.encode([9u8;32])}]})).unwrap();
        crate::encryption::install_process_keyring(
            crate::encryption::Keyring::load(key.path()).unwrap(),
            true,
        )
        .unwrap();
        let directory = tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
        engine
            .execute(request(
                "CREATE TABLE documents (id INTEGER PRIMARY KEY, body TEXT)",
            ))
            .unwrap();
        engine
            .execute(request(
                "INSERT INTO documents VALUES (100, 'first'), (10, 'second')",
            ))
            .unwrap();
        engine.checkpoint().unwrap();
        assert!(
            engine.state.read().tables["documents"]
                .rows
                .delta
                .is_empty()
        );
        assert_eq!(value(&engine, 1), "first");
        assert_eq!(value(&engine, 2), "second");
        engine
            .execute(request("UPDATE documents SET id = 200 WHERE id = 100"))
            .unwrap();
        engine.checkpoint().unwrap();
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        assert_eq!(value(&engine, 1), "first");
        assert_eq!(
            engine.state.read().tables["documents"]
                .rows
                .visible(1, engine.state.read().sequence)
                .unwrap()
                .unwrap()
                .values[0],
            RelationalValue::Integer(200)
        );
        assert!(
            engine.state.read().tables["documents"]
                .rows
                .delta
                .is_empty()
        );
    }
}
