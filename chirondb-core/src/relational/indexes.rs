//! Current scalar membership is an immutable disk generation plus mutations
//! keyed by (physical prefix, row identity). Removing a member is a tombstone,
//! never a copy of every posting for the same value.

#[cfg(test)]
mod rebuild_tests;
#[cfg(test)]
mod tests;

mod catalog;
pub(super) use catalog::Catalog;

use super::*;

#[derive(Clone, Debug)]
pub(super) struct ScalarIndex {
    id: u64,
    types: catalog::Types,
    // Both levels share tree branches between snapshots. Sharing encoded keys
    // also prevents a tree-path copy from duplicating large text/index values.
    delta: imbl::OrdMap<Arc<Vec<u8>>, imbl::OrdMap<u64, bool>>,
    memory: memory::Charge,
}

impl ScalarIndex {
    pub(super) fn new(definition: &TableDefinition, columns: &[String]) -> Result<Self> {
        let id = existing_index_id(definition, columns)
            .ok_or_else(|| invalid("scalar index has no physical identity"))?;
        let types =
            catalog::Types::copy(columns.iter().map(|column| {
                Ok(&definition.columns[column_index(definition, column)?].data_type)
            }))?;
        Ok(Self {
            id,
            types,
            delta: imbl::OrdMap::new(),
            memory: memory::Charge::default(),
        })
    }

    pub(super) fn key(&self, values: &[&RelationalValue]) -> Result<Option<Vec<u8>>> {
        if values.len() != self.types.len() {
            return Err(invalid("scalar index key arity mismatch"));
        }
        if values
            .iter()
            .any(|value| matches!(value, RelationalValue::Null))
        {
            return Ok(None);
        }
        let columns = self
            .types
            .iter()
            .zip(values.iter().copied())
            .collect::<Vec<_>>();
        encode_index_prefix_v1(self.id, &columns).map(Some)
    }

    pub(super) fn set(
        &mut self,
        row_id: u64,
        values: &[&RelationalValue],
        present: bool,
    ) -> Result<()> {
        if let Some(key) = self.key(values)? {
            let existing = self.delta.get(&key);
            let bytes = match existing {
                Some(members) if members.contains_key(&row_id) => self.memory.bytes(),
                Some(members) => self
                    .memory
                    .bytes()
                    .saturating_sub(memory::tree_bytes(members.len()))
                    .saturating_add(memory::tree_bytes(members.len() + 1)),
                None => self
                    .memory
                    .bytes()
                    .saturating_sub(memory::tree_bytes(self.delta.len()))
                    .saturating_add(memory::tree_bytes(self.delta.len() + 1))
                    .saturating_add(memory::tree_bytes(1))
                    .saturating_add(key.capacity() as u64)
                    .saturating_add(64),
            };
            self.memory.prepare(bytes)?;
            self.delta
                .entry(Arc::new(key))
                .or_default()
                .insert(row_id, present);
        }
        Ok(())
    }

    pub(super) fn retained_bytes(&self) -> u64 {
        self.memory.bytes()
    }

    pub(super) fn lookup(
        &self,
        backings: &[TableSegmentBacking],
        snapshot: u64,
        values: &[&RelationalValue],
    ) -> Result<BTreeSet<u64>> {
        let Some(key) = self.key(values)? else {
            return Ok(BTreeSet::new());
        };
        let mut rows = BTreeSet::new();
        for entry in self.entries(backings, snapshot, Some(&key))? {
            let (_, row_id) = entry?;
            if rows.len() == MAX_ROWS_PER_RESULT {
                return Err(GaussError::ResourceExhausted(format!(
                    "disk index lookup exceeded {MAX_ROWS_PER_RESULT} candidate rows"
                )));
            }
            rows.insert(row_id);
        }
        Ok(rows)
    }

    pub(super) fn has_duplicates(
        &self,
        backings: &[TableSegmentBacking],
        snapshot: u64,
    ) -> Result<bool> {
        let mut previous = None;
        for entry in self.entries(backings, snapshot, None)? {
            let entry = entry?;
            if previous
                .as_ref()
                .is_some_and(|(key, row_id)| key == &entry.0 && *row_id != entry.1)
            {
                return Ok(true);
            }
            previous = Some(entry);
        }
        Ok(false)
    }

    pub(super) fn has_duplicate_key(
        &self,
        backings: &[TableSegmentBacking],
        snapshot: u64,
        values: &[&RelationalValue],
    ) -> Result<bool> {
        let Some(key) = self.key(values)? else {
            return Ok(false);
        };
        let mut first = None;
        for entry in self.entries(backings, snapshot, Some(&key))? {
            let (_, row_id) = entry?;
            if first.is_some_and(|seen| seen != row_id) {
                return Ok(true);
            }
            first = Some(row_id);
        }
        Ok(false)
    }

    pub(super) fn entries<'a>(
        &'a self,
        backings: &[TableSegmentBacking],
        snapshot: u64,
        key: Option<&[u8]>,
    ) -> Result<IndexEntries<'a>> {
        self.entries_with_lower(backings, snapshot, key, None)
    }

    pub(super) fn entries_from<'a>(
        &'a self,
        backings: &[TableSegmentBacking],
        snapshot: u64,
        lower_bound: &[u8],
    ) -> Result<IndexEntries<'a>> {
        self.entries_with_lower(backings, snapshot, None, Some(lower_bound))
    }

    fn entries_with_lower<'a>(
        &'a self,
        backings: &[TableSegmentBacking],
        snapshot: u64,
        key: Option<&[u8]>,
        lower_bound: Option<&[u8]>,
    ) -> Result<IndexEntries<'a>> {
        // The first 11 bytes name the physical index; the following tuple
        // count/components distinguish every logical key within that index.
        let mut prefix = encode_index_prefix_v1(self.id, &[])?;
        prefix.truncate(11);
        if let Some(key) = key {
            prefix = key.to_vec();
        }
        if lower_bound.is_some_and(|lower| !lower.starts_with(&prefix)) {
            return Err(invalid("scalar index lower bound is outside index"));
        }
        let delta: Box<dyn Iterator<Item = _>> = match (key, lower_bound) {
            (Some(key), _) => Box::new(self.delta.get_key_value(&key.to_vec()).into_iter()),
            (None, Some(lower)) => Box::new(self.delta.range(lower.to_vec()..)),
            (None, None) => Box::new(self.delta.iter()),
        };
        let delta = Box::new(delta.flat_map(|(key, members)| {
            members
                .iter()
                .map(move |(id, present)| (key.as_ref(), *id, *present))
        }));
        let mut entries = IndexEntries {
            disk: DiskIndexEntries::new(backings, snapshot, &prefix, lower_bound)?,
            delta,
            disk_head: None,
            delta_head: None,
            finished: false,
        };
        entries.disk_head = entries.disk.next().transpose()?;
        entries.delta_head = entries.delta.next();
        Ok(entries)
    }
}

/// Merge the small mutation overlay with streamed current disk memberships.
/// Only the current pair from each side is retained, including for hot keys.
pub(super) struct IndexEntries<'a> {
    disk: DiskIndexEntries,
    delta: Box<dyn Iterator<Item = (&'a Vec<u8>, u64, bool)> + 'a>,
    disk_head: Option<(Vec<u8>, u64)>,
    delta_head: Option<(&'a Vec<u8>, u64, bool)>,
    finished: bool,
}

impl Iterator for IndexEntries<'_> {
    type Item = Result<(Vec<u8>, u64)>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        loop {
            if let Err(error) = check_sql_cancelled() {
                self.finished = true;
                return Some(Err(error));
            }
            let take_disk = match (&self.disk_head, &self.delta_head) {
                (Some((disk_key, disk_id)), Some((delta_key, delta_id, _))) => {
                    (disk_key, disk_id) < (*delta_key, delta_id)
                }
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => {
                    self.finished = true;
                    return None;
                }
            };
            let output = if take_disk {
                self.disk_head.take()
            } else {
                let (key, id, present) = self.delta_head.take().expect("selected delta");
                self.delta_head = self.delta.next();
                if self
                    .disk_head
                    .as_ref()
                    .is_some_and(|(disk_key, disk_id)| disk_key == key && *disk_id == id)
                {
                    self.disk_head = None;
                }
                present.then(|| (key.clone(), id))
            };
            if self.disk_head.is_none() {
                match self.disk.next().transpose() {
                    Ok(next) => self.disk_head = next,
                    Err(error) => {
                        self.finished = true;
                        return Some(Err(error));
                    }
                }
            }
            if let Some(output) = output {
                return Some(Ok(output));
            }
        }
    }
}

struct DiskIndexEntries {
    cursors: Vec<segment::SegmentPrefixCursor>,
    heads: Vec<Option<SegmentRecord>>,
    sequences: Vec<u64>,
    snapshot: u64,
    finished: bool,
}

impl DiskIndexEntries {
    fn new(
        backings: &[TableSegmentBacking],
        snapshot: u64,
        prefix: &[u8],
        lower_bound: Option<&[u8]>,
    ) -> Result<Self> {
        let mut cursors = Vec::new();
        let mut heads = Vec::new();
        let mut sequences = Vec::new();
        for backing in backings {
            let mut cursor = match lower_bound {
                Some(lower) => backing.reader.prefix_cursor_from(prefix, lower)?,
                None => backing.reader.prefix_cursor(prefix)?,
            };
            heads.push(cursor.next().transpose()?);
            cursors.push(cursor);
            sequences.push(backing.sequence);
        }
        Ok(Self {
            cursors,
            heads,
            sequences,
            snapshot,
            finished: false,
        })
    }
}

fn decode_index_record(
    record: &SegmentRecord,
    sequence: u64,
) -> Result<(Vec<u8>, PersistedIndexVersion)> {
    let persisted: PersistedIndexVersion = serde_json::from_slice(&record.value)?;
    let suffix = record
        .key
        .len()
        .checked_sub(16)
        .filter(|suffix| *suffix >= 13)
        .ok_or_else(|| invalid("truncated physical index key"))?;
    if persisted.row_id == 0
        || persisted.begin == 0
        || persisted.begin > sequence
        || persisted
            .end
            .is_some_and(|end| end <= persisted.begin || end > sequence)
        || record.key[suffix..suffix + 8] != persisted.row_id.to_be_bytes()
        || record.key[suffix + 8..] != (!persisted.begin).to_be_bytes()
        || serde_json::to_vec(&persisted)? != record.value
    {
        return Err(invalid(
            "index key/value identity or MVCC interval mismatch",
        ));
    }
    Ok((record.key[..suffix].to_vec(), persisted))
}

impl Iterator for DiskIndexEntries {
    type Item = Result<(Vec<u8>, u64)>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        loop {
            let newest = self
                .heads
                .iter()
                .enumerate()
                .filter_map(|(index, head)| head.as_ref().map(|record| (index, &record.key)))
                .min_by(|(a, ak), (b, bk)| ak.cmp(bk).then_with(|| b.cmp(a)))
                .map(|(index, _)| index);
            let Some(newest) = newest else {
                self.finished = true;
                return None;
            };
            let record = self.heads[newest].take().expect("selected index head");
            let decoded = decode_index_record(&record, self.sequences[newest]);
            for (index, (head, cursor)) in self.heads.iter_mut().zip(&mut self.cursors).enumerate()
            {
                if index == newest || head.as_ref().is_some_and(|head| head.key == record.key) {
                    *head = None;
                    match cursor.next().transpose() {
                        Ok(next) => *head = next,
                        Err(error) => {
                            self.finished = true;
                            return Some(Err(error));
                        }
                    }
                }
            }
            match decoded {
                Ok((key, version))
                    if version.begin <= self.snapshot
                        && version.end.is_none_or(|end| self.snapshot < end) =>
                {
                    return Some(Ok((key, version.row_id)));
                }
                Ok(_) => {}
                Err(error) => {
                    self.finished = true;
                    return Some(Err(error));
                }
            }
        }
    }
}

/// Verify every stored projection against its row, then check cardinality to
/// detect omissions. Sorted merge guarantees unique keys, so valid membership
/// plus equal cardinality proves equality without materializing either set.
pub(super) fn validate_projection(
    table: &TableState,
    directory: &Path,
    references: &[RelationalSegmentReference],
    snapshot: u64,
) -> Result<()> {
    let physical = catalog_index_owners(&table.definition).collect::<BTreeMap<_, _>>();
    let mut actual = 0_u64;
    for record in runs::RunMerge::open(directory, SegmentKind::Index, references)? {
        check_sql_cancelled()?;
        let record = record?;
        let (_, persisted) = decode_index_record(&record, snapshot)?;
        if !record.key.starts_with(b"IK\x01") {
            return Err(invalid("unsupported physical index key"));
        }
        let id = u64::from_be_bytes(record.key[3..11].try_into().expect("checked key length"));
        let columns = physical
            .get(&id)
            .ok_or_else(|| invalid("index projection references an unknown index"))?;
        let versions = table
            .rows
            .get(&persisted.row_id)?
            .ok_or_else(|| invalid("index projection references a missing row"))?;
        let version = versions
            .iter()
            .find(|version| version.begin == persisted.begin)
            .filter(|version| version.end == persisted.end)
            .ok_or_else(|| invalid("index projection references an unknown row version"))?;
        let values = columns
            .iter()
            .map(|column| {
                let position = column_index(&table.definition, column)?;
                Ok((
                    &table.definition.columns[position].data_type,
                    &version.values[position],
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        if values
            .iter()
            .any(|(_, value)| matches!(value, RelationalValue::Null))
            || encode_index_key_v1(id, &values, persisted.row_id, version.begin)? != record.key
        {
            return Err(invalid("index segment projection is inconsistent"));
        }
        actual = actual.checked_add(1).ok_or_else(sql_overloaded)?;
    }
    let positions = physical
        .values()
        .map(|columns| {
            columns
                .iter()
                .map(|column| column_index(&table.definition, column))
                .collect::<Result<Vec<_>>>()
        })
        .collect::<Result<Vec<_>>>()?;
    let mut expected = 0_u64;
    for row in table.rows.iter() {
        check_sql_cancelled()?;
        let (_, versions) = row?;
        for version in versions.iter() {
            for columns in &positions {
                if columns
                    .iter()
                    .all(|index| !matches!(version.values[*index], RelationalValue::Null))
                {
                    expected = expected.checked_add(1).ok_or_else(sql_overloaded)?;
                }
            }
        }
    }
    if actual != expected {
        return Err(invalid("index segment projection cardinality mismatch"));
    }
    Ok(())
}
