//! Derived row-ID directory. Only run readers and scalar frontiers stay in RAM;
//! row/version addresses are sorted in an encrypted, generation-pinned file.

use super::*;

#[cfg(test)]
mod tests;

#[cfg(test)]
thread_local! {
    pub(in crate::relational) static ORDERED_SEEKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Debug)]
pub(super) struct DiskRows {
    locator: segment::SegmentReader,
    sources: Vec<segment::SegmentReader>,
    sequence: u64,
    next_row_id: u64,
    min_end: Option<u64>,
    max_end: Option<u64>,
}

pub(super) struct OrderedReader<'a> {
    rows: &'a DiskRows,
    cursor: Option<segment::SegmentPrefixCursor>,
    pending: Option<Entry>,
    previous_id: Option<u64>,
}

impl<'a> OrderedReader<'a> {
    pub(super) fn new(rows: &'a DiskRows) -> Self {
        Self {
            rows,
            cursor: None,
            pending: None,
            previous_id: None,
        }
    }

    pub(super) fn visible(
        &mut self,
        id: u64,
        frontier: u64,
        snapshot: u64,
    ) -> Result<Option<RowVersion>> {
        // Continue a cursor only for adjacent physical identities. A key
        // order that differs from insertion order still uses bounded seeks.
        if self
            .previous_id
            .and_then(|previous| previous.checked_add(1))
            != Some(id)
        {
            #[cfg(test)]
            ORDERED_SEEKS.with(|seeks| seeks.set(seeks.get() + 1));
            self.cursor = Some(self.rows.locator.range_cursor_from(&id.to_be_bytes())?);
            self.pending = None;
        }
        self.previous_id = Some(id);
        loop {
            let entry = match self.pending.take() {
                Some(entry) => entry,
                None => {
                    let Some(record) = self.cursor.as_mut().expect("ordered row cursor").next()
                    else {
                        return Ok(None);
                    };
                    self.rows.decode(record?)?
                }
            };
            if entry.row_id < id {
                continue;
            }
            if entry.row_id > id {
                self.pending = Some(entry);
                return Ok(None);
            }
            if entry.begin > snapshot {
                return Ok(None);
            }
            if entry.end.is_none_or(|end| end > frontier && end > snapshot) {
                return self.rows.load(&entry).map(Some);
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    row_id: u64,
    begin: u64,
    end: Option<u64>,
    source: usize,
    offset: usize,
    length: usize,
}

fn key(row_id: u64, begin: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&row_id.to_be_bytes());
    key[8..].copy_from_slice(&begin.to_be_bytes());
    key
}

impl DiskRows {
    fn decode(&self, record: SegmentRecord) -> Result<Entry> {
        let entry: Entry = serde_json::from_slice(&record.value)?;
        if entry.row_id == 0
            || entry.row_id >= self.next_row_id
            || entry.begin == 0
            || entry.begin > self.sequence
            || entry
                .end
                .is_some_and(|end| end <= entry.begin || end > self.sequence)
            || entry.source >= self.sources.len()
            || record.key.as_slice() != key(entry.row_id, entry.begin)
        {
            return Err(relational_checkpoint_corruption(
                Path::new("relational-row-locator"),
                "derived row locator has an invalid identity or interval",
            ));
        }
        Ok(entry)
    }

    fn load(&self, entry: &Entry) -> Result<RowVersion> {
        let record = self.sources[entry.source].read_record(entry.offset, entry.length)?;
        let persisted = values::persisted_row(&record.value)?;
        if persisted.row_id != entry.row_id
            || persisted.version.begin != entry.begin
            || persisted.version.end != entry.end
        {
            return Err(relational_checkpoint_corruption(
                Path::new("relational-row"),
                "relational disk row disagrees with its immutable locator",
            ));
        }
        Ok(persisted.version)
    }

    fn entries(&self) -> impl Iterator<Item = Result<Entry>> + '_ {
        self.locator.cursor().map(|record| self.decode(record?))
    }

    pub(super) fn contains(&self, id: u64, frontier: u64) -> Result<bool> {
        for record in self.locator.prefix_cursor(&id.to_be_bytes())? {
            let entry = self.decode(record?)?;
            if entry.end.is_none_or(|end| end > frontier) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn get(&self, id: u64, frontier: u64) -> Result<VersionChain> {
        let mut versions = VersionChain::default();
        for record in self.locator.prefix_cursor(&id.to_be_bytes())? {
            check_sql_cancelled()?;
            let entry = self.decode(record?)?;
            if entry.end.is_none_or(|end| end > frontier) {
                versions.push(self.load(&entry)?)?;
            }
        }
        Ok(versions)
    }

    pub(super) fn visible(
        &self,
        id: u64,
        frontier: u64,
        snapshot: u64,
    ) -> Result<Option<RowVersion>> {
        for record in self.locator.prefix_cursor(&id.to_be_bytes())? {
            let entry = self.decode(record?)?;
            if entry.begin > snapshot {
                break;
            }
            if entry.end.is_none_or(|end| end > frontier && end > snapshot) {
                return self.load(&entry).map(Some);
            }
        }
        Ok(None)
    }

    /// Sequential scan groups adjacent row identities without point-seeking
    /// each row. Overlay shadows are skipped before decoding row payloads.
    pub(super) fn scan<'a>(
        &'a self,
        frontier: u64,
        snapshot: Option<u64>,
        shadow: &'a imbl::OrdMap<u64, Arc<VersionChain>>,
    ) -> impl Iterator<Item = Result<(u64, ChainRead<'a>)>> + 'a {
        let mut entries = self.entries().peekable();
        let mut finished = false;
        std::iter::from_fn(move || {
            if finished {
                return None;
            }
            let mut next_row = || -> Result<Option<(u64, ChainRead<'a>)>> {
                loop {
                    check_sql_cancelled()?;
                    let Some(first) = entries.next() else {
                        return Ok(None);
                    };
                    let mut entry = first?;
                    let id = entry.row_id;
                    let hidden = shadow.contains_key(&id);
                    let mut versions = VersionChain::default();
                    loop {
                        if !hidden
                            && entry.end.is_none_or(|end| end > frontier)
                            && snapshot.is_none_or(|snapshot| {
                                entry.begin <= snapshot
                                    && entry.end.is_none_or(|end| snapshot < end)
                            })
                        {
                            versions.push(self.load(&entry)?)?;
                        }
                        match entries.peek() {
                            Some(Ok(next)) if next.row_id == id => {
                                entry = entries.next().expect("peeked entry")?
                            }
                            Some(Err(_)) => {
                                return Err(entries.next().expect("peeked error").unwrap_err());
                            }
                            _ => break,
                        }
                    }
                    if !versions.is_empty() {
                        return Ok(Some((id, ChainRead::Owned(versions))));
                    }
                }
            };
            match next_row() {
                Ok(Some(row)) => Some(Ok(row)),
                result => {
                    finished = true;
                    result.err().map(Err)
                }
            }
        })
    }

    pub(super) fn reclaimable(
        &self,
        retained: u64,
        frontier: u64,
        shadow: &imbl::OrdMap<u64, Arc<VersionChain>>,
    ) -> Result<usize> {
        if frontier <= retained
            || self.max_end.is_none_or(|end| end <= retained)
            || self.min_end.is_none_or(|end| end > frontier)
        {
            return Ok(0);
        }
        self.entries().try_fold(0_usize, |count, entry| {
            check_sql_cancelled()?;
            let entry = entry?;
            if !shadow.contains_key(&entry.row_id)
                && entry
                    .end
                    .is_some_and(|end| end > retained && end <= frontier)
            {
                count.checked_add(1).ok_or_else(sql_overloaded)
            } else {
                Ok(count)
            }
        })
    }

    #[cfg(test)]
    pub(super) fn version_count(&self) -> u64 {
        self.locator.metadata().record_count
    }
}

pub(super) fn build(
    table: &RelationalCheckpointTable,
    sequence: u64,
    directory: &Path,
) -> Result<DiskRows> {
    let references = checkpoint_row_references(table);
    let mut merge = runs::RunMerge::open(directory, SegmentKind::Row, references)?;
    let sources = merge.readers();
    let unordered = std::cell::Cell::new(false);
    let unordered_flag = &unordered;
    let ordered = checkpoint::sort::ordered_locator(directory, sequence, || {
        let mut input = runs::RunMerge::open(directory, SegmentKind::Row, references)?;
        let mut previous = None;
        Ok(std::iter::from_fn(move || {
            input.next_positioned().map(|record| {
                let (record, source, offset) = record?;
                let entry = locator_entry(table, sequence, directory, &record, source, offset)?;
                let entry_key = key(entry.row_id, entry.begin);
                if previous.is_some_and(|old| old >= entry_key) {
                    unordered_flag.set(true);
                    return Err(invalid("row locator requires external ordering"));
                }
                previous = Some(entry_key);
                SegmentRecord::json_admitted(segment::RecordBytes::copy(&entry_key)?, &entry)
            })
        }))
    });
    let locator = match ordered {
        Ok(run) => run.into_reader()?,
        Err(_) if unordered.get() => {
            let mut sorter = checkpoint::sort::Sorter::locator(directory, sequence)?;
            while let Some(record) = merge.next_positioned() {
                check_sql_cancelled()?;
                let (record, source, offset) = record?;
                let entry = locator_entry(table, sequence, directory, &record, source, offset)?;
                sorter.push(SegmentRecord::json_admitted(
                    segment::RecordBytes::copy(&key(entry.row_id, entry.begin))?,
                    &entry,
                )?)?;
            }
            sorter.finish()?.into_reader()?
        }
        Err(error) => return Err(error),
    };
    drop(merge);
    let rows = DiskRows {
        locator,
        sources,
        sequence,
        next_row_id: table.next_row_id,
        min_end: None,
        max_end: None,
    };
    let mut previous: Option<Entry> = None;
    let mut min_end: Option<u64> = None;
    let mut max_end: Option<u64> = None;
    for entry in rows.entries() {
        let entry = entry?;
        if previous.as_ref().is_some_and(|old| {
            old.row_id == entry.row_id && old.end.is_none_or(|end| end > entry.begin)
        }) {
            return Err(invalid(
                "relational checkpoint contains overlapping row versions",
            ));
        }
        if let Some(end) = entry.end {
            min_end = Some(min_end.map_or(end, |old| old.min(end)));
            max_end = Some(max_end.map_or(end, |old| old.max(end)));
        }
        previous = Some(entry);
    }
    crate::failpoint::check("relational_locator.before_install")?;
    Ok(DiskRows {
        min_end,
        max_end,
        ..rows
    })
}

fn locator_entry(
    table: &RelationalCheckpointTable,
    sequence: u64,
    directory: &Path,
    record: &SegmentRecord,
    source: usize,
    offset: usize,
) -> Result<Entry> {
    check_sql_cancelled()?;
    let persisted = values::persisted_row(&record.value)?;
    if !values::canonical_matches(&persisted, &record.value)? {
        return Err(relational_checkpoint_corruption(
            directory,
            "row segment value is not canonical",
        ));
    }
    let version = persisted.version;
    if persisted.row_id == 0
        || persisted.row_id >= table.next_row_id
        || version.begin == 0
        || version.begin > sequence
        || version
            .end
            .is_some_and(|end| end <= version.begin || end > sequence)
    {
        return Err(invalid(
            "relational checkpoint contains an invalid row identity or MVCC interval",
        ));
    }
    validate_row(&table.definition, &version.values)?;
    if row_segment_key(&table.definition, persisted.row_id, &version)? != record.key {
        return Err(relational_checkpoint_corruption(
            directory,
            "row segment key/value projection is inconsistent",
        ));
    }
    Ok(Entry {
        row_id: persisted.row_id,
        begin: version.begin,
        end: version.end,
        source,
        offset,
        length: 12_usize
            .checked_add(record.key.len())
            .and_then(|size| size.checked_add(record.value.len()))
            .ok_or_else(sql_overloaded)?,
    })
}
