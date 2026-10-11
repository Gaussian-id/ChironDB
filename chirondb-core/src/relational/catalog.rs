//! Persistent runtime table names. Snapshots share names and tree roots;
//! mutations admit a conservative complete tree before copying changed paths.
use super::*;
use std::{borrow::Borrow, cmp::Ordering, mem::size_of, ops::Index};

#[cfg(test)]
mod tests;

#[derive(Debug)]
struct NameAllocation {
    value: String,
    _memory: memory::Charge,
}
#[derive(Clone, Debug)]
struct Name(Arc<NameAllocation>);
impl Borrow<str> for Name {
    fn borrow(&self) -> &str {
        &self.0.value
    }
}
impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.0.value == other.0.value
    }
}
impl Eq for Name {}
impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Name {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.value.cmp(&other.0.value)
    }
}
impl Name {
    fn copy(value: &str) -> Result<Self> {
        check_sql_cancelled()?;
        let bytes = (size_of::<NameAllocation>() as u64 + 128)
            .checked_add(value.len() as u64)
            .ok_or_else(sql_overloaded)?;
        let mut memory = memory::Charge::storage();
        memory.prepare(bytes)?;
        let mut name = String::new();
        name.try_reserve_exact(value.len())
            .map_err(|_| sql_overloaded())?;
        name.push_str(value);
        Ok(Self(Arc::new(NameAllocation {
            value: name,
            _memory: memory,
        })))
    }
}

#[derive(Clone, Debug)]
pub(super) struct Catalog {
    entries: imbl::OrdMap<Name, Arc<TableState>>,
    // Drop the tree before releasing its reservation.
    memory: memory::Charge,
}
const OWNER_BYTES: u64 = size_of::<Catalog>() as u64 + 128;
fn map_bytes(count: usize) -> Result<u64> {
    OWNER_BYTES
        .checked_add(memory::tree_bytes(count))
        .ok_or_else(sql_overloaded)
}

/// Prepared before checkpoint publication. Installation can fork a live map
/// without acquiring quota or consulting request cancellation after publication.
pub(super) struct WritePermit {
    memory: memory::Charge,
    capacity: usize,
}
pub(super) struct PreparedTables(Catalog);

impl Catalog {
    pub(super) fn empty() -> Result<Self> {
        check_sql_cancelled()?;
        let mut memory = memory::Charge::storage();
        memory.prepare(OWNER_BYTES)?;
        Ok(Self {
            entries: imbl::OrdMap::new(),
            memory,
        })
    }
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
    pub(super) fn get(&self, name: &str) -> Option<&Arc<TableState>> {
        self.entries.get(name)
    }
    pub(super) fn contains_key(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }
    pub(super) fn iter(&self) -> impl DoubleEndedIterator<Item = (&String, &Arc<TableState>)> {
        self.entries
            .iter()
            .map(|(name, table)| (&name.0.value, table))
    }
    pub(super) fn keys(&self) -> impl DoubleEndedIterator<Item = &String> {
        self.iter().map(|(name, _)| name)
    }
    pub(super) fn values(&self) -> impl DoubleEndedIterator<Item = &Arc<TableState>> {
        self.entries.values()
    }
    pub(super) fn get_mut(&mut self, name: &str) -> Result<Option<&mut Arc<TableState>>> {
        check_sql_cancelled()?;
        if !self.contains_key(name) {
            return Ok(None);
        }
        self.memory.prepare(map_bytes(self.len())?)?;
        Ok(self.entries.get_mut(name))
    }
    pub(super) fn insert(
        &mut self,
        name: &str,
        table: Arc<TableState>,
    ) -> Result<Option<Arc<TableState>>> {
        check_sql_cancelled()?;
        let existing = self.entries.get_key_value(name).map(|(key, _)| key.clone());
        // Prepare on a candidate lease: a refused name must not detach the
        // live root's shared reservation or change any catalog entry.
        let mut memory = self.memory.clone();
        memory.prepare(map_bytes(self.len() + usize::from(existing.is_none()))?)?;
        let key = match existing {
            Some(key) => key,
            None => Name::copy(name)?,
        };
        self.memory = memory;
        Ok(self.entries.insert(key, table))
    }
    pub(super) fn remove(&mut self, name: &str) -> Result<Option<Arc<TableState>>> {
        check_sql_cancelled()?;
        if !self.contains_key(name) {
            return Ok(None);
        }
        self.memory.prepare(map_bytes(self.len())?)?;
        let removed = self.entries.remove(name);
        // Removed nodes are gone; the remaining root has a private lease.
        self.memory.prepare(map_bytes(self.len())?)?;
        Ok(removed)
    }
    pub(super) fn try_update_all(
        &mut self,
        mut update: impl FnMut(&Arc<TableState>) -> Result<Option<Arc<TableState>>>,
    ) -> Result<()> {
        let mut candidate = self.clone();
        for (name, table) in self.iter() {
            if let Some(replacement) = update(table)? {
                *candidate.get_mut(name)?.expect("existing table") = replacement;
            }
        }
        *self = candidate;
        Ok(())
    }
    pub(super) fn prepare_install(&self) -> Result<WritePermit> {
        check_sql_cancelled()?;
        let mut memory = memory::Charge::storage();
        memory.prepare(map_bytes(self.len())?)?;
        Ok(WritePermit {
            memory,
            capacity: self.len(),
        })
    }
    pub(super) fn begin_prepared(&self, permit: WritePermit) -> Option<PreparedTables> {
        if self.len() > permit.capacity {
            return None;
        }
        Some(PreparedTables(Self {
            entries: self.entries.clone(),
            memory: permit.memory,
        }))
    }
}
impl PreparedTables {
    pub(super) fn get_mut(&mut self, name: &str) -> Option<&mut Arc<TableState>> {
        self.0.entries.get_mut(name)
    }
    pub(super) fn finish(self) -> Catalog {
        self.0
    }
}
impl<Q: AsRef<str> + ?Sized> Index<&Q> for Catalog {
    type Output = Arc<TableState>;
    fn index(&self, name: &Q) -> &Self::Output {
        self.get(name.as_ref()).expect("table exists")
    }
}
