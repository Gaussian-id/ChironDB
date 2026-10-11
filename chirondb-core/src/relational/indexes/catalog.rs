//! Admitted scalar-index descriptions and copy-on-write table maps. Overlay
//! memberships keep their independent retained-memory charges.
use super::*;
use std::{collections::btree_map, mem::size_of, ops::Deref};

#[cfg(test)]
mod tests;

#[derive(Debug)]
struct TypeAllocation {
    values: Vec<RelationalType>,
    _memory: memory::Charge,
}

#[derive(Clone, Debug)]
pub(super) struct Types(Arc<TypeAllocation>);

impl Types {
    pub(super) fn copy<'a>(
        types: impl ExactSizeIterator<Item = Result<&'a RelationalType>> + Clone,
    ) -> Result<Self> {
        check_sql_cancelled()?;
        let mut bytes = (size_of::<TypeAllocation>() as u64 + 128)
            .checked_add(
                (types.len() as u64)
                    .checked_mul(size_of::<RelationalType>() as u64)
                    .ok_or_else(sql_overloaded)?,
            )
            .ok_or_else(sql_overloaded)?;
        for value in types.clone() {
            check_sql_cancelled()?;
            let heap = match value? {
                RelationalType::RecordRef { namespace } => namespace.capacity() as u64,
                RelationalType::Boolean
                | RelationalType::SmallInt
                | RelationalType::Integer
                | RelationalType::BigInt
                | RelationalType::Real
                | RelationalType::Float
                | RelationalType::Decimal { .. }
                | RelationalType::Text
                | RelationalType::Varchar { .. }
                | RelationalType::Bytea
                | RelationalType::Date
                | RelationalType::TimestampUtc
                | RelationalType::Uuid
                | RelationalType::Jsonb
                | RelationalType::Vector { .. } => 0,
            };
            bytes = bytes.checked_add(heap).ok_or_else(sql_overloaded)?;
        }
        let mut memory = memory::Charge::storage();
        memory.prepare(bytes)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(types.len())
            .map_err(|_| sql_overloaded())?;
        for value in types {
            check_sql_cancelled()?;
            values.push(value?.clone());
        }
        Ok(Self(Arc::new(TypeAllocation {
            values,
            _memory: memory,
        })))
    }
}

impl Deref for Types {
    type Target = [RelationalType];
    fn deref(&self) -> &Self::Target {
        &self.0.values
    }
}

#[derive(Debug)]
struct Allocation {
    entries: BTreeMap<Vec<String>, ScalarIndex>,
    _memory: memory::Charge,
}
const OWNER_BYTES: u64 = size_of::<Allocation>() as u64 + 128;

#[derive(Clone, Debug)]
pub(in crate::relational) struct Catalog(Arc<Allocation>);

fn key_bytes(columns: &[String]) -> Result<u64> {
    let mut bytes = (columns.len() as u64)
        .checked_mul(size_of::<String>() as u64)
        .ok_or_else(sql_overloaded)?;
    for name in columns {
        check_sql_cancelled()?;
        bytes = bytes
            .checked_add(name.capacity() as u64)
            .ok_or_else(sql_overloaded)?;
    }
    Ok(bytes)
}

fn map_bytes(count: usize, keys: u64) -> Result<u64> {
    // The existing conservative small-handle tree allowance also covers these
    // BTreeMap nodes. Keys' Vec/string payloads are admitted separately.
    OWNER_BYTES
        .checked_add(memory::tree_bytes(count))
        .and_then(|n| n.checked_add(keys))
        .ok_or_else(sql_overloaded)
}

impl Catalog {
    pub(in crate::relational) fn new(definition: &TableDefinition) -> Result<Self> {
        check_sql_cancelled()?;
        let mut memory = memory::Charge::storage();
        memory.prepare(OWNER_BYTES)?;
        let mut entries = BTreeMap::new();
        let mut keys = 0_u64;
        // Borrow the same specifications as the legacy constructor, including
        // a PK whose identity is resolved through a matching unique owner.
        let specifications = std::iter::once(definition.primary_key.as_slice())
            .filter(|columns| !columns.is_empty())
            .chain(
                definition
                    .unique_constraints
                    .iter()
                    .map(|c| c.columns.as_slice()),
            )
            .chain(definition.foreign_keys.iter().map(|c| c.columns.as_slice()))
            .chain(
                definition
                    .indexes
                    .iter()
                    .map(|index| index.columns.as_slice()),
            )
            .chain(
                definition
                    .reference_index_ids
                    .keys()
                    .map(std::slice::from_ref),
            );
        for columns in specifications {
            check_sql_cancelled()?;
            if entries.contains_key(columns) {
                continue;
            }
            keys = keys
                .checked_add(key_bytes(columns)?)
                .ok_or_else(sql_overloaded)?;
            memory.prepare(map_bytes(entries.len() + 1, keys)?)?;
            let index = ScalarIndex::new(definition, columns)?;
            entries.insert(columns.to_vec(), index);
        }
        Ok(Self(Arc::new(Allocation {
            entries,
            _memory: memory,
        })))
    }

    fn writable(&mut self) -> Result<&mut BTreeMap<Vec<String>, ScalarIndex>> {
        check_sql_cancelled()?;
        if Arc::get_mut(&mut self.0).is_none() {
            let mut keys = 0_u64;
            for columns in self.0.entries.keys() {
                keys = keys
                    .checked_add(key_bytes(columns)?)
                    .ok_or_else(sql_overloaded)?;
            }
            let mut memory = memory::Charge::storage();
            memory.prepare(map_bytes(self.len(), keys)?)?;
            // ScalarIndex clones share immutable types and overlay roots; only
            // these map nodes and owned column-name keys are copied here.
            let entries = self.0.entries.clone();
            self.0 = Arc::new(Allocation {
                entries,
                _memory: memory,
            });
        }
        Ok(&mut Arc::get_mut(&mut self.0)
            .expect("private admitted index map")
            .entries)
    }

    pub(in crate::relational) fn iter_mut(
        &mut self,
    ) -> Result<btree_map::IterMut<'_, Vec<String>, ScalarIndex>> {
        Ok(self.writable()?.iter_mut())
    }

    #[cfg(test)]
    pub(in crate::relational) fn remove_for_test(&mut self, key: &[String]) -> Result<()> {
        self.writable()?.remove(key);
        Ok(())
    }
}

impl Deref for Catalog {
    type Target = BTreeMap<Vec<String>, ScalarIndex>;
    fn deref(&self) -> &Self::Target {
        &self.0.entries
    }
}
