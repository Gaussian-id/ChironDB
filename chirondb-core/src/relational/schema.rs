//! Immutable runtime schemas retain their storage admission across table,
//! transaction and prepared-execution snapshots. Public/persisted DTOs keep
//! their existing representation; their builders are a separate allocation path.
use super::*;
use std::{mem::size_of, ops::Deref};

#[cfg(test)]
mod tests;

#[derive(Debug)]
struct Allocation {
    definition: TableDefinition,
    // Release the reservation only after the owned definition is destroyed.
    _memory: memory::Charge,
}

const OWNER_BYTES: u64 = size_of::<Allocation>() as u64 + 128;

#[derive(Clone, Debug)]
pub(super) struct Schema(Arc<Allocation>);

impl Schema {
    /// Admit retention of an existing DTO, including unused Vec capacity.
    /// This does not admit the parser/DDL work that originally constructed it.
    pub(super) fn adopt(definition: TableDefinition) -> Result<Self> {
        let memory = Self::reserve(heap_bytes(&definition, true)?)?;
        Ok(Self(Arc::new(Allocation {
            definition,
            _memory: memory,
        })))
    }

    /// Admit a new independent copy before cloning any definition fields.
    pub(super) fn copy(definition: &TableDefinition) -> Result<Self> {
        let memory = Self::reserve(copy_bytes(definition)?)?;
        Ok(Self(Arc::new(Allocation {
            definition: definition.clone(),
            _memory: memory,
        })))
    }

    fn reserve(heap: u64) -> Result<memory::Charge> {
        check_sql_cancelled()?;
        let mut memory = memory::Charge::storage();
        memory.prepare(OWNER_BYTES.checked_add(heap).ok_or_else(sql_overloaded)?)?;
        Ok(memory)
    }
}

impl AsRef<TableDefinition> for Schema {
    fn as_ref(&self) -> &TableDefinition {
        &self.0.definition
    }
}

impl Deref for Schema {
    type Target = TableDefinition;
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl PartialEq for Schema {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0) || self.as_ref() == other.as_ref()
    }
}

/// Heap budget for a DTO clone. Its inline owner is charged by the caller.
pub(super) fn copy_bytes(definition: &TableDefinition) -> Result<u64> {
    heap_bytes(definition, false)
}

fn heap_bytes(definition: &TableDefinition, retained: bool) -> Result<u64> {
    let mut bytes = Bytes { total: 0, retained };
    bytes.definition(definition)?;
    Ok(bytes.total)
}

struct Bytes {
    total: u64,
    retained: bool,
}
impl Bytes {
    fn add(&mut self, bytes: u64) -> Result<()> {
        check_sql_cancelled()?;
        self.total = self.total.checked_add(bytes).ok_or_else(sql_overloaded)?;
        Ok(())
    }

    // Vec (not slice) is intentional: adoption must count spare capacity.
    fn vector<T>(&mut self, values: &Vec<T>) -> Result<()> {
        let count = if self.retained {
            values.capacity()
        } else {
            values.len()
        };
        self.add(
            (count as u64)
                .checked_mul(size_of::<T>() as u64)
                .ok_or_else(sql_overloaded)?,
        )
    }

    fn strings(&mut self, values: &Vec<String>) -> Result<()> {
        self.vector(values)?;
        for value in values {
            self.add(value.capacity() as u64)?;
        }
        Ok(())
    }

    fn optional_string(&mut self, value: &Option<String>) -> Result<()> {
        if let Some(value) = value {
            self.add(value.capacity() as u64)?;
        }
        Ok(())
    }

    fn definition(&mut self, definition: &TableDefinition) -> Result<()> {
        // Destructure exhaustively so new catalog fields require an ownership
        // review. Copies need length slots; adopted Vecs retain spare capacity.
        let TableDefinition {
            table_id: _,
            managed_by_ml: _,
            security_incarnation: _,
            creator_principal_id,
            tenant_id,
            name,
            columns,
            primary_key,
            primary_key_name,
            primary_key_index_id: _,
            unique_constraints,
            check_constraints,
            foreign_keys,
            indexes,
            reference_index_ids,
        } = definition;
        self.optional_string(creator_principal_id)?;
        self.optional_string(tenant_id)?;
        self.add(name.capacity() as u64)?;
        self.optional_string(primary_key_name)?;
        self.strings(primary_key)?;
        self.vector(columns)?;
        for column in columns {
            let RelationalColumn {
                name,
                data_type,
                nullable: _,
                default,
                identity: _,
            } = column;
            self.add(name.capacity() as u64)?;
            if let RelationalType::RecordRef { namespace } = data_type {
                self.add(namespace.capacity() as u64)?;
            }
            if let Some(value) = default {
                self.add(memory::value_heap_bytes(value))?;
            }
        }
        self.vector(unique_constraints)?;
        for constraint in unique_constraints {
            let UniqueConstraint {
                index_id: _,
                name,
                columns,
            } = constraint;
            self.optional_string(name)?;
            self.strings(columns)?;
        }
        self.vector(check_constraints)?;
        for constraint in check_constraints {
            let CheckConstraintDefinition { name, expression } = constraint;
            self.optional_string(name)?;
            self.add(expression.capacity() as u64)?;
        }
        self.vector(foreign_keys)?;
        for constraint in foreign_keys {
            let ForeignKeyDefinition {
                index_id: _,
                name,
                columns,
                referenced_table,
                referenced_columns,
                referenced_key_kind: _,
                referenced_key_name,
                match_kind: _,
                on_delete: _,
                on_update: _,
                deferrable: _,
                initially_deferred: _,
            } = constraint;
            self.optional_string(name)?;
            self.strings(columns)?;
            self.add(referenced_table.capacity() as u64)?;
            self.strings(referenced_columns)?;
            self.optional_string(referenced_key_name)?;
        }
        self.vector(indexes)?;
        for index in indexes {
            let ScalarIndexDefinition {
                index_id: _,
                name,
                columns,
                unique: _,
            } = index;
            self.add(name.capacity() as u64)?;
            self.strings(columns)?;
        }
        self.add(memory::tree_bytes(reference_index_ids.len()))?;
        for name in reference_index_ids.keys() {
            self.add(name.capacity() as u64)?;
        }
        Ok(())
    }
}
