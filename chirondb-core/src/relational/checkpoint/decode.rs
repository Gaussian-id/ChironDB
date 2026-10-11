//! Admission for the existing checkpoint serde model. This adapter is scoped to
//! its derived DTOs (including serde's tagged-enum Content buffering), not an
//! allocator contract for arbitrary custom Deserialize implementations.
use super::*;
use serde::de::{
    DeserializeSeed, EnumAccess, Error as _, MapAccess, SeqAccess, VariantAccess, Visitor,
};
use std::{fmt, io::BufReader, mem::size_of};

mod scratch;
#[cfg(test)]
mod tests;

const BUFFER_BYTES: usize = 64 * 1024;

struct Budget {
    charge: memory::Charge,
    exhausted: bool,
}

impl Budget {
    fn add<E: serde::de::Error>(&mut self, bytes: u64) -> std::result::Result<(), E> {
        check_sql_cancelled().map_err(E::custom)?;
        let next = self.charge.bytes().checked_add(bytes).ok_or_else(|| {
            self.exhausted = true;
            E::custom("storage decode memory overflow")
        })?;
        self.charge.prepare(next).map_err(|error| {
            self.exhausted = true;
            E::custom(error)
        })
    }

    fn slot<T, E: serde::de::Error>(&mut self) -> std::result::Result<(), E> {
        // Map/field slots include geometric growth and the smaller typed
        // containers consuming serde Content. Sequences admit capacity blocks
        // separately, so scalar array lengths do not accumulate eight slots.
        self.add((size_of::<T>() as u64).saturating_mul(8))
    }
}

pub(in crate::relational) fn read(
    reader: impl Read,
    payload_len: usize,
) -> Result<RelationalCheckpoint> {
    let (mut checkpoint, charge) = read_owned::<RelationalCheckpoint>(reader, payload_len)?;
    checkpoint.owned_memory = charge;
    Ok(checkpoint)
}

/// Internal derived DTO admission shared by checkpoint and borrowed journal
/// inspection. The caller must retain the charge until the decoded DTO dies.
pub(in crate::relational) fn read_owned<T: serde::de::DeserializeOwned>(
    reader: impl Read,
    payload_len: usize,
) -> Result<(T, memory::Charge)> {
    check_sql_cancelled()?;
    let mut scratch = memory::Charge::storage();
    scratch.prepare(
        (payload_len as u64)
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add((2 * BUFFER_BYTES + 4096) as u64))
            .ok_or_else(sql_overloaded)?,
    )?;
    let mut decoder = serde_json::Deserializer::from_reader(BufReader::with_capacity(
        BUFFER_BYTES,
        reader.take(payload_len as u64),
    ));
    finish_owned(&mut decoder)
}

/// Slice callers already own the input. serde_json borrows unescaped strings;
/// its escaped-string scratch reserves growth overlap, without a read buffer.
pub(in crate::relational) fn slice_owned<T: serde::de::DeserializeOwned>(
    input: &[u8],
) -> Result<(T, memory::Charge)> {
    check_sql_cancelled()?;
    let mut scratch = memory::Charge::storage();
    scratch.prepare(scratch::slice_bound(input)?)?;
    let mut decoder = serde_json::Deserializer::from_slice(input);
    finish_owned(&mut decoder)
}

fn finish_owned<'de, T: serde::de::DeserializeOwned, R: serde_json::de::Read<'de>>(
    decoder: &mut serde_json::Deserializer<R>,
) -> Result<(T, memory::Charge)> {
    let mut budget = Budget {
        charge: memory::Charge::storage(),
        exhausted: false,
    };
    budget
        .charge
        .prepare(256_u64.saturating_add(size_of::<T>() as u64))?;
    let storage = memory::StorageDecodeScope::enter();
    let result = T::deserialize(Guard {
        inner: &mut *decoder,
        budget: &mut budget,
    });
    if budget.exhausted || storage.failed() {
        return Err(sql_overloaded());
    }
    check_sql_cancelled()?;
    let value = result?;
    decoder.end()?;
    Ok((value, budget.charge))
}

/// Copy JSON from a borrowed value/projection without an encode/parse roundtrip.
/// The existing guarded visitors admit every owned JSON container and string.
pub(in crate::relational) fn borrowed_value_owned<'de>(
    decoder: impl serde::Deserializer<'de, Error = serde_json::Error>,
) -> Result<(serde_json::Value, memory::Charge)> {
    borrowed_owned(decoder)
}

/// Receiving derived DTOs use the same guarded visitors as JSON/checkpoints.
/// The borrowed source must remain owned/admitted separately during this copy.
pub(in crate::relational) fn borrowed_owned<'de, T: serde::de::DeserializeOwned>(
    decoder: impl serde::Deserializer<'de, Error = serde_json::Error>,
) -> Result<(T, memory::Charge)> {
    check_sql_cancelled()?;
    let mut budget = Budget {
        charge: memory::Charge::storage(),
        exhausted: false,
    };
    budget.charge.prepare(256 + size_of::<T>() as u64)?;
    let storage = memory::StorageDecodeScope::enter();
    let result = T::deserialize(Guard {
        inner: decoder,
        budget: &mut budget,
    });
    if budget.exhausted || storage.failed() {
        return Err(sql_overloaded());
    }
    check_sql_cancelled()?;
    Ok((result?, budget.charge))
}

struct Guard<'a, D> {
    inner: D,
    budget: &'a mut Budget,
}
struct Wrapped<'a, V> {
    inner: V,
    budget: &'a mut Budget,
    map_allocates: bool,
}
struct Seed<'a, S> {
    inner: S,
    budget: &'a mut Budget,
    map_entry: bool,
    container_slots: bool,
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Seed<'_, S> {
    type Value = S::Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        inner: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        if self.map_entry {
            // BTree node headers/child pointers and HashMap control bytes.
            // Pair storage is charged separately by slot() and the first block.
            self.budget.add(128)?;
        }
        if self.container_slots {
            self.budget.slot::<S::Value, D::Error>()?;
        } else {
            // Derived field/variant dispatch has no growing container of its
            // own. Inline storage is already in its enclosing DTO/sequence;
            // retain one additional slot for construction, not eight slots.
            self.budget.add(size_of::<S::Value>() as u64)?;
        }
        self.inner.deserialize(Guard {
            inner,
            budget: self.budget,
        })
    }
}

struct SequenceSeed<'a, S> {
    inner: S,
    budget: &'a mut Budget,
    count: &'a mut usize,
    capacity: &'a mut usize,
}
impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for SequenceSeed<'_, S> {
    type Value = S::Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        inner: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        let next = self
            .count
            .checked_add(1)
            .ok_or_else(|| D::Error::custom("sequence overflow"))?;
        let capacity = next
            .checked_next_power_of_two()
            .ok_or_else(|| D::Error::custom("sequence overflow"))?
            .max(8);
        // Suppressed size hints give standard derived Vec visitors geometric
        // growth. Three capacity blocks cover old/new growth and the smaller
        // typed Vec consuming tagged Content. Reserve before element decode,
        // so the visitor cannot grow first. None never invokes this seed.
        let bytes = ((capacity - *self.capacity) as u64)
            .checked_mul(size_of::<S::Value>() as u64)
            .and_then(|bytes| bytes.checked_mul(3))
            .ok_or_else(|| D::Error::custom("sequence memory overflow"))?;
        self.budget.add(bytes)?;
        *self.count = next;
        *self.capacity = capacity;
        self.inner.deserialize(Guard {
            inner,
            budget: self.budget,
        })
    }
}

macro_rules! deserialize_methods {
    ($($method:ident $(, $arg:ident : $ty:ty)*);* $(;)?) => {$(
        fn $method<V: Visitor<'de>>(self, $($arg: $ty,)* visitor: V) -> std::result::Result<V::Value, Self::Error> {
            self.inner.$method($($arg,)* Wrapped { inner: visitor, budget: self.budget, map_allocates: true })
        }
    )*};
}
impl<'de, D: serde::Deserializer<'de>> serde::Deserializer<'de> for Guard<'_, D> {
    type Error = D::Error;
    deserialize_methods! {
        deserialize_any; deserialize_bool; deserialize_i8; deserialize_i16;
        deserialize_i32; deserialize_i64; deserialize_i128; deserialize_u8;
        deserialize_u16; deserialize_u32; deserialize_u64; deserialize_u128;
        deserialize_f32; deserialize_f64; deserialize_char; deserialize_str;
        deserialize_string; deserialize_bytes; deserialize_byte_buf;
        deserialize_option; deserialize_unit;
        deserialize_unit_struct, name: &'static str;
        deserialize_seq; deserialize_tuple, len: usize;
        deserialize_tuple_struct, name: &'static str, len: usize;
        deserialize_map;
        deserialize_identifier;
    }
    fn deserialize_ignored_any<V: Visitor<'de>>(
        self,
        visitor: V,
    ) -> std::result::Result<V::Value, Self::Error> {
        // Supported derived DTOs use serde's allocation-free IgnoredAny for
        // skipped/unknown values. Parser scratch is already admitted by the
        // caller; no retained map/element allocation happens in this branch.
        self.inner.deserialize_ignored_any(visitor)
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> std::result::Result<V::Value, Self::Error> {
        if name == replay::LEGACY_HISTORY {
            // Only the checkpoint's validated, allocation-free UUID discard
            // visitor uses this marker. Do not accumulate container/string
            // retention charges for elements it immediately destroys.
            return self.inner.deserialize_newtype_struct(name, visitor);
        }
        self.inner.deserialize_newtype_struct(
            name,
            Wrapped {
                inner: visitor,
                budget: self.budget,
                map_allocates: true,
            },
        )
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> std::result::Result<V::Value, Self::Error> {
        // Boxed supported DTOs may transparently call their struct visitor;
        // admit the concrete value size before construction (including a copy
        // consuming tagged Content), even when no container seed sees the box.
        self.budget
            .add((size_of::<V::Value>() as u64).saturating_mul(2))?;
        // A derived struct's field dispatch does not allocate a BTreeMap. Its
        // nested containers and any tagged Content are intercepted separately.
        self.inner.deserialize_struct(
            name,
            fields,
            Wrapped {
                inner: visitor,
                budget: self.budget,
                map_allocates: false,
            },
        )
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> std::result::Result<V::Value, Self::Error> {
        // WalEntry is also transparently boxed inside transaction DTOs.
        self.budget
            .add((size_of::<V::Value>() as u64).saturating_mul(2))?;
        self.inner.deserialize_enum(
            name,
            variants,
            Wrapped {
                inner: visitor,
                budget: self.budget,
                map_allocates: true,
            },
        )
    }
    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

macro_rules! visit_scalars {
    ($($method:ident : $ty:ty),* $(,)?) => {$(
        fn $method<E: serde::de::Error>(self, value: $ty) -> std::result::Result<Self::Value, E> {
            self.inner.$method(value)
        }
    )*};
}
impl<'de, V: Visitor<'de>> Visitor<'de> for Wrapped<'_, V> {
    type Value = V::Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.expecting(f)
    }
    visit_scalars! {
        visit_bool: bool, visit_i8: i8, visit_i16: i16, visit_i32: i32,
        visit_i64: i64, visit_i128: i128, visit_u8: u8, visit_u16: u16,
        visit_u32: u32, visit_u64: u64, visit_u128: u128,
        visit_f32: f32, visit_f64: f64, visit_char: char
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
        // Includes a possible owned Content string and its final typed copy.
        self.budget.add((value.len() as u64).saturating_mul(2))?;
        self.inner.visit_str(value)
    }
    fn visit_borrowed_str<E: serde::de::Error>(
        self,
        value: &'de str,
    ) -> std::result::Result<Self::Value, E> {
        self.budget.add((value.len() as u64).saturating_mul(2))?;
        self.inner.visit_borrowed_str(value)
    }
    fn visit_string<E: serde::de::Error>(
        self,
        value: String,
    ) -> std::result::Result<Self::Value, E> {
        self.budget
            .add((value.capacity() as u64).saturating_mul(2))?;
        self.inner.visit_string(value)
    }
    fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> std::result::Result<Self::Value, E> {
        self.budget.add((value.len() as u64).saturating_mul(2))?;
        self.inner.visit_bytes(value)
    }
    fn visit_borrowed_bytes<E: serde::de::Error>(
        self,
        value: &'de [u8],
    ) -> std::result::Result<Self::Value, E> {
        self.budget.add((value.len() as u64).saturating_mul(2))?;
        self.inner.visit_borrowed_bytes(value)
    }
    fn visit_byte_buf<E: serde::de::Error>(
        self,
        value: Vec<u8>,
    ) -> std::result::Result<Self::Value, E> {
        self.budget
            .add((value.capacity() as u64).saturating_mul(2))?;
        self.inner.visit_byte_buf(value)
    }
    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
        self.inner.visit_none()
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
        self.inner.visit_unit()
    }
    fn visit_some<D: serde::Deserializer<'de>>(
        self,
        inner: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        self.budget.add(128)?;
        self.inner.visit_some(Guard {
            inner,
            budget: self.budget,
        })
    }
    fn visit_newtype_struct<D: serde::Deserializer<'de>>(
        self,
        inner: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        self.budget.add(128)?;
        self.inner.visit_newtype_struct(Guard {
            inner,
            budget: self.budget,
        })
    }
    fn visit_seq<A: SeqAccess<'de>>(self, inner: A) -> std::result::Result<Self::Value, A::Error> {
        self.budget.add(128)?;
        self.inner.visit_seq(Access {
            inner,
            budget: self.budget,
            map_allocates: false,
            map_started: false,
            key_bytes: 0,
            sequence_count: 0,
            sequence_capacity: 0,
        })
    }
    fn visit_map<A: MapAccess<'de>>(self, inner: A) -> std::result::Result<Self::Value, A::Error> {
        // Empty HashMap/BTreeMap/serde Content maps allocate no nodes. Reserve
        // the first block after reading its charged key, before the visitor can
        // insert any entry; size hints remain suppressed.
        self.inner.visit_map(Access {
            inner,
            budget: self.budget,
            map_allocates: self.map_allocates,
            map_started: false,
            key_bytes: 0,
            sequence_count: 0,
            sequence_capacity: 0,
        })
    }
    fn visit_enum<A: EnumAccess<'de>>(
        self,
        inner: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        self.inner.visit_enum(Access {
            inner,
            budget: self.budget,
            map_allocates: false,
            map_started: false,
            key_bytes: 0,
            sequence_count: 0,
            sequence_capacity: 0,
        })
    }
}

struct Access<'a, A> {
    inner: A,
    budget: &'a mut Budget,
    map_allocates: bool,
    map_started: bool,
    key_bytes: usize,
    sequence_count: usize,
    sequence_capacity: usize,
}
impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for Access<'_, A> {
    type Error = A::Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> std::result::Result<Option<T::Value>, Self::Error> {
        self.inner.next_element_seed(SequenceSeed {
            inner: seed,
            budget: self.budget,
            count: &mut self.sequence_count,
            capacity: &mut self.sequence_capacity,
        })
    }
    fn size_hint(&self) -> Option<usize> {
        None
    }
}
impl<'de, A: MapAccess<'de>> MapAccess<'de> for Access<'_, A> {
    type Error = A::Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> std::result::Result<Option<K::Value>, Self::Error> {
        let key = self.inner.next_key_seed(Seed {
            inner: seed,
            budget: self.budget,
            map_entry: self.map_allocates,
            container_slots: self.map_allocates,
        })?;
        self.key_bytes = size_of::<K::Value>();
        Ok(key)
    }
    fn next_value_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> std::result::Result<T::Value, Self::Error> {
        if self.map_allocates && !self.map_started {
            // std BTreeMap's first node has eleven pairs. Eight per-entry
            // slots plus four initial pairs cover it; subsequent nodes have
            // at least five occupied pairs. The same bound covers HashMap's
            // initial four buckets, growth overlap, and tagged Content copies.
            // 256 bytes cover the initial node header/alignment. Use actual
            // key/value sizes instead of a per-map 4 KiB placeholder.
            let pairs = (self.key_bytes as u64)
                .checked_add(size_of::<T::Value>() as u64)
                .and_then(|bytes| bytes.checked_mul(4))
                .and_then(|bytes| bytes.checked_add(256))
                .ok_or_else(|| Self::Error::custom("map memory overflow"))?;
            self.budget.add(pairs)?;
            self.map_started = true;
        }
        self.inner.next_value_seed(Seed {
            inner: seed,
            budget: self.budget,
            map_entry: false,
            container_slots: self.map_allocates,
        })
    }
    fn size_hint(&self) -> Option<usize> {
        None
    }
}
impl<'de, 'a, A: EnumAccess<'de>> EnumAccess<'de> for Access<'a, A> {
    type Error = A::Error;
    type Variant = Access<'a, A::Variant>;
    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> std::result::Result<(V::Value, Self::Variant), Self::Error> {
        let (value, inner) = self.inner.variant_seed(Seed {
            inner: seed,
            budget: self.budget,
            map_entry: false,
            container_slots: false,
        })?;
        Ok((
            value,
            Access {
                inner,
                budget: self.budget,
                map_allocates: false,
                map_started: false,
                key_bytes: 0,
                sequence_count: 0,
                sequence_capacity: 0,
            },
        ))
    }
}
impl<'de, A: VariantAccess<'de>> VariantAccess<'de> for Access<'_, A> {
    type Error = A::Error;
    fn unit_variant(self) -> std::result::Result<(), Self::Error> {
        self.inner.unit_variant()
    }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> std::result::Result<T::Value, Self::Error> {
        self.inner.newtype_variant_seed(Seed {
            inner: seed,
            budget: self.budget,
            map_entry: false,
            container_slots: false,
        })
    }
    fn tuple_variant<V: Visitor<'de>>(
        self,
        len: usize,
        visitor: V,
    ) -> std::result::Result<V::Value, Self::Error> {
        self.inner.tuple_variant(
            len,
            Wrapped {
                inner: visitor,
                budget: self.budget,
                map_allocates: false,
            },
        )
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> std::result::Result<V::Value, Self::Error> {
        self.inner.struct_variant(
            fields,
            Wrapped {
                inner: visitor,
                budget: self.budget,
                map_allocates: false,
            },
        )
    }
}
