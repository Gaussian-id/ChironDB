//! Borrowed field projection decoded by the existing admitted serde visitors.
//! Paths are scratch owners; hidden subtrees never produce an owned JSON copy.
use super::{PropertyAction, ResourceRecord, SubjectAttributes, policy};
use crate::{
    GaussError, Result,
    relational::wal_decode::{self, MetadataCharge, Owned},
};
use serde::de::{DeserializeSeed, Error as _, IntoDeserializer, MapAccess, Visitor};
use serde_json::Value;
use std::cell::RefCell;

#[derive(Default)]
pub(crate) struct Path {
    text: String,
    memory: MetadataCharge,
}
impl Path {
    pub(crate) fn field(key: &str) -> Result<Self> {
        let mut path = Self::default();
        path.push(key)?;
        Ok(path)
    }
    pub(crate) fn as_str(&self) -> &str {
        &self.text
    }
    fn push(&mut self, key: &str) -> Result<usize> {
        let before = self.text.len();
        let length = key
            .bytes()
            .try_fold(
                before.checked_add(1).ok_or_else(|| {
                    GaussError::ResourceExhausted("projection path overflow".into())
                })?,
                |n, byte| n.checked_add(if byte == b'~' || byte == b'/' { 2 } else { 1 }),
            )
            .ok_or_else(|| GaussError::ResourceExhausted("projection path overflow".into()))?;
        let capacity = self.text.capacity();
        let peak = (length.max(capacity) as u64)
            .checked_add(if length > capacity {
                capacity as u64
            } else {
                0
            })
            .and_then(|n| n.checked_add(128))
            .ok_or_else(|| GaussError::ResourceExhausted("projection path overflow".into()))?;
        self.memory.prepare(peak)?;
        self.text
            .try_reserve_exact(length - before)
            .map_err(|_| GaussError::ResourceExhausted("projection path memory is full".into()))?;
        self.text.push('/');
        for ch in key.chars() {
            match ch {
                '~' => self.text.push_str("~0"),
                '/' => self.text.push_str("~1"),
                ch => self.text.push(ch),
            }
        }
        self.memory.reduce(self.text.capacity() as u64 + 128);
        Ok(before)
    }
    fn pop(&mut self, length: usize) {
        self.text.truncate(length);
    }
}

#[derive(Clone, Copy)]
struct Projection<'a> {
    record: &'a ResourceRecord,
    attributes: &'a SubjectAttributes,
    action: PropertyAction,
    value: &'a Value,
    path: &'a RefCell<Path>,
}
impl Projection<'_> {
    fn present(self) -> Result<bool> {
        let path = self.path.borrow();
        if self.record.properties.contains_key(path.text.as_str()) || !self.value.is_object() {
            return Ok(policy::field_allowed(
                self.record,
                self.attributes,
                &path.text,
                self.action,
            ));
        }
        if path.text.is_empty() {
            return Ok(true);
        }
        drop(path);
        for (key, value) in self.value.as_object().expect("object projection") {
            let before = self.path.borrow_mut().push(key)?;
            let present = Self { value, ..self }.present();
            self.path.borrow_mut().pop(before);
            if present? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl<'de> serde::Deserializer<'de> for Projection<'de> {
    type Error = serde_json::Error;
    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> serde_json::Result<V::Value> {
        let path = self.path.borrow();
        let opaque =
            self.record.properties.contains_key(path.text.as_str()) || !self.value.is_object();
        let allowed =
            opaque && policy::field_allowed(self.record, self.attributes, &path.text, self.action);
        drop(path);
        if allowed {
            return self.value.deserialize_any(visitor);
        }
        let fields = if opaque {
            None
        } else {
            self.value.as_object().map(|fields| fields.iter())
        };
        visitor.visit_map(Fields {
            projection: self,
            fields,
            current: None,
        })
    }
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes byte_buf
        option unit unit_struct newtype_struct seq tuple tuple_struct map struct enum identifier ignored_any
    }
}

struct Fields<'a> {
    projection: Projection<'a>,
    fields: Option<serde_json::map::Iter<'a>>,
    current: Option<(usize, &'a Value)>,
}
impl<'de> MapAccess<'de> for Fields<'de> {
    type Error = serde_json::Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> serde_json::Result<Option<K::Value>> {
        let Some(fields) = &mut self.fields else {
            return Ok(None);
        };
        for (key, value) in fields {
            let before = self
                .projection
                .path
                .borrow_mut()
                .push(key)
                .map_err(serde_json::Error::custom)?;
            let child = Projection {
                value,
                ..self.projection
            };
            let present = child.present();
            match present {
                Ok(true) => {
                    self.current = Some((before, value));
                    return seed.deserialize(key.as_str().into_deserializer()).map(Some);
                }
                result => {
                    self.projection.path.borrow_mut().pop(before);
                    result.map_err(serde_json::Error::custom)?;
                }
            }
        }
        Ok(None)
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> serde_json::Result<V::Value> {
        let (before, value) = self.current.take().expect("projection key before value");
        let result = seed.deserialize(Projection {
            value,
            ..self.projection
        });
        self.projection.path.borrow_mut().pop(before);
        result
    }
}

pub(super) fn copy(
    record: &ResourceRecord,
    attributes: &SubjectAttributes,
    value: &Value,
    action: PropertyAction,
) -> Result<Owned<Value>> {
    let path = RefCell::new(Path::default());
    wal_decode::borrowed_json(Projection {
        record,
        attributes,
        value,
        action,
        path: &path,
    })
}
