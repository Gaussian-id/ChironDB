//! A noncanonical prefix must preserve duplicate object keys for the receiving
//! derived visitor to reject. serde_json::Value's maps would silently erase
//! them. This small owned JSON tree is only used for fields before `kind`;
//! guarded map/sequence seeds admit its containers and owned strings as usual.
use serde::{
    Deserialize, Deserializer,
    de::{self, IntoDeserializer, MapAccess, SeqAccess, Visitor},
};
use std::fmt;

pub(super) enum Value {
    Scalar(serde_json::Value),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

struct Tree;
impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(Tree)
    }
}
impl<'de> Visitor<'de> for Tree {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("JSON value")
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Scalar(serde_json::Value::Null))
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Scalar(v.into()))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Scalar(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Scalar(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(|n| Value::Scalar(n.into()))
            .ok_or_else(|| E::custom("nonfinite JSON number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        self.visit_string(v.into())
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::Scalar(v.into()))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element()? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut fields = Vec::new();
        while let Some(field) = map.next_entry()? {
            fields.push(field);
        }
        Ok(Value::Object(fields))
    }
}

impl<'de> IntoDeserializer<'de, serde_json::Error> for Value {
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}
impl<'de> Deserializer<'de> for Value {
    type Error = serde_json::Error;
    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self {
            Self::Scalar(v) => v.deserialize_any(visitor),
            Self::Array(v) => {
                de::value::SeqDeserializer::new(v.into_iter()).deserialize_any(visitor)
            }
            Self::Object(v) => {
                de::value::MapDeserializer::new(v.into_iter()).deserialize_any(visitor)
            }
        }
    }
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        if matches!(self, Self::Scalar(serde_json::Value::Null)) {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        match self {
            Self::Scalar(v) => v.deserialize_enum(name, variants, visitor),
            Self::Object(v) => de::value::MapDeserializer::new(v.into_iter())
                .deserialize_enum(name, variants, visitor),
            Self::Array(_) => Err(de::Error::custom("expected enum")),
        }
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit unit_struct seq tuple tuple_struct map struct identifier ignored_any
    }
}
