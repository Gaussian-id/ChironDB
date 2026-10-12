//! Bounded typed JSON values shared by disk rows and encrypted spill. Callers
//! admit encoded input/parser scratch; this decoder admits each owned payload.
use super::*;
use serde::de::{DeserializeOwned, DeserializeSeed, SeqAccess, Visitor};
use serde_json::{Value, value::RawValue};
use std::{fmt, marker::PhantomData, mem::size_of};

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Null,
    Boolean,
    Integer,
    Float,
    Decimal,
    Text,
    Bytes,
    Date,
    TimestampUtc,
    Uuid,
    Json,
    Vector,
    RecordRef,
}

// Borrow the content irrespective of field order. An adjacently tagged enum
// can otherwise buffer an owned serde Content tree when value precedes type.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValueInput<'a> {
    #[serde(rename = "type")]
    kind: Kind,
    #[serde(default, borrow, deserialize_with = "raw_some")]
    value: Option<&'a RawValue>,
}

fn raw_some<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<&'de RawValue>, D::Error> {
    <&RawValue>::deserialize(d).map(Some)
}

// A local share of the already admitted SQL request. On error every partially
// decoded owner is dropped before this scope returns; no reservation survives.
struct Budget {
    limit: usize,
    used: usize,
    exhausted: bool,
    charge: Option<memory::Charge>,
}

impl Budget {
    fn add<E: serde::de::Error>(&mut self, bytes: usize) -> std::result::Result<(), E> {
        let Some(next) = self.used.checked_add(bytes).filter(|n| *n <= self.limit) else {
            self.exhausted = true;
            return Err(E::custom("spill decoded memory exhausted"));
        };
        if let Some(charge) = &mut self.charge {
            charge.prepare(next as u64).map_err(|e| {
                self.exhausted = true;
                E::custom(e)
            })?;
        }
        self.used = next;
        Ok(())
    }

    fn push<T, E: serde::de::Error>(
        &mut self,
        values: &mut Vec<T>,
        value: T,
    ) -> std::result::Result<(), E> {
        check_sql_cancelled().map_err(E::custom)?;
        if values.len() == values.capacity() {
            let old = values.capacity() * size_of::<T>();
            let capacity = values.capacity().max(4).checked_mul(2).ok_or_else(|| {
                self.exhausted = true;
                E::custom("spill capacity overflow")
            })?;
            let bytes = capacity.checked_mul(size_of::<T>()).ok_or_else(|| {
                self.exhausted = true;
                E::custom("spill capacity overflow")
            })?;
            // Keep both blocks charged until reallocation has returned.
            self.add(bytes)?;
            values
                .try_reserve_exact(capacity - values.len())
                .map_err(|e| {
                    self.exhausted = true;
                    E::custom(e)
                })?;
            self.used -= old;
            if let Some(charge) = &mut self.charge {
                charge.prepare(self.used as u64).map_err(E::custom)?;
            }
        }
        values.push(value);
        Ok(())
    }
}

pub(super) struct DecodedValues {
    pub(super) values: Vec<RelationalValue>,
    pub(super) bytes: usize,
    pub(super) charge: Option<memory::Charge>,
}

pub(super) fn values(
    payload: &str,
    limit: usize,
    charge: Option<memory::Charge>,
) -> Result<DecodedValues> {
    let mut budget = Budget {
        limit,
        used: charge.as_ref().map_or(0, |c| c.bytes() as usize),
        exhausted: false,
        charge,
    };
    if budget.used > limit {
        return Err(sql_overloaded());
    }
    let result = Rows(&mut budget).deserialize(&mut serde_json::Deserializer::from_str(payload));
    if budget.exhausted {
        return Err(sql_overloaded());
    }
    check_sql_cancelled()?;
    Ok(DecodedValues {
        values: result?,
        bytes: budget.used,
        charge: budget.charge,
    })
}

struct Rows<'a>(&'a mut Budget);
impl<'de> DeserializeSeed<'de> for Rows<'_> {
    type Value = Vec<RelationalValue>;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        d: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        d.deserialize_seq(self)
    }
}
impl<'de> Visitor<'de> for Rows<'_> {
    type Value = Vec<RelationalValue>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("spill values")
    }
    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(raw) = seq.next_element::<&RawValue>()? {
            check_sql_cancelled().map_err(serde::de::Error::custom)?;
            let value = value(raw, self.0).map_err(serde::de::Error::custom)?;
            self.0.push(&mut values, value)?;
        }
        Ok(values)
    }
}

fn value(raw: &RawValue, budget: &mut Budget) -> serde_json::Result<RelationalValue> {
    let input: ValueInput<'_> = serde_json::from_str(raw.get())?;
    if matches!(input.kind, Kind::Null) {
        return Ok(RelationalValue::Null);
    }
    let v = input
        .value
        .ok_or_else(|| <serde_json::Error as serde::de::Error>::custom("spill value is missing"))?;
    let result = match input.kind {
        Kind::Null => unreachable!(),
        Kind::Boolean => RelationalValue::Boolean(serde_json::from_str(v.get())?),
        Kind::Integer => RelationalValue::Integer(serde_json::from_str(v.get())?),
        Kind::Float => RelationalValue::Float(serde_json::from_str(v.get())?),
        Kind::Uuid => RelationalValue::Uuid(serde_json::from_str(v.get())?),
        Kind::Decimal => RelationalValue::Decimal(string(v, budget)?),
        Kind::Text => RelationalValue::Text(string(v, budget)?),
        Kind::Date => RelationalValue::Date(string(v, budget)?),
        Kind::TimestampUtc => RelationalValue::TimestampUtc(string(v, budget)?),
        Kind::Bytes => RelationalValue::Bytes(
            ScalarVec::<u8>(budget, PhantomData)
                .deserialize(&mut serde_json::Deserializer::from_str(v.get()))?,
        ),
        Kind::Vector => RelationalValue::Vector(
            ScalarVec::<f32>(budget, PhantomData)
                .deserialize(&mut serde_json::Deserializer::from_str(v.get()))?,
        ),
        Kind::Json => RelationalValue::Json(
            Json(budget).deserialize(&mut serde_json::Deserializer::from_str(v.get()))?,
        ),
        Kind::RecordRef => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Reference<'a> {
                #[serde(borrow)]
                namespace: &'a RawValue,
                #[serde(borrow)]
                id: &'a RawValue,
            }
            let r: Reference<'_> = serde_json::from_str(v.get())?;
            RelationalValue::RecordRef(chirondb_types::RecordRef {
                namespace: string(r.namespace, budget)?,
                id: string(r.id, budget)?,
            })
        }
    };
    Ok(result)
}

fn string(raw: &RawValue, budget: &mut Budget) -> serde_json::Result<String> {
    Text(budget).deserialize(&mut serde_json::Deserializer::from_str(raw.get()))
}
struct Text<'a>(&'a mut Budget);
impl<'de> DeserializeSeed<'de> for Text<'_> {
    type Value = String;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        d: D,
    ) -> std::result::Result<String, D::Error> {
        d.deserialize_str(self)
    }
}
impl Visitor<'_> for Text<'_> {
    type Value = String;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a string")
    }
    fn visit_str<E: serde::de::Error>(self, s: &str) -> std::result::Result<String, E> {
        self.0.add(s.len())?;
        let mut result = String::new();
        result.try_reserve_exact(s.len()).map_err(|e| {
            self.0.exhausted = true;
            E::custom(e)
        })?;
        result.push_str(s);
        Ok(result)
    }
}
struct ScalarVec<'a, T>(&'a mut Budget, PhantomData<T>);
impl<'de, T: DeserializeOwned> DeserializeSeed<'de> for ScalarVec<'_, T> {
    type Value = Vec<T>;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        d: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        d.deserialize_seq(self)
    }
}
impl<'de, T: DeserializeOwned> Visitor<'de> for ScalarVec<'_, T> {
    type Value = Vec<T>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("scalar values")
    }
    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element()? {
            self.0.push(&mut values, value)?;
        }
        Ok(values)
    }
}
struct Json<'a>(&'a mut Budget);
impl<'de> DeserializeSeed<'de> for Json<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        d: D,
    ) -> std::result::Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Json<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("JSON")
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        Text(self.0).visit_str(v).map(Value::String)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(Json(self.0))? {
            self.0.push(&mut values, value)?;
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key_seed(Text(self.0))? {
            check_sql_cancelled().map_err(serde::de::Error::custom)?;
            // Conservative BTree node envelope also used by relational storage.
            // Retain duplicate-key charges until the entire head is dropped.
            if values.is_empty() {
                self.0.add(4096)?;
            }
            self.0.add(1024)?;
            let value = map.next_value_seed(Json(self.0))?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
