//! Byte admission for retained protected frontend state and its request copies.
//! SQL parser, analysis and operator scratch are outside this pool's scope.
use std::{
    fmt,
    mem::size_of,
    sync::{Arc, LazyLock, Mutex},
};

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

type PgError = (&'static str, String);

static SHARED: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(shared_capacity())));
static METRIC_OBSERVATION: Mutex<()> = Mutex::new(());

fn shared_capacity() -> usize {
    (chirondb_core::resource_profile::current().sql_pool_bytes / 4).max(1) as usize
}

fn exhausted() -> PgError {
    ("53200", "protected session memory budget exhausted".into())
}

fn refused() -> PgError {
    metrics::counter!("chirondb_pgwire_memory_rejections_total").increment(1);
    exhausted()
}

#[derive(Clone, Debug)]
pub(super) struct SessionMemory {
    shared: Arc<Semaphore>,
    local: Arc<Semaphore>,
}

impl SessionMemory {
    pub(super) fn new() -> Self {
        let capacity = (chirondb_core::resource_profile::current().sql_request_working_set_bytes
            / 4)
        .max(1) as usize;
        Self {
            shared: SHARED.clone(),
            local: Arc::new(Semaphore::new(capacity)),
        }
    }

    pub(super) fn reserve(&self, bytes: usize) -> Result<Charge, PgError> {
        let bytes = u32::try_from(bytes).map_err(|_| refused())?;
        let local = self
            .local
            .clone()
            .try_acquire_many_owned(bytes)
            .map_err(|_| refused())?;
        let shared = self
            .shared
            .clone()
            .try_acquire_many_owned(bytes)
            .map_err(|_| refused())?;
        self.observe();
        Ok(Charge {
            memory: self.clone(),
            shared: Some(shared),
            local: Some(local),
        })
    }

    fn observe(&self) {
        if Arc::ptr_eq(&self.shared, &SHARED) {
            // Keep read+publication ordered across concurrent releases; an
            // older observation must not overwrite the final zero value.
            let _observation = METRIC_OBSERVATION.lock().unwrap_or_else(|e| e.into_inner());
            metrics::gauge!("chirondb_pgwire_session_reserved_bytes")
                .set((shared_capacity() - self.shared.available_permits()) as f64);
            metrics::gauge!("chirondb_pgwire_session_capacity_bytes").set(shared_capacity() as f64);
        }
    }

    #[cfg(test)]
    pub(super) fn with_capacity(bytes: usize) -> Self {
        Self {
            shared: Arc::new(Semaphore::new(bytes)),
            local: Arc::new(Semaphore::new(bytes)),
        }
    }

    #[cfg(test)]
    pub(super) fn available(&self) -> (usize, usize) {
        (
            self.shared.available_permits(),
            self.local.available_permits(),
        )
    }
}

#[derive(Debug)]
pub(super) struct Charge {
    memory: SessionMemory,
    shared: Option<OwnedSemaphorePermit>,
    local: Option<OwnedSemaphorePermit>,
}

impl Drop for Charge {
    fn drop(&mut self) {
        drop(self.shared.take());
        drop(self.local.take());
        self.memory.observe();
    }
}

impl Charge {
    pub(super) fn grow(&mut self, bytes: usize) -> Result<(), PgError> {
        let mut additional = self.memory.reserve(bytes)?;
        self.shared
            .as_mut()
            .expect("live charge")
            .merge(additional.shared.take().expect("new charge"));
        self.local
            .as_mut()
            .expect("live charge")
            .merge(additional.local.take().expect("new charge"));
        Ok(())
    }

    pub(super) fn release(&mut self, bytes: usize) {
        drop(
            self.shared
                .as_mut()
                .expect("live charge")
                .split(bytes)
                .expect("reserved bytes"),
        );
        drop(
            self.local
                .as_mut()
                .expect("live charge")
                .split(bytes)
                .expect("reserved bytes"),
        );
        self.memory.observe();
    }
}

pub(super) fn checked_bytes(parts: &[usize]) -> Result<usize, PgError> {
    parts.iter().try_fold(0usize, |total, bytes| {
        total.checked_add(*bytes).ok_or_else(exhausted)
    })
}

pub(super) fn decode_json(bytes: &[u8], charge: &mut Charge) -> Result<Value, PgError> {
    // Decoded strings cannot exceed the input length. serde's scratch Vec uses
    // geometric growth, so reserve twice that length (or its minimum 8-byte
    // capacity), separately from owned output until the decoder is dropped.
    let scratch = bytes.len().checked_mul(2).ok_or_else(exhausted)?.max(8);
    charge.grow(scratch)?;
    let result = {
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        JsonSeed {
            charge,
            exhausted: false,
        }
        .decode(&mut decoder)
    };
    charge.release(scratch);
    result
}

struct JsonSeed<'a> {
    charge: &'a mut Charge,
    exhausted: bool,
}

impl JsonSeed<'_> {
    fn add<E: serde::de::Error>(&mut self, bytes: usize) -> Result<(), E> {
        self.charge.grow(bytes).map_err(|_| {
            self.exhausted = true;
            E::custom("JSON memory budget exhausted")
        })
    }

    fn decode<'de, R: serde_json::de::Read<'de>>(
        mut self,
        decoder: &mut serde_json::Deserializer<R>,
    ) -> Result<Value, PgError> {
        let result = (&mut self).deserialize(&mut *decoder).and_then(|value| {
            decoder.end()?;
            Ok(value)
        });
        result.map_err(|_| {
            if self.exhausted {
                exhausted()
            } else {
                ("22P02", "invalid JSONB parameter".into())
            }
        })
    }
}

impl<'de> DeserializeSeed<'de> for &mut JsonSeed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for &mut JsonSeed<'_> {
    type Value = Value;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a JSON value")
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(value.into())
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(value.into())
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(value.into())
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        self.add(value.len())?;
        Ok(Value::String(value.to_owned()))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(&mut *self)? {
            // Nested heap storage is already charged; the next Value is still
            // on the stack. Admit array growth before placing it in a buffer.
            if values.len() == values.capacity() {
                let growth = values.capacity().max(4);
                let bytes = growth.checked_mul(size_of::<Value>()).ok_or_else(|| {
                    self.exhausted = true;
                    serde::de::Error::custom("JSON array capacity overflow")
                })?;
                self.add(bytes)?;
                values.try_reserve_exact(growth).map_err(|error| {
                    self.exhausted = true;
                    serde::de::Error::custom(error)
                })?;
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        // The same conservative BTree node envelope used by relational storage:
        // 4 KiB root + 1 KiB per entry. Duplicate keys retain their charge until
        // this binding drops, so replacing values cannot bypass admission.
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key_seed(JsonKey(&mut *self))? {
            if values.is_empty() {
                self.add(4096)?;
            }
            self.add(1024)?;
            let value = map.next_value_seed(&mut *self)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

struct JsonKey<'a, 'b>(&'a mut JsonSeed<'b>);
impl<'de> DeserializeSeed<'de> for JsonKey<'_, '_> {
    type Value = String;
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<String, D::Error> {
        decoder.deserialize_str(self)
    }
}
impl Visitor<'_> for JsonKey<'_, '_> {
    type Value = String;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a JSON key")
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<String, E> {
        self.0.add(value.len())?;
        Ok(value.to_owned())
    }
}

// Request copies are charged before cloning. Tree envelopes match the bounded
// JSON decoder above; vector capacities here use the source allocation as an
// upper bound for Vec::clone, whose requested capacity is the source length.
pub(super) fn parameter_bytes(values: &[crate::RelationalValue]) -> usize {
    values.iter().fold(
        values
            .len()
            .saturating_mul(size_of::<crate::RelationalValue>()),
        |sum, value| {
            use crate::RelationalValue::*;
            sum.saturating_add(match value {
                Decimal(s) | Text(s) | Date(s) | TimestampUtc(s) => s.len(),
                Bytes(v) => v.len(),
                Vector(v) => v.len().saturating_mul(size_of::<f32>()),
                RecordRef(r) => r.namespace.len().saturating_add(r.id.len()),
                Json(value) => json_bytes(value),
                _ => 0,
            })
        },
    )
}

fn json_bytes(value: &Value) -> usize {
    match value {
        Value::String(s) => s.len(),
        Value::Array(v) => v
            .iter()
            .fold(v.len().saturating_mul(size_of::<Value>()), |n, v| {
                n.saturating_add(json_bytes(v))
            }),
        Value::Object(m) if !m.is_empty() => m.iter().fold(
            4096usize.saturating_add(m.len().saturating_mul(1024)),
            |n, (k, v)| n.saturating_add(k.len()).saturating_add(json_bytes(v)),
        ),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        Db, SqlDeallocateTarget, apply_deallocate_target, close_native_target, decode_pg_parameter,
        parse_native_bind_message_admitted, parse_native_parse_message_admitted,
    };
    use super::*;
    use std::collections::HashMap;

    fn parse(name: &str, sql: &str, oids: &[u32]) -> Vec<u8> {
        let mut payload = format!("{name}\0{sql}\0").into_bytes();
        payload.extend_from_slice(&(oids.len() as i16).to_be_bytes());
        for oid in oids {
            payload.extend_from_slice(&oid.to_be_bytes());
        }
        payload
    }

    fn bind(name: &str, statement: &str, value: &[u8]) -> Vec<u8> {
        let mut payload = format!("{name}\0{statement}\0").into_bytes();
        payload.extend_from_slice(&0i16.to_be_bytes());
        payload.extend_from_slice(&1i16.to_be_bytes());
        payload.extend_from_slice(&(value.len() as i32).to_be_bytes());
        payload.extend_from_slice(value);
        payload.extend_from_slice(&0i16.to_be_bytes());
        payload
    }

    #[test]
    fn two_level_admission_is_atomic_and_shared_leases_return_once() {
        let first = SessionMemory::with_capacity(100);
        let second = SessionMemory {
            shared: first.shared.clone(),
            local: Arc::new(Semaphore::new(100)),
        };
        let held = Arc::new(first.reserve(60).unwrap());
        assert!(second.reserve(41).is_err());
        assert_eq!(second.local.available_permits(), 100);
        let clone = held.clone();
        drop(held);
        assert_eq!(first.available(), (40, 40));
        drop(clone);
        assert_eq!(first.available(), (100, 100));
        let local = first.local.clone().try_acquire_many_owned(95).unwrap();
        assert!(first.reserve(10).is_err());
        assert_eq!(first.shared.available_permits(), 100);
        drop(local);
        assert!(first.reserve(usize::MAX).is_err());
        assert_eq!(first.available(), (100, 100));
    }

    #[test]
    fn admitted_json_matches_serde_and_refuses_expansion_before_growing() {
        let memory = SessionMemory::with_capacity(1024 * 1024);
        for input in [
            r#"{"u":"雪\uD834\uDD1E","a":[null,true,-1,18446744073709551615,1.2e-3],"a":[]}"#,
            r#"[{},[],"a\nb",0,18446744073709551616]"#,
            r#"null"#,
        ] {
            let mut charge = memory.reserve(0).unwrap();
            let value = decode_json(input.as_bytes(), &mut charge).unwrap();
            assert_eq!(value, serde_json::from_str::<Value>(input).unwrap());
            drop(value);
            drop(charge);
            assert_eq!(memory.available(), (1024 * 1024, 1024 * 1024));
        }
        let small = SessionMemory::with_capacity(4096);
        let input = format!("[{}]", vec!["0"; 1000].join(","));
        let mut charge = small.reserve(0).unwrap();
        assert_eq!(
            decode_json(input.as_bytes(), &mut charge).unwrap_err().0,
            "53200"
        );
        drop(charge);
        assert_eq!(small.available(), (4096, 4096));
        for input in ["{", "[1,]", "{} x", "{\"x\":NaN}"] {
            let mut charge = memory.reserve(0).unwrap();
            assert_eq!(
                decode_json(input.as_bytes(), &mut charge).unwrap_err().0,
                "22P02"
            );
        }
        assert_eq!(memory.available(), (1024 * 1024, 1024 * 1024));
    }

    #[test]
    fn frontend_state_shares_sql_and_releases_on_replace_close_and_deallocate() {
        let temp = tempfile::tempdir().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let budget = 256 * 1024;
        let memory = SessionMemory::with_capacity(budget);
        let (name, statement) = parse_native_parse_message_admitted(
            &parse("s", "SELECT $1", &[3802]),
            &db,
            false,
            Some(&memory),
        )
        .unwrap();
        let mut statements = HashMap::from([(name, statement)]);
        let mut portals = HashMap::new();
        let input = bind("p", "s", br#"{"nested":[1,true,"value"]}"#);
        let mut used = None;
        for _ in 0..1000 {
            let (name, portal) =
                parse_native_bind_message_admitted(&input, &statements, Some(&memory)).unwrap();
            assert!(Arc::ptr_eq(&portal.statement, &statements["s"]));
            portals.insert(name, portal);
            let after = memory.available();
            assert_eq!(
                *used.get_or_insert(after),
                after,
                "rebind cannot retain earlier allocations"
            );
        }
        let before = memory.available();
        let huge = bind(
            "p",
            "s",
            format!("[{}]", vec!["0"; 20000].join(",")).as_bytes(),
        );
        assert_eq!(
            parse_native_bind_message_admitted(&huge, &statements, Some(&memory))
                .unwrap_err()
                .0,
            "53200"
        );
        assert_eq!(memory.available(), before);
        assert_eq!(
            portals["p"].parameters[0],
            crate::RelationalValue::Json(serde_json::json!({"nested":[1,true,"value"]}))
        );
        close_native_target(b"Pp\0", &mut statements, &mut portals).unwrap();
        assert!(memory.available().0 > before.0);
        assert!(apply_deallocate_target(
            SqlDeallocateTarget::All,
            &mut statements,
            &mut portals
        ));
        assert_eq!(memory.available(), (budget, budget));
    }

    #[test]
    fn parse_refuses_capacity_and_malformed_counts_before_sql_analysis() {
        let temp = tempfile::tempdir().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let memory = SessionMemory::with_capacity(16);
        assert_eq!(
            parse_native_parse_message_admitted(
                &parse("", "not valid sql", &[]),
                &db,
                false,
                Some(&memory)
            )
            .unwrap_err()
            .0,
            "53200"
        );
        assert_eq!(memory.available(), (16, 16));
        let mut negative = b"s\0SELECT 1\0".to_vec();
        negative.extend_from_slice(&(-1i16).to_be_bytes());
        assert_eq!(
            parse_native_parse_message_admitted(&negative, &db, false, None)
                .unwrap_err()
                .0,
            "08P01"
        );
        assert_eq!(
            decode_pg_parameter(17, 0, "\\x💥".as_bytes())
                .unwrap_err()
                .0,
            "22P02"
        );
    }
}
