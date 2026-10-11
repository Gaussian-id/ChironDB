//! Stable binary key encoding for relational rows and scalar indexes.
//!
//! Version 1 keys sort first by catalog object, then by logical key, row
//! identity, and newest commit sequence. Variable-width values use a zero-byte
//! escaping scheme so their bytewise ordering follows binary collation without
//! ambiguous component boundaries.

use chrono::{Datelike, Timelike};

use super::{
    memory::Charge,
    segment::{EncodedBuffer, RECORD_OWNER_BYTES, RecordBytes},
    sql_overloaded,
};
use crate::{GaussError, RelationalType, RelationalValue, Result};

pub(crate) const KEY_ENCODING_VERSION: u8 = 1;
const ROW_MAGIC: &[u8; 2] = b"RK";
const INDEX_MAGIC: &[u8; 2] = b"IK";

const TAG_NULL: u8 = 0;
const TAG_BOOL: u8 = 1;
const TAG_INTEGER: u8 = 2;
const TAG_FLOAT64: u8 = 3;
const TAG_DECIMAL: u8 = 4;
const TAG_TEXT: u8 = 5;
const TAG_BYTES: u8 = 6;
const TAG_DATE: u8 = 7;
const TAG_TIMESTAMP: u8 = 8;
const TAG_UUID: u8 = 9;
const TAG_JSONB: u8 = 10;
const TAG_VECTOR: u8 = 11;
const TAG_RECORD_REF: u8 = 12;
const TAG_FLOAT32: u8 = 13;

pub(crate) enum RowIdentityKey<'a> {
    Primary(&'a [(&'a RelationalType, &'a RelationalValue)]),
    Hidden(u64),
}

trait KeyWriter {
    fn push(&mut self, byte: u8) -> Result<()>;
    fn extend(&mut self, bytes: &[u8]) -> Result<()>;

    fn json_escaped(&mut self, value: &serde_json::Value) -> Result<()> {
        let bytes = serde_json::to_vec(value)
            .map_err(|error| invalid(format!("cannot encode JSONB key: {error}")))?;
        append_escaped(self, &bytes)
    }

    fn decimal(&mut self, value: &str, scale: u8) -> Result<i128> {
        scaled_decimal(value, scale)
    }
}

impl KeyWriter for Vec<u8> {
    fn push(&mut self, byte: u8) -> Result<()> {
        Vec::push(self, byte);
        Ok(())
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

struct AdmittedKey {
    bytes: Vec<u8>,
    charge: Charge,
    limit: usize,
}

impl AdmittedKey {
    fn new() -> Result<Self> {
        let mut charge = Charge::storage();
        charge.prepare(RECORD_OWNER_BYTES)?;
        Ok(Self {
            bytes: Vec::new(),
            charge,
            limit: crate::resource_profile::current().sql_request_working_set_bytes as usize,
        })
    }

    fn reserve(&mut self, added: usize) -> Result<()> {
        if self.bytes.len() & 4095 == 0 || added >= 4096 {
            super::check_sql_cancelled()?;
        }
        let required = self
            .bytes
            .len()
            .checked_add(added)
            .ok_or_else(sql_overloaded)?;
        if required > self.limit {
            return Err(sql_overloaded());
        }
        if required <= self.bytes.capacity() {
            return Ok(());
        }
        let old = self.bytes.capacity();
        let target = old.saturating_mul(2).max(required).max(8).min(self.limit);
        self.charge.prepare(
            (old as u64)
                .checked_add(target as u64)
                .and_then(|n| n.checked_add(RECORD_OWNER_BYTES))
                .ok_or_else(sql_overloaded)?,
        )?;
        self.bytes
            .try_reserve_exact(target - self.bytes.len())
            .map_err(|_| sql_overloaded())?;
        self.charge.prepare(
            (self.bytes.capacity() as u64)
                .checked_add(RECORD_OWNER_BYTES)
                .ok_or_else(sql_overloaded)?,
        )
    }

    fn finish(self) -> RecordBytes {
        RecordBytes::from_admitted(self.bytes, self.charge)
    }
}

impl KeyWriter for AdmittedKey {
    fn push(&mut self, byte: u8) -> Result<()> {
        self.reserve(1)?;
        self.bytes.push(byte);
        Ok(())
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<()> {
        self.reserve(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn json_escaped(&mut self, value: &serde_json::Value) -> Result<()> {
        super::check_sql_cancelled()?;
        let scratch = EncodedBuffer::encode(value, self.limit.saturating_sub(self.bytes.len()))?;
        super::check_sql_cancelled()?;
        append_escaped(self, &scratch.bytes)
    }

    fn decimal(&mut self, value: &str, scale: u8) -> Result<i128> {
        // canonical_decimal and scaled_decimal overlap temporary strings.
        // Input length and scale bound both scratch strings before allocation.
        let mut scratch = Charge::storage();
        scratch.prepare(
            (value.len() as u64)
                .checked_mul(4)
                .and_then(|n| n.checked_add(u64::from(scale) + 256))
                .ok_or_else(sql_overloaded)?,
        )?;
        scaled_decimal(value, scale)
    }
}

pub(crate) fn encode_row_key_v1(
    table_id: u64,
    identity: RowIdentityKey<'_>,
    commit_sequence: u64,
) -> Result<Vec<u8>> {
    let mut key = Vec::new();
    write_row_key(&mut key, table_id, identity, commit_sequence)?;
    Ok(key)
}

pub(in crate::relational) fn encode_row_key_v1_admitted(
    table_id: u64,
    identity: RowIdentityKey<'_>,
    commit_sequence: u64,
) -> Result<RecordBytes> {
    let mut key = AdmittedKey::new()?;
    write_row_key(&mut key, table_id, identity, commit_sequence)?;
    Ok(key.finish())
}

fn write_row_key(
    key: &mut impl KeyWriter,
    table_id: u64,
    identity: RowIdentityKey<'_>,
    commit_sequence: u64,
) -> Result<()> {
    if table_id == 0 || commit_sequence == 0 {
        return Err(invalid(
            "row keys require non-zero table and commit identifiers",
        ));
    }
    key.extend(ROW_MAGIC)?;
    key.push(KEY_ENCODING_VERSION)?;
    key.extend(&table_id.to_be_bytes())?;
    match identity {
        RowIdentityKey::Hidden(row_id) => {
            if row_id == 0 {
                return Err(invalid("hidden row identity must be non-zero"));
            }
            key.push(0)?;
            key.extend(&row_id.to_be_bytes())?;
        }
        RowIdentityKey::Primary(columns) => {
            key.push(1)?;
            encode_column_tuple(key, columns)?;
        }
    }
    key.extend(&(!commit_sequence).to_be_bytes())
}

pub(crate) fn encode_index_key_v1(
    index_id: u64,
    columns: &[(&RelationalType, &RelationalValue)],
    row_id: u64,
    commit_sequence: u64,
) -> Result<Vec<u8>> {
    let mut key = Vec::new();
    write_index_key(&mut key, index_id, columns, row_id, commit_sequence)?;
    Ok(key)
}

pub(in crate::relational) fn encode_index_key_v1_admitted(
    index_id: u64,
    columns: &[(&RelationalType, &RelationalValue)],
    row_id: u64,
    commit_sequence: u64,
) -> Result<RecordBytes> {
    let mut key = AdmittedKey::new()?;
    write_index_key(&mut key, index_id, columns, row_id, commit_sequence)?;
    Ok(key.finish())
}

fn write_index_key(
    key: &mut impl KeyWriter,
    index_id: u64,
    columns: &[(&RelationalType, &RelationalValue)],
    row_id: u64,
    commit_sequence: u64,
) -> Result<()> {
    if index_id == 0 || row_id == 0 || commit_sequence == 0 {
        return Err(invalid(
            "index keys require non-zero index, row, and commit identifiers",
        ));
    }
    write_index_prefix(key, index_id, columns)?;
    key.extend(&row_id.to_be_bytes())?;
    key.extend(&(!commit_sequence).to_be_bytes())
}

pub(crate) fn encode_index_prefix_v1(
    index_id: u64,
    columns: &[(&RelationalType, &RelationalValue)],
) -> Result<Vec<u8>> {
    let mut key = Vec::new();
    write_index_prefix(&mut key, index_id, columns)?;
    Ok(key)
}

fn write_index_prefix(
    key: &mut impl KeyWriter,
    index_id: u64,
    columns: &[(&RelationalType, &RelationalValue)],
) -> Result<()> {
    if index_id == 0 {
        return Err(invalid(
            "index prefixes require a non-zero index identifier",
        ));
    }
    key.extend(INDEX_MAGIC)?;
    key.push(KEY_ENCODING_VERSION)?;
    key.extend(&index_id.to_be_bytes())?;
    encode_column_tuple(key, columns)
}

fn encode_column_tuple(
    output: &mut impl KeyWriter,
    columns: &[(&RelationalType, &RelationalValue)],
) -> Result<()> {
    let count = u16::try_from(columns.len())
        .map_err(|_| invalid("relational key contains too many columns"))?;
    output.extend(&count.to_be_bytes())?;
    for (data_type, value) in columns {
        encode_ordered_value(output, data_type, value)?;
    }
    Ok(())
}

pub(crate) fn encode_equality_value(value: &RelationalValue) -> Vec<u8> {
    let mut output = Vec::new();
    match value {
        RelationalValue::Null => output.push(TAG_NULL),
        RelationalValue::Boolean(value) => output.extend_from_slice(&[TAG_BOOL, u8::from(*value)]),
        RelationalValue::Integer(value) => {
            output.push(TAG_INTEGER);
            output.extend_from_slice(&value.to_be_bytes());
        }
        RelationalValue::Float(value) => {
            output.push(TAG_FLOAT64);
            let bits = if *value == 0.0 { 0 } else { value.to_bits() };
            output.extend_from_slice(&bits.to_be_bytes());
        }
        RelationalValue::Decimal(value) => {
            output.push(TAG_DECIMAL);
            append_framed(&mut output, canonical_decimal(value).as_bytes());
        }
        RelationalValue::Text(value) => {
            output.push(TAG_TEXT);
            append_framed(&mut output, value.as_bytes());
        }
        RelationalValue::Bytes(value) => {
            output.push(TAG_BYTES);
            append_framed(&mut output, value);
        }
        RelationalValue::Date(value) => {
            output.push(TAG_DATE);
            append_framed(&mut output, value.as_bytes());
        }
        RelationalValue::TimestampUtc(value) => {
            output.push(TAG_TIMESTAMP);
            let canonical = chrono::DateTime::parse_from_rfc3339(value)
                .map(|value| {
                    value
                        .to_utc()
                        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
                })
                .unwrap_or_else(|_| value.clone());
            append_framed(&mut output, canonical.as_bytes());
        }
        RelationalValue::Uuid(value) => {
            output.push(TAG_UUID);
            output.extend_from_slice(value.as_bytes());
        }
        RelationalValue::Json(value) => {
            output.push(TAG_JSONB);
            append_framed(
                &mut output,
                serde_json::to_string(value)
                    .unwrap_or_else(|_| "null".to_string())
                    .as_bytes(),
            );
        }
        RelationalValue::Vector(value) => {
            output.push(TAG_VECTOR);
            output.extend_from_slice(&(value.len() as u64).to_be_bytes());
            for component in value {
                let bits = if *component == 0.0 {
                    0
                } else {
                    component.to_bits()
                };
                output.extend_from_slice(&bits.to_be_bytes());
            }
        }
        RelationalValue::RecordRef(value) => {
            output.push(TAG_RECORD_REF);
            append_framed(&mut output, value.namespace.as_bytes());
            append_framed(&mut output, value.id.as_bytes());
        }
    }
    output
}

fn encode_ordered_value(
    output: &mut impl KeyWriter,
    data_type: &RelationalType,
    value: &RelationalValue,
) -> Result<()> {
    if matches!(value, RelationalValue::Null) {
        output.push(TAG_NULL)?;
        return Ok(());
    }
    match (data_type, value) {
        (RelationalType::Boolean, RelationalValue::Boolean(value)) => {
            output.extend(&[TAG_BOOL, u8::from(*value)])?;
        }
        (
            RelationalType::SmallInt | RelationalType::Integer | RelationalType::BigInt,
            RelationalValue::Integer(value),
        ) => {
            output.push(TAG_INTEGER)?;
            output.extend(&((*value as u64) ^ (1_u64 << 63)).to_be_bytes())?;
        }
        (RelationalType::Real, RelationalValue::Float(value)) => {
            let value = *value as f32;
            output.push(TAG_FLOAT32)?;
            output.extend(&ordered_f32(value).to_be_bytes())?;
        }
        (RelationalType::Float, RelationalValue::Float(value)) => {
            output.push(TAG_FLOAT64)?;
            output.extend(&ordered_f64(*value).to_be_bytes())?;
        }
        (RelationalType::Decimal { scale, .. }, RelationalValue::Decimal(value)) => {
            output.push(TAG_DECIMAL)?;
            let scaled = output.decimal(value, *scale)?;
            let mut bytes = scaled.to_be_bytes();
            bytes[0] ^= 0x80;
            output.extend(&bytes)?;
        }
        (RelationalType::Text | RelationalType::Varchar { .. }, RelationalValue::Text(value)) => {
            output.push(TAG_TEXT)?;
            append_escaped(output, value.as_bytes())?;
        }
        (RelationalType::Bytea, RelationalValue::Bytes(value)) => {
            output.push(TAG_BYTES)?;
            append_escaped(output, value)?;
        }
        (RelationalType::Date, RelationalValue::Date(value)) => {
            output.push(TAG_DATE)?;
            let date = chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
                .map_err(|_| invalid("invalid DATE in relational key"))?;
            let ordered = (date.num_days_from_ce() as u32) ^ (1_u32 << 31);
            output.extend(&ordered.to_be_bytes())?;
        }
        (RelationalType::TimestampUtc, RelationalValue::TimestampUtc(value)) => {
            output.push(TAG_TIMESTAMP)?;
            let timestamp = chrono::DateTime::parse_from_rfc3339(value)
                .map_err(|_| invalid("invalid TIMESTAMP in relational key"))?;
            let nanos = i128::from(timestamp.timestamp()) * 1_000_000_000
                + i128::from(timestamp.nanosecond());
            let mut bytes = nanos.to_be_bytes();
            bytes[0] ^= 0x80;
            output.extend(&bytes)?;
        }
        (RelationalType::Uuid, RelationalValue::Uuid(value)) => {
            output.push(TAG_UUID)?;
            output.extend(value.as_bytes())?;
        }
        (RelationalType::Jsonb, RelationalValue::Json(value)) => {
            output.push(TAG_JSONB)?;
            output.json_escaped(value)?;
        }
        (RelationalType::Vector { dimension }, RelationalValue::Vector(value)) => {
            if value.len() != *dimension {
                return Err(invalid(
                    "vector dimension does not match relational key type",
                ));
            }
            output.push(TAG_VECTOR)?;
            output.extend(&(*dimension as u32).to_be_bytes())?;
            for component in value {
                output.extend(&ordered_f32(*component).to_be_bytes())?;
            }
        }
        (RelationalType::RecordRef { namespace }, RelationalValue::RecordRef(value)) => {
            if &value.namespace != namespace {
                return Err(invalid(
                    "RECORD_REF namespace does not match relational key type",
                ));
            }
            output.push(TAG_RECORD_REF)?;
            append_escaped(output, value.namespace.as_bytes())?;
            append_escaped(output, value.id.as_bytes())?;
        }
        _ => {
            return Err(invalid(
                "relational key value does not match its declared type",
            ));
        }
    }
    Ok(())
}

fn ordered_f64(value: f64) -> u64 {
    let bits = if value == 0.0 { 0 } else { value.to_bits() };
    if bits & (1_u64 << 63) != 0 {
        !bits
    } else {
        bits ^ (1_u64 << 63)
    }
}

fn ordered_f32(value: f32) -> u32 {
    let bits = if value == 0.0 { 0 } else { value.to_bits() };
    if bits & (1_u32 << 31) != 0 {
        !bits
    } else {
        bits ^ (1_u32 << 31)
    }
}

fn scaled_decimal(value: &str, scale: u8) -> Result<i128> {
    let canonical = canonical_decimal(value);
    let (negative, unsigned) = canonical
        .strip_prefix('-')
        .map_or((false, canonical.as_str()), |value| (true, value));
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if fraction.len() > usize::from(scale) {
        return Err(invalid("decimal value exceeds declared scale"));
    }
    let mut digits = String::with_capacity(whole.len() + usize::from(scale));
    digits.push_str(if whole.is_empty() { "0" } else { whole });
    digits.push_str(fraction);
    digits.extend(std::iter::repeat_n(
        '0',
        usize::from(scale) - fraction.len(),
    ));
    let magnitude = digits
        .parse::<i128>()
        .map_err(|_| invalid("decimal value cannot be represented in a v1 key"))?;
    Ok(if negative { -magnitude } else { magnitude })
}

fn canonical_decimal(value: &str) -> String {
    let (negative, unsigned) = value
        .strip_prefix('-')
        .map_or((false, value), |value| (true, value));
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    let whole = whole.trim_start_matches('0');
    let whole = if whole.is_empty() { "0" } else { whole };
    let fraction = fraction.trim_end_matches('0');
    let zero = whole == "0" && fraction.is_empty();
    format!(
        "{}{}{}",
        if negative && !zero { "-" } else { "" },
        whole,
        if fraction.is_empty() {
            String::new()
        } else {
            format!(".{fraction}")
        }
    )
}

fn append_framed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn append_escaped<W: KeyWriter + ?Sized>(output: &mut W, value: &[u8]) -> Result<()> {
    for byte in value {
        if *byte == 0 {
            output.extend(&[0, 0xff])?;
        } else {
            output.push(*byte)?;
        }
    }
    output.extend(&[0, 0])
}

fn invalid(message: impl Into<String>) -> GaussError {
    GaussError::InvalidRequest(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relational::memory::{self, with_storage_pool};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct GoldenFixture {
        hidden_row_hex: String,
        primary_row_hex: String,
        index_hex: String,
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn v1_golden_bytes_are_frozen() {
        let fixture: GoldenFixture = serde_json::from_str(include_str!(
            "../../tests/fixtures/relational_key_encoding_v1.json"
        ))
        .unwrap();
        let integer_type = RelationalType::Integer;
        let text_type = RelationalType::Text;
        let integer = RelationalValue::Integer(-7);
        let text = RelationalValue::Text("a\0z".into());
        let columns = [(&integer_type, &integer), (&text_type, &text)];

        assert_eq!(
            hex(&encode_row_key_v1(42, RowIdentityKey::Hidden(7), 9).unwrap()),
            fixture.hidden_row_hex
        );
        assert_eq!(
            hex(&encode_row_key_v1(42, RowIdentityKey::Primary(&columns), 9).unwrap()),
            fixture.primary_row_hex
        );
        assert_eq!(
            hex(&encode_index_key_v1(91, &columns, 7, 9).unwrap()),
            fixture.index_hex
        );
    }

    #[test]
    fn ordered_values_and_inverted_sequences_follow_byte_order() {
        let integer_type = RelationalType::Integer;
        let values = [-9, -1, 0, 1, 20]
            .into_iter()
            .map(RelationalValue::Integer)
            .collect::<Vec<_>>();
        let keys = values
            .iter()
            .map(|value| encode_index_key_v1(1, &[(&integer_type, value)], 1, 1).unwrap())
            .collect::<Vec<_>>();
        assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));

        let newest = encode_row_key_v1(1, RowIdentityKey::Hidden(1), 11).unwrap();
        let older = encode_row_key_v1(1, RowIdentityKey::Hidden(1), 10).unwrap();
        assert!(newest < older, "newest MVCC version must sort first");
    }

    #[test]
    fn binary_collation_and_decimal_scale_are_canonical() {
        let text_type = RelationalType::Text;
        let strings = ["a", "a\0", "aa", "b"]
            .into_iter()
            .map(|value| RelationalValue::Text(value.into()))
            .collect::<Vec<_>>();
        let keys = strings
            .iter()
            .map(|value| encode_index_key_v1(1, &[(&text_type, value)], 1, 1).unwrap())
            .collect::<Vec<_>>();
        assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));

        let decimal_type = RelationalType::Decimal {
            precision: 10,
            scale: 2,
        };
        let one = RelationalValue::Decimal("1.0".into());
        let same = RelationalValue::Decimal("1.00".into());
        assert_eq!(
            encode_index_key_v1(1, &[(&decimal_type, &one)], 1, 1).unwrap(),
            encode_index_key_v1(1, &[(&decimal_type, &same)], 1, 1).unwrap()
        );
    }

    #[test]
    fn admitted_keys_match_frozen_encoder_for_all_ordered_value_families() {
        let cases = [
            (RelationalType::Boolean, RelationalValue::Boolean(true)),
            (RelationalType::Integer, RelationalValue::Integer(-7)),
            (RelationalType::Real, RelationalValue::Float(-2.5)),
            (RelationalType::Float, RelationalValue::Float(3.25)),
            (
                RelationalType::Decimal {
                    precision: 10,
                    scale: 2,
                },
                RelationalValue::Decimal("-001.20".into()),
            ),
            (RelationalType::Text, RelationalValue::Text("a\0z".into())),
            (RelationalType::Bytea, RelationalValue::Bytes(vec![0, 255])),
            (
                RelationalType::Date,
                RelationalValue::Date("2026-09-25".into()),
            ),
            (
                RelationalType::TimestampUtc,
                RelationalValue::TimestampUtc("2026-09-25T12:00:00+07:00".into()),
            ),
            (
                RelationalType::Uuid,
                RelationalValue::Uuid(uuid::Uuid::nil()),
            ),
            (
                RelationalType::Jsonb,
                RelationalValue::Json(serde_json::json!({"quoted": "\u{0000}", "n": 2})),
            ),
            (
                RelationalType::Vector { dimension: 3 },
                RelationalValue::Vector(vec![-1.0, 0.0, 2.0]),
            ),
            (
                RelationalType::RecordRef {
                    namespace: "docs".into(),
                },
                RelationalValue::RecordRef(crate::RecordRef {
                    namespace: "docs".into(),
                    id: "a\0b".into(),
                }),
            ),
        ];
        with_storage_pool(1024 * 1024, |pool| {
            for (data_type, value) in &cases {
                let columns = [(data_type, value)];
                let plain = encode_index_key_v1(7, &columns, 11, 13).unwrap();
                let key = encode_index_key_v1_admitted(7, &columns, 11, 13).unwrap();
                assert_eq!(key.as_slice(), plain);
                assert_eq!(
                    pool.used(),
                    key.capacity() as u64 + RECORD_OWNER_BYTES + memory::LEASE_ROOT_BYTES
                );
                let clone = key.clone();
                drop(key);
                assert!(pool.used() > 0);
                drop(clone);
                assert_eq!(pool.used(), 0);
                let plain = encode_row_key_v1(3, RowIdentityKey::Primary(&columns), 13).unwrap();
                let key =
                    encode_row_key_v1_admitted(3, RowIdentityKey::Primary(&columns), 13).unwrap();
                assert_eq!(key.as_slice(), plain);
                drop(key);
                assert_eq!(pool.used(), 0);
            }
            let plain = encode_row_key_v1(3, RowIdentityKey::Hidden(11), 13).unwrap();
            let key = encode_row_key_v1_admitted(3, RowIdentityKey::Hidden(11), 13).unwrap();
            assert_eq!(key.as_slice(), plain);
            drop(key);
            assert_eq!(pool.used(), 0);
        });
    }

    #[test]
    fn admitted_key_growth_and_json_scratch_refuse_without_retained_bytes() {
        let data_type = RelationalType::Text;
        let text = RelationalValue::Text("\0".repeat(16 * 1024));
        let columns = [(&data_type, &text)];
        with_storage_pool(16 * 1024, |pool| {
            assert!(matches!(
                encode_index_key_v1_admitted(7, &columns, 11, 13),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(pool.used(), 0);
        });
        let plain = encode_index_key_v1(7, &columns, 11, 13).unwrap();
        with_storage_pool(128 * 1024, |pool| {
            let key = encode_index_key_v1_admitted(7, &columns, 11, 13).unwrap();
            assert_eq!(key.as_slice(), plain);
            drop(key);
            assert_eq!(pool.used(), 0);
        });

        let data_type = RelationalType::Jsonb;
        let value = RelationalValue::Json(serde_json::json!({"payload": "x".repeat(8192)}));
        let columns = [(&data_type, &value)];
        with_storage_pool(1024, |pool| {
            assert!(matches!(
                encode_row_key_v1_admitted(3, RowIdentityKey::Primary(&columns), 13),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(pool.used(), 0);
        });
    }

    #[test]
    fn invalid_admitted_key_values_release_partial_output() {
        let cases = [
            (
                RelationalType::Decimal {
                    precision: 10,
                    scale: 2,
                },
                RelationalValue::Decimal("1.234".into()),
            ),
            (
                RelationalType::Vector { dimension: 2 },
                RelationalValue::Vector(vec![1.0]),
            ),
            (
                RelationalType::RecordRef {
                    namespace: "docs".into(),
                },
                RelationalValue::RecordRef(crate::RecordRef {
                    namespace: "elsewhere".into(),
                    id: "1".into(),
                }),
            ),
        ];
        with_storage_pool(1024 * 1024, |pool| {
            for (data_type, value) in &cases {
                assert!(matches!(
                    encode_index_key_v1_admitted(7, &[(data_type, value)], 11, 13),
                    Err(GaussError::InvalidRequest(_))
                ));
                assert_eq!(pool.used(), 0);
            }
        });
    }

    #[test]
    fn admitted_key_handoff_to_sorter_keeps_one_payload_lease_and_v1_bytes() {
        use crate::relational::{checkpoint::sort::Sorter, segment::SegmentRecord};
        let directory = tempfile::tempdir().unwrap();
        let data_type = RelationalType::Text;
        let value = RelationalValue::Text("a\0b".repeat(100));
        let columns = [(&data_type, &value)];
        let expected = encode_index_key_v1(7, &columns, 11, 13).unwrap();
        with_storage_pool(256 * 1024, |pool| {
            let key = encode_index_key_v1_admitted(7, &columns, 11, 13).unwrap();
            let key_charge = pool.used();
            let record = SegmentRecord::json_admitted(key, &"payload").unwrap();
            let record_charge = pool.used();
            assert_eq!(
                record_charge,
                key_charge
                    + record.value.capacity() as u64
                    + RECORD_OWNER_BYTES
                    + memory::LEASE_ROOT_BYTES
            );
            let mut sorter = Sorter::locator(directory.path(), 1).unwrap();
            let slots = pool.used() - record_charge;
            sorter.push(record).unwrap();
            assert_eq!(pool.used(), record_charge + slots);
            let sorted = sorter.finish().unwrap();
            assert_eq!(pool.used(), 0);
            let reader = sorted.into_reader().unwrap();
            let found = reader.cursor().next().unwrap().unwrap();
            assert_eq!(found.key.as_slice(), expected);
            assert_eq!(found.value.as_slice(), b"\"payload\"");
            drop(found);
            drop(reader);
            assert_eq!(pool.used(), 0);
        });
    }

    #[test]
    fn cancelled_key_growth_keeps_the_existing_reservation_until_drop() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        with_storage_pool(64 * 1024, |pool| {
            let mut key = AdmittedKey::new().unwrap();
            key.extend(&vec![b'x'; 4096]).unwrap();
            let held = pool.used();
            let cancelled = Arc::new(AtomicBool::new(false));
            let error = super::super::with_sql_cancellation(Arc::clone(&cancelled), || {
                cancelled.store(true, Ordering::Release);
                key.extend(b"y")
            })
            .unwrap_err();
            assert!(error.to_string().contains("query canceled"));
            assert_eq!(key.bytes.len(), 4096);
            assert_eq!(pool.used(), held);
            drop(key);
            assert_eq!(pool.used(), 0);
        });
    }
}
