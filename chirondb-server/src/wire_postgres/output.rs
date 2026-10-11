//! PostgreSQL receiving metadata and rows are admitted before allocation.
//! Source SQL/catalog ownership and TLS/socket buffers have separate lifetimes.
use super::{ColumnSpec, MAX_MESSAGE_LEN, PgType, relational_pg_type};
use crate::response_buffer::{ResponseBuffer, ResponseReservation};
use crate::{RelationalType, RelationalValue as V, SqlResult};
use std::{fmt, io, mem::size_of};
use tokio::io::{AsyncWrite, AsyncWriteExt};

#[derive(Debug)]
struct Refusal {
    state: &'static str,
    message: &'static str,
}
impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for Refusal {}
pub(super) fn full() -> io::Error {
    io::Error::other(Refusal {
        state: "53200",
        message: "PostgreSQL response memory limit exceeded",
    })
}
fn too_large() -> io::Error {
    io::Error::other(Refusal {
        state: "54000",
        message: "PostgreSQL response message limit exceeded",
    })
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
pub(super) fn reserve(bytes: usize) -> io::Result<ResponseReservation> {
    ResponseReservation::new(u64::try_from(bytes).map_err(|_| full())?).map_err(|_| full())
}
fn add(a: usize, b: usize) -> io::Result<usize> {
    a.checked_add(b).ok_or_else(too_large)
}

pub(super) struct Columns {
    values: Vec<ColumnSpec>,
    _memory: ResponseReservation,
}
impl std::ops::Deref for Columns {
    type Target = [ColumnSpec];
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
impl Columns {
    pub(super) fn sql(names: &[String], types: &[RelationalType]) -> io::Result<Self> {
        if names.len() != types.len() {
            return Err(invalid("SQL column/type count does not match"));
        }
        let mut bytes = names
            .len()
            .checked_mul(size_of::<ColumnSpec>() + 64)
            .and_then(|n| n.checked_add(512))
            .ok_or_else(full)?;
        for name in names {
            bytes = add(bytes, name.len())?;
        }
        let memory = reserve(bytes)?;
        let mut values = Vec::new();
        values.try_reserve_exact(names.len()).map_err(|_| full())?;
        for (name, data_type) in names.iter().zip(types) {
            values.push(ColumnSpec {
                name: name.clone(),
                pg_type: relational_pg_type(data_type),
            });
        }
        Ok(Self {
            values,
            _memory: memory,
        })
    }
    pub(super) fn explain() -> io::Result<Self> {
        let memory = reserve(size_of::<ColumnSpec>() + 512)?;
        Ok(Self {
            values: vec![ColumnSpec {
                name: "QUERY PLAN".into(),
                pg_type: PgType::Text,
            }],
            _memory: memory,
        })
    }
    pub(super) fn first(results: &[SqlResult]) -> io::Result<Option<Self>> {
        match results.first() {
            Some(SqlResult::Rows {
                columns,
                column_types,
                ..
            }) => Self::sql(columns, column_types).map(Some),
            Some(SqlResult::Explain { .. }) => Self::explain().map(Some),
            _ => Ok(None),
        }
    }
}
#[derive(Debug)]
pub(super) struct Formats {
    values: Vec<i16>,
    _memory: ResponseReservation,
}
impl std::ops::Deref for Formats {
    type Target = [i16];
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
impl<const N: usize> PartialEq<[i16; N]> for Formats {
    fn eq(&self, other: &[i16; N]) -> bool {
        self.values == other
    }
}
impl Formats {
    pub(super) fn new(requested: &[i16], count: usize) -> io::Result<Self> {
        if requested.len() > 1 && requested.len() != count {
            return Err(invalid(
                "PostgreSQL result format count must be zero, one, or match the column count",
            ));
        }
        if requested.iter().any(|v| !matches!(v, 0 | 1)) {
            return Err(invalid("unknown PostgreSQL result format"));
        }
        let memory = reserve(
            count
                .checked_mul(size_of::<i16>())
                .and_then(|n| n.checked_add(512))
                .ok_or_else(full)?,
        )?;
        let mut values = Vec::new();
        values.try_reserve_exact(count).map_err(|_| full())?;
        match requested {
            [] => values.resize(count, 0),
            [format] => values.resize(count, *format),
            _ => values.extend_from_slice(requested),
        }
        Ok(Self {
            values,
            _memory: memory,
        })
    }
}
pub(super) fn input_full() -> io::Error {
    io::Error::other(Refusal {
        state: "53200",
        message: "PostgreSQL frontend memory limit exceeded",
    })
}
pub(super) fn input(length: usize, limit: usize) -> io::Result<ResponseBuffer> {
    if length > limit {
        return Err(too_large());
    }
    ResponseBuffer::allocate(length, limit).map_err(|_| input_full())
}
pub(super) fn frame(kind: u8, payload: usize) -> io::Result<ResponseBuffer> {
    let message = add(payload, 4)?;
    if message > MAX_MESSAGE_LEN {
        return Err(too_large());
    }
    let mut frame =
        ResponseBuffer::allocate(add(message, 1)?, MAX_MESSAGE_LEN + 1).map_err(|_| full())?;
    frame.as_mut()[0] = kind;
    frame.as_mut()[1..5].copy_from_slice(&(message as u32).to_be_bytes());
    Ok(frame)
}

// Small control replies must remain reachable when receiving memory is full.
// Fixed stack backing has no heap admission; larger metadata/errors retain the
// same accounted frame owner as rows. Both expose only their exact wire slice.
pub(super) struct ControlFrame {
    bytes: [u8; 1024],
    len: usize,
    owned: Option<ResponseBuffer>,
}
impl AsRef<[u8]> for ControlFrame {
    fn as_ref(&self) -> &[u8] {
        self.owned
            .as_ref()
            .map_or(&self.bytes[..self.len], AsRef::as_ref)
    }
}
impl AsMut<[u8]> for ControlFrame {
    fn as_mut(&mut self) -> &mut [u8] {
        self.owned
            .as_mut()
            .map_or(&mut self.bytes[..self.len], AsMut::as_mut)
    }
}
pub(super) fn control(kind: u8, payload: usize) -> io::Result<ControlFrame> {
    let message = add(payload, 4)?;
    if message > MAX_MESSAGE_LEN {
        return Err(too_large());
    }
    let len = add(message, 1)?;
    if len > 1024 {
        return Ok(ControlFrame {
            bytes: [0; 1024],
            len: 0,
            owned: Some(frame(kind, payload)?),
        });
    }
    let mut bytes = [0; 1024];
    bytes[0] = kind;
    bytes[1..5].copy_from_slice(&(message as u32).to_be_bytes());
    Ok(ControlFrame {
        bytes,
        len,
        owned: None,
    })
}
pub(super) fn description(columns: &[ColumnSpec], formats: &[i16]) -> io::Result<ResponseBuffer> {
    if columns.len() != formats.len() {
        return Err(invalid(
            "PostgreSQL result format count does not match columns",
        ));
    }
    let count = u16::try_from(columns.len()).map_err(|_| too_large())?;
    let mut length = 2;
    for col in columns {
        if col.name.contains('\0') {
            return Err(invalid("PostgreSQL column name contains NUL"));
        }
        length = add(length, add(col.name.len(), 19)?)?;
    }
    let mut owner = frame(b'T', length)?;
    let bytes = owner.as_mut();
    bytes[5..7].copy_from_slice(&count.to_be_bytes());
    let mut offset = 7;
    for (col, format) in columns.iter().zip(formats) {
        put(bytes, &mut offset, col.name.as_bytes());
        put(bytes, &mut offset, &[0]);
        put(bytes, &mut offset, &0_u32.to_be_bytes());
        put(bytes, &mut offset, &0_u16.to_be_bytes());
        put(bytes, &mut offset, &col.pg_type.oid().to_be_bytes());
        put(bytes, &mut offset, &col.pg_type.typlen().to_be_bytes());
        put(bytes, &mut offset, &(-1_i32).to_be_bytes());
        put(bytes, &mut offset, &format.to_be_bytes());
    }
    debug_assert_eq!(offset, bytes.len());
    Ok(owner)
}
fn put(bytes: &mut [u8], offset: &mut usize, value: &[u8]) {
    bytes[*offset..*offset + value.len()].copy_from_slice(value);
    *offset += value.len();
}

enum Cell<'a> {
    Null,
    Borrowed(&'a [u8]),
    Buffer(ResponseBuffer, bool),
    Legacy {
        bytes: Vec<u8>,
        _memory: ResponseReservation,
    },
}
impl Cell<'_> {
    fn payload(&self) -> Option<(&[u8], bool)> {
        match self {
            Self::Null => None,
            Self::Borrowed(bytes) => Some((bytes, false)),
            Self::Buffer(bytes, prefix) => Some((bytes.as_ref(), *prefix)),
            Self::Legacy { bytes, .. } => Some((bytes, false)),
        }
    }
}
fn legacy_cell(
    bytes: usize,
    encode: impl FnOnce() -> io::Result<Vec<u8>>,
) -> io::Result<Cell<'static>> {
    // Covers legacy numeric padding/digit arrays and array split/unescape/child
    // buffers, geometric old/new overlap, output bytes and smallest allocations.
    // Scalar JSON validation uses no owned Value (see JsonValidation below).
    let memory = reserve(bytes)?;
    Ok(Cell::Legacy {
        bytes: encode()?,
        _memory: memory,
    })
}
fn scratch(length: usize, pg_type: PgType) -> io::Result<usize> {
    if length > MAX_MESSAGE_LEN {
        return Err(too_large());
    }
    let multiplier = if matches!(
        pg_type,
        PgType::TextArray | PgType::BoolArray | PgType::Int2Array
    ) {
        64
    } else {
        12
    };
    length
        .checked_mul(multiplier)
        .and_then(|n| n.checked_add(4096))
        .ok_or_else(full)
}
fn json_cell(value: &impl serde::Serialize, prefix: bool) -> io::Result<Cell<'static>> {
    ResponseBuffer::json_native(value, MAX_MESSAGE_LEN)
        .map(|bytes| Cell::Buffer(bytes, prefix))
        .map_err(|_| full())
}
fn sql_cell<'a>(value: &'a V, pg_type: PgType, format: i16) -> io::Result<Cell<'a>> {
    if matches!(value, V::Null) {
        return Ok(Cell::Null);
    }
    match format {
        0 => match value {
            V::Decimal(s) | V::Text(s) | V::Date(s) | V::TimestampUtc(s) => {
                Ok(Cell::Borrowed(s.as_bytes()))
            }
            V::Json(value) => json_cell(value, false),
            V::Vector(value) => json_cell(value, false),
            V::RecordRef(value) => json_cell(value, false),
            V::Bytes(value) => {
                let length = value
                    .len()
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(2))
                    .ok_or_else(too_large)?;
                if length > MAX_MESSAGE_LEN {
                    return Err(too_large());
                }
                let mut owner =
                    ResponseBuffer::allocate(length, MAX_MESSAGE_LEN).map_err(|_| full())?;
                let out = owner.as_mut();
                out[..2].copy_from_slice(b"\\x");
                let hex = b"0123456789abcdef";
                for (i, byte) in value.iter().enumerate() {
                    out[2 + i * 2] = hex[(byte >> 4) as usize];
                    out[3 + i * 2] = hex[(byte & 15) as usize];
                }
                Ok(Cell::Buffer(owner, false))
            }
            _ => legacy_cell(4096, || {
                Ok(super::relational_text_value(value)
                    .expect("non-null scalar")
                    .into_bytes())
            }),
        },
        1 => match (value, pg_type) {
            (V::Text(value), PgType::Text | PgType::Varchar) => {
                Ok(Cell::Borrowed(value.as_bytes()))
            }
            (V::Bytes(value), PgType::Bytea) => Ok(Cell::Borrowed(value)),
            (V::Json(value), PgType::Jsonb) => json_cell(value, true),
            (V::RecordRef(value), PgType::Jsonb) => json_cell(value, true),
            (V::Vector(value), PgType::Text) => json_cell(value, false),
            (V::Decimal(value), PgType::Numeric) => {
                legacy_cell(scratch(value.len(), pg_type)?, || {
                    super::encode_pg_numeric(value)
                })
            }
            (V::Boolean(_), PgType::Bool)
            | (V::Integer(_), PgType::Int2 | PgType::Int4 | PgType::Int8)
            | (V::Float(_), PgType::Float4 | PgType::Float8)
            | (V::Date(_), PgType::Date)
            | (V::TimestampUtc(_), PgType::TimestampTz)
            | (V::Uuid(_), PgType::Uuid) => {
                legacy_cell(4096, || super::encode_relational_binary(value, pg_type))
            }
            _ => Err(invalid(
                "relational value does not match PostgreSQL result type",
            )),
        },
        _ => Err(invalid("unknown PostgreSQL result format")),
    }
}
fn cells<'a>(
    count: usize,
    mut encode: impl FnMut(usize) -> io::Result<Cell<'a>>,
) -> io::Result<ResponseBuffer> {
    let count_wire = u16::try_from(count).map_err(|_| too_large())?;
    let _memory = reserve(
        count
            .checked_mul(size_of::<Cell>())
            .and_then(|n| n.checked_add(512))
            .ok_or_else(full)?,
    )?;
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| full())?;
    let mut length = 2;
    for i in 0..count {
        let cell = encode(i)?;
        let cell_len = cell.payload().map_or(Ok(0), |(bytes, prefix)| {
            add(bytes.len(), usize::from(prefix))
        })?;
        i32::try_from(cell_len).map_err(|_| too_large())?;
        length = add(length, add(4, cell_len)?)?;
        if add(length, 4)? > MAX_MESSAGE_LEN {
            return Err(too_large());
        }
        values.push(cell);
    }
    let mut owner = frame(b'D', length)?;
    let bytes = owner.as_mut();
    bytes[5..7].copy_from_slice(&count_wire.to_be_bytes());
    let mut offset = 7;
    for cell in &values {
        match cell.payload() {
            None => put(bytes, &mut offset, &(-1_i32).to_be_bytes()),
            Some((value, prefix)) => {
                put(
                    bytes,
                    &mut offset,
                    &((value.len() + usize::from(prefix)) as i32).to_be_bytes(),
                );
                if prefix {
                    put(bytes, &mut offset, &[1]);
                }
                put(bytes, &mut offset, value);
            }
        }
    }
    debug_assert_eq!(offset, bytes.len());
    Ok(owner)
}
pub(super) fn sql_row(
    row: &[V],
    columns: &[ColumnSpec],
    formats: &[i16],
) -> io::Result<ResponseBuffer> {
    if row.len() != columns.len() || row.len() != formats.len() {
        return Err(invalid(
            "relational row shape does not match its PostgreSQL description",
        ));
    }
    cells(row.len(), |i| {
        sql_cell(&row[i], columns[i].pg_type, formats[i])
    })
}
pub(super) fn text_row(
    row: &[Option<String>],
    columns: &[ColumnSpec],
    formats: &[i16],
) -> io::Result<ResponseBuffer> {
    if row.len() != columns.len() || row.len() != formats.len() {
        return Err(invalid(
            "PostgreSQL row shape does not match its description",
        ));
    }
    cells(row.len(), |i| match (&row[i], formats[i]) {
        (None, _) => Ok(Cell::Null),
        (Some(value), 0) => Ok(Cell::Borrowed(value.as_bytes())),
        (Some(value), 1) if matches!(columns[i].pg_type, PgType::Text | PgType::Varchar) => {
            Ok(Cell::Borrowed(value.as_bytes()))
        }
        (Some(value), 1) => legacy_cell(scratch(value.len(), columns[i].pg_type)?, || {
            super::encode_pg_binary_text(columns[i].pg_type, value)
        }),
        _ => Err(invalid("unknown PostgreSQL result format")),
    })
}
pub(super) fn simple_row(row: &[Option<String>]) -> io::Result<ResponseBuffer> {
    cells(row.len(), |i| {
        Ok(row[i]
            .as_ref()
            .map_or(Cell::Null, |s| Cell::Borrowed(s.as_bytes())))
    })
}
pub(super) fn explain_row(value: &str, format: i16) -> io::Result<ResponseBuffer> {
    if !matches!(format, 0 | 1) {
        return Err(invalid("unknown PostgreSQL result format"));
    }
    cells(1, |_| Ok(Cell::Borrowed(value.as_bytes())))
}
/// The fixed ERROR frame needs no heap or admission, so overload can be reported
/// while the shared receiving pool is full. The connection then closes rather
/// than claiming successful publication or automatically replaying a mutation.
pub(super) async fn prepare<T, W: AsyncWrite + Unpin>(
    writer: &mut W,
    owner: io::Result<T>,
) -> io::Result<T> {
    match owner {
        Ok(owner) => Ok(owner),
        Err(error) => {
            if let Some(refusal) = error.get_ref().and_then(|e| e.downcast_ref::<Refusal>()) {
                let mut bytes = [0_u8; 256];
                let mut pos = 5;
                bytes[0] = b'E';
                for (code, value) in [
                    (b'S', "ERROR"),
                    (b'C', refusal.state),
                    (b'M', refusal.message),
                ] {
                    put(&mut bytes, &mut pos, &[code]);
                    put(&mut bytes, &mut pos, value.as_bytes());
                    put(&mut bytes, &mut pos, &[0]);
                }
                put(&mut bytes, &mut pos, &[0]);
                bytes[1..5].copy_from_slice(&((pos - 1) as u32).to_be_bytes());
                writer.write_all(&bytes[..pos]).await?;
                // TLS/buffered writers can accept plaintext before delivering
                // it. Flush the refusal before returning the connection error.
                writer.flush().await?;
            }
            Err(error)
        }
    }
}

pub(super) async fn send<W: AsyncWrite + Unpin>(
    writer: &mut W,
    owner: io::Result<ResponseBuffer>,
) -> io::Result<()> {
    let owner = prepare(writer, owner).await?;
    writer.write_all(owner.as_ref()).await
}

// Match Value's parser validation (including finite numbers and recursion limit)
// without allocating a complete second Value merely to encode trusted text.
struct JsonValidation;
impl<'de> serde::de::DeserializeSeed<'de> for JsonValidation {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
        decoder.deserialize_any(self)
    }
}
impl<'de> serde::de::Visitor<'de> for JsonValidation {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("JSON value")
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<(), E> {
        if value.is_finite() {
            Ok(())
        } else {
            Err(E::custom("nonfinite JSON number"))
        }
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        while values.next_element_seed(JsonValidation)?.is_some() {}
        Ok(())
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        while values.next_key_seed(JsonValidation)?.is_some() {
            values.next_value_seed(JsonValidation)?;
        }
        Ok(())
    }
}
pub(super) fn validate_json(value: &str) -> io::Result<()> {
    use serde::de::DeserializeSeed;
    let mut decoder = serde_json::Deserializer::from_str(value);
    JsonValidation
        .deserialize(&mut decoder)
        .and_then(|()| decoder.end())
        .map_err(|_| invalid("invalid JSONB result"))
}
#[cfg(test)]
mod tests;
