//! Explicit receiving/operation memory follows the unique ChironQL result.
//! Initial non-SQL engine/JSON construction has its separate working set.
use crate::response_buffer::{ResponseBuffer, ResponseReservation};
use crate::{GaussError, RelationalValue as V, Result, SqlResult};
use chirondb_types::chironql::{ChironQlError, ChironQlResponse};
use serde_json::Value;
use std::mem::size_of;
#[cfg(test)]
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// DTO with unique receiving admission. Embedded `into_dto` assumes the budget;
/// server consumers keep this owner until an admitted receiver takes its data.
#[derive(Debug)]
pub struct QueryResult {
    value: ChironQlResponse,
    memory: QueryMemory,
}
impl std::ops::Deref for QueryResult {
    type Target = ChironQlResponse;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
impl serde::Serialize for QueryResult {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.value.serialize(serializer)
    }
}
impl QueryResult {
    pub(crate) fn new(value: ChironQlResponse, memory: QueryMemory) -> Self {
        Self { value, memory }
    }
    pub fn into_dto(self) -> ChironQlResponse {
        self.value
    }
    pub fn consume<T>(self, consumer: impl FnOnce(ChironQlResponse) -> T) -> Result<T> {
        let Self { value, memory } = self;
        memory.check()?;
        Ok(consumer(value))
    }
}

/// Conservative receiving/operation bounds are accumulated explicitly before
/// growth, including old/new overlap. They remain with the result after the
/// request. This avoids a collector allocation or hidden thread-local owner.
#[derive(Debug)]
pub(crate) struct QueryMemory {
    bytes: u64,
    cancellation: Option<crate::security::IdentityCancellation>,
    #[cfg(test)]
    test_cancellation: Option<Arc<AtomicBool>>,
    _memory: ResponseReservation,
}
impl QueryMemory {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            bytes: 4096,
            cancellation: None,
            #[cfg(test)]
            test_cancellation: None,
            _memory: ResponseReservation::new(4096)?,
        })
    }
    pub(crate) fn cancel_identity(&mut self, identity: &crate::security::AuthenticatedIdentity) {
        self.cancellation = Some(identity.cancellation());
    }
    #[cfg(test)]
    pub(crate) fn bytes_for_test(&self) -> u64 {
        self.bytes
    }
    #[cfg(test)]
    pub(crate) fn cancel_with(&mut self, flag: Arc<AtomicBool>) {
        self.test_cancellation = Some(flag);
    }
    pub(crate) fn check(&self) -> Result<()> {
        #[cfg(test)]
        if self
            .test_cancellation
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            return Err(GaussError::InvalidRequest("query canceled".into()));
        }
        if self
            .cancellation
            .as_ref()
            .is_some_and(crate::security::IdentityCancellation::is_cancelled)
        {
            Err(GaussError::InvalidRequest("query canceled".into()))
        } else {
            Ok(())
        }
    }
    pub(crate) fn admit(&mut self, bytes: u64) -> Result<()> {
        self.check()?;
        let next = self.bytes.checked_add(bytes).ok_or_else(full)?;
        self._memory.prepare(next)?;
        self.bytes = next;
        Ok(())
    }
    pub(crate) fn ql(&mut self, bytes: u64, id: &str) -> std::result::Result<(), ChironQlError> {
        self.admit(bytes).map_err(|e| error(id, e))
    }
    pub(crate) fn response(&mut self, value: &ChironQlResponse) -> Result<()> {
        self.admit(response_bytes(value, &|| self.check())?)
    }
    pub(crate) fn metadata(&mut self, value: &ChironQlResponse) -> Result<()> {
        let mut bytes = 4096;
        for string in std::iter::once(&value.query_id)
            .chain(value.next.iter())
            .chain(value.snapshot_id.iter())
            .chain(value.transaction_id.iter())
        {
            bytes = add(bytes, string.capacity() as u64)?;
        }
        bytes = add(
            bytes,
            (value.domains.capacity() as u64)
                * size_of::<chirondb_types::chironql::ExecutionDomain>() as u64,
        )?;
        if let Some(trace) = &value.trace {
            bytes = add(bytes, trace.query_id.capacity() as u64)?;
            bytes = add(
                bytes,
                (trace.stages.capacity() as u64)
                    * size_of::<chirondb_types::chironql::TraceStage>() as u64,
            )?;
            for stage in &trace.stages {
                bytes = add(bytes, stage.name.capacity() as u64)?;
                if let chirondb_types::chironql::StageOutcome::Failed { code, message } =
                    &stage.outcome
                {
                    bytes = add(bytes, (code.capacity() + message.capacity()) as u64)?;
                }
                if let Some(value) = &stage.detail {
                    bytes = add(bytes, self.json_heap(value)?)?
                }
            }
        }
        if let Some(credential) = &value.credential {
            bytes = add(
                bytes,
                (credential.id.capacity() + credential.secret.capacity()) as u64,
            )?;
        }
        self.admit(bytes)
    }
    pub(crate) fn json_heap(&self, value: &Value) -> Result<u64> {
        json_heap_checked(value, &|| self.check())
    }
    pub(crate) fn sql(&mut self, value: &crate::SqlExecutionResponse) -> Result<()> {
        let mut bytes = 4096;
        if let Some(id) = &value.transaction_id {
            bytes = add(bytes, id.capacity() as u64)?;
        }
        if let Some(result) = value.results.first() {
            match result {
                SqlResult::Rows {
                    columns,
                    column_types,
                    rows,
                } => {
                    bytes = add(
                        bytes,
                        (columns.capacity() as u64) * size_of::<String>() as u64,
                    )?;
                    for column in columns {
                        bytes = add(bytes, column.capacity() as u64)?;
                    }
                    bytes = add(
                        bytes,
                        (column_types.capacity() as u64)
                            * size_of::<crate::RelationalType>() as u64,
                    )?;
                    for data_type in column_types {
                        bytes = add(bytes, type_heap(data_type))?;
                    }
                    bytes = add(bytes, (rows.len() as u64) * size_of::<Value>() as u64)?;
                    for row in rows {
                        self.check()?;
                        for (column, value) in columns.iter().zip(row) {
                            bytes = add(bytes, 1024 + column.capacity() as u64)?;
                            bytes = add(bytes, sql_json_heap(value, &|| self.check())?)?;
                        }
                    }
                }
                SqlResult::Explain { plan } => {
                    bytes = add(
                        bytes,
                        (plan.len() as u64) * (size_of::<Value>() as u64 + 1024),
                    )?;
                    for line in plan {
                        bytes = add(bytes, line.capacity() as u64)?;
                    }
                }
                _ => {}
            }
        }
        self.admit(bytes)
    }
}

pub(crate) fn error(id: &str, failure: GaussError) -> ChironQlError {
    ChironQlError {
        error: failure.to_string(),
        code: if matches!(failure, GaussError::ResourceExhausted(_)) {
            "chironql.resource_exhausted"
        } else {
            "chironql.invalid_request"
        }
        .into(),
        hint: None,
        position: None,
        affected_estimate: None,
        query_id: id.into(),
        trace: None,
    }
}
pub(crate) fn full() -> GaussError {
    GaussError::ResourceExhausted("ChironQL result memory limit exceeded".into())
}
pub(crate) fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or_else(full)
}
pub(crate) fn type_heap(value: &crate::RelationalType) -> u64 {
    if let crate::RelationalType::RecordRef { namespace } = value {
        namespace.capacity() as u64
    } else {
        0
    }
}
fn json_heap_checked(value: &Value, check: &impl Fn() -> Result<()>) -> Result<u64> {
    check()?;
    match value {
        Value::String(value) => Ok(value.capacity() as u64),
        Value::Array(values) => {
            let mut bytes = (values.capacity() as u64)
                .checked_mul(size_of::<Value>() as u64)
                .ok_or_else(full)?;
            for value in values {
                bytes = add(bytes, json_heap_checked(value, check)?)?;
            }
            Ok(bytes)
        }
        Value::Object(values) => {
            let mut bytes = (values.len() as u64).checked_mul(1024).ok_or_else(full)?;
            for (key, value) in values {
                bytes = add(bytes, key.capacity() as u64)?;
                bytes = add(bytes, json_heap_checked(value, check)?)?;
            }
            Ok(bytes)
        }
        _ => Ok(0),
    }
}
fn sql_json_heap(value: &V, check: &impl Fn() -> Result<()>) -> Result<u64> {
    Ok(match value {
        V::Decimal(s) | V::Text(s) | V::Date(s) | V::TimestampUtc(s) => s.capacity() as u64,
        V::Uuid(_) => 128,
        V::Json(value) => json_heap_checked(value, check)?,
        V::Bytes(values) => (values.len() as u64)
            .checked_mul(size_of::<Value>() as u64)
            .ok_or_else(full)?,
        V::Vector(values) => (values.len() as u64)
            .checked_mul(size_of::<Value>() as u64)
            .ok_or_else(full)?,
        V::RecordRef(value) => add(
            2048,
            (value.namespace.capacity() + value.id.capacity()) as u64,
        )?,
        _ => 0,
    })
}
fn response_bytes(value: &ChironQlResponse, check: &impl Fn() -> Result<()>) -> Result<u64> {
    let mut bytes = 4096;
    bytes = add(
        bytes,
        (value.columns.capacity() as u64) * size_of::<String>() as u64,
    )?;
    for column in &value.columns {
        bytes = add(bytes, column.capacity() as u64)?;
    }
    bytes = add(
        bytes,
        (value.column_types.capacity() as u64) * size_of::<crate::RelationalType>() as u64,
    )?;
    for data_type in &value.column_types {
        bytes = add(bytes, type_heap(data_type))?;
    }
    bytes = add(
        bytes,
        (value.rows.capacity() as u64) * size_of::<Value>() as u64,
    )?;
    for row in &value.rows {
        bytes = add(bytes, json_heap_checked(row, check)?)?;
    }
    Ok(bytes)
}

/// Canonical join/sort key and encoding charge remain together. Probes have the
/// same short owner; retained right keys hold their own buffers through lookup.
pub(crate) struct JsonKey {
    text: String,
    _memory: ResponseReservation,
}
impl JsonKey {
    pub(crate) fn new(value: &Value) -> Result<Self> {
        let (bytes, memory) = ResponseBuffer::json_native(value, 8 * 1024 * 1024)?.into_parts();
        Ok(Self {
            text: String::from_utf8(bytes).map_err(|_| full())?,
            _memory: memory,
        })
    }
    pub(crate) fn text(&self) -> &str {
        &self.text
    }
}
impl std::hash::Hash for JsonKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.text.hash(state);
    }
}
impl PartialEq for JsonKey {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
    }
}
impl Eq for JsonKey {}
