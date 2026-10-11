//! Frontend byte buffers and retained startup/session containers own admission.
//! SQL parser/catalog/authority and TLS/socket construction have separate bounds.
use super::{NativePortal, NativePreparedStatement, memory, output};
use crate::response_buffer::ResponseBuffer;
use std::{collections::HashMap, io, mem::size_of, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{Duration, timeout};

pub(super) const MAX_SESSION_OBJECTS: usize = 32;

pub(super) fn vector<T>(count: usize) -> Result<Vec<T>, (&'static str, String)> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| ("53200", "frontend allocation failed".into()))?;
    Ok(values)
}
pub(super) fn string(value: &str) -> Result<String, (&'static str, String)> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| ("53200", "frontend allocation failed".into()))?;
    owned.push_str(value);
    Ok(owned)
}

pub(super) fn session(
    memory: &memory::SessionMemory,
) -> Result<memory::Charge, (&'static str, String)> {
    // Bucket capacity stays allocated after clear; reserve the two maximum maps
    // up front. Per-entry strings and decoded parameters have their own charges.
    memory.reserve(
        8192 + 64
            * (size_of::<(String, NativePortal)>()
                + size_of::<(String, Arc<NativePreparedStatement>)>()
                + 16),
    )
}

pub(super) fn request(
    sql: &str,
    parameters: &[crate::RelationalValue],
    memory: &memory::SessionMemory,
) -> Result<(crate::SqlExecutionRequest, memory::Charge), (&'static str, String)> {
    let charge = memory.reserve(memory::checked_bytes(&[
        4096,
        sql.len(),
        memory::parameter_bytes(parameters),
    ])?)?;
    Ok((
        crate::SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql: sql.into(),
                parameters: parameters.to_vec(),
            }],
            idempotency_key: None,
            retry_id: None,
        },
        charge,
    ))
}

pub(super) async fn read<R: AsyncRead + Unpin>(
    reader: &mut R,
    length: usize,
    limit: usize,
) -> io::Result<ResponseBuffer> {
    let mut bytes = output::input(length, limit)?;
    timeout(Duration::from_secs(10), reader.read_exact(bytes.as_mut()))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "frontend payload timed out"))??;
    Ok(bytes)
}

pub(super) async fn discard<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut remaining: usize,
) -> io::Result<()> {
    timeout(Duration::from_secs(10), async {
        let mut scratch = [0u8; 4096];
        while remaining != 0 {
            let count = remaining.min(scratch.len());
            reader.read_exact(&mut scratch[..count]).await?;
            remaining -= count;
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "discarded frame timed out"))?
}

pub(super) struct Startup {
    params: HashMap<String, String>,
    _memory: memory::Charge,
}
impl std::ops::Deref for Startup {
    type Target = HashMap<String, String>;
    fn deref(&self) -> &Self::Target {
        &self.params
    }
}

fn pairs(body: &[u8], mut visit: impl FnMut(&str, &str) -> io::Result<()>) -> io::Result<()> {
    let mut offset = 0;
    while offset < body.len() && body[offset] != 0 {
        let key = super::read_frontend_str(body, &mut offset)
            .map_err(|(_, message)| io::Error::new(io::ErrorKind::InvalidData, message))?;
        let value = super::read_frontend_str(body, &mut offset)
            .map_err(|(_, message)| io::Error::new(io::ErrorKind::InvalidData, message))?;
        visit(key, value)?;
    }
    Ok(())
}

pub(super) fn startup(body: &[u8], memory: &memory::SessionMemory) -> io::Result<Startup> {
    let mut count = 0usize;
    let mut strings = 0usize;
    pairs(body, |key, value| {
        count = count
            .checked_add(1)
            .ok_or_else(|| io::Error::other("startup capacity overflow"))?;
        strings = strings
            .checked_add(key.len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or_else(|| io::Error::other("startup capacity overflow"))?;
        Ok(())
    })?;
    // Admit power-of-two buckets at a 7/8 load, including control bytes and
    // group alignment. Small tables fit within eight buckets. Duplicate keys
    // only lower actual use; the bound remains with the completed map.
    let buckets = count
        .checked_mul(8)
        .map(|n| n.div_ceil(7))
        .and_then(usize::checked_next_power_of_two)
        .map(|n| n.max(8))
        .and_then(|n| n.checked_mul(size_of::<(String, String)>() + 1))
        .and_then(|n| n.checked_add(32))
        .and_then(|n| n.checked_add(strings))
        .ok_or_else(|| io::Error::other("startup capacity overflow"))?;
    let charge = memory.reserve(buckets).map_err(|_| output::input_full())?;
    let mut params = HashMap::new();
    params.try_reserve(count).map_err(io::Error::other)?;
    pairs(body, |key, value| {
        params.insert(key.to_owned(), value.to_owned());
        Ok(())
    })?;
    Ok(Startup {
        params,
        _memory: charge,
    })
}

#[cfg(test)]
mod tests;
