//! Query terms borrow no mutable index state and keep copies admitted.
use crate::{GaussError, Result, relational::wal_decode::MetadataCharge};
use std::{mem::size_of, ops::Deref};

pub(super) struct Terms {
    values: Vec<String>,
    _memory: MetadataCharge,
}
impl Deref for Terms {
    type Target = [String];
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
impl Terms {
    pub(super) fn new(query: &str) -> Result<Self> {
        let exhausted = || GaussError::ResourceExhausted("BM25 query terms memory is full".into());
        let tokens = || {
            query
                .split(|ch: char| !ch.is_alphanumeric())
                .filter(|s| !s.is_empty())
        };
        let (count, text_bytes) = tokens().try_fold((0usize, 0u64), |(n, bytes), term| {
            Ok::<_, GaussError>((
                n.checked_add(1).ok_or_else(exhausted)?,
                bytes.checked_add(term.len() as u64).ok_or_else(exhausted)?,
            ))
        })?;
        let mut result = Self {
            values: Vec::new(),
            _memory: Default::default(),
        };
        if count == 0 {
            return Ok(result);
        }
        let peak = (count as u64)
            .checked_mul(size_of::<String>() as u64)
            .and_then(|n| n.checked_add(text_bytes))
            .and_then(|n| n.checked_add(256))
            .ok_or_else(exhausted)?;
        result._memory.prepare(peak)?;
        result
            .values
            .try_reserve_exact(count)
            .map_err(|_| exhausted())?;
        for token in tokens() {
            let mut value = String::new();
            value
                .try_reserve_exact(token.len())
                .map_err(|_| exhausted())?;
            value.push_str(token);
            value.make_ascii_lowercase();
            result.values.push(value);
        }
        result.values.sort_unstable();
        result.values.dedup();
        let retained = result
            .values
            .iter()
            .try_fold(
                (result.values.capacity() * size_of::<String>()) as u64,
                |n, term| n.checked_add(term.capacity() as u64).ok_or_else(exhausted),
            )?
            .checked_add(128)
            .ok_or_else(exhausted)?;
        if retained > peak {
            return Err(exhausted());
        }
        result._memory.reduce(retained);
        Ok(result)
    }
}
