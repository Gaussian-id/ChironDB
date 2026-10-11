//! Spill framing delegates typed ownership to the common bounded decoder.
use super::*;
use serde_json::value::RawValue;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record<'a> {
    position: usize,
    #[serde(borrow)]
    values: &'a RawValue,
}

pub(super) fn record(payload: &[u8], limit: usize) -> Result<SpillRecord> {
    let fixed = std::mem::size_of::<SpillRecord>();
    let available = limit.checked_sub(fixed).ok_or_else(spill_exhausted)?;
    let input: Record<'_> = serde_json::from_slice(payload)?;
    let decoded = value_decode::values(input.values.get(), available, None).map_err(|error| {
        if matches!(error, GaussError::ResourceExhausted(_)) {
            spill_exhausted()
        } else {
            error
        }
    })?;
    Ok(SpillRecord {
        position: input.position,
        values: decoded.values,
        charge: fixed + decoded.bytes,
    })
}
