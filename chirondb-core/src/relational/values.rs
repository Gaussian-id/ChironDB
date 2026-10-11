//! Immutable typed row payloads keep their storage reservation across snapshots,
//! locator reads and query operators. Cloning a version shares its value owner.
use super::*;
use std::ops::Deref;

#[cfg(test)]
mod tests;

const OWNER_BYTES: u64 = 256;

#[derive(Debug)]
struct Allocation {
    values: Vec<RelationalValue>,
    // Drop owned values before returning their reservation.
    _charge: memory::Charge,
}

#[derive(Clone, Debug)]
pub(super) struct RowValues(Arc<Allocation>);

impl RowValues {
    fn decode(raw: &serde_json::value::RawValue) -> Result<Self> {
        let mut charge = memory::Charge::storage();
        charge.prepare(OWNER_BYTES)?;
        let decoded = value_decode::values(
            raw.get(),
            crate::resource_profile::current().sql_request_working_set_bytes as usize,
            Some(charge),
        )?;
        Ok(Self(Arc::new(Allocation {
            values: decoded.values,
            _charge: decoded.charge.expect("disk values use a storage charge"),
        })))
    }

    pub(super) fn copy(values: &[RelationalValue]) -> Result<Self> {
        Self::concat(values, &[])
    }

    pub(super) fn concat(left: &[RelationalValue], right: &[RelationalValue]) -> Result<Self> {
        let len = left
            .len()
            .checked_add(right.len())
            .ok_or_else(sql_overloaded)?;
        let bytes = left.iter().chain(right).fold(
            OWNER_BYTES.saturating_add(
                (len as u64).saturating_mul(std::mem::size_of::<RelationalValue>() as u64),
            ),
            |sum, value| sum.saturating_add(memory::value_heap_bytes(value)),
        );
        let mut charge = memory::Charge::storage();
        charge.prepare(bytes)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(len)
            .map_err(|_| sql_overloaded())?;
        values.extend(left.iter().chain(right).cloned());
        Ok(Self(Arc::new(Allocation {
            values,
            _charge: charge,
        })))
    }

    pub(super) fn adopt(values: Vec<RelationalValue>) -> Result<Self> {
        let mut charge = memory::Charge::storage();
        charge.prepare(Self::bytes(&values))?;
        Ok(Self(Arc::new(Allocation {
            values,
            _charge: charge,
        })))
    }

    fn bytes(values: &Vec<RelationalValue>) -> u64 {
        values.iter().fold(
            OWNER_BYTES.saturating_add(
                (values.capacity() * std::mem::size_of::<RelationalValue>()) as u64,
            ),
            |sum, value| sum.saturating_add(memory::value_heap_bytes(value)),
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<'a> {
    row_id: u64,
    #[serde(borrow)]
    version: &'a serde_json::value::RawValue,
}
#[derive(Deserialize)]
struct Version<'a> {
    begin: u64,
    end: Option<u64>,
    #[serde(borrow)]
    values: &'a serde_json::value::RawValue,
}

fn scratch(bytes: usize) -> Result<memory::Charge> {
    let mut charge = memory::Charge::storage();
    // The input is already owned by charged RecordBytes. At most two serde
    // decoders are alive together; each scratch Vec needs up to 3x input
    // including overlapping old/new capacity while growing.
    charge.prepare(
        (bytes as u64)
            .checked_mul(6)
            .and_then(|n| n.checked_add(4096))
            .ok_or_else(sql_overloaded)?,
    )?;
    Ok(charge)
}

pub(super) fn persisted_row(bytes: &[u8]) -> Result<PersistedRowVersion> {
    let _scratch = scratch(bytes.len())?;
    let row: Envelope<'_> = serde_json::from_slice(bytes)?;
    let version: Version<'_> = serde_json::from_str(row.version.get())?;
    Ok(PersistedRowVersion {
        row_id: row.row_id,
        version: RowVersion {
            begin: version.begin,
            end: version.end,
            values: RowValues::decode(version.values)?,
        },
    })
}

pub(super) fn canonical_matches(value: &impl Serialize, bytes: &[u8]) -> Result<bool> {
    struct Compare<'a> {
        remaining: &'a [u8],
        matches: bool,
    }
    impl std::io::Write for Compare<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.remaining.get(..bytes.len()) == Some(bytes) {
                self.remaining = &self.remaining[bytes.len()..];
            } else {
                self.matches = false;
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut out = Compare {
        remaining: bytes,
        matches: true,
    };
    serde_json::to_writer(&mut out, value)?;
    Ok(out.matches && out.remaining.is_empty())
}

impl Deref for RowValues {
    type Target = Vec<RelationalValue>;
    fn deref(&self) -> &Self::Target {
        &self.0.values
    }
}
impl Serialize for RowValues {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.0.values.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for RowValues {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        // Legacy inline checkpoints retain their generic decoder. This charges
        // retained ownership only; disk row runs use preadmitted persisted_row.
        Self::adopt(Vec::<RelationalValue>::deserialize(decoder)?).map_err(serde::de::Error::custom)
    }
}
impl PartialEq for RowValues {
    fn eq(&self, other: &Self) -> bool {
        self.0.values == other.0.values
    }
}
impl PartialEq<Vec<RelationalValue>> for RowValues {
    fn eq(&self, other: &Vec<RelationalValue>) -> bool {
        &self.0.values == other
    }
}
impl<'a> IntoIterator for &'a RowValues {
    type Item = &'a RelationalValue;
    type IntoIter = std::slice::Iter<'a, RelationalValue>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.values.iter()
    }
}
