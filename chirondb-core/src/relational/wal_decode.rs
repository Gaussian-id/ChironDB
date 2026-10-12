//! Journal DTO and frame admission follows its borrowed or shared owner.
//! Ordinary public WAL and receipt conversion need separate ownership.
use super::*;

#[cfg(test)]
mod owners_tests;
#[cfg(test)]
mod tests;

pub(crate) struct FrameAdmission(memory::Charge);

impl FrameAdmission {
    pub(crate) fn new() -> Result<Self> {
        check_sql_cancelled()?;
        let mut charge = memory::Charge::storage();
        charge.prepare(4096)?;
        Ok(Self(charge))
    }

    pub(crate) fn prepare(&mut self, payload_len: usize, encrypted_segment: bool) -> Result<()> {
        check_sql_cancelled()?;
        // Reads retain raw input, bounded plaintext output and one ciphertext
        // chunk (<= three frames). Writes additionally reserve exact envelope
        // output and the old/new block overlap of one default encryption chunk;
        // the caller already owns/admitted its encoded plaintext. Keep the
        // larger of these peaks, rather than four full frames for every size.
        // Whole-file encrypted legacy reads also touch two max chunks.
        let length = payload_len as u64;
        let chunk = crate::encryption::DEFAULT_CHUNK_SIZE as u64;
        let read_peak = length.checked_mul(3).ok_or_else(sql_overloaded)?;
        let write_peak = length
            .checked_add(
                length
                    .div_ceil(chunk)
                    .checked_mul(20)
                    .ok_or_else(sql_overloaded)?,
            )
            .and_then(|n| n.checked_add(length.min(chunk).checked_mul(3)?))
            .ok_or_else(sql_overloaded)?;
        let chunks = if encrypted_segment {
            (crate::encryption::MAX_ENCRYPTION_CHUNK_SIZE as u64) * 2
        } else {
            0
        };
        self.0.prepare(
            read_peak
                .max(write_peak)
                .checked_add(chunks + 4096)
                .ok_or_else(sql_overloaded)?,
        )
    }
}

/// A unique decoded DTO and its reservation travel together. Fields drop in
/// order: the allocation dies before its charge, including during panic unwind.
#[derive(Debug)]
pub(crate) struct Owned<T> {
    value: Option<T>,
    reservation: Reservation,
}

#[derive(Debug, Default)]
pub(crate) struct Reservation {
    _charge: memory::Charge,
}

/// Unique metadata reservation. Callers keep it after the covered containers
/// and reserve before growing/copying them. Reducing it never allocates.
#[derive(Debug)]
pub(crate) struct MetadataCharge(memory::Charge);
impl Default for MetadataCharge {
    fn default() -> Self {
        Self(memory::Charge::storage())
    }
}
impl MetadataCharge {
    pub(crate) fn empty_in_same_pool(&self) -> Self {
        Self(self.0.empty_in_same_pool())
    }
    pub(crate) fn into_reservation(self) -> Reservation {
        Reservation { _charge: self.0 }
    }
    pub(super) fn into_charge(self) -> memory::Charge {
        self.0
    }

    pub(crate) fn prepare(&mut self, bytes: u64) -> Result<()> {
        check_sql_cancelled()?;
        self.0.prepare(bytes)
    }
    pub(crate) fn reduce(&mut self, bytes: u64) {
        assert!(bytes <= self.0.bytes(), "metadata reduction cannot grow");
        self.0
            .prepare(bytes)
            .expect("unique metadata lease reduction");
    }
}

/// Advisory only: the atomic reservation remains the admission decision.
pub(crate) fn storage_available_bytes() -> u64 {
    memory::storage_available_bytes()
}

impl<T> std::ops::Deref for Owned<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.value.as_ref().expect("owned DTO")
    }
}
impl<T> Owned<T> {
    /// Allocation-free adoption of payloads already covered by this reservation.
    pub(crate) fn from_parts(value: T, reservation: Reservation) -> Self {
        Self {
            value: Some(value),
            reservation,
        }
    }
    pub(crate) fn reserve_extra(&mut self, bytes: u64) -> Result<()> {
        check_sql_cancelled()?;
        self.reservation._charge.prepare(
            self.reservation
                ._charge
                .bytes()
                .checked_add(bytes)
                .ok_or_else(sql_overloaded)?,
        )
    }
    pub(crate) fn try_map<U>(mut self, f: impl FnOnce(T) -> Result<U>) -> Result<Owned<U>> {
        let value = f(self.value.take().expect("owned DTO"))?;
        Ok(Owned {
            value: Some(value),
            reservation: std::mem::take(&mut self.reservation),
        })
    }
    /// Only immediate, allocation-free DTO adoption may split ownership. The
    /// receiving struct must put its payload fields before this reservation.
    pub(crate) fn into_parts(mut self) -> (T, Reservation) {
        (
            self.value.take().expect("owned DTO"),
            std::mem::take(&mut self.reservation),
        )
    }
    /// Synchronous consumers must finish/drop the moved value before return.
    pub(crate) fn consume<R>(mut self, f: impl FnOnce(T) -> Result<R>) -> Result<R> {
        f(self.value.take().expect("owned DTO"))
    }
}

pub(crate) fn decode<T: serde::de::DeserializeOwned>(input: &[u8]) -> Result<Owned<T>> {
    let (value, charge) = checkpoint::decode::slice_owned::<T>(input)?;
    Ok(Owned {
        value: Some(value),
        reservation: Reservation { _charge: charge },
    })
}

pub(crate) fn copy<T: Serialize + serde::de::DeserializeOwned>(value: &T) -> Result<Owned<T>> {
    let encoded = segment::EncodedBuffer::encode(value, crate::wal::MAX_WAL_RECORD_BYTES)?;
    decode(&encoded.bytes)
}

pub(crate) fn borrowed_json<'de>(
    decoder: impl serde::Deserializer<'de, Error = serde_json::Error>,
) -> Result<Owned<serde_json::Value>> {
    let (value, charge) = checkpoint::decode::borrowed_value_owned(decoder)?;
    Ok(Owned {
        value: Some(value),
        reservation: Reservation { _charge: charge },
    })
}

pub(crate) fn borrowed<'de, T: serde::de::DeserializeOwned>(
    decoder: impl serde::Deserializer<'de, Error = serde_json::Error>,
) -> Result<Owned<T>> {
    let (value, charge) = checkpoint::decode::borrowed_owned(decoder)?;
    Ok(Owned::from_parts(value, Reservation { _charge: charge }))
}

/// Form an owned JSON receipt from borrowed DTO fields. Encoding and receiving
/// Value backing are admitted independently, with their overlap retained. The
/// formatter preserves the former to_value widening of f32 fields to f64.
pub(crate) fn json(value: &impl Serialize) -> Result<Owned<serde_json::Value>> {
    let mut root = MetadataCharge::default();
    root.prepare(256 + std::mem::size_of::<serde_json::Value>() as u64)?;
    let encoded = encode_limited(value, crate::wal::MAX_WAL_RECORD_BYTES)?;
    decode(&encoded)
}

pub(crate) fn inspect<T: serde::de::DeserializeOwned, R>(
    input: &[u8],
    visitor: impl FnOnce(&T) -> Result<R>,
) -> Result<R> {
    let decoded = decode::<T>(input)?;
    visitor(&decoded)
}

pub(crate) struct Encoded(segment::EncodedBuffer);
impl Encoded {
    pub(crate) fn into_parts(self) -> Result<(Vec<u8>, MetadataCharge)> {
        let (bytes, charge) = self.0.into_parts()?;
        Ok((bytes, MetadataCharge(charge)))
    }
}
impl std::ops::Deref for Encoded {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0.bytes
    }
}
pub(crate) fn encode(value: &impl Serialize) -> Result<Encoded> {
    encode_native_limited(value, crate::wal::MAX_WAL_RECORD_BYTES)
}
pub(crate) fn encode_native_limited(value: &impl Serialize, limit: usize) -> Result<Encoded> {
    Ok(Encoded(segment::EncodedBuffer::encode(value, limit)?))
}
pub(crate) fn encode_limited(value: &impl Serialize, limit: usize) -> Result<Encoded> {
    struct ResponseFormatter;
    impl serde_json::ser::Formatter for ResponseFormatter {
        fn write_f32<W: std::io::Write + ?Sized>(
            &mut self,
            writer: &mut W,
            value: f32,
        ) -> std::io::Result<()> {
            // Former HTTP field wrappers serialized through Value, widening
            // f32 to f64 first. Keep the same JSON numeric value without cloning.
            serde_json::ser::CompactFormatter.write_f64(writer, value as f64)
        }
    }
    Ok(Encoded(segment::EncodedBuffer::encode_with_formatter(
        value,
        limit,
        ResponseFormatter,
    )?))
}
pub(crate) fn check_write_set(value: &impl Serialize) -> Result<()> {
    enforce_serialized_limit(
        value,
        crate::wal::MAX_WAL_RECORD_BYTES / 2,
        "transaction write set",
    )
}

// Independent Db fixtures share a process only because of the unit harness.
// Give large correctness fixtures the identical profile capacity, so unrelated
// test databases cannot exhaust it. Concurrency within each fixture is unchanged.
#[cfg(test)]
pub(crate) fn with_isolated_test_storage<T>(operation: impl FnOnce() -> T) -> T {
    memory::with_storage_pool(
        (crate::resource_profile::current().sql_pool_bytes / 2).max(1),
        |_| operation(),
    )
}

#[cfg(test)]
pub(crate) fn with_test_storage_pool<T>(
    capacity: u64,
    operation: impl FnOnce(&dyn Fn() -> u64) -> T,
) -> T {
    memory::with_storage_pool(capacity, |pool| operation(&|| pool.used()))
}

pub(crate) fn lease_root_bytes() -> u64 {
    memory::LEASE_ROOT_BYTES
}
