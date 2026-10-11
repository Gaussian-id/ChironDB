//! Transport buffers share core admission and keep reservations with their data.
use crate::{
    GaussError, Result,
    relational::wal_decode::{self, MetadataCharge},
};
use serde::Serialize;

/// Reservation for a receiving transport's containers and encoding workspace.
/// Reserve before allocating; retain this owner until all covered data drops.
#[derive(Debug)]
pub struct ResponseReservation {
    memory: MetadataCharge,
}
impl ResponseReservation {
    pub fn new(bytes: u64) -> Result<Self> {
        let mut value = Self {
            memory: MetadataCharge::default(),
        };
        value.prepare(bytes)?;
        Ok(value)
    }
    /// Replace the retained/peak bound, including transport controller overhead.
    pub fn prepare(&mut self, bytes: u64) -> Result<()> {
        self.memory
            .prepare(bytes.checked_add(256).ok_or_else(full)?)
    }
}

/// Fixed byte allocation, admitted before growth and retained by its owner.
/// Suitable for Bytes::from_owner: clones/slices retain the original allocation.
pub struct ResponseBuffer {
    bytes: Vec<u8>,
    reservation: ResponseReservation,
}
impl ResponseBuffer {
    /// Preserve direct serde JSON numbers (including compact f32 encoding).
    pub fn json_native(value: &impl Serialize, limit: usize) -> Result<Self> {
        let (bytes, memory) = wal_decode::encode_native_limited(value, limit)?.into_parts()?;
        Ok(Self {
            bytes,
            reservation: ResponseReservation { memory },
        })
    }
    /// Stream JSON into a bounded admitted buffer without an intermediate Value.
    /// f32 numbers preserve the former serde_json::Value widening to f64.
    /// Caller-provided Serialize implementations own their separate scratch.
    pub fn json(value: &impl Serialize, limit: usize) -> Result<Self> {
        let (bytes, memory) = wal_decode::encode_limited(value, limit)?.into_parts()?;
        Ok(Self {
            bytes,
            reservation: ResponseReservation { memory },
        })
    }
    /// Allocate a fixed frame. Encoders receive a slice and cannot grow it.
    pub fn allocate(length: usize, limit: usize) -> Result<Self> {
        if length > limit {
            return Err(full());
        }
        let mut reservation = ResponseReservation::new(length as u64)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| full())?;
        bytes.resize(length, 0);
        reservation.prepare(bytes.capacity() as u64)?;
        Ok(Self { bytes, reservation })
    }
    /// Transfer into another DTO without copying. The receiving owner must keep
    /// the returned reservation after the byte/string data in its drop order.
    pub fn into_parts(self) -> (Vec<u8>, ResponseReservation) {
        (self.bytes, self.reservation)
    }
}
impl AsRef<[u8]> for ResponseBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl AsMut<[u8]> for ResponseBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}
fn full() -> GaussError {
    GaussError::ResourceExhausted("response buffer limit exceeded".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn response_buffer_refuses_before_growth_and_retains_transferred_data() {
        let value = serde_json::json!({"text":"\n日本語".repeat(1024)});
        wal_decode::with_test_storage_pool(1, |used| {
            assert!(matches!(
                ResponseBuffer::json(&value, 65536),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert!(matches!(
                ResponseBuffer::allocate(32, 64),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
        });
        wal_decode::with_test_storage_pool(65536, |used| {
            let encoded = ResponseBuffer::json(&value, 65536).unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(encoded.as_ref()).unwrap(),
                value
            );
            let (bytes, reservation) = encoded.into_parts();
            assert!(used() >= bytes.capacity() as u64);
            drop(bytes);
            assert!(used() > 0);
            drop(reservation);
            assert_eq!(used(), 0);
            let mut frame = ResponseBuffer::allocate(32, 64).unwrap();
            frame.as_mut().fill(7);
            assert_eq!(frame.as_ref(), &[7; 32]);
            drop(frame);
            assert_eq!(used(), 0);
            assert!(ResponseBuffer::allocate(65, 64).is_err());
            assert_eq!(used(), 0);
            assert!(ResponseBuffer::json(&value, 8).is_err());
            assert_eq!(used(), 0);
        });
    }
    #[test]
    fn response_json_preserves_value_widening_and_mid_serialization_cancel_cleanup() {
        use serde::ser::SerializeSeq;
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let values = [0.7181532_f32, 0.1, -0.0, f32::MAX, f32::MIN_POSITIVE];
        let expected = serde_json::to_value(values).unwrap();
        wal_decode::with_test_storage_pool(65536, |used| {
            let output = ResponseBuffer::json(&values, 65536).unwrap();
            assert_eq!(output.as_ref(), serde_json::to_vec(&expected).unwrap());
            let decoded: Vec<f32> = serde_json::from_slice(output.as_ref()).unwrap();
            assert_eq!(
                decoded.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
                values.iter().map(|v| v.to_bits()).collect::<Vec<_>>()
            );
            drop(output);
            assert_eq!(used(), 0);
            let storage = wal_decode::encode(&values).unwrap();
            assert_eq!(&*storage, serde_json::to_vec(&values).unwrap());
            drop(storage);
            assert_eq!(used(), 0);
            struct CancelAfterValue(Arc<AtomicBool>);
            impl Serialize for CancelAfterValue {
                fn serialize<S: serde::Serializer>(
                    &self,
                    serializer: S,
                ) -> std::result::Result<S::Ok, S::Error> {
                    let mut sequence = serializer.serialize_seq(Some(2))?;
                    sequence.serialize_element("a value before cancellation")?;
                    self.0.store(true, Ordering::Release);
                    sequence.serialize_element("must not be published")?;
                    sequence.end()
                }
            }
            let flag = Arc::new(AtomicBool::new(false));
            let result = crate::relational::with_sql_cancellation(flag.clone(), || {
                ResponseBuffer::json(&CancelAfterValue(flag.clone()), 65536)
            });
            assert!(result.is_err_and(|e| e.to_string().contains("query canceled")));
            assert_eq!(used(), 0);
        });
    }
}
