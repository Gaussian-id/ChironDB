//! Decoded vector reservations remain with the row through scoring and training.
use crate::{GaussError, Result, relational::wal_decode::MetadataCharge};
use std::{borrow::Cow, mem::size_of, ops::Deref};

/// A borrowed vector or an owned row with storage admission retained until drop.
/// External sources remain responsible for admission before producing owned rows.
#[derive(Debug)]
pub struct VectorRead<'a> {
    values: Cow<'a, [f32]>,
    // Drop values before their reservation, including error-path temporaries.
    memory: MetadataCharge,
}

impl Deref for VectorRead<'_> {
    type Target = [f32];
    fn deref(&self) -> &[f32] {
        &self.values
    }
}
impl AsRef<[f32]> for VectorRead<'_> {
    fn as_ref(&self) -> &[f32] {
        self
    }
}

fn exhausted() -> GaussError {
    GaussError::ResourceExhausted("decoded vector memory is full".into())
}
fn bytes(count: usize, overhead: u64) -> Result<u64> {
    (count as u64)
        .checked_mul(size_of::<f32>() as u64)
        .and_then(|n| n.checked_add(overhead))
        .ok_or_else(exhausted)
}

impl<'a> VectorRead<'a> {
    /// Borrow existing storage without making an output allocation.
    pub fn borrowed(values: &'a [f32]) -> Self {
        Self {
            values: Cow::Borrowed(values),
            memory: Default::default(),
        }
    }
    pub fn is_borrowed(&self) -> bool {
        matches!(self.values, Cow::Borrowed(_))
    }

    /// Reserve before copying an independently owned row.
    pub fn copy(values: &[f32]) -> Result<VectorRead<'static>> {
        Self::decode(values.len(), values.iter().copied())
    }

    pub(crate) fn decode(
        count: usize,
        values: impl Iterator<Item = f32>,
    ) -> Result<VectorRead<'static>> {
        if count == 0 {
            return Ok(VectorRead::borrowed(&[]));
        }
        Self::owned_with(count, || {
            let mut row = Vec::new();
            row.try_reserve_exact(count).map_err(|_| exhausted())?;
            // Never let a malformed source grow past its admitted dimension.
            row.extend(values.take(count));
            if row.len() != count {
                return Err(GaussError::InvalidRequest(
                    "decoded vector dimension mismatch".into(),
                ));
            }
            Ok(row)
        })
    }

    pub(crate) fn owned_with(
        count: usize,
        produce: impl FnOnce() -> Result<Vec<f32>>,
    ) -> Result<VectorRead<'static>> {
        let peak = bytes(count, 256)?;
        let mut memory = MetadataCharge::default();
        memory.prepare(peak)?;
        let mut owned = (Vec::new(), memory);
        owned.0 = produce()?;
        let retained = bytes(
            owned.0.capacity(),
            (size_of::<VectorRead<'_>>() + 64) as u64,
        )?;
        if owned.0.len() != count || retained > peak {
            return Err(exhausted());
        }
        owned.1.reduce(retained);
        Ok(VectorRead {
            values: Cow::Owned(owned.0),
            memory: owned.1,
        })
    }

    pub(crate) fn adopt(values: Cow<'a, [f32]>) -> Result<Self> {
        if let Cow::Borrowed(values) = values {
            return Ok(Self::borrowed(values));
        }
        let mut owner = Self {
            values,
            memory: Default::default(),
        };
        let Cow::Owned(row) = &owner.values else {
            unreachable!()
        };
        if row.capacity() != 0 {
            owner
                .memory
                .prepare(bytes(row.capacity(), (size_of::<Self>() + 64) as u64)?)?;
        }
        Ok(owner)
    }

    // Compatibility Cow/Vec APIs cannot carry the engine reservation.
    pub(crate) fn into_compat(self) -> Cow<'a, [f32]> {
        self.values
    }

    pub(crate) fn into_owned_read(self) -> Result<VectorRead<'static>> {
        match self.values {
            Cow::Borrowed(values) => Self::copy(values),
            Cow::Owned(values) => Ok(VectorRead {
                values: Cow::Owned(values),
                memory: self.memory,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relational::wal_decode::with_test_storage_pool;
    use std::sync::{Arc, atomic::AtomicBool};

    #[test]
    fn decoded_admission_precedes_producer_and_releases_failed_rows() {
        let mut called = false;
        with_test_storage_pool(1, |used| {
            assert!(matches!(
                VectorRead::owned_with(4096, || {
                    called = true;
                    Ok(vec![1.0; 4096])
                }),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert!(!called);
            assert_eq!(used(), 0);
        });
        with_test_storage_pool(64 * 1024, |used| {
            assert!(matches!(
                VectorRead::decode(16, [1.0].into_iter()),
                Err(GaussError::InvalidRequest(_))
            ));
            assert_eq!(used(), 0);
            assert!(
                VectorRead::owned_with(16, || Err(GaussError::InvalidRequest(
                    "source failed".into()
                )))
                .is_err()
            );
            assert_eq!(used(), 0);
            let error =
                crate::relational::with_sql_cancellation(Arc::new(AtomicBool::new(true)), || {
                    VectorRead::owned_with(16, || {
                        called = true;
                        Ok(vec![1.0; 16])
                    })
                })
                .unwrap_err();
            assert!(
                matches!(error, GaussError::InvalidRequest(message) if message=="query canceled")
            );
            assert!(!called);
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn decoded_rows_survive_moves_and_refuse_until_held_output_drops() {
        let original = vec![2.5; 2048];
        with_test_storage_pool(16 * 1024, |used| {
            let first = VectorRead::copy(&original).unwrap();
            let held = used();
            assert!(matches!(
                VectorRead::copy(&original),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), held);
            let first = first.into_owned_read().unwrap();
            assert_eq!(used(), held);
            assert_eq!(first.as_ref(), original);
            drop(first);
            assert_eq!(used(), 0);
            let next = VectorRead::copy(&original).unwrap();
            assert_eq!(next.as_ref(), original);
            drop(next);
            assert_eq!(used(), 0);
        });
        with_test_storage_pool(1, |used| {
            let row = VectorRead::borrowed(&original);
            assert!(row.is_borrowed());
            assert_eq!(row.as_ptr(), original.as_ptr());
            assert_eq!(used(), 0);
            let empty = VectorRead::copy(&[]).unwrap();
            assert!(empty.is_empty());
            assert_eq!(used(), 0);
            assert!(matches!(
                row.into_owned_read(),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn vector_source_addition_preserves_existing_implementations_and_object_safety() {
        struct Legacy;
        impl crate::index::ivf::VectorSource for Legacy {
            fn len(&self) -> usize {
                1
            }
            fn vector(&self, _ordinal: usize) -> Result<Cow<'_, [f32]>> {
                Ok(Cow::Owned(vec![1.0, -2.0]))
            }
        }
        let source: &dyn crate::index::ivf::VectorSource = &Legacy;
        with_test_storage_pool(4096, |used| {
            let row = source.read_vector(0).unwrap();
            assert_eq!(row.as_ref(), [1.0, -2.0]);
            assert!(used() > 0);
            drop(row);
            assert_eq!(used(), 0);
            assert_eq!(source.vector(0).unwrap().as_ref(), [1.0, -2.0]);
            assert_eq!(used(), 0);
        });
    }
}
