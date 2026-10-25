//! Protected data drops before retained projection and container leases.
use super::{AccessContext, AuthorizedOutput};
use crate::{
    GaussError, Point, Result, ScrollResponse, SearchHit,
    relational::wal_decode::{MetadataCharge, Owned, Reservation},
};
use std::mem::size_of;

#[derive(Default)]
pub(crate) struct OutputAdmission {
    leases: Vec<Reservation>,
    memory: MetadataCharge,
}

#[derive(Default)]
pub(crate) struct Points {
    values: Vec<Point>,
    admission: OutputAdmission,
}
impl Points {
    pub(crate) fn into_parts(self) -> (Vec<Point>, OutputAdmission) {
        (self.values, self.admission)
    }
    fn retained(&self, extra: u64) -> Result<u64> {
        (self.values.capacity() as u64)
            .checked_mul(size_of::<Point>() as u64)
            .and_then(|n| {
                n.checked_add(
                    (self.admission.leases.capacity() as u64)
                        .checked_mul(size_of::<Reservation>() as u64)?,
                )
            })
            .and_then(|n| n.checked_add(extra))
            .and_then(|n| n.checked_add(128))
            .ok_or_else(full)
    }
    pub(crate) fn push(&mut self, point: super::point::ProjectedPoint) -> Result<&Point> {
        let old = self.values.capacity();
        let old_leases = self.admission.leases.capacity();
        let capacity = if self.values.len() == old {
            self.values
                .len()
                .checked_add(1)
                .and_then(usize::checked_next_power_of_two)
                .ok_or_else(full)?
        } else {
            old
        };
        let leases = self
            .admission
            .leases
            .len()
            .checked_add(2)
            .and_then(usize::checked_next_power_of_two)
            .ok_or_else(full)?
            .max(old_leases);
        let peak = (capacity as u64)
            .checked_mul(size_of::<Point>() as u64)
            .and_then(|n| {
                n.checked_add((leases as u64).checked_mul(size_of::<Reservation>() as u64)?)
            })
            .and_then(|n| {
                n.checked_add(if capacity > old {
                    (old * size_of::<Point>()) as u64
                } else {
                    0
                })
            })
            .and_then(|n| {
                n.checked_add(if leases > old_leases {
                    (old_leases * size_of::<Reservation>()) as u64
                } else {
                    0
                })
            })
            .and_then(|n| n.checked_add(256))
            .ok_or_else(full)?;
        self.admission.memory.prepare(peak)?;
        self.values
            .try_reserve_exact(capacity - self.values.len())
            .map_err(|_| full())?;
        self.admission
            .leases
            .try_reserve_exact(leases - self.admission.leases.len())
            .map_err(|_| full())?;
        let retained = self.retained(0)?;
        if retained > peak {
            return Err(full());
        }
        let (value, leases) = point.into_parts();
        self.values.push(value);
        self.admission.leases.extend(leases);
        self.admission.memory.reduce(retained);
        Ok(self.values.last().expect("inserted point"))
    }
    pub(crate) fn finish(self, context: AccessContext) -> AuthorizedOutput<Vec<Point>> {
        AuthorizedOutput::admitted(context, self.values, self.admission)
    }
    pub(crate) fn finish_scroll(
        mut self,
        context: AccessContext,
        more: bool,
    ) -> Result<AuthorizedOutput<ScrollResponse>> {
        let next_offset = if more {
            let id = &self.values.last().expect("nonempty page").id;
            self.admission.memory.prepare(
                self.retained(id.len() as u64)?
                    .checked_add(128)
                    .ok_or_else(full)?,
            )?;
            let mut copied = String::new();
            copied.try_reserve_exact(id.len()).map_err(|_| full())?;
            copied.push_str(id);
            self.admission
                .memory
                .reduce(self.retained(copied.capacity() as u64)?);
            Some(copied)
        } else {
            None
        };
        Ok(AuthorizedOutput::admitted(
            context,
            ScrollResponse {
                points: self.values,
                next_offset,
            },
            self.admission,
        ))
    }
}

#[derive(Default)]
pub(crate) struct Hits {
    values: Vec<SearchHit>,
    id_bytes: u64,
    admission: OutputAdmission,
}
impl Hits {
    pub(crate) fn into_parts(self) -> (Vec<SearchHit>, OutputAdmission) {
        (self.values, self.admission)
    }

    pub(crate) fn push(
        &mut self,
        id: &str,
        score: f32,
        payload: Owned<serde_json::Value>,
    ) -> Result<&SearchHit> {
        let old = self.values.capacity();
        let old_leases = self.admission.leases.capacity();
        let capacity = if self.values.len() == old {
            self.values
                .len()
                .checked_add(1)
                .and_then(usize::checked_next_power_of_two)
                .ok_or_else(full)?
        } else {
            old
        };
        let leases = if self.admission.leases.len() == old_leases {
            capacity
        } else {
            old_leases
        };
        let peak = (capacity as u64)
            .checked_mul(size_of::<SearchHit>() as u64)
            .and_then(|n| {
                n.checked_add((leases as u64).checked_mul(size_of::<Reservation>() as u64)?)
            })
            .and_then(|n| {
                n.checked_add(if capacity > old {
                    (old * size_of::<SearchHit>()) as u64
                } else {
                    0
                })
            })
            .and_then(|n| {
                n.checked_add(if leases > old_leases {
                    (old_leases * size_of::<Reservation>()) as u64
                } else {
                    0
                })
            })
            .and_then(|n| n.checked_add(self.id_bytes))
            .and_then(|n| n.checked_add(id.len() as u64))
            .and_then(|n| n.checked_add(256))
            .ok_or_else(full)?;
        self.admission.memory.prepare(peak)?;
        self.values
            .try_reserve_exact(capacity - self.values.len())
            .map_err(|_| full())?;
        self.admission
            .leases
            .try_reserve_exact(leases - self.admission.leases.len())
            .map_err(|_| full())?;
        let mut copied = String::new();
        copied.try_reserve_exact(id.len()).map_err(|_| full())?;
        copied.push_str(id);
        let id_bytes = self
            .id_bytes
            .checked_add(copied.capacity() as u64)
            .ok_or_else(full)?;
        let retained = (self.values.capacity() as u64)
            .checked_mul(size_of::<SearchHit>() as u64)
            .and_then(|n| {
                n.checked_add(
                    (self.admission.leases.capacity() as u64)
                        .checked_mul(size_of::<Reservation>() as u64)?,
                )
            })
            .and_then(|n| n.checked_add(id_bytes))
            .and_then(|n| n.checked_add(128))
            .ok_or_else(full)?;
        if retained > peak {
            return Err(full());
        }
        let (payload, lease) = payload.into_parts();
        self.values.push(SearchHit {
            id: copied,
            score,
            payload,
        });
        self.admission.leases.push(lease);
        self.id_bytes = id_bytes;
        self.admission.memory.reduce(retained);
        Ok(self.values.last().expect("inserted hit"))
    }
    pub(crate) fn finish(self, context: AccessContext) -> AuthorizedOutput<Vec<SearchHit>> {
        AuthorizedOutput::admitted(context, self.values, self.admission)
    }
}
fn full() -> GaussError {
    GaussError::ResourceExhausted("protected output memory is full".into())
}

pub(crate) fn ids(
    context: AccessContext,
    values: crate::search::AdmittedVec<String>,
) -> AuthorizedOutput<Vec<String>> {
    let (values, memory) = values.into_parts();
    AuthorizedOutput::admitted(
        context,
        values,
        OutputAdmission {
            leases: Vec::new(),
            memory,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protected_hit_growth_refusal_preserves_prior_output_and_projection_leases() {
        let oversized_id = "x".repeat(16384);
        crate::relational::wal_decode::with_test_storage_pool(16384, |used| {
            let mut hits = Hits::default();
            let payload =
                crate::relational::wal_decode::borrowed_json(&serde_json::Value::Null).unwrap();
            hits.push("row", 1.0, payload).unwrap();
            let before = used();
            let capacity = hits.values.capacity();
            let payload =
                crate::relational::wal_decode::borrowed_json(&serde_json::Value::Null).unwrap();
            assert!(matches!(
                hits.push(&oversized_id, 0.0, payload),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(hits.values.len(), 1);
            assert_eq!(hits.values[0].id, "row");
            assert_eq!(hits.values.capacity(), capacity);
            assert_eq!(used(), before);
            drop(hits);
            assert_eq!(used(), 0);
        });
    }
}
