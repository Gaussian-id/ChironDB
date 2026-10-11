//! Mutation Point copies and receipt IDs retain admission before durable work.
use super::{NewPoint, ResourceRecord, output::OutputAdmission};
use crate::{GaussError, Point, Result, search::AdmittedVec};
use sha2::{Digest, Sha256};

pub(crate) struct PointCopies {
    values: Vec<Point>,
    admission: OutputAdmission,
}
impl PointCopies {
    pub(crate) fn new_points(
        points: &[NewPoint],
        records: Option<&[ResourceRecord]>,
    ) -> Result<Self> {
        if records.is_some_and(|records| records.len() != points.len()) {
            return Err(super::SecurityError::Unavailable.into());
        }
        let mut copied = super::output::Points::default();
        for (index, point) in points.iter().enumerate() {
            let mut storage = [0; 36];
            let id = match records {
                Some(records) => records[index]
                    .storage_id
                    .hyphenated()
                    .encode_lower(&mut storage),
                None => "validation",
            };
            copied.push(super::point::copy_new(id, point)?)?;
        }
        let (values, admission) = copied.into_parts();
        Ok(Self { values, admission })
    }
    pub(crate) fn points(points: &[Point]) -> Result<Self> {
        let mut copied = super::output::Points::default();
        for point in points {
            copied.push(super::point::copy_input(point)?)?;
        }
        let (values, admission) = copied.into_parts();
        Ok(Self { values, admission })
    }
    pub(crate) fn into_parts(self) -> (Vec<Point>, OutputAdmission) {
        (self.values, self.admission)
    }
}

pub(crate) fn ids<'a>(values: impl Iterator<Item = &'a str>) -> Result<AdmittedVec<String>> {
    let mut copied = AdmittedVec::<String>::default();
    for id in values {
        copied.copy_push(id)?;
    }
    Ok(copied)
}

pub(crate) fn fingerprint(value: &impl serde::Serialize) -> Result<[u8; 32]> {
    struct Sink(Sha256);
    impl std::io::Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Sink(Sha256::new());
    serde_json::to_writer(&mut sink, value).map_err(GaussError::from)?;
    Ok(sink.0.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relational::wal_decode::with_test_storage_pool;

    fn point() -> NewPoint {
        NewPoint {
            vector: vec![-0.0, f32::MAX],
            vectors: std::collections::BTreeMap::from([("named".into(), vec![f32::MIN_POSITIVE])]),
            sparse_vector: Some(crate::SparseVector {
                indices: vec![0, u32::MAX],
                values: vec![-0.0, 1.0],
            }),
            payload: serde_json::json!({"float":1.2345678901234567e300_f64,"zero":-0.0,"integer":u64::MAX,"text":"日本語\n".repeat(1024)}),
        }
    }

    #[test]
    fn native_point_copies_admit_before_allocation_preserve_bits_and_retain_handoff() {
        let input = vec![point()];
        with_test_storage_pool(1, |used| {
            assert!(matches!(
                PointCopies::new_points(&input, None),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
        });
        with_test_storage_pool(128 * 1024, |used| {
            let (rows, admission) = PointCopies::new_points(&input, None).unwrap().into_parts();
            assert!(used() > 0);
            assert_eq!(rows[0].id, "validation");
            assert_eq!(rows[0].vector[0].to_bits(), (-0.0_f32).to_bits());
            assert_eq!(
                rows[0].vectors["named"][0].to_bits(),
                f32::MIN_POSITIVE.to_bits()
            );
            assert_eq!(rows[0].sparse_vector, input[0].sparse_vector);
            for field in ["float", "zero"] {
                assert_eq!(
                    rows[0].payload[field].as_f64().unwrap().to_bits(),
                    input[0].payload[field].as_f64().unwrap().to_bits()
                );
            }
            assert_eq!(rows[0].payload["integer"].as_u64(), Some(u64::MAX));
            assert_ne!(rows[0].vector.as_ptr(), input[0].vector.as_ptr());
            let retained = used();
            let copied = PointCopies::points(&rows).unwrap();
            assert!(used() > retained);
            drop(copied);
            assert_eq!(used(), retained);
            drop(rows);
            assert_eq!(
                used(),
                retained,
                "receiving code holds the transferred lease"
            );
            drop(admission);
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn native_fingerprint_stream_matches_original_bytes_with_tiny_pool() {
        let request = super::super::CreatePoints {
            template: "standard".into(),
            idempotency_key: "native-fingerprint".into(),
            points: vec![point()],
        };
        let expected: [u8; 32] = Sha256::digest(serde_json::to_vec(&request).unwrap()).into();
        with_test_storage_pool(1, |used| {
            assert_eq!(fingerprint(&request).unwrap(), expected);
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn native_receipt_id_copy_refuses_before_growth_and_releases_after_output() {
        let values = ["public-日本語".repeat(1024), "second".into()];
        with_test_storage_pool(1, |used| {
            assert!(matches!(
                ids(values.iter().map(String::as_str)),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
        });
        with_test_storage_pool(64 * 1024, |used| {
            let copied = ids(values.iter().map(String::as_str)).unwrap();
            assert_eq!(&*copied, values);
            assert_ne!(copied[0].as_ptr(), values[0].as_ptr());
            let (rows, admission) = copied.into_parts();
            let retained = used();
            assert!(retained > rows[0].len() as u64);
            drop(rows);
            assert_eq!(used(), retained);
            drop(admission);
            assert_eq!(used(), 0);
        });
    }
}
