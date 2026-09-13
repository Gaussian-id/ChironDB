//! P0/C19 structural-point embedding policy.
//!
//! Structural graph nodes remain ordinary points (D18), so their unnamed
//! vector is total. This module keeps the policy out of `db.rs`: typed graph
//! entry points reject the shared all-zero sentinel, while legacy/generic
//! point upserts retain their existing compatibility behavior.

use sha2::{Digest, Sha256};

use crate::{GaussError, Point, Result};

pub const MAX_UNSAFE_STRUCTURAL_REASON_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsafeStructuralEmbeddingAudit {
    pub reason: String,
    pub point_count: usize,
    pub zero_vector_points: usize,
    pub point_id_sha256: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuralUpsertReceipt {
    pub total: usize,
    pub operation_lsn: u64,
    pub unsafe_override_audited: bool,
}

pub fn validate_structural_points(
    points: &[Point],
    unsafe_reason: Option<&str>,
) -> Result<Option<UnsafeStructuralEmbeddingAudit>> {
    let mut zero_vector_points = 0usize;
    for point in points {
        if point.vector.iter().any(|value| !value.is_finite()) {
            return Err(GaussError::InvalidRequest(format!(
                "structural point '{}': vector values must be finite",
                point.id
            )));
        }
        if point.vector.iter().all(|value| *value == 0.0) {
            zero_vector_points += 1;
        }
    }

    let reason = unsafe_reason
        .map(str::trim)
        .filter(|reason| !reason.is_empty());
    if zero_vector_points > 0 && reason.is_none() {
        return Err(GaussError::InvalidRequest(format!(
            "{zero_vector_points} structural point(s) use an all-zero vector; derive the vector from the point identity or provide an explicit audited unsafe override"
        )));
    }
    if unsafe_reason.is_some() && reason.is_none() {
        return Err(GaussError::InvalidRequest(
            "unsafe structural embedding override reason must not be empty".to_string(),
        ));
    }
    let Some(reason) = reason else {
        return Ok(None);
    };
    if reason.len() > MAX_UNSAFE_STRUCTURAL_REASON_BYTES {
        return Err(GaussError::InvalidRequest(format!(
            "unsafe structural embedding override reason is {} bytes; maximum is {MAX_UNSAFE_STRUCTURAL_REASON_BYTES}",
            reason.len()
        )));
    }
    if zero_vector_points == 0 {
        return Err(GaussError::InvalidRequest(
            "unsafe structural embedding override was supplied but the batch has no all-zero structural vector"
                .to_string(),
        ));
    }

    Ok(Some(UnsafeStructuralEmbeddingAudit {
        reason: reason.to_string(),
        point_count: points.len(),
        zero_vector_points,
        point_id_sha256: points
            .iter()
            .map(|point| sha256_hex(point.id.as_bytes()))
            .collect(),
    }))
}

fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("write to String");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;

    fn point(id: &str, vector: Vec<f32>) -> Point {
        Point {
            id: id.to_string(),
            vector,
            vectors: HashMap::new(),
            sparse_vector: None,
            payload: json!({}),
        }
    }

    #[test]
    fn rejects_zero_without_override() {
        let error =
            validate_structural_points(&[point("line-3", vec![0.0, -0.0])], None).unwrap_err();
        assert!(error.to_string().contains("all-zero vector"));
    }

    #[test]
    fn accepts_identity_embedding_without_audit_override() {
        assert_eq!(
            validate_structural_points(&[point("line-3", vec![0.2, -0.1])], None).unwrap(),
            None
        );
    }

    #[test]
    fn unsafe_override_is_reasoned_and_hashes_ids() {
        let audit = validate_structural_points(
            &[point("line-3", vec![0.0, 0.0])],
            Some("legacy import cannot be re-embedded"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(audit.point_count, 1);
        assert_eq!(audit.zero_vector_points, 1);
        assert_eq!(audit.point_id_sha256[0].len(), 64);
        assert!(!audit.point_id_sha256[0].contains("line-3"));
    }
}
