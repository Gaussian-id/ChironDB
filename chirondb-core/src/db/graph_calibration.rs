//! Checked, compare-and-swap publication of planner calibration evidence.
//!
//! The calibration harness is intentionally outside the request path. This
//! module is the single installation boundary: candidates must bind the
//! current graph/vector cut, publish atomically, and become visible in memory
//! only after the durable file is installed.

use std::sync::Arc;

use crate::{GaussError, Result, graph_estimator::GraphCalibrationStore};

use super::{Db, audit_context, collection_dir};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "consumed by the local calibration harness before G3 admin surfaces"
)]
pub(crate) struct GraphCalibrationPublicationReceipt {
    pub(crate) previous_version: Option<u64>,
    pub(crate) published_version: u64,
    pub(crate) envelope_count: usize,
}

impl Db {
    #[allow(
        dead_code,
        reason = "consumed by the local calibration harness before G3 admin surfaces"
    )]
    pub(crate) fn publish_graph_calibration_candidate_scoped(
        &self,
        collection_name: &str,
        expected_current_version: Option<u64>,
        candidate: GraphCalibrationStore,
        scope: &crate::tenant::TenantScope,
    ) -> Result<GraphCalibrationPublicationReceipt> {
        let audit = self.audit_operation_with_context(
            "graph_calibration_publish",
            Some(collection_name),
            audit_context(scope),
        )?;
        let result = (|| {
            if !scope.is_system() && !scope.can_cross_write() {
                return Err(GaussError::InvalidRequest(
                    "graph calibration publication requires an administrative writer".into(),
                ));
            }
            candidate.validate()?;
            let _lifecycle = self.lifecycle_gate.write();
            self.ensure_storage_mutations_available()?;
            let _admission = self.maintenance_barrier.read();
            let root = self.inner.read().root.clone();
            let coll = self.get_coll(collection_name)?;
            let mut collection = coll.write();
            super::graph_runtime::active_mutable_graph(&collection)?;
            if collection.graph_backfill_pending() {
                return Err(GaussError::InvalidRequest(
                    "graph calibration cannot publish while point-handle backfill is pending"
                        .into(),
                ));
            }
            let visibility = collection.overlay_read_state();
            let state = super::graph_retrieval::graph_planner_state(&collection, &visibility)?;
            let current_version = collection
                .graph_calibration
                .as_ref()
                .map(|store| store.calibration_version);
            if current_version != expected_current_version {
                return Err(GaussError::InvalidRequest(format!(
                    "graph calibration compare-and-swap failed: expected {expected_current_version:?}, current {current_version:?}"
                )));
            }
            if candidate.calibration_version <= current_version.unwrap_or(0) {
                return Err(GaussError::InvalidRequest(
                    "graph calibration version must advance monotonically".into(),
                ));
            }
            for envelope in &candidate.envelopes {
                let dimension = match envelope.vector_field.as_deref() {
                    Some(name) => collection.config.named_vector_dims.get(name).copied(),
                    None => Some(collection.config.vector_dim),
                };
                if dimension != usize::try_from(envelope.dimension).ok()
                    || envelope.metric != collection.config.metric
                    || envelope.graph_epoch != state.graph_epoch
                    || envelope.schema_epoch != state.schema_epoch
                    || envelope.manifest_generation != state.manifest_generation
                    || envelope.overlay_generation != state.overlay_generation
                    || envelope.planner_policy_version
                        != super::graph_retrieval::GRAPH_PLANNER_POLICY_VERSION
                    || envelope.branch_depth_policy_version
                        != super::graph_retrieval::GRAPH_BRANCH_DEPTH_POLICY_VERSION
                {
                    return Err(GaussError::InvalidRequest(
                        "graph calibration candidate does not bind the active graph/vector state"
                            .into(),
                    ));
                }
            }

            candidate.publish(&collection_dir(&root, collection_name))?;
            let receipt = GraphCalibrationPublicationReceipt {
                previous_version: current_version,
                published_version: candidate.calibration_version,
                envelope_count: candidate.envelopes.len(),
            };
            collection.graph_calibration = Some(Arc::new(candidate));
            Ok(receipt)
        })();

        match result {
            Ok(receipt) => {
                audit.success(serde_json::json!({
                    "previous_version": receipt.previous_version,
                    "published_version": receipt.published_version,
                    "envelope_count": receipt.envelope_count,
                }))?;
                Ok(receipt)
            }
            Err(error) => {
                audit.failure(super::graph_retrieval::audit_error_code(&error))?;
                Err(error)
            }
        }
    }
}
