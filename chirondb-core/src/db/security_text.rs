//! Protected text retrieval. Both ranking branches use public IDs and a field
//! domain derived from current authority. Hidden documents never affect BM25.
use super::{security_retrieval::ReadBudget, *};
use crate::search::PointResolver;
use crate::security::{AccessContext, Action, AuthorizedOutput, SecurityError, SecurityFilter};
impl Db {
    /// BM25 alone (empty vector) or dense + BM25 RRF. The dense branch is the
    /// exact protected reference path; ANN/resource qualification is separate.
    /// Only hits are exposed, never physical candidate counts or storage timing.
    pub fn text_hybrid_search_authorized(
        &self,
        context: &AccessContext,
        request: crate::TextHybridSearchRequest,
        cancelled: Option<&AtomicBool>,
    ) -> Result<AuthorizedOutput<Vec<SearchHit>>> {
        if context.action() != Action::Search {
            return Err(SecurityError::Forbidden.into());
        }
        validate_k(request.k, "k")?;
        if request.text_field.is_empty()
            || request.text_field.len() > 8192
            || request.query.len() > 8192
        {
            return Err(SecurityError::Invalid("invalid text field or query length".into()).into());
        }
        if request.vector.len() > MAX_VECTOR_DIM || request.vector.iter().any(|v| !v.is_finite()) {
            return Err(SecurityError::Invalid("invalid query vector".into()).into());
        }
        let filter = request.filter.map(SecurityFilter::compile).transpose()?;
        let budget = ReadBudget::new(
            context,
            request.budget_ms,
            cancelled,
            self.build_lifecycle.cancellation(),
        );
        budget.check()?;
        let _lifecycle = self.lifecycle_gate.read();
        let _admission = self.maintenance_barrier.read();
        let _inflight = SearchInflightGuard::new(self.search_inflight.clone());
        budget.check()?;
        self.ensure_collection_cold_materialized_authorized(context)?;
        let collection = self.get_coll_authorized(context)?;
        let collection = collection.read();
        let _lease = context.publication_permit()?;
        if !request.vector.is_empty() && request.vector.len() != collection.config.vector_dim {
            return Err(GaussError::DimensionMismatch {
                expected: collection.config.vector_dim,
                actual: request.vector.len(),
            });
        }
        // TextIndex indexes literal top-level keys, never dotted aliases.
        let resources = context.read_resources()?;
        let path = crate::security::PropertyPath::field(&request.text_field)?;
        let authorize = |physical: &str| -> Result<Option<&str>> {
            budget.check()?;
            let physical =
                uuid::Uuid::parse_str(physical).map_err(|_| SecurityError::Unavailable)?;
            let checked = resources.physical(physical).and_then(|record| {
                record.query_field(path.as_str())?;
                Ok(record.id())
            });
            match checked {
                Ok(id) => Ok(Some(id)),
                Err(SecurityError::NotFound) => Ok(None),
                Err(error) => Err(error.into()),
            }
        };
        let eligible = |physical: &str| -> Result<bool> {
            budget.check()?;
            let Some(filter) = &filter else {
                return Ok(true);
            };
            let record = resources.physical(
                uuid::Uuid::parse_str(physical).map_err(|_| SecurityError::Unavailable)?,
            )?;
            let point = collection
                .resolve_candidate(physical)?
                .ok_or(SecurityError::Unavailable)?;
            Ok(record.matches_filter(filter, &point.payload)?)
        };
        let branch_limit = request.k.saturating_mul(4);
        let text = &collection.sparse_index.text;
        let mut dense = crate::search::RankedHeap::new(branch_limit);
        if !request.vector.is_empty() && request.k > 0 {
            for physical in text.document_ids(&request.text_field) {
                let Some(id) = authorize(physical)? else {
                    continue;
                };
                if !resources
                    .physical(
                        uuid::Uuid::parse_str(physical).map_err(|_| SecurityError::Unavailable)?,
                    )?
                    .representation_visible("dense")?
                    || !eligible(physical)?
                {
                    continue;
                }
                let point = collection
                    .resolve_candidate(physical)?
                    .ok_or(SecurityError::Unavailable)?;
                let score = collection
                    .config
                    .metric
                    .score(&request.vector, &point.vector)?;
                if !score.is_finite() {
                    return Err(SecurityError::Unavailable.into());
                }
                dense.copy_push(id, score)?;
            }
        }
        let lexical = text.search_authorized(
            &request.text_field,
            &request.query,
            branch_limit,
            &authorize,
            &eligible,
            &|| Ok(budget.check()?),
        )?;
        let ranked = if request.vector.is_empty() {
            lexical.ranked
        } else {
            let dense = dense.finish();
            crate::search::fuse_text_rankings(&dense, &lexical.ranked)?
        };
        let mut hits = crate::security::output::Hits::default();
        let mut bytes = 0;
        for ranked in ranked.into_iter().take(request.k) {
            budget.check()?;
            let record = resources.public(&ranked.id)?;
            let mut storage = [0; 36];
            let point = collection
                .resolve_candidate(record.storage_name(&mut storage))?
                .ok_or(SecurityError::Unavailable)?;
            let payload = record.project(&point.payload)?;
            let hit = hits.push(&ranked.id, ranked.score, payload)?;
            bytes += crate::security::storage::serialized_len(hit, 8 * 1024 * 1024 - bytes)?;
        }
        budget.check()?;
        Ok(hits.finish(context.clone()))
    }
}
