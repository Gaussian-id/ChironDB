//! Native text retrieval against one pinned collection generation.
use super::*;
use crate::{TenantScope, TextHybridSearchRequest};

struct TextOrdinalFilter<'a, F> {
    collection: &'a Collection,
    eligible: &'a F,
}

impl<F: Fn(&str) -> bool + Send + Sync> crate::index::OrdinalFilterPredicate
    for TextOrdinalFilter<'_, F>
{
    fn matches_ordinal(&self, segment: &str, ordinal: u32) -> bool {
        self.collection
            .searchers
            .iter()
            .find(|searcher| searcher.id == segment)
            .and_then(|searcher| match &searcher.store {
                crate::searcher::SegmentStore::V4(store) => store.id(ordinal as usize),
                crate::searcher::SegmentStore::Heap(_) => None,
            })
            .is_some_and(self.eligible)
    }
}

impl Db {
    pub fn text_hybrid_search_scoped(
        &self,
        collection: &str,
        request: TextHybridSearchRequest,
        scope: &TenantScope,
    ) -> Result<SearchResponse> {
        self.text_hybrid_search_with_cancellation_scoped(
            collection,
            request,
            scope,
            self.build_lifecycle.cancellation(),
        )
    }

    /// Cancellation is cooperative throughout candidate selection and postings.
    pub fn text_hybrid_search_with_cancellation_scoped(
        &self,
        collection_name: &str,
        mut request: TextHybridSearchRequest,
        scope: &TenantScope,
        cancelled: &AtomicBool,
    ) -> Result<SearchResponse> {
        let started = Instant::now();
        let budget = Duration::from_millis(request.budget_ms.unwrap_or(30_000));
        let stopped = || {
            if started.elapsed() >= budget {
                cancelled.store(true, Ordering::Relaxed);
            }
            cancelled.load(Ordering::Relaxed)
        };
        let enforcement = self.tenant_enforcement();
        request.filter = scope.scope_filter(enforcement, request.filter)?;
        validate_k(request.k, "k")?;
        validate_filter_complexity(request.filter.as_ref())?;
        if request.text_field.is_empty() || request.query.len() > 8192 {
            return Err(GaussError::InvalidRequest(
                "text_field must be nonempty and query must not exceed 8192 bytes".into(),
            ));
        }
        if request.vector.iter().any(|value| !value.is_finite()) {
            return Err(GaussError::InvalidRequest(
                "dense vector values must be finite".into(),
            ));
        }
        let _lifecycle = self.lifecycle_gate.read();
        let _inflight = SearchInflightGuard::new(self.search_inflight.clone());
        let mut metrics = OperationGuard::start("text_hybrid_search");
        self.ensure_collection_cold_materialized_scope(
            collection_name,
            ColdMaterializeScope::HybridSearch,
        )?;
        let coll = self.get_coll(collection_name)?;
        let collection = coll.read();
        if !request.vector.is_empty() && request.vector.len() != collection.config.vector_dim {
            return Err(GaussError::DimensionMismatch {
                expected: collection.config.vector_dim,
                actual: request.vector.len(),
            });
        }
        let visibility = collection.overlay_read_state();
        let resolver = CollectionReadResolver {
            collection: &collection,
            state: &visibility,
        };
        let payload_candidates =
            collection.payload_candidates(&visibility, request.filter.as_ref());
        // ANN predicates use only the pinned membership/posting domain. Payload
        // predicates run after fallible hydration, so their errors are not lost
        // in the backend's boolean predicate contract.
        let admitted = |id: &str| {
            !stopped()
                && collection
                    .sparse_index
                    .text
                    .contains(&request.text_field, id)
                && payload_candidates
                    .as_ref()
                    .is_none_or(|set| collection.payload_candidate_contains(set, id))
        };
        let eligible = |id: &str| -> Result<bool> {
            if !admitted(id) {
                return Ok(false);
            }
            let Some(filter) = &request.filter else {
                return Ok(true);
            };
            Ok(collection
                .try_resolve_in_read_state(&visibility, id)?
                .is_some_and(|point| filter.matches(&point.payload)))
        };
        let ordinal_filter = TextOrdinalFilter {
            collection: &collection,
            eligible: &admitted,
        };
        let branch_limit = request.k.saturating_mul(4).max(request.k);
        let recall_target = collection
            .config
            .recall_sla
            .unwrap_or(crate::h2qg::DEFAULT_RECALL_TARGET);
        let ef = collection
            .config
            .hnsw_ef_search
            .map(|ef| (ef as usize).max(branch_limit))
            .or_else(|| {
                collection.config.recall_sla.map(|target| {
                    crate::h2qg::ef_search_for_recall_target(
                        branch_limit,
                        target,
                        collection.live_points(),
                        collection.config.vector_dim,
                    )
                })
            });
        let mut dense = crate::search::Rankings::default();
        let mut searched = 0;
        if !request.vector.is_empty() && request.k > 0 && !stopped() {
            for point in crate::search::fan_out_candidates(
                collection.global_backend(),
                &collection.streamer,
                collection.sealing.as_deref(),
                &collection.searchers,
                &visibility,
                &resolver,
                collection.live_points(),
                &request.vector,
                branch_limit,
                None,
                ef,
                recall_target,
                Some(&admitted),
                Some(&ordinal_filter),
                Some(cancelled),
            )? {
                if stopped() {
                    break;
                }
                if admitted(&point.id)
                    && request
                        .filter
                        .as_ref()
                        .is_none_or(|filter| filter.matches(&point.payload))
                {
                    searched += 1;
                    dense.copy_push(
                        &point.id,
                        collection
                            .config
                            .metric
                            .score(&request.vector, &point.vector)?,
                    )?;
                }
            }
        }
        dense.sort_unstable_by(rank_order);
        dense.truncate(branch_limit);
        let tenant = if enforcement.blocks() && !scope.is_system() && !scope.can_cross_read() {
            scope.tenant_id()
        } else {
            None
        };
        let lexical = collection.sparse_index.text.try_search(
            &request.text_field,
            &request.query,
            tenant,
            branch_limit,
            &eligible,
            &stopped,
        )?;
        searched += lexical.searched;
        let fused = if request.vector.is_empty() {
            lexical.ranked
        } else {
            crate::search::fuse_text_rankings(&dense, &lexical.ranked)?
        };
        let hits = fused
            .into_iter()
            .take(request.k)
            .filter_map(|ranked| {
                collection
                    .try_resolve_in_read_state(&visibility, &ranked.id)
                    .map(|point| {
                        point.map(|point| SearchHit {
                            id: point.id.clone(),
                            score: ranked.score,
                            payload: point.payload.clone(),
                        })
                    })
                    .transpose()
            })
            .collect::<Result<Vec<_>>>()?;
        let degraded = lexical.degraded || stopped();
        if degraded {
            observe_degraded("text_hybrid_search");
        }
        metrics.succeed();
        Ok(SearchResponse {
            hits,
            degraded,
            searched,
            elapsed_ms: started.elapsed().as_millis(),
            graph: None,
        })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod benchmark;
