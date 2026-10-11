//! Exact protected retrieval: policy domain first, query predicates second.
//! This is the reference path for validating future ANN/pushdown optimizations.
use super::*;
use crate::search::PointResolver;
use crate::security::{AccessContext, Action, AuthorizedOutput, SecurityError, SecurityFilter};

pub(super) struct ReadBudget<'a> {
    context: &'a AccessContext,
    started: Instant,
    duration: Duration,
    cancelled: Option<&'a AtomicBool>,
    shutdown: &'a AtomicBool,
}
impl<'a> ReadBudget<'a> {
    pub(super) fn new(
        context: &'a AccessContext,
        milliseconds: Option<u64>,
        cancelled: Option<&'a AtomicBool>,
        shutdown: &'a AtomicBool,
    ) -> Self {
        Self {
            context,
            started: Instant::now(),
            duration: Duration::from_millis(milliseconds.unwrap_or(30_000).min(30_000)),
            cancelled,
            shutdown,
        }
    }
    pub(super) fn check(&self) -> std::result::Result<(), SecurityError> {
        self.context.publication_permit()?;
        if self.shutdown.load(Ordering::Acquire)
            || self.started.elapsed() >= self.duration
            || self
                .cancelled
                .is_some_and(|cancelled| cancelled.load(Ordering::Acquire))
        {
            return Err(SecurityError::BudgetExceeded);
        }
        Ok(())
    }
}

impl Db {
    pub fn count_authorized(
        &self,
        context: &AccessContext,
        filter: Option<Filter>,
    ) -> Result<AuthorizedOutput<CountResponse>> {
        if context.action() != Action::Read {
            return Err(SecurityError::Forbidden.into());
        }
        self.count_domain_authorized(context, filter)
    }

    pub fn count_deletable_authorized(
        &self,
        context: &AccessContext,
        filter: Filter,
    ) -> Result<AuthorizedOutput<CountResponse>> {
        if context.action() != Action::Delete {
            return Err(SecurityError::Forbidden.into());
        }
        self.count_domain_authorized(context, Some(filter))
    }

    fn count_domain_authorized(
        &self,
        context: &AccessContext,
        filter: Option<Filter>,
    ) -> Result<AuthorizedOutput<CountResponse>> {
        let filter = filter.map(SecurityFilter::compile).transpose()?;
        let budget = ReadBudget::new(context, None, None, self.build_lifecycle.cancellation());
        let _lifecycle = self.lifecycle_gate.read();
        let _admission = self.maintenance_barrier.read();
        budget.check()?;
        self.ensure_collection_cold_materialized_authorized(context)?;
        let collection = self.get_coll_authorized(context)?;
        let collection = collection.read();
        let _lease = context.publication_permit()?;
        let mut count = 0usize;
        let resources = context.read_resources()?;
        resources.for_each_authorized(
            || Ok(budget.check()?),
            |record| {
                budget.check()?;
                if let Some(filter) = &filter {
                    let mut storage = [0; 36];
                    let point = collection
                        .resolve_candidate(record.storage_name(&mut storage))?
                        .ok_or(SecurityError::Unavailable)?;
                    if !record.matches_filter(filter, &point.payload)? {
                        return Ok(());
                    }
                }
                count += 1;
                Ok(())
            },
        )?;
        budget.check()?;
        Ok(AuthorizedOutput::new(
            context.clone(),
            CountResponse { count },
        ))
    }

    pub fn scroll_authorized(
        &self,
        context: &AccessContext,
        request: crate::model::ScrollRequest,
    ) -> Result<AuthorizedOutput<ScrollResponse>> {
        if context.action() != Action::Read {
            return Err(SecurityError::Forbidden.into());
        }
        if request.limit == 0
            || request.limit > 1024
            || request
                .offset
                .as_ref()
                .is_some_and(|id| id.len() > MAX_POINT_ID_BYTES)
        {
            return Err(SecurityError::BudgetExceeded.into());
        }
        let filter = request.filter.map(SecurityFilter::compile).transpose()?;
        let budget = ReadBudget::new(context, None, None, self.build_lifecycle.cancellation());
        let _lifecycle = self.lifecycle_gate.read();
        let _admission = self.maintenance_barrier.read();
        budget.check()?;
        self.ensure_collection_cold_materialized_authorized(context)?;
        let collection = self.get_coll_authorized(context)?;
        let collection = collection.read();
        let _lease = context.publication_permit()?;
        let resources = context.read_resources()?;
        let mut page = crate::search::RankedHeap::new(request.limit + 1);
        resources.for_each_authorized(
            || Ok(budget.check()?),
            |record| {
                budget.check()?;
                if let Some(filter) = &filter {
                    let mut storage = [0; 36];
                    let point = collection
                        .resolve_candidate(record.storage_name(&mut storage))?
                        .ok_or(SecurityError::Unavailable)?;
                    if !record.matches_filter(filter, &point.payload)? {
                        return Ok(());
                    }
                }
                if request
                    .offset
                    .as_ref()
                    .is_some_and(|offset| record.id() <= offset.as_str())
                {
                    return Ok(());
                }
                page.copy_push(record.id(), 0.0)?;
                Ok(())
            },
        )?;
        let mut page = page.finish();
        let more = page.len() > request.limit;
        page.truncate(request.limit);
        let mut points = crate::security::output::Points::default();
        let mut bytes = 0usize;
        for row in page {
            budget.check()?;
            let record = resources.public(&row.id)?;
            let mut storage = [0; 36];
            let point = collection
                .resolve_candidate(record.storage_name(&mut storage))?
                .ok_or(SecurityError::Unavailable)?;
            let point = points.push(record.project_point(&point)?)?;
            bytes += crate::security::storage::serialized_len(point, 8 * 1024 * 1024 - bytes)?;
        }
        budget.check()?;
        points.finish_scroll(context.clone(), more)
    }

    /// Returns only authorized IDs, scores and projected payload. Internal
    /// candidate counts, physical IDs, graph traces and storage receipts have
    /// no representation in this response.
    pub fn search_authorized(
        &self,
        context: &AccessContext,
        request: SearchRequest,
        cancelled: Option<&AtomicBool>,
    ) -> Result<AuthorizedOutput<Vec<SearchHit>>> {
        if context.action() != Action::Search {
            return Err(SecurityError::Forbidden.into());
        }
        validate_k(request.k, "k")?;
        if request.graph.is_some() {
            return Err(SecurityError::Unavailable.into());
        }
        if request.vector.is_empty()
            || request.vector.len() > MAX_VECTOR_DIM
            || request.vector.iter().any(|value| !value.is_finite())
        {
            return Err(SecurityError::Invalid("invalid query vector".into()).into());
        }
        if let Some(name) = &request.vector_name {
            validate_vector_name(name)?;
        }
        if request
            .recall_target
            .is_some_and(|value| !value.is_finite() || !(0.5..=1.0).contains(&value))
        {
            return Err(SecurityError::Invalid("invalid recall target".into()).into());
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
        if request.vector.len() != collection.config.vector_dim {
            return Err(GaussError::DimensionMismatch {
                expected: collection.config.vector_dim,
                actual: request.vector.len(),
            });
        }
        let resources = context.read_resources()?;
        let mut candidates = crate::search::RankedHeap::new(request.k);
        resources.for_each_authorized(
            || Ok(budget.check()?),
            |record| {
                budget.check()?;
                if !record
                    .representation_visible(request.vector_name.as_deref().unwrap_or("dense"))?
                {
                    return Ok(());
                }
                let mut storage = [0; 36];
                let point = collection
                    .resolve_candidate(record.storage_name(&mut storage))?
                    .ok_or(SecurityError::Unavailable)?;
                if let Some(filter) = &filter
                    && !record.matches_filter(filter, &point.payload)?
                {
                    return Ok(());
                }
                let Some(vector) = point_vector(&point, request.vector_name.as_deref()) else {
                    return Ok(());
                };
                let score = collection.config.metric.score(&request.vector, vector)?;
                if !score.is_finite() {
                    return Err(SecurityError::Unavailable.into());
                }
                candidates.copy_push(record.id(), score)?;
                Ok(())
            },
        )?;
        let mut hits = crate::security::output::Hits::default();
        let mut bytes = 0usize;
        for candidate in candidates.finish() {
            budget.check()?;
            let payload = if request
                .with_payload
                .unwrap_or_else(|| self.default_with_payload())
            {
                let record = resources.public(&candidate.id)?;
                let mut storage = [0; 36];
                let point = collection
                    .resolve_candidate(record.storage_name(&mut storage))?
                    .ok_or(SecurityError::Unavailable)?;
                record.project(&point.payload)?
            } else {
                crate::relational::wal_decode::borrowed_json(&Value::Null)?
            };
            let hit = hits.push(&candidate.id, candidate.score, payload)?;
            bytes += crate::security::storage::serialized_len(hit, 8 * 1024 * 1024 - bytes)?;
        }
        budget.check()?;
        Ok(hits.finish(context.clone()))
    }
}
