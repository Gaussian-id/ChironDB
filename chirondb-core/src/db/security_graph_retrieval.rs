//! Current endpoint authority and field-safe predicates for graph expansion.
use super::*;
use crate::{
    graph::{GraphTraverseRequest, Nid},
    graph_resolver::PointIncarnationResolver,
    graph_traversal::TraversalAccess,
    security::{AccessContext, SecurityError, SecurityFilter},
};

pub(super) struct TraversalAuthority<'a> {
    context: &'a AccessContext,
    epoch: crate::graph::GraphEpoch,
    resolver: &'a PointIncarnationResolver,
    filter: Option<SecurityFilter>,
    cancelled: &'a AtomicBool,
    started: Instant,
    duration: Duration,
}

impl<'a> TraversalAuthority<'a> {
    pub(super) fn new(
        context: &'a AccessContext,
        resolver: &'a PointIncarnationResolver,
        epoch: crate::graph::GraphEpoch,
        request: &GraphTraverseRequest,
        cancelled: &'a AtomicBool,
    ) -> Result<Self> {
        Ok(Self {
            context,
            epoch,
            resolver,
            filter: request
                .node_filter
                .clone()
                .map(SecurityFilter::compile)
                .transpose()?,
            cancelled,
            started: Instant::now(),
            duration: Duration::from_millis(request.budget.max_time_ms.min(30_000)),
        })
    }

    pub(super) fn matches_point(&self, physical: &str, payload: &Value) -> Result<bool> {
        self.check()?;
        let record = self.context.authorize_physical(
            uuid::Uuid::parse_str(physical).map_err(|_| SecurityError::Unavailable)?,
        )?;
        self.filter.as_ref().map_or(Ok(true), |filter| {
            Ok(self
                .context
                .matches_filter(&record.key.id, filter, payload)?)
        })
    }
}

impl TraversalAccess for TraversalAuthority<'_> {
    fn check(&self) -> Result<()> {
        self.context.publication_permit()?;
        if self.cancelled.load(Ordering::Acquire) || self.started.elapsed() >= self.duration {
            return Err(SecurityError::BudgetExceeded.into());
        }
        Ok(())
    }

    fn visible(&self, nid: Nid) -> Result<bool> {
        self.check()?;
        let Some(physical) = self.resolver.live_point_id(nid) else {
            return Ok(false);
        };
        match self.context.authorize_physical(
            uuid::Uuid::parse_str(physical).map_err(|_| SecurityError::Unavailable)?,
        ) {
            Ok(_) => Ok(true),
            Err(SecurityError::NotFound) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn matches_node(&self, nid: Nid, payload: &Value) -> Result<bool> {
        let physical = self
            .resolver
            .live_point_id(nid)
            .ok_or(SecurityError::Unavailable)?;
        self.matches_point(physical, payload)
    }

    fn edge_visible(&self, edge: crate::graph::EdgeId) -> Result<bool> {
        self.check()?;
        match self.context.authorize_edge(edge, self.epoch) {
            Ok(_) => Ok(true),
            Err(SecurityError::NotFound) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn matches_edge(
        &self,
        edge: crate::graph::EdgeId,
        source: Nid,
        target: Nid,
        filter: &Filter,
        properties: &Value,
    ) -> Result<bool> {
        self.check()?;
        let public = |nid| -> Result<String> {
            let physical = self
                .resolver
                .live_point_id(nid)
                .ok_or(SecurityError::Unavailable)?;
            Ok(self
                .context
                .authorize_physical(
                    uuid::Uuid::parse_str(physical).map_err(|_| SecurityError::Unavailable)?,
                )?
                .key
                .id)
        };
        Ok(self.context.matches_edge_filter(
            (self.epoch, edge),
            &public(source)?,
            &public(target)?,
            &SecurityFilter::compile(filter.clone())?,
            properties,
        )?)
    }
}
