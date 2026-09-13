//! Exact BFS over scoped mutable and pinned sealed adjacency candidates.

use std::{
    borrow::Cow,
    collections::HashSet,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use serde_json::Value;

use crate::{
    Filter, GaussError, Result,
    graph::{
        EdgeId, GraphDirection, GraphError, GraphErrorCode, GraphNamespace, Nid, TraversalBudget,
        TraversalResult, TraversalStats, TraversalTruncationReason, TraversalVisit,
    },
    graph_group::AdjacencyStep,
    mutable_graph::MutableGraphState,
};

// Includes conservative HashSet bucket/allocator overhead plus the eventual
// public point-id result (fixed public point-id cap is 1 KiB).
const NODE_STATE_BYTES: u64 = 1_152;
const FRONTIER_NODE_BYTES: u64 = 8;
const CAPTURED_EDGE_BYTES: u64 = 64;
const EDGE_CHECK_INTERVAL: u64 = 4_096;

pub(crate) trait TraversalGraph {
    type EdgeIds<'a>: Iterator<Item = Result<AdjacencyStep>>
    where
        Self: 'a;

    fn outgoing(&self, namespace: &GraphNamespace, nid: Nid) -> Result<Self::EdgeIds<'_>>;
    fn incoming(&self, namespace: &GraphNamespace, nid: Nid) -> Result<Self::EdgeIds<'_>>;
    fn edge_visible(&self, _edge_id: EdgeId) -> bool {
        true
    }
    fn edge_properties(&self, edge_id: EdgeId) -> Result<Option<Cow<'_, Value>>>;
    fn cursor_memory_bytes(&self) -> u64 {
        0
    }
    fn property_memory_bytes(&self, _edge_id: EdgeId) -> u64 {
        0
    }
    fn local_reference_superseded(&self, _base: u32, _neighbor: Nid) -> bool {
        false
    }
}

impl TraversalGraph for MutableGraphState {
    type EdgeIds<'a> = crate::mutable_graph::adjacency::EdgeCandidates<'a>;

    fn outgoing(&self, namespace: &GraphNamespace, nid: Nid) -> Result<Self::EdgeIds<'_>> {
        self.edge_candidates(namespace, nid, false)
    }

    fn incoming(&self, namespace: &GraphNamespace, nid: Nid) -> Result<Self::EdgeIds<'_>> {
        self.edge_candidates(namespace, nid, true)
    }

    fn cursor_memory_bytes(&self) -> u64 {
        self.adjacency_cursor_memory_bytes()
    }

    fn edge_visible(&self, edge_id: EdgeId) -> bool {
        MutableGraphState::edge_visible(self, edge_id)
    }

    fn edge_properties(&self, edge_id: EdgeId) -> Result<Option<Cow<'_, Value>>> {
        MutableGraphState::edge_properties(self, edge_id)
    }

    fn property_memory_bytes(&self, edge_id: EdgeId) -> u64 {
        if !self.has_mutable_properties(edge_id) {
            // Conservative query-owned JSON tree/string/map/parse scratch,
            // plus both bounded rank bitmap ranges. Shared chunk-cache RSS is
            // separately owned and must still be measured by C18.
            (crate::graph::MAX_EDGE_PROPERTY_BYTES as u64) * 64 + 2 * 4096
        } else {
            0 // Borrow an existing tail document; no query-owned hydration.
        }
    }
}

pub(crate) struct MutableTraversal<'a, G, FPayload, FNamespaces>
where
    G: TraversalGraph,
    FPayload: Fn(Nid) -> Option<Value>,
    FNamespaces: Fn(&Value) -> Vec<GraphNamespace>,
{
    pub(crate) graph: &'a G,
    pub(crate) anchors: Vec<Nid>,
    pub(crate) visible_anchor_count: u64,
    pub(crate) selected_types: Option<HashSet<crate::graph::TypeId>>,
    pub(crate) direction: GraphDirection,
    pub(crate) node_filter: Option<&'a Filter>,
    /// Statement `WHERE`, shared by retrieval branches. Kept separate from
    /// the graph clause's node predicate so duplicate field conditions remain
    /// a true conjunction rather than overwriting one another.
    pub(crate) statement_filter: Option<&'a Filter>,
    pub(crate) edge_filter: Option<&'a Filter>,
    pub(crate) budget: TraversalBudget,
    pub(crate) cancelled: &'a AtomicBool,
    pub(crate) payload_for_nid: FPayload,
    pub(crate) namespaces_for_payload: FNamespaces,
}

/// Executor-only accounting kept outside the public traversal contract.
///
/// `internal_edges_examined` advances before authorization and is used only
/// for enforcing physical-work budgets and isolation tests. Protocol-facing
/// code consumes `result`; it must never serialize the internal counter.
pub(crate) struct TraversalExecution {
    pub(crate) result: TraversalResult,
    pub(crate) edges: Vec<TraversalEdgeVisit>,
    pub(crate) paths: Vec<TraversalPathVisit>,
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "internal budget accounting is not public telemetry"
        )
    )]
    pub(crate) internal_edges_examined: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TraversalEdgeVisit {
    pub(crate) edge_id: EdgeId,
    pub(crate) source: Nid,
    pub(crate) target: Nid,
    pub(crate) type_id: crate::graph::TypeId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TraversalPathVisit {
    pub(crate) nodes: Vec<Nid>,
    pub(crate) edges: Vec<TraversalEdgeVisit>,
}

pub(crate) fn exact_bfs<G, FPayload, FNamespaces>(
    traversal: MutableTraversal<'_, G, FPayload, FNamespaces>,
) -> Result<TraversalExecution>
where
    G: TraversalGraph,
    FPayload: Fn(Nid) -> Option<Value>,
    FNamespaces: Fn(&Value) -> Vec<GraphNamespace>,
{
    exact_bfs_internal(traversal, false)
}

pub(crate) fn exact_bfs_with_edges<G, FPayload, FNamespaces>(
    traversal: MutableTraversal<'_, G, FPayload, FNamespaces>,
) -> Result<TraversalExecution>
where
    G: TraversalGraph,
    FPayload: Fn(Nid) -> Option<Value>,
    FNamespaces: Fn(&Value) -> Vec<GraphNamespace>,
{
    exact_bfs_internal(traversal, true)
}

fn exact_bfs_internal<G, FPayload, FNamespaces>(
    traversal: MutableTraversal<'_, G, FPayload, FNamespaces>,
    capture_edges: bool,
) -> Result<TraversalExecution>
where
    G: TraversalGraph,
    FPayload: Fn(Nid) -> Option<Value>,
    FNamespaces: Fn(&Value) -> Vec<GraphNamespace>,
{
    let MutableTraversal {
        graph,
        mut anchors,
        visible_anchor_count,
        selected_types,
        direction,
        node_filter,
        statement_filter,
        edge_filter,
        budget,
        cancelled,
        payload_for_nid,
        namespaces_for_payload,
    } = traversal;
    let started = Instant::now();
    if cancelled.load(Ordering::Acquire) {
        return Err(cancelled_error());
    }

    anchors.sort_unstable();
    anchors.dedup();
    let mut stats = TraversalStats {
        nodes_visited: visible_anchor_count,
        max_frontier_size: visible_anchor_count,
        ..TraversalStats::default()
    };
    if visible_anchor_count > budget.max_visited {
        return Ok(execution(
            truncated(stats, TraversalTruncationReason::Visited),
            0,
            Vec::new(),
            Vec::new(),
        ));
    }

    let mut visited = anchors.iter().copied().collect::<HashSet<_>>();
    let mut frontier = anchors;
    let mut visits = if budget.max_depth == 0 {
        frontier
            .iter()
            .filter(|nid| {
                payload_for_nid(**nid).is_some_and(|payload| {
                    node_filters_match(node_filter, statement_filter, &payload)
                })
            })
            .map(|nid| TraversalVisit {
                nid: *nid,
                depth: 0,
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let cursor_memory = if budget.max_depth == 0 {
        0
    } else {
        graph.cursor_memory_bytes()
    };
    if estimated_memory(stats.nodes_visited, &frontier, 0, &visits, 0).saturating_add(cursor_memory)
        > budget.max_memory_bytes
    {
        return Ok(execution(
            truncated(stats, TraversalTruncationReason::Memory),
            0,
            Vec::new(),
            Vec::new(),
        ));
    }
    if budget.max_depth == 0 {
        stats.elapsed_ms = elapsed_ms(started);
        return Ok(execution(
            TraversalResult {
                visits,
                stats,
                truncation: None,
                warnings: Vec::new(),
            },
            0,
            Vec::new(),
            Vec::new(),
        ));
    }

    let mut internal_edges = 0_u64;
    let mut captured_edge_ids = HashSet::new();
    let mut captured_edges = Vec::new();
    let mut truncation = None;
    for depth in 1..=budget.max_depth {
        if let Some(reason) = boundary_reason(cancelled, started, &budget, frontier.len())? {
            truncation = Some(reason);
            break;
        }

        let mut next = Vec::new();
        'frontier: for current in &frontier {
            let Some(current_payload) = payload_for_nid(*current) else {
                continue;
            };
            for namespace in namespaces_for_payload(&current_payload) {
                let outgoing = matches!(direction, GraphDirection::Outgoing | GraphDirection::Both)
                    .then(|| graph.outgoing(&namespace, *current))
                    .transpose()?
                    .into_iter()
                    .flatten();
                let incoming = matches!(direction, GraphDirection::Incoming | GraphDirection::Both)
                    .then(|| graph.incoming(&namespace, *current))
                    .transpose()?
                    .into_iter()
                    .flatten();
                let edges = outgoing
                    .map(|edge_id| (edge_id, true))
                    .chain(incoming.map(|edge_id| (edge_id, false)));

                for (step, from_outgoing) in edges {
                    let step = step?;
                    let Some(edge) = step.edge() else {
                        stats.fragments_read = stats.fragments_read.saturating_add(1);
                        if cancelled.load(Ordering::Acquire) {
                            return Err(cancelled_error());
                        }
                        if started.elapsed() >= budget.wall_time() {
                            truncation = Some(TraversalTruncationReason::Time);
                            break 'frontier;
                        }
                        continue;
                    };
                    let edge_id = edge.edge_id;
                    let visible = graph.edge_visible(edge_id);
                    // BOTH sees a self-loop in both adjacency rows. Its stable
                    // EdgeId consumes one work unit, while distinct
                    // multi-edges stay distinct.
                    if direction == GraphDirection::Both
                        && !from_outgoing
                        && visible
                        && edge.source == *current
                        && edge.target == *current
                    {
                        continue;
                    }
                    if internal_edges >= budget.max_edges {
                        truncation = Some(TraversalTruncationReason::Edges);
                        break 'frontier;
                    }
                    internal_edges += 1;
                    if internal_edges.is_multiple_of(EDGE_CHECK_INTERVAL) {
                        if cancelled.load(Ordering::Acquire) {
                            return Err(cancelled_error());
                        }
                        if started.elapsed() >= budget.wall_time() {
                            truncation = Some(TraversalTruncationReason::Time);
                            break 'frontier;
                        }
                    }

                    if !visible {
                        continue;
                    }
                    let neighbour = if from_outgoing {
                        if edge.source != *current {
                            continue;
                        }
                        edge.target
                    } else {
                        if edge.target != *current {
                            continue;
                        }
                        edge.source
                    };
                    // VIA is evaluated before edge-property hydration, and
                    // EDGE WHERE before node payload hydration.
                    if selected_types
                        .as_ref()
                        .is_some_and(|types| !types.contains(&edge.type_id))
                    {
                        continue;
                    }
                    if let Some(filter) = edge_filter {
                        if estimated_memory(
                            stats.nodes_visited,
                            &frontier,
                            next.len(),
                            &visits,
                            captured_edges.len(),
                        )
                        .saturating_add(cursor_memory)
                        .saturating_add(graph.property_memory_bytes(edge_id))
                            > budget.max_memory_bytes
                        {
                            truncation = Some(TraversalTruncationReason::Memory);
                            break 'frontier;
                        }
                        if cancelled.load(Ordering::Acquire) {
                            return Err(cancelled_error());
                        }
                        if started.elapsed() >= budget.wall_time() {
                            truncation = Some(TraversalTruncationReason::Time);
                            break 'frontier;
                        }
                        let properties = graph.edge_properties(edge_id)?.ok_or_else(|| {
                            GaussError::InvalidRequest("live graph edge has no properties".into())
                        })?;
                        if !filter.matches(&properties) {
                            continue;
                        }
                    }
                    if visited.contains(&neighbour) {
                        // Anchors are exempt only while acting as expansion
                        // roots. When an edge reaches an anchor again it is a
                        // neighbour and must pass the node predicates.
                        let Some(payload) = payload_for_nid(neighbour) else {
                            continue;
                        };
                        stats.visible_edges_examined += 1;
                        record_resolution(&mut stats, graph, edge, neighbour);
                        if !node_filters_match(node_filter, statement_filter, &payload) {
                            continue;
                        }
                        let capture = capture_edges && !captured_edge_ids.contains(&edge_id);
                        if capture
                            && estimated_memory(
                                stats.nodes_visited,
                                &frontier,
                                next.len(),
                                &visits,
                                captured_edges.len().saturating_add(1),
                            )
                            .saturating_add(cursor_memory)
                                > budget.max_memory_bytes
                        {
                            truncation = Some(TraversalTruncationReason::Memory);
                            break 'frontier;
                        }
                        if capture {
                            captured_edge_ids.insert(edge_id);
                            captured_edges.push(edge_visit(edge));
                        }
                        continue;
                    }
                    let Some(payload) = payload_for_nid(neighbour) else {
                        continue;
                    };
                    // This counter is observable, so it advances only after
                    // namespace and neighbour visibility have been proven.
                    stats.visible_edges_examined += 1;
                    record_resolution(&mut stats, graph, edge, neighbour);
                    if !node_filters_match(node_filter, statement_filter, &payload) {
                        continue;
                    }
                    let capture = capture_edges && !captured_edge_ids.contains(&edge_id);
                    if capture
                        && estimated_memory(
                            stats.nodes_visited,
                            &frontier,
                            next.len(),
                            &visits,
                            captured_edges.len().saturating_add(1),
                        )
                        .saturating_add(cursor_memory)
                            > budget.max_memory_bytes
                    {
                        truncation = Some(TraversalTruncationReason::Memory);
                        break 'frontier;
                    }
                    if capture {
                        captured_edge_ids.insert(edge_id);
                        captured_edges.push(edge_visit(edge));
                    }
                    if stats.nodes_visited >= budget.max_visited {
                        truncation = Some(TraversalTruncationReason::Visited);
                        break 'frontier;
                    }
                    if estimated_memory(
                        stats.nodes_visited.saturating_add(1),
                        &frontier,
                        next.len().saturating_add(1),
                        &visits,
                        captured_edges.len(),
                    )
                    .saturating_add(cursor_memory)
                        > budget.max_memory_bytes
                    {
                        truncation = Some(TraversalTruncationReason::Memory);
                        break 'frontier;
                    }
                    visited.insert(neighbour);
                    stats.nodes_visited += 1;
                    next.push(neighbour);
                }
            }
        }

        next.sort_unstable();
        next.dedup();
        stats.max_frontier_size = stats.max_frontier_size.max(next.len() as u64);
        visits.extend(next.iter().map(|nid| TraversalVisit { nid: *nid, depth }));
        if truncation.is_some() {
            break;
        }
        if next.len() as u64 > budget.max_frontier {
            truncation = Some(TraversalTruncationReason::Frontier);
            break;
        }
        stats.hops_completed = depth;
        if next.is_empty() {
            break;
        }
        frontier = next;
    }

    stats.elapsed_ms = elapsed_ms(started);
    Ok(execution(
        TraversalResult {
            visits,
            stats,
            truncation,
            warnings: Vec::new(),
        },
        internal_edges,
        captured_edges,
        Vec::new(),
    ))
}

/// Enumerate exact simple paths in deterministic breadth-first order.
///
/// Unlike node traversal, path expansion cannot use a global visited set: two
/// distinct simple paths may end at the same node. Each frontier row therefore
/// carries its own visited sequence, and a neighbour already present in that
/// sequence is never traversed.
pub(crate) fn exact_simple_paths<G, FPayload, FNamespaces>(
    traversal: MutableTraversal<'_, G, FPayload, FNamespaces>,
    limit: usize,
) -> Result<TraversalExecution>
where
    G: TraversalGraph,
    FPayload: Fn(Nid) -> Option<Value>,
    FNamespaces: Fn(&Value) -> Vec<GraphNamespace>,
{
    let MutableTraversal {
        graph,
        mut anchors,
        visible_anchor_count,
        selected_types,
        direction,
        node_filter,
        statement_filter,
        edge_filter,
        budget,
        cancelled,
        payload_for_nid,
        namespaces_for_payload,
    } = traversal;
    let started = Instant::now();
    if cancelled.load(Ordering::Acquire) {
        return Err(cancelled_error());
    }

    anchors.sort_unstable();
    anchors.dedup();
    let mut stats = TraversalStats {
        nodes_visited: visible_anchor_count,
        max_frontier_size: visible_anchor_count,
        ..TraversalStats::default()
    };
    if visible_anchor_count > budget.max_visited {
        return Ok(execution(
            truncated(stats, TraversalTruncationReason::Visited),
            0,
            Vec::new(),
            Vec::new(),
        ));
    }

    let mut frontier = anchors
        .into_iter()
        .map(|anchor| TraversalPathVisit {
            nodes: vec![anchor],
            edges: Vec::new(),
        })
        .collect::<Vec<_>>();
    let mut paths = if budget.max_depth == 0 {
        frontier
            .iter()
            .filter(|path| {
                payload_for_nid(path.nodes[0]).is_some_and(|payload| {
                    node_filters_match(node_filter, statement_filter, &payload)
                })
            })
            .cloned()
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let cursor_memory = if budget.max_depth == 0 {
        0
    } else {
        graph.cursor_memory_bytes()
    };
    if estimated_path_memory(&frontier, &[], &paths).saturating_add(cursor_memory)
        > budget.max_memory_bytes
    {
        return Ok(execution(
            truncated(stats, TraversalTruncationReason::Memory),
            0,
            Vec::new(),
            Vec::new(),
        ));
    }
    if budget.max_depth == 0 {
        let truncation = truncate_paths_to_limit(&mut paths, limit);
        stats.elapsed_ms = elapsed_ms(started);
        return Ok(execution(
            TraversalResult {
                visits: Vec::new(),
                stats,
                truncation,
                warnings: Vec::new(),
            },
            0,
            Vec::new(),
            paths,
        ));
    }

    let mut internal_edges = 0_u64;
    let mut truncation = None;
    for depth in 1..=budget.max_depth {
        if let Some(reason) = boundary_reason(cancelled, started, &budget, frontier.len())? {
            truncation = Some(reason);
            break;
        }

        let mut next = Vec::new();
        'frontier: for path in &frontier {
            let current = *path.nodes.last().expect("path always has an anchor");
            let Some(current_payload) = payload_for_nid(current) else {
                continue;
            };
            for namespace in namespaces_for_payload(&current_payload) {
                let outgoing = matches!(direction, GraphDirection::Outgoing | GraphDirection::Both)
                    .then(|| graph.outgoing(&namespace, current))
                    .transpose()?
                    .into_iter()
                    .flatten();
                let incoming = matches!(direction, GraphDirection::Incoming | GraphDirection::Both)
                    .then(|| graph.incoming(&namespace, current))
                    .transpose()?
                    .into_iter()
                    .flatten();
                let edges = outgoing
                    .map(|edge_id| (edge_id, true))
                    .chain(incoming.map(|edge_id| (edge_id, false)));

                for (step, from_outgoing) in edges {
                    let step = step?;
                    let Some(edge) = step.edge() else {
                        stats.fragments_read = stats.fragments_read.saturating_add(1);
                        if cancelled.load(Ordering::Acquire) {
                            return Err(cancelled_error());
                        }
                        if started.elapsed() >= budget.wall_time() {
                            truncation = Some(TraversalTruncationReason::Time);
                            break 'frontier;
                        }
                        continue;
                    };
                    if direction == GraphDirection::Both
                        && !from_outgoing
                        && graph.edge_visible(edge.edge_id)
                        && edge.source == current
                        && edge.target == current
                    {
                        continue;
                    }
                    if internal_edges >= budget.max_edges {
                        truncation = Some(TraversalTruncationReason::Edges);
                        break 'frontier;
                    }
                    internal_edges += 1;
                    if internal_edges.is_multiple_of(EDGE_CHECK_INTERVAL) {
                        if cancelled.load(Ordering::Acquire) {
                            return Err(cancelled_error());
                        }
                        if started.elapsed() >= budget.wall_time() {
                            truncation = Some(TraversalTruncationReason::Time);
                            break 'frontier;
                        }
                    }
                    if !graph.edge_visible(edge.edge_id) {
                        continue;
                    }
                    let neighbour = if from_outgoing {
                        if edge.source != current {
                            continue;
                        }
                        edge.target
                    } else {
                        if edge.target != current {
                            continue;
                        }
                        edge.source
                    };
                    if selected_types
                        .as_ref()
                        .is_some_and(|types| !types.contains(&edge.type_id))
                    {
                        continue;
                    }
                    if let Some(filter) = edge_filter {
                        if estimated_path_memory(&frontier, &next, &paths)
                            .saturating_add(cursor_memory)
                            .saturating_add(graph.property_memory_bytes(edge.edge_id))
                            > budget.max_memory_bytes
                        {
                            truncation = Some(TraversalTruncationReason::Memory);
                            break 'frontier;
                        }
                        if cancelled.load(Ordering::Acquire) {
                            return Err(cancelled_error());
                        }
                        if started.elapsed() >= budget.wall_time() {
                            truncation = Some(TraversalTruncationReason::Time);
                            break 'frontier;
                        }
                        let properties = graph.edge_properties(edge.edge_id)?.ok_or_else(|| {
                            GaussError::InvalidRequest("live graph edge has no properties".into())
                        })?;
                        if !filter.matches(&properties) {
                            continue;
                        }
                    }
                    let Some(payload) = payload_for_nid(neighbour) else {
                        continue;
                    };
                    stats.visible_edges_examined += 1;
                    record_resolution(&mut stats, graph, edge, neighbour);
                    if !node_filters_match(node_filter, statement_filter, &payload)
                        || path.nodes.contains(&neighbour)
                    {
                        continue;
                    }
                    if stats.nodes_visited >= budget.max_visited {
                        truncation = Some(TraversalTruncationReason::Visited);
                        break 'frontier;
                    }
                    let mut candidate = path.clone();
                    candidate.nodes.push(neighbour);
                    candidate.edges.push(edge_visit(edge));
                    next.push(candidate);
                    if estimated_path_memory(&frontier, &next, &paths)
                        .saturating_add(path_slice_memory(&next))
                        .saturating_add(cursor_memory)
                        > budget.max_memory_bytes
                    {
                        next.pop();
                        truncation = Some(TraversalTruncationReason::Memory);
                        break 'frontier;
                    }
                    stats.nodes_visited += 1;
                }
            }
        }

        next.sort_by(path_order);
        stats.max_frontier_size = stats.max_frontier_size.max(next.len() as u64);
        if truncation.is_none() && next.len() as u64 > budget.max_frontier {
            truncation = Some(TraversalTruncationReason::Frontier);
        }
        paths.extend(next.iter().cloned());
        if truncation.is_some() {
            break;
        }
        stats.hops_completed = depth;
        if paths.len() > limit {
            paths.truncate(limit);
            truncation = Some(TraversalTruncationReason::Limit);
            break;
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }

    stats.elapsed_ms = elapsed_ms(started);
    Ok(execution(
        TraversalResult {
            visits: Vec::new(),
            stats,
            truncation,
            warnings: Vec::new(),
        },
        internal_edges,
        Vec::new(),
        paths,
    ))
}

fn path_order(left: &TraversalPathVisit, right: &TraversalPathVisit) -> std::cmp::Ordering {
    left.nodes.cmp(&right.nodes).then_with(|| {
        left.edges
            .iter()
            .map(|edge| edge.edge_id)
            .cmp(right.edges.iter().map(|edge| edge.edge_id))
    })
}

fn truncate_paths_to_limit(
    paths: &mut Vec<TraversalPathVisit>,
    limit: usize,
) -> Option<TraversalTruncationReason> {
    if paths.len() > limit {
        paths.truncate(limit);
        Some(TraversalTruncationReason::Limit)
    } else {
        None
    }
}

fn estimated_path_memory(
    frontier: &[TraversalPathVisit],
    next: &[TraversalPathVisit],
    paths: &[TraversalPathVisit],
) -> u64 {
    path_slice_memory(frontier)
        .saturating_add(path_slice_memory(next))
        .saturating_add(path_slice_memory(paths))
}

fn path_slice_memory(paths: &[TraversalPathVisit]) -> u64 {
    paths.iter().fold(0_u64, |bytes, path| {
        bytes.saturating_add(48).saturating_add(
            (path.nodes.len() as u64)
                .saturating_mul(std::mem::size_of::<Nid>() as u64)
                .saturating_add((path.edges.len() as u64).saturating_mul(CAPTURED_EDGE_BYTES)),
        )
    })
}

fn edge_visit(edge: crate::graph_group::AdjacencyEdge) -> TraversalEdgeVisit {
    TraversalEdgeVisit {
        edge_id: edge.edge_id,
        source: edge.source,
        target: edge.target,
        type_id: edge.type_id,
    }
}

fn record_resolution<G: TraversalGraph>(
    stats: &mut TraversalStats,
    graph: &G,
    edge: crate::graph_group::AdjacencyEdge,
    neighbour: Nid,
) {
    if let Some(base) = edge.local_base {
        stats.hop_local = stats.hop_local.saturating_add(1);
        if graph.local_reference_superseded(base, neighbour) {
            stats.supersession_followed = stats.supersession_followed.saturating_add(1);
        }
    } else {
        stats.hop_global = stats.hop_global.saturating_add(1);
    }
}

fn node_filters_match(
    graph_filter: Option<&Filter>,
    statement_filter: Option<&Filter>,
    payload: &Value,
) -> bool {
    graph_filter.is_none_or(|filter| filter.matches(payload))
        && statement_filter.is_none_or(|filter| filter.matches(payload))
}

fn execution(
    result: TraversalResult,
    internal_edges_examined: u64,
    edges: Vec<TraversalEdgeVisit>,
    paths: Vec<TraversalPathVisit>,
) -> TraversalExecution {
    TraversalExecution {
        result,
        edges,
        paths,
        internal_edges_examined,
    }
}

fn boundary_reason(
    cancelled: &AtomicBool,
    started: Instant,
    budget: &TraversalBudget,
    frontier_len: usize,
) -> Result<Option<TraversalTruncationReason>> {
    if cancelled.load(Ordering::Acquire) {
        return Err(cancelled_error());
    }
    if started.elapsed() >= budget.wall_time() {
        return Ok(Some(TraversalTruncationReason::Time));
    }
    if frontier_len as u64 > budget.max_frontier {
        return Ok(Some(TraversalTruncationReason::Frontier));
    }
    Ok(None)
}

fn estimated_memory(
    visible_nodes: u64,
    frontier: &[Nid],
    next_len: usize,
    visits: &[TraversalVisit],
    captured_edges: usize,
) -> u64 {
    visible_nodes
        .saturating_mul(NODE_STATE_BYTES)
        .saturating_add(
            (frontier.len().saturating_add(next_len) as u64).saturating_mul(FRONTIER_NODE_BYTES),
        )
        .saturating_add(
            (visits.len() as u64).saturating_mul(std::mem::size_of::<TraversalVisit>() as u64),
        )
        .saturating_add((captured_edges as u64).saturating_mul(CAPTURED_EDGE_BYTES))
}

fn truncated(stats: TraversalStats, reason: TraversalTruncationReason) -> TraversalResult {
    TraversalResult {
        visits: Vec::new(),
        stats,
        truncation: Some(reason),
        warnings: Vec::new(),
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn cancelled_error() -> GaussError {
    GraphError::new(
        GraphErrorCode::Cancelled,
        "graph traversal was cancelled during expansion",
    )
    .into()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use serde_json::json;

    use super::*;
    use crate::graph::{
        ColdTraversalBudget, EdgeId, EdgeMutation, GraphEpoch, RelateMutation,
        TraversalTruncationReason, TypeId,
    };

    struct SyntheticHub {
        edges: u64,
        properties: Value,
    }

    struct SyntheticEdgeIds {
        next: u64,
        end: u64,
    }

    impl Iterator for SyntheticEdgeIds {
        type Item = Result<AdjacencyStep>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.next >= self.end {
                return None;
            }
            let counter = self.next;
            self.next += 1;
            Some(Ok(AdjacencyStep::Edge(crate::graph_group::AdjacencyEdge {
                edge_id: edge_id(counter),
                source: nid(1),
                target: nid(counter % 1_024 + 2),
                type_id: TypeId::from_raw(1),
                local_base: None,
            })))
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = self.end.saturating_sub(self.next) as usize;
            (remaining, Some(remaining))
        }
    }

    impl TraversalGraph for SyntheticHub {
        type EdgeIds<'a> = SyntheticEdgeIds;

        fn outgoing(&self, namespace: &GraphNamespace, node: Nid) -> Result<Self::EdgeIds<'_>> {
            let selected =
                node == nid(1) && namespace == &GraphNamespace::Tenant("acme".to_string());
            Ok(SyntheticEdgeIds {
                next: 1,
                end: if selected { self.edges + 1 } else { 1 },
            })
        }

        fn incoming(&self, namespace: &GraphNamespace, node: Nid) -> Result<Self::EdgeIds<'_>> {
            let _ = (namespace, node);
            Ok(SyntheticEdgeIds { next: 1, end: 1 })
        }

        fn edge_properties(&self, edge_id: EdgeId) -> Result<Option<Cow<'_, Value>>> {
            Ok((edge_id.counter() <= self.edges).then_some(Cow::Borrowed(&self.properties)))
        }
    }

    #[test]
    fn disk_scan_checkpoints_observe_cancellation_and_propagate_read_errors() {
        struct Scan<'a> {
            cancelled: &'a AtomicBool,
            fail: bool,
        }
        impl TraversalGraph for Scan<'_> {
            type EdgeIds<'a>
                = std::iter::Once<Result<AdjacencyStep>>
            where
                Self: 'a;
            fn outgoing(&self, _: &GraphNamespace, _: Nid) -> Result<Self::EdgeIds<'_>> {
                Ok(std::iter::once(if self.fail {
                    Err(GaussError::SegmentCorruption {
                        path: "edge.gdx".into(),
                        message: "cursor read failed".into(),
                    })
                } else {
                    self.cancelled.store(true, Ordering::Release);
                    Ok(AdjacencyStep::Checkpoint)
                }))
            }
            fn incoming(&self, ns: &GraphNamespace, nid: Nid) -> Result<Self::EdgeIds<'_>> {
                self.outgoing(ns, nid)
            }
            fn edge_properties(&self, _: EdgeId) -> Result<Option<Cow<'_, Value>>> {
                Ok(None)
            }
        }
        for fail in [false, true] {
            let cancelled = AtomicBool::new(false);
            let graph = Scan {
                cancelled: &cancelled,
                fail,
            };
            let result = exact_bfs(MutableTraversal {
                graph: &graph,
                anchors: vec![nid(1)],
                visible_anchor_count: 1,
                selected_types: None,
                direction: GraphDirection::Outgoing,
                node_filter: None,
                statement_filter: None,
                edge_filter: None,
                budget: TraversalBudget {
                    max_depth: 1,
                    ..TraversalBudget::default()
                },
                cancelled: &cancelled,
                payload_for_nid: |_| Some(serde_json::json!({"tenant_id":"acme"})),
                namespaces_for_payload: |_| vec![GraphNamespace::Tenant("acme".into())],
            });
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("scan must fail closed"),
            };
            assert!(
                error
                    .to_string()
                    .contains(if fail { "cursor read failed" } else { "cancel" })
            );
        }
    }

    #[test]
    fn property_reads_follow_type_and_work_admission_and_fail_closed() {
        struct MissingProperties(SyntheticHub);
        impl TraversalGraph for MissingProperties {
            type EdgeIds<'a> = SyntheticEdgeIds;
            fn outgoing(&self, namespace: &GraphNamespace, nid: Nid) -> Result<Self::EdgeIds<'_>> {
                self.0.outgoing(namespace, nid)
            }
            fn incoming(&self, namespace: &GraphNamespace, nid: Nid) -> Result<Self::EdgeIds<'_>> {
                self.0.incoming(namespace, nid)
            }
            fn edge_properties(&self, _: EdgeId) -> Result<Option<Cow<'_, Value>>> {
                Err(GaussError::SegmentCorruption {
                    path: "edgeprop.gdx".into(),
                    message: "property read failed".into(),
                })
            }
            fn property_memory_bytes(&self, _: EdgeId) -> u64 {
                4 * 1024 * 1024
            }
        }
        let graph = MissingProperties(SyntheticHub {
            edges: 1,
            properties: json!({}),
        });
        let cancelled = AtomicBool::new(false);
        let filter = Filter(json!({"name":"fixture"}));
        for case in 0..5 {
            let execution = exact_bfs(MutableTraversal {
                graph: &graph,
                anchors: vec![nid(1)],
                visible_anchor_count: 1,
                selected_types: (case == 1).then(|| HashSet::from([TypeId::from_raw(2)])),
                direction: GraphDirection::Outgoing,
                node_filter: None,
                statement_filter: None,
                edge_filter: (case != 0).then_some(&filter),
                budget: TraversalBudget {
                    max_depth: 1,
                    max_edges: if case == 2 { 0 } else { 10 },
                    max_memory_bytes: if case == 3 {
                        64 * 1024
                    } else {
                        8 * 1024 * 1024
                    },
                    ..TraversalBudget::default()
                },
                cancelled: &cancelled,
                payload_for_nid: |_| Some(json!({"tenant_id":"acme"})),
                namespaces_for_payload: |_| vec![GraphNamespace::Tenant("acme".into())],
            });
            if case == 4 {
                assert!(
                    execution
                        .err()
                        .unwrap()
                        .to_string()
                        .contains("property read failed")
                );
            } else {
                let result = execution.unwrap().result;
                let expected = match case {
                    2 => Some(TraversalTruncationReason::Edges),
                    3 => Some(TraversalTruncationReason::Memory),
                    _ => None,
                };
                assert_eq!(result.truncation, expected);
                assert_eq!(result.visits.len(), usize::from(case == 0));
            }
        }
    }

    fn nid(counter: u64) -> Nid {
        Nid::from_parts(11, counter).unwrap()
    }

    fn edge_id(counter: u64) -> EdgeId {
        EdgeId::from_parts(11, counter).unwrap()
    }

    fn relate(
        counter: u64,
        source: u64,
        target: u64,
        type_id: u32,
        properties: Value,
    ) -> EdgeMutation {
        EdgeMutation::Relate(RelateMutation {
            edge_id: edge_id(counter),
            source: nid(source),
            target: nid(target),
            type_id: TypeId::from_raw(type_id),
            namespace: GraphNamespace::Tenant("acme".to_string()),
            properties,
        })
    }

    fn fixture() -> (MutableGraphState, HashMap<Nid, Value>) {
        let mut graph = MutableGraphState::new(GraphEpoch::INITIAL);
        graph
            .types_mut()
            .configure(TypeId::from_raw(1), "LINK".to_string(), None)
            .unwrap();
        graph
            .types_mut()
            .configure(TypeId::from_raw(2), "OTHER".to_string(), None)
            .unwrap();
        graph.apply_validated_edge_mutations(&[
            relate(1, 1, 2, 1, json!({"enabled": true})),
            relate(2, 1, 2, 1, json!({"enabled": false})),
            relate(3, 2, 3, 1, json!({"enabled": true})),
            relate(4, 2, 2, 1, json!({"enabled": true})),
            relate(5, 3, 4, 2, json!({"enabled": true})),
        ]);
        let payloads = [
            (nid(1), json!({"allowed": true})),
            (nid(2), json!({"allowed": true})),
            (nid(3), json!({"allowed": true})),
            (nid(4), json!({"allowed": false})),
        ]
        .into_iter()
        .collect();
        (graph, payloads)
    }

    struct TestOptions<'a> {
        direction: GraphDirection,
        budget: TraversalBudget,
        node_filter: Option<&'a Filter>,
        edge_filter: Option<&'a Filter>,
        selected_types: Option<HashSet<TypeId>>,
        cancelled: &'a AtomicBool,
    }

    fn run(
        graph: &MutableGraphState,
        payloads: &HashMap<Nid, Value>,
        options: TestOptions<'_>,
    ) -> Result<TraversalResult> {
        exact_bfs(MutableTraversal {
            graph,
            anchors: vec![nid(1)],
            visible_anchor_count: 1,
            selected_types: options.selected_types,
            direction: options.direction,
            node_filter: options.node_filter,
            statement_filter: None,
            edge_filter: options.edge_filter,
            budget: options.budget,
            cancelled: options.cancelled,
            payload_for_nid: |nid| payloads.get(&nid).cloned(),
            namespaces_for_payload: |_| vec![GraphNamespace::Tenant("acme".to_string())],
        })
        .map(|execution| execution.result)
    }

    #[test]
    fn bfs_is_hop_then_handle_ordered_and_preserves_multi_edge_and_self_loop_semantics() {
        let (graph, payloads) = fixture();
        let result = run(
            &graph,
            &payloads,
            TestOptions {
                direction: GraphDirection::Both,
                budget: TraversalBudget {
                    max_depth: 3,
                    ..TraversalBudget::default()
                },
                node_filter: None,
                edge_filter: None,
                selected_types: None,
                cancelled: &AtomicBool::new(false),
            },
        )
        .unwrap();

        assert_eq!(
            result.visits,
            vec![
                TraversalVisit {
                    nid: nid(2),
                    depth: 1
                },
                TraversalVisit {
                    nid: nid(3),
                    depth: 2
                },
                TraversalVisit {
                    nid: nid(4),
                    depth: 3
                },
            ]
        );
        assert_eq!(result.stats.nodes_visited, 4);
        assert_eq!(result.stats.hops_completed, 3);
        assert_eq!(result.stats.visible_edges_examined, 8);
        assert_eq!(result.truncation, None);
        let mut incoming_loop = graph.clone();
        incoming_loop.apply_validated_edge_mutations(&[relate(6, 1, 1, 1, json!({}))]);
        let incoming = run(
            &incoming_loop,
            &payloads,
            TestOptions {
                direction: GraphDirection::Incoming,
                budget: TraversalBudget {
                    max_depth: 1,
                    ..TraversalBudget::default()
                },
                node_filter: None,
                edge_filter: None,
                selected_types: None,
                cancelled: &AtomicBool::new(false),
            },
        )
        .unwrap();
        assert_eq!(
            incoming.stats.visible_edges_examined, 1,
            "INCOMING counts its self-loop once; only BOTH suppresses the mirror"
        );
    }

    #[test]
    fn via_edge_where_and_node_where_filter_expansion_in_normative_order() {
        let (graph, payloads) = fixture();
        let edge_filter = Filter(json!({"enabled": true}));
        let node_filter = Filter(json!({"allowed": true}));
        let result = run(
            &graph,
            &payloads,
            TestOptions {
                direction: GraphDirection::Outgoing,
                budget: TraversalBudget {
                    max_depth: 4,
                    ..TraversalBudget::default()
                },
                node_filter: Some(&node_filter),
                edge_filter: Some(&edge_filter),
                selected_types: Some(HashSet::from([TypeId::from_raw(1)])),
                cancelled: &AtomicBool::new(false),
            },
        )
        .unwrap();

        assert_eq!(
            result.visits,
            vec![
                TraversalVisit {
                    nid: nid(2),
                    depth: 1
                },
                TraversalVisit {
                    nid: nid(3),
                    depth: 2
                },
            ]
        );
        assert_eq!(result.truncation, None);
    }

    #[test]
    fn edge_capture_is_distinct_and_simple_paths_keep_multiedges_without_cycles() {
        let (graph, payloads) = fixture();
        let execution = exact_bfs_with_edges(MutableTraversal {
            graph: &graph,
            anchors: vec![nid(1)],
            visible_anchor_count: 1,
            selected_types: None,
            direction: GraphDirection::Both,
            node_filter: None,
            statement_filter: None,
            edge_filter: None,
            budget: TraversalBudget {
                max_depth: 3,
                ..TraversalBudget::default()
            },
            cancelled: &AtomicBool::new(false),
            payload_for_nid: |nid| payloads.get(&nid).cloned(),
            namespaces_for_payload: |_| vec![GraphNamespace::Tenant("acme".to_string())],
        })
        .unwrap();
        assert_eq!(
            execution
                .edges
                .iter()
                .map(|edge| edge.edge_id)
                .collect::<BTreeSet<_>>(),
            (1..=5).map(edge_id).collect()
        );
        assert_eq!(execution.edges.len(), 5, "BOTH captures a self-loop once");

        let paths = exact_simple_paths(
            MutableTraversal {
                graph: &graph,
                anchors: vec![nid(1)],
                visible_anchor_count: 1,
                selected_types: None,
                direction: GraphDirection::Outgoing,
                node_filter: None,
                statement_filter: None,
                edge_filter: None,
                budget: TraversalBudget {
                    max_depth: 3,
                    ..TraversalBudget::default()
                },
                cancelled: &AtomicBool::new(false),
                payload_for_nid: |nid| payloads.get(&nid).cloned(),
                namespaces_for_payload: |_| vec![GraphNamespace::Tenant("acme".to_string())],
            },
            100,
        )
        .unwrap();
        assert_eq!(paths.paths.len(), 6);
        assert!(paths.paths.iter().all(|path| {
            path.nodes.iter().copied().collect::<HashSet<_>>().len() == path.nodes.len()
        }));
        assert_eq!(
            paths
                .paths
                .iter()
                .map(|path| path
                    .edges
                    .iter()
                    .map(|edge| edge.edge_id)
                    .collect::<Vec<_>>())
                .collect::<Vec<_>>(),
            vec![
                vec![edge_id(1)],
                vec![edge_id(2)],
                vec![edge_id(1), edge_id(3)],
                vec![edge_id(2), edge_id(3)],
                vec![edge_id(1), edge_id(3), edge_id(5)],
                vec![edge_id(2), edge_id(3), edge_id(5)],
            ]
        );

        let limited = exact_simple_paths(
            MutableTraversal {
                graph: &graph,
                anchors: vec![nid(1)],
                visible_anchor_count: 1,
                selected_types: None,
                direction: GraphDirection::Outgoing,
                node_filter: None,
                statement_filter: None,
                edge_filter: None,
                budget: TraversalBudget {
                    max_depth: 3,
                    ..TraversalBudget::default()
                },
                cancelled: &AtomicBool::new(false),
                payload_for_nid: |nid| payloads.get(&nid).cloned(),
                namespaces_for_payload: |_| vec![GraphNamespace::Tenant("acme".to_string())],
            },
            2,
        )
        .unwrap();
        assert_eq!(limited.paths.len(), 2);
        assert_eq!(
            limited.result.truncation,
            Some(TraversalTruncationReason::Limit)
        );
    }

    #[test]
    fn every_budget_truncation_is_explicit_and_cancellation_is_an_error() {
        let (graph, payloads) = fixture();
        let edges = run(
            &graph,
            &payloads,
            TestOptions {
                direction: GraphDirection::Outgoing,
                budget: TraversalBudget {
                    max_depth: 3,
                    max_edges: 1,
                    ..TraversalBudget::default()
                },
                node_filter: None,
                edge_filter: None,
                selected_types: None,
                cancelled: &AtomicBool::new(false),
            },
        )
        .unwrap();
        assert_eq!(edges.truncation, Some(TraversalTruncationReason::Edges));

        let memory = run(
            &graph,
            &payloads,
            TestOptions {
                direction: GraphDirection::Outgoing,
                budget: TraversalBudget {
                    max_depth: 3,
                    max_memory_bytes: 1,
                    ..TraversalBudget::default()
                },
                node_filter: None,
                edge_filter: None,
                selected_types: None,
                cancelled: &AtomicBool::new(false),
            },
        )
        .unwrap();
        assert_eq!(memory.truncation, Some(TraversalTruncationReason::Memory));

        let cancelled = AtomicBool::new(true);
        let error = run(
            &graph,
            &payloads,
            TestOptions {
                direction: GraphDirection::Outgoing,
                budget: TraversalBudget::default(),
                node_filter: None,
                edge_filter: None,
                selected_types: None,
                cancelled: &cancelled,
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("graph.cancelled"));
    }

    #[test]
    fn randomized_exact_bfs_matches_an_independent_in_memory_oracle() {
        const NODES: u64 = 32;
        const EDGES: u64 = 256;
        for seed in 1..=64_u64 {
            let mut random = seed;
            let mut next_random = || {
                random = random
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                random
            };
            let mut graph = MutableGraphState::new(GraphEpoch::INITIAL);
            graph
                .types_mut()
                .configure(TypeId::from_raw(1), "LINK".to_string(), None)
                .unwrap();
            let mut adjacency = vec![Vec::new(); NODES as usize + 1];
            let mut mutations = Vec::with_capacity(EDGES as usize);
            for counter in 1..=EDGES {
                let source = next_random() % NODES + 1;
                let target = next_random() % NODES + 1;
                adjacency[source as usize].push(target);
                mutations.push(relate(counter, source, target, 1, json!({})));
            }
            graph.apply_validated_edge_mutations(&mutations);
            let anchor = next_random() % NODES + 1;
            let depth_limit = (next_random() % 4 + 1) as u32;
            let payloads = (1..=NODES)
                .map(|counter| (nid(counter), json!({"visible": true})))
                .collect::<HashMap<_, _>>();

            let actual = exact_bfs(MutableTraversal {
                graph: &graph,
                anchors: vec![nid(anchor)],
                visible_anchor_count: 1,
                selected_types: None,
                direction: GraphDirection::Outgoing,
                node_filter: None,
                statement_filter: None,
                edge_filter: None,
                budget: TraversalBudget {
                    max_depth: depth_limit,
                    ..TraversalBudget::default()
                },
                cancelled: &AtomicBool::new(false),
                payload_for_nid: |nid| payloads.get(&nid).cloned(),
                namespaces_for_payload: |_| vec![GraphNamespace::Tenant("acme".to_string())],
            })
            .unwrap()
            .result;

            let mut oracle_visited = HashSet::from([anchor]);
            let mut oracle_frontier = vec![anchor];
            let mut expected = Vec::new();
            for depth in 1..=depth_limit {
                let mut next = BTreeSet::new();
                for source in &oracle_frontier {
                    for target in &adjacency[*source as usize] {
                        if oracle_visited.insert(*target) {
                            next.insert(*target);
                        }
                    }
                }
                expected.extend(next.iter().map(|target| (nid(*target), depth)));
                oracle_frontier = next.into_iter().collect();
                if oracle_frontier.is_empty() {
                    break;
                }
            }

            assert_eq!(
                actual
                    .visits
                    .iter()
                    .map(|visit| (visit.nid, visit.depth))
                    .collect::<Vec<_>>(),
                expected,
                "seed={seed}"
            );
            assert_eq!(actual.truncation, None, "seed={seed}");
        }
    }

    #[test]
    fn c8_ten_million_edge_hub_truncates_inside_every_declared_budget() {
        let hub = SyntheticHub {
            edges: 10_000_000,
            properties: json!({}),
        };
        let result = exact_bfs(MutableTraversal {
            graph: &hub,
            anchors: vec![nid(1)],
            visible_anchor_count: 1,
            selected_types: None,
            direction: GraphDirection::Outgoing,
            node_filter: None,
            statement_filter: None,
            edge_filter: None,
            budget: TraversalBudget {
                max_depth: 5,
                max_frontier: 2_048,
                max_visited: 2_048,
                max_edges: 100_000,
                max_time_ms: 5_000,
                max_memory_bytes: 8 * 1024 * 1024,
                cold: Some(ColdTraversalBudget {
                    max_fragments: 1,
                    max_bytes: 64 * 1024,
                }),
            },
            cancelled: &AtomicBool::new(false),
            payload_for_nid: |node| (node.counter() <= 1_025).then(|| json!({"visible": true})),
            namespaces_for_payload: |_| vec![GraphNamespace::Tenant("acme".to_string())],
        })
        .unwrap()
        .result;

        assert_eq!(result.truncation, Some(TraversalTruncationReason::Edges));
        assert_eq!(result.stats.visible_edges_examined, 100_000);
        assert_eq!(result.stats.nodes_visited, 1_025);
        assert_eq!(result.stats.max_frontier_size, 1_024);
        assert_eq!(result.stats.cold_fragments_read, 0);
        assert_eq!(result.stats.cold_bytes_read, 0);
        assert_eq!(result.visits.len(), 1_024);
        assert_eq!(result.visits.first().unwrap().nid, nid(2));
        assert_eq!(result.visits.last().unwrap().nid, nid(1_025));
        assert!(result.visits.iter().all(|visit| visit.depth == 1));
    }
}
