//! Pinned sealed adjacency plus unsealed mutable topology.

use super::*;
use crate::graph_generation::{GraphGeneration, cursor::SealedEdges};
use crate::graph_group::{AdjacencyEdge, AdjacencyStep};
use std::sync::Arc;

pub(crate) struct EdgeCandidates<'a> {
    graph: &'a MutableGraphState,
    sealed: Option<SealedEdges<'a>>,
    tail: std::iter::Copied<std::slice::Iter<'a, EdgeId>>,
    failed: bool,
}

impl Iterator for EdgeCandidates<'_> {
    type Item = Result<AdjacencyStep>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let next = self.sealed.as_mut().and_then(Iterator::next).or_else(|| {
            self.tail.next().map(|id| {
                let edge = self.graph.edges.get(&id).ok_or_else(|| {
                    GaussError::InvalidRequest("mutable adjacency has no topology".into())
                })?;
                Ok(AdjacencyStep::Edge(AdjacencyEdge {
                    edge_id: id,
                    source: edge.source,
                    target: edge.target,
                    type_id: edge.type_id,
                    local_base: None,
                }))
            })
        });
        self.failed = next.as_ref().is_some_and(Result::is_err);
        next
    }
}

impl MutableGraphState {
    pub(crate) fn edge_candidates(
        &self,
        namespace: &GraphNamespace,
        nid: Nid,
        incoming: bool,
    ) -> Result<EdgeCandidates<'_>> {
        let tail = self
            .adjacency
            .namespace(namespace)
            .map_or(&[][..], |adjacency| {
                if incoming {
                    adjacency.incoming(nid)
                } else {
                    adjacency.outgoing(nid)
                }
            });
        Ok(EdgeCandidates {
            graph: self,
            sealed: self
                .sealed_adjacency
                .as_ref()
                .map(|base| base.edge_candidates(namespace, nid, incoming))
                .transpose()?,
            tail: tail.iter().copied(),
            failed: false,
        })
    }

    /// Resolve only the requested edge identities. Sealed topology is streamed
    /// under the caller's deadline; no all-edge map or point hydration is built.
    pub(crate) fn requested_endpoints(
        &self,
        ids: &std::collections::HashSet<EdgeId>,
        check: impl Fn() -> Result<()>,
    ) -> Result<std::collections::HashMap<EdgeId, (Nid, Nid)>> {
        let mut found = std::collections::HashMap::new();
        for id in ids {
            check()?;
            if !self.edge_visible(*id) {
                continue;
            }
            if let Some(edge) = self.edges.get(id) {
                found.insert(*id, (edge.source, edge.target));
            }
        }
        if found.len() != ids.len()
            && let Some(generation) = &self.sealed_adjacency
        {
            let mut visited = 0usize;
            generation.visit_topology(|_, edge| {
                if visited.is_multiple_of(64) {
                    check()?;
                }
                visited += 1;
                if ids.contains(&edge.edge_id) && self.edge_visible(edge.edge_id) {
                    let endpoints = (edge.source, edge.target);
                    if let Some(previous) = found.insert(edge.edge_id, endpoints)
                        && previous != endpoints
                    {
                        return Err(GaussError::WalUnavailable(
                            "edge identity has conflicting endpoints".into(),
                        ));
                    }
                }
                Ok(())
            })?;
        }
        check()?;
        Ok(found)
    }

    /// After recovery (before replay), or after acknowledging a published cut.
    /// The pin must no longer own recovered mutable state, preventing an Arc cycle.
    pub(crate) fn attach_sealed_adjacency(&mut self, generation: Arc<GraphGeneration>) {
        assert_eq!(
            generation.manifest.graph.as_ref().unwrap().epoch,
            self.epoch
        );
        assert!(generation.recovered.is_none());
        self.attach_sealed_ledger(generation.ledger.clone());
        self.attach_sealed_properties(generation.property_pin());
        self.sealed_namespaces = generation.edge_namespaces.clone();
        self.edges
            .retain(|id, _| self.persist_changes.topology.contains_key(id));
        self.adjacency = MutableAdjacency::default();
        for id in self.persist_changes.topology.keys() {
            self.adjacency.insert(&self.edges[id]);
        }
        self.sealed_adjacency = Some(generation);
    }

    pub(crate) fn adjacency_cursor_memory_bytes(&self) -> u64 {
        self.sealed_adjacency
            .as_ref()
            .map_or(0, |base| base.adjacency_cursor_memory_bytes())
    }

    // Mutation validation alone may inspect all namespaces when the old point
    // had no tenant. Public traversal always supplies one authorized namespace.
    pub(super) fn incident_namespaces(&self, tenant: Option<&str>) -> HashSet<GraphNamespace> {
        let mut namespaces = HashSet::from([GraphNamespace::AdminCrossTenant]);
        if let Some(tenant) = tenant {
            namespaces.insert(GraphNamespace::Tenant(tenant.into()));
        } else {
            namespaces.extend(
                self.adjacency
                    .tenants
                    .keys()
                    .cloned()
                    .map(GraphNamespace::Tenant),
            );
            if let Some(generation) = &self.sealed_adjacency {
                for base in &generation.bases {
                    namespaces.extend(
                        base.adjacency
                            .namespaces()
                            .iter()
                            .map(|ns| ns.namespace.clone()),
                    );
                }
                for delta in &generation.deltas {
                    namespaces.extend(
                        delta
                            .reader
                            .namespaces()
                            .iter()
                            .map(|ns| ns.namespace.clone()),
                    );
                }
            }
        }
        namespaces
    }

    #[cfg(test)]
    pub(crate) fn unsealed_adjacency_entries(&self) -> usize {
        self.adjacency
            .tenants
            .values()
            .chain(std::iter::once(&self.adjacency.admin_cross_tenant))
            .map(|ns| {
                ns.outgoing.values().map(Vec::len).sum::<usize>()
                    + ns.incoming.values().map(Vec::len).sum::<usize>()
            })
            .sum()
    }

    #[cfg(test)]
    pub(crate) fn unsealed_topology_rows(&self) -> usize {
        self.edges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        graph::{GraphDirection, TraversalBudget},
        graph_traversal::{MutableTraversal, exact_bfs},
    };
    use std::sync::atomic::AtomicBool;

    #[test]
    fn sealed_traversal_and_incident_checks_need_no_topology_map() {
        let nid = |counter| Nid::from_parts(1, counter).unwrap();
        let id = |counter| EdgeId::from_parts(1, counter).unwrap();
        let ns = GraphNamespace::Tenant("acme".into());
        for csc in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let (manifest, _store) =
                crate::graph_generation::tests::fixture_with_csc(temp.path(), csc);
            let generation = GraphGeneration::load_candidate(temp.path(), manifest).unwrap();
            let mut graph = MutableGraphState::new(GraphEpoch::INITIAL);
            graph.attach_sealed_adjacency(Arc::new(generation));
            assert!(graph.edges.is_empty()); // No fallback metadata can satisfy these reads.
            let requested = HashSet::from([id(1), id(2), id(999)]);
            let endpoints = graph.requested_endpoints(&requested, || Ok(())).unwrap();
            assert_eq!(endpoints.len(), 2);
            assert_eq!(endpoints[&id(1)], (nid(1), nid(2)));
            assert_eq!(endpoints[&id(2)], (nid(1), nid(2)));
            assert!(
                graph
                    .requested_endpoints(&requested, || Err(GaussError::ResourceExhausted(
                        "cancelled".into()
                    )))
                    .is_err()
            );
            let traverse = |graph: &MutableGraphState, direction, selected_types| {
                exact_bfs(MutableTraversal {
                    access: None,
                    graph,
                    anchors: vec![nid(if direction == GraphDirection::Incoming {
                        2
                    } else {
                        1
                    })],
                    visible_anchor_count: 1,
                    selected_types,
                    direction,
                    node_filter: None,
                    statement_filter: None,
                    edge_filter: None,
                    budget: TraversalBudget {
                        max_depth: 1,
                        ..TraversalBudget::default()
                    },
                    cancelled: &AtomicBool::new(false),
                    payload_for_nid: |_| Ok(Some(serde_json::json!({"tenant_id":"acme"}))),
                    namespaces_for_payload: |_| vec![ns.clone()],
                })
                .unwrap()
            };
            for direction in [
                GraphDirection::Outgoing,
                GraphDirection::Incoming,
                GraphDirection::Both,
            ] {
                let result = traverse(&graph, direction, None);
                assert!(result.result.truncation.is_none());
                assert_eq!(result.result.visits.len(), 1);
                assert_eq!(
                    result.result.visits[0].nid,
                    nid(if direction == GraphDirection::Incoming {
                        1
                    } else {
                        2
                    })
                );
                assert_eq!(result.result.stats.visible_edges_examined, 2);
            }
            assert!(
                traverse(
                    &graph,
                    GraphDirection::Outgoing,
                    Some(HashSet::from([TypeId::from_raw(99)]))
                )
                .result
                .visits
                .is_empty()
            );
            assert!(
                graph
                    .has_live_incident_edge_excluding(nid(1), Some("acme"), &HashSet::new())
                    .unwrap()
            );
            assert!(
                !graph
                    .has_live_incident_edge_excluding(nid(99), Some("acme"), &HashSet::new())
                    .unwrap()
            );
            assert!(
                !graph
                    .has_live_incident_edge_excluding(nid(1), Some("other"), &HashSet::new())
                    .unwrap()
            );
            graph.edge_tombstones.insert(id(1).raw());
            assert!(
                !graph
                    .requested_endpoints(&requested, || Ok(()))
                    .unwrap()
                    .contains_key(&id(1))
            );

            assert!(
                !graph
                    .has_live_incident_edge_excluding(nid(1), Some("acme"), &HashSet::from([id(2)]))
                    .unwrap()
            );
            graph.edge_tombstones.insert(id(2).raw());
            assert!(
                traverse(&graph, GraphDirection::Outgoing, None)
                    .result
                    .visits
                    .is_empty()
            );
        }
    }
}
