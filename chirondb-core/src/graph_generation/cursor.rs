//! Lazy namespace-scoped adjacency candidates for a pinned generation.

use super::fragments::FragmentLocation;
use super::*;
use crate::graph::{GraphNamespace, Nid};
use crate::graph_group::AdjacencyStep;

struct RowPlan {
    source: FragmentLocation,
    group: usize,
    rows: std::ops::Range<u32>,
    incoming: bool,
}

enum RowEdges<'a> {
    Base(crate::graph_edge::cursor::BaseEdges<'a>),
    Delta(crate::graph_tdelta::DeltaEdges<'a>),
}

pub(crate) struct SealedEdges<'a> {
    generation: &'a GraphGeneration,
    plans: std::vec::IntoIter<RowPlan>,
    plan: Option<RowPlan>,
    row: Option<RowEdges<'a>>,
    failed: bool,
}

impl GraphGeneration {
    /// Incoming without CSC scans outgoing rows in this namespace only. These
    /// are physical candidates: callers must check endpoint, visibility/type,
    /// and account for every candidate before rejecting non-incident edges.
    pub(crate) fn edge_candidates(
        &self,
        namespace: &GraphNamespace,
        nid: Nid,
        incoming: bool,
    ) -> Result<SealedEdges<'_>> {
        let mut plans = Vec::new();
        for row in self.fragment_rows(namespace, nid)? {
            let namespaces = match row.location {
                FragmentLocation::Base(i) => {
                    if incoming && !self.bases[i].adjacency.has_csc() {
                        continue;
                    }
                    self.bases[i].adjacency.namespaces()
                }
                FragmentLocation::Delta(i) => self.deltas[i].reader.namespaces(),
            };
            let group = namespaces
                .iter()
                .position(|g| &g.namespace == namespace)
                .expect("validated fragment namespace");
            plans.push(RowPlan {
                source: row.location,
                group,
                rows: row.row_hint..row.row_hint + 1,
                incoming,
            });
        }
        if incoming {
            for (i, base) in self
                .bases
                .iter()
                .enumerate()
                .filter(|(_, base)| !base.adjacency.has_csc())
            {
                if let Some((group, ns)) = base
                    .adjacency
                    .namespaces()
                    .iter()
                    .enumerate()
                    .find(|(_, ns)| &ns.namespace == namespace)
                {
                    plans.push(RowPlan {
                        source: FragmentLocation::Base(i),
                        group,
                        rows: 0..ns.row_count,
                        incoming: false,
                    });
                }
            }
        }
        Ok(SealedEdges {
            generation: self,
            plans: plans.into_iter(),
            plan: None,
            row: None,
            failed: false,
        })
    }

    /// Conservative scratch reservation for BOTH cursors: eight 64-KiB buffers,
    /// cursor objects/construction scratch, row plans and temporary directory
    /// reference lookup containers per file. Shared cache/RSS is separate.
    pub(crate) fn adjacency_cursor_memory_bytes(&self) -> u64 {
        (8 * crate::graph_group::AUTHENTICATED_CHUNK_BYTES + 4096) as u64
            + (self.bases.len() as u64 + self.deltas.len() as u64).saturating_mul(256)
    }
}

impl<'a> SealedEdges<'a> {
    fn read_next(&mut self) -> Result<Option<AdjacencyStep>> {
        if let Some(row) = &mut self.row {
            let next = match row {
                RowEdges::Base(edges) => edges.next(),
                RowEdges::Delta(edges) => edges.next(),
            };
            if let Some(id) = next {
                let source = self.plan.as_ref().map(|plan| plan.source);
                return id.map(|mut id| {
                    id.local_base = match (id.local_base, source) {
                        (Some(_), Some(FragmentLocation::Base(index))) => {
                            Some(u32::try_from(index).unwrap_or(u32::MAX))
                        }
                        _ => None,
                    };
                    Some(AdjacencyStep::Edge(id))
                });
            }
            self.row = None;
        }
        if let Some(plan) = &mut self.plan
            && let Some(row) = plan.rows.next()
        {
            self.row = Some(match plan.source {
                FragmentLocation::Base(i) => {
                    let base = &self.generation.bases[i];
                    RowEdges::Base(base.adjacency.edges(
                        &base.nids,
                        plan.group,
                        row,
                        plan.incoming,
                    )?)
                }
                FragmentLocation::Delta(i) => RowEdges::Delta(
                    self.generation.deltas[i]
                        .reader
                        .edges(plan.group, row, plan.incoming)?,
                ),
            });
            return Ok(Some(AdjacencyStep::Checkpoint));
        }
        self.plan = self.plans.next();
        if self.plan.is_none() {
            return Ok(None);
        }
        Ok(Some(AdjacencyStep::Checkpoint))
    }
}

impl Iterator for SealedEdges<'_> {
    type Item = Result<AdjacencyStep>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        match self.read_next() {
            Ok(id) => id.map(Ok),
            Err(error) => {
                self.failed = true;
                self.row = None;
                Some(Err(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scoped_cursors_cover_csc_and_no_csc_incoming_fallback() {
        let nid = |id| Nid::from_parts(1, id).unwrap();
        for csc in [true, false] {
            let temp = tempfile::tempdir().unwrap();
            let (manifest, _store) =
                crate::graph_generation::tests::fixture_with_csc(temp.path(), csc);
            let generation = GraphGeneration::load_candidate(temp.path(), manifest).unwrap();
            let ns = GraphNamespace::Tenant("acme".into());
            for (node, incoming) in [(nid(1), false), (nid(2), true)] {
                let mut ids = generation
                    .edge_candidates(&ns, node, incoming)
                    .unwrap()
                    .filter_map(|step| step.map(AdjacencyStep::edge).transpose())
                    .inspect(|edge| {
                        let edge = edge.as_ref().unwrap();
                        assert_eq!(
                            (edge.source, edge.target, edge.type_id.raw()),
                            (nid(1), nid(2), 1)
                        );
                    })
                    .map(|edge| edge.map(|edge| edge.edge_id))
                    .collect::<Result<Vec<_>>>()
                    .unwrap();
                ids.sort_unstable(); // Physical file order is not traversal result order.
                assert_eq!(
                    ids,
                    vec![
                        EdgeId::from_parts(1, 1).unwrap(),
                        EdgeId::from_parts(1, 2).unwrap()
                    ]
                );
            }
            assert_eq!(
                generation
                    .edge_candidates(&ns, nid(99), true)
                    .unwrap()
                    .filter_map(|step| step.unwrap().edge())
                    .count(),
                usize::from(!csc),
                "without CSC, incoming fallback returns scoped physical candidates for endpoint checking"
            );
            for ns in [
                GraphNamespace::Tenant("other".into()),
                GraphNamespace::AdminCrossTenant,
            ] {
                assert_eq!(
                    generation
                        .edge_candidates(&ns, nid(1), false)
                        .unwrap()
                        .filter_map(|step| step.unwrap().edge())
                        .count(),
                    0
                );
                assert_eq!(
                    generation
                        .edge_candidates(&ns, nid(2), true)
                        .unwrap()
                        .filter_map(|step| step.unwrap().edge())
                        .count(),
                    0
                );
            }
        }
    }
}
