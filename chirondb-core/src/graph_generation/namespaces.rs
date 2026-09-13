//! Derived namespace labels indexed by immutable ledger rank. No key or
//! endpoint copy and no adjacency scan on an edge-addressed request.

use std::{collections::HashMap, sync::Arc};

use crate::{
    GaussError, Result,
    graph::{EdgeId, GraphNamespace},
    graph_edgeid::OpenedEdgeLedgerRun,
};

#[derive(Default)]
struct NamespaceIndex {
    namespaces: Vec<GraphNamespace>,
    runs: Vec<NamespaceRun>,
    topology_keys: u64,
}

struct NamespaceRun {
    reader: Arc<OpenedEdgeLedgerRun>,
    codes: PackedCodes,
}

/// Fixed-width packed codes: zero means no selected topology (e.g. pending).
/// Width is ceil(log2(namespace_count + 1)); these are derived RAM bytes only.
struct PackedCodes {
    bits: u32,
    words: Vec<u64>,
}

impl PackedCodes {
    fn new(count: usize, max_code: u32) -> Result<Self> {
        let bits = u32::BITS - max_code.leading_zeros();
        let len = count
            .checked_mul(bits as usize)
            .ok_or_else(|| invalid("namespace label size overflow"))?
            .div_ceil(64);
        Ok(Self {
            bits,
            words: vec![0; len],
        })
    }

    fn get(&self, rank: usize) -> u32 {
        if self.bits == 0 {
            return 0;
        }
        let bit = rank * self.bits as usize;
        let (word, shift) = (bit / 64, bit % 64);
        let mut value = self.words[word] >> shift;
        if shift + self.bits as usize > 64 {
            value |= self.words[word + 1] << (64 - shift);
        }
        (value & ((1_u64 << self.bits) - 1)) as u32
    }

    fn set(&mut self, rank: usize, code: u32) {
        let bit = rank * self.bits as usize;
        let (word, shift) = (bit / 64, bit % 64);
        let mask = (1_u64 << self.bits) - 1;
        self.words[word] = (self.words[word] & !(mask << shift)) | (u64::from(code) << shift);
        if shift + self.bits as usize > 64 {
            self.words[word + 1] = (self.words[word + 1] & !(mask >> (64 - shift)))
                | (u64::from(code) >> (64 - shift));
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct SealedNamespaces(Arc<NamespaceIndex>);

impl std::fmt::Debug for SealedNamespaces {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedNamespaces")
            .field("runs", &self.0.runs.len())
            .field("namespaces", &self.0.namespaces.len())
            .field("topology_keys", &self.0.topology_keys)
            .finish()
    }
}

impl NamespaceIndex {
    fn new(ledger: &super::ledger::SealedLedger, namespaces: Vec<GraphNamespace>) -> Result<Self> {
        let max_code =
            u32::try_from(namespaces.len()).map_err(|_| invalid("too many graph namespaces"))?;
        let runs = ledger
            .readers()
            .iter()
            .map(|reader| {
                Ok(NamespaceRun {
                    reader: Arc::clone(reader),
                    codes: PackedCodes::new(reader.len(), max_code)?,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            namespaces,
            runs,
            topology_keys: 0,
        })
    }

    fn assign(&mut self, edge_id: EdgeId, code: u32) -> Result<()> {
        // The newest containing run is canonical even when ledger runs overlap.
        // Lookup uses the identical rule; a duplicate never gets another label.
        for run in self.runs.iter_mut().rev() {
            if let Some(rank) = run.reader.find_edge(edge_id)? {
                let previous = run.codes.get(rank);
                if previous != 0 && previous != code {
                    return Err(invalid(
                        "selected topology gives an EdgeId multiple namespaces",
                    ));
                }
                if previous == 0 {
                    run.codes.set(rank, code);
                    self.topology_keys += 1;
                }
                return Ok(());
            }
        }
        Err(invalid(
            "graph topology references an EdgeId absent from the pinned ledger",
        ))
    }
}

impl SealedNamespaces {
    pub(super) fn build(generation: &super::GraphGeneration) -> Result<Self> {
        let mut namespaces = Vec::new();
        let mut codes = HashMap::new();
        for ns in generation
            .bases
            .iter()
            .flat_map(|base| base.adjacency.namespaces())
            .chain(
                generation
                    .deltas
                    .iter()
                    .flat_map(|delta| delta.reader.namespaces()),
            )
        {
            if !codes.contains_key(&ns.namespace) {
                let code = u32::try_from(namespaces.len())
                    .ok()
                    .and_then(|n| n.checked_add(1))
                    .ok_or_else(|| invalid("too many graph namespaces"))?;
                codes.insert(ns.namespace.clone(), code);
                namespaces.push(ns.namespace.clone());
            }
        }
        let mut index = NamespaceIndex::new(&generation.ledger, namespaces)?;
        generation
            .visit_topology(|namespace, edge| index.assign(edge.edge_id, codes[namespace]))?;
        Ok(Self(Arc::new(index)))
    }

    pub(crate) fn lookup(&self, edge_id: EdgeId) -> Result<Option<&GraphNamespace>> {
        for run in self.0.runs.iter().rev() {
            if let Some(rank) = run.reader.find_edge(edge_id)? {
                let code = run.codes.get(rank);
                return Ok(code
                    .checked_sub(1)
                    .map(|code| &self.0.namespaces[code as usize]));
            }
        }
        Ok(None)
    }

    pub(crate) fn len(&self) -> u64 {
        self.0.topology_keys
    }
}

impl super::GraphGeneration {
    /// Complete admission/maintenance scan. Query paths must use scoped cursors.
    pub(crate) fn visit_topology(
        &self,
        mut visit: impl FnMut(&GraphNamespace, crate::graph_group::AdjacencyEdge) -> Result<()>,
    ) -> Result<()> {
        for base in &self.bases {
            for (group, ns) in base.adjacency.namespaces().iter().enumerate() {
                for row in 0..ns.row_count {
                    for incoming in [false, true] {
                        if incoming && !base.adjacency.has_csc() {
                            continue;
                        }
                        for edge in base.adjacency.edges(&base.nids, group, row, incoming)? {
                            visit(&ns.namespace, edge?)?;
                        }
                    }
                }
            }
        }
        for delta in &self.deltas {
            for (group, ns) in delta.reader.namespaces().iter().enumerate() {
                for row in 0..ns.row_count {
                    for incoming in [false, true] {
                        for edge in delta.reader.edges(group, row, incoming)? {
                            visit(&ns.namespace, edge?)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn invalid(message: &str) -> GaussError {
    GaussError::InvalidRequest(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        graph::GraphEpoch,
        graph_edgeid::{self, EdgeLedgerRun, EdgeLedgerRunKind, EdgeLedgerRunMetadata},
    };

    #[test]
    fn packed_namespace_codes_cover_word_boundaries_and_full_u32_width() {
        for max in [0, 1, 2, 3, 255, 4097, 65535, u32::MAX] {
            let mut codes = PackedCodes::new(193, max).unwrap();
            let values = (0..193)
                .map(|i| ((i as u64 * 811) % (u64::from(max) + 1)) as u32)
                .collect::<Vec<_>>();
            for (rank, code) in values.iter().copied().enumerate() {
                if max != 0 {
                    codes.set(rank, code);
                }
            }
            for (rank, code) in values.into_iter().enumerate() {
                assert_eq!(codes.get(rank), code);
            }
            if max == 0 {
                assert!(codes.words.is_empty());
            }
            for rank in (0..193).rev() {
                if max != 0 {
                    codes.set(rank, max);
                }
            }
            for rank in 0..193 {
                assert_eq!(codes.get(rank), max);
            }
        }
        assert!(PackedCodes::new(usize::MAX, u32::MAX).is_err());
    }

    #[test]
    fn namespace_rank_lookup_preserves_overlap_reserved_keys_and_shared_pins() {
        let temp = tempfile::tempdir().unwrap();
        let edge = |id| EdgeId::from_parts(1, id).unwrap();
        let readers = [(1..=20_013), (10_000..=25_000)]
            .into_iter()
            .enumerate()
            .map(|(i, keys)| {
                let path = temp.path().join(format!("ledger-{i}.gdx"));
                let run = EdgeLedgerRun::build(
                    EdgeLedgerRunMetadata {
                        graph_epoch: GraphEpoch::INITIAL,
                        first_lsn: i as u64,
                        last_lsn: i as u64,
                        kind: if i == 0 {
                            EdgeLedgerRunKind::Base
                        } else {
                            EdgeLedgerRunKind::Delta
                        },
                    },
                    keys.map(edge).collect(),
                )
                .unwrap();
                graph_edgeid::write(&path, &run).unwrap();
                Arc::new(graph_edgeid::open(&path).unwrap())
            })
            .collect();
        let ledger = super::super::ledger::SealedLedger::new(readers).unwrap();
        let namespaces = vec![
            GraphNamespace::Tenant("acme".into()),
            GraphNamespace::Tenant("other".into()),
            GraphNamespace::AdminCrossTenant,
        ];
        let mut index = NamespaceIndex::new(&ledger, namespaces.clone()).unwrap();
        for (id, code) in [(1, 1), (10_000, 2), (25_000, 3), (10_000, 2)] {
            index.assign(edge(id), code).unwrap();
        }
        assert_eq!(index.topology_keys, 3);
        assert!(
            index
                .assign(edge(10_000), 1)
                .unwrap_err()
                .to_string()
                .contains("multiple namespaces")
        );
        assert!(
            index
                .assign(edge(30_000), 1)
                .unwrap_err()
                .to_string()
                .contains("absent")
        );
        assert_eq!(
            index.runs[0].codes.get(9_999),
            0,
            "overlap uses only newest run rank"
        );
        assert_eq!(index.runs[1].codes.get(0), 2);
        let labels_bytes: usize = index.runs.iter().map(|run| run.codes.words.len() * 8).sum();
        assert_eq!(
            labels_bytes,
            (20_013_usize * 2).div_ceil(64) * 8 + (15_001_usize * 2).div_ceil(64) * 8
        );
        let pin = SealedNamespaces(Arc::new(index));
        let old = pin.clone();
        assert!(Arc::ptr_eq(&pin.0, &old.0));
        drop(pin);
        drop(ledger);
        for (id, expected) in [(1, 0), (10_000, 1), (25_000, 2)] {
            assert_eq!(old.lookup(edge(id)).unwrap(), Some(&namespaces[expected]));
        }
        assert!(
            old.lookup(edge(9_000)).unwrap().is_none(),
            "reserved key has no topology"
        );
        assert!(old.lookup(edge(30_000)).unwrap().is_none());
        assert!(old.lookup(EdgeId::from_raw(0)).unwrap().is_none());
        assert!(
            SealedNamespaces::default()
                .lookup(edge(1))
                .unwrap()
                .is_none()
        );
    }
}
