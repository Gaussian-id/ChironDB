//! Partition a frozen topology interval at whole-edge boundaries. Both
//! directions stay together; every emitted file retains the real base LSN.

use super::*;

impl TopologyDelta {
    /// Deterministic greedy packing in namespace/source/type/target/EdgeId
    /// order. Emit one checked delta at a time, never all normalized parts.
    pub(crate) fn build_partitioned(
        base_lsn: u64,
        mut groups: Vec<DeltaGroupInput>,
        mut emit: impl FnMut(TopologyDelta) -> Result<()>,
    ) -> Result<usize> {
        if groups.is_empty() {
            return Err(invalid(
                "tdelta.gdx cannot represent an empty topology delta",
            ));
        }
        groups.sort_unstable_by(|a, b| compare_namespaces(&a.namespace, &b.namespace));
        if groups
            .windows(2)
            .any(|pair| pair[0].namespace == pair[1].namespace)
        {
            return Err(invalid("tdelta.gdx contains duplicate graph namespaces"));
        }
        // Reject duplicate identities across parts, not merely within each
        // emitted file. Validate identities before any callback writes bytes.
        let mut ids = RoaringTreemap::new();
        for group in &mut groups {
            if group.edges.is_empty() {
                return Err(invalid(
                    "tdelta.gdx cannot persist an empty namespace group",
                ));
            }
            for edge in &group.edges {
                validate_nid(edge.source_nid)?;
                validate_nid(edge.target_nid)?;
                validate_edge_id(edge.edge_id)?;
                validate_type_id(edge.type_id)?;
                if !ids.insert(edge.edge_id.raw()) {
                    return Err(invalid("tdelta.gdx contains a duplicate EdgeId"));
                }
            }
            group.edges.sort_unstable_by_key(|edge| {
                (edge.source_nid, edge.type_id, edge.target_nid, edge.edge_id)
            });
        }
        drop(ids);

        let mut parts = 0;
        let mut fragment = Vec::new();
        let mut total_edges = 0_u64;
        for group in groups {
            let mut edges = Vec::new();
            // Counts are namespace-local and direction-specific, including
            // separate in/out accounting for self loops. Each row starts with
            // its terminal u64 offset; every neighbor adds one offset + tuple.
            let mut row_bytes = BTreeMap::<(Nid, bool), usize>::new();
            for edge in group.edges {
                let out = (edge.source_nid, false);
                let incoming = (edge.target_nid, true);
                let out_bytes = 8 + graph_group::tagged_neighbor_encoded_len(
                    TaggedNeighbor::Global(edge.target_nid),
                )?;
                let in_bytes = 8 + graph_group::tagged_neighbor_encoded_len(
                    TaggedNeighbor::Global(edge.source_nid),
                )?;
                if total_edges == MAX_DIRECTED_ENTRIES
                    || row_bytes.get(&out).copied().unwrap_or(8) + out_bytes
                        > MAX_ROW_FRAGMENT_BYTES
                    || row_bytes.get(&incoming).copied().unwrap_or(8) + in_bytes
                        > MAX_ROW_FRAGMENT_BYTES
                {
                    if !edges.is_empty() {
                        fragment.push(DeltaGroupInput {
                            namespace: group.namespace.clone(),
                            edges: std::mem::take(&mut edges),
                        });
                    }
                    emit(Self::build(base_lsn, std::mem::take(&mut fragment))?)?;
                    parts += 1;
                    total_edges = 0;
                    row_bytes.clear();
                }
                // Neighbor bytes dominate the 8-byte ID and 4-byte type
                // columns. The normal builder rechecks every column/mirror.
                *row_bytes.entry(out).or_insert(8) += out_bytes;
                *row_bytes.entry(incoming).or_insert(8) += in_bytes;
                edges.push(edge);
                total_edges += 1;
            }
            fragment.push(DeltaGroupInput {
                namespace: group.namespace,
                edges,
            });
        }
        if !fragment.is_empty() {
            emit(Self::build(base_lsn, fragment)?)?;
            parts += 1;
        }
        Ok(parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(counter: u64, source_nid: Nid, target_nid: Nid) -> DeltaEdgeInput {
        DeltaEdgeInput {
            source_nid,
            target_nid,
            edge_id: EdgeId::from_parts(1, counter).unwrap(),
            type_id: TypeId::from_raw(1),
        }
    }

    fn partition(groups: Vec<DeltaGroupInput>) -> Vec<TopologyDelta> {
        let mut parts = Vec::new();
        let count = TopologyDelta::build_partitioned(71, groups, |delta| {
            parts.push(delta);
            Ok(())
        })
        .unwrap();
        assert_eq!(count, parts.len());
        parts
    }

    #[test]
    fn partition_respects_exact_encoded_row_boundary_and_both_mirrors() {
        // Exercise differing varint widths and self loops. The test derives
        // the boundary from the codec, not an arbitrary edge-count threshold.
        let small = Nid::from_parts(1, 1).unwrap();
        let large =
            Nid::from_parts(GRAPH_ALLOCATOR_MAX_EPOCH, GRAPH_ALLOCATOR_MAX_COUNTER).unwrap();
        for (source, target) in [
            (small, small),
            (small, large),
            (large, small),
            (large, large),
        ] {
            let width = [source, target]
                .map(|nid| {
                    8 + graph_group::tagged_neighbor_encoded_len(TaggedNeighbor::Global(nid))
                        .unwrap()
                })
                .into_iter()
                .max()
                .unwrap();
            let capacity = (MAX_ROW_FRAGMENT_BYTES - 8) / width;
            for count in [capacity - 1, capacity, capacity + 1] {
                let input = vec![DeltaGroupInput {
                    namespace: GraphNamespace::Tenant("acme".into()),
                    edges: (1..=count as u64)
                        .map(|id| edge(id, source, target))
                        .collect(),
                }];
                assert_eq!(
                    TopologyDelta::build(71, input.clone()).is_ok(),
                    count <= capacity
                );
                let parts = partition(input);
                assert_eq!(parts.len(), count.div_ceil(capacity));
                let temp = tempfile::TempDir::new().unwrap();
                let mut outgoing = BTreeSet::new();
                let mut incoming = BTreeSet::new();
                for (index, part) in parts.iter().enumerate() {
                    assert_eq!(part.base_lsn(), 71);
                    let path = temp.path().join(format!("part-{index}.gdx"));
                    write(&path, part).unwrap();
                    let opened = open(&path, 99).unwrap();
                    assert_eq!(opened.base_lsn(), 71);
                    for row in opened.read_group(&path, 0).unwrap().rows {
                        for item in row.outgoing {
                            assert_eq!((row.nid, item.neighbor_nid), (source, target));
                            assert!(outgoing.insert(item.edge_id));
                        }
                        for item in row.incoming {
                            assert_eq!((item.neighbor_nid, row.nid), (source, target));
                            assert!(incoming.insert(item.edge_id));
                        }
                    }
                }
                assert_eq!(outgoing.len(), count);
                assert_eq!(outgoing, incoming);
            }
        }
    }

    #[test]
    fn partition_is_canonical_across_namespaces_and_input_order() {
        let source = Nid::from_parts(1, 1).unwrap();
        let target = Nid::from_parts(1, 2).unwrap();
        let mut input = Vec::new();
        let mut next_id = 1;
        for namespace in [
            GraphNamespace::Tenant("acme".into()),
            GraphNamespace::Tenant("globex".into()),
            GraphNamespace::AdminCrossTenant,
        ] {
            let edges = (0..5_000)
                .map(|index| {
                    let mut item = edge(next_id, source, target);
                    item.type_id = TypeId::from_raw(1 + index % 2);
                    next_id += 1;
                    item
                })
                .collect();
            input.push(DeltaGroupInput { namespace, edges });
        }
        let expected = partition(input.clone());
        input.reverse();
        for group in &mut input {
            group.edges.reverse();
        }
        assert_eq!(partition(input), expected);
        assert_eq!(
            expected.iter().map(TopologyDelta::edge_count).sum::<u64>(),
            15_000
        );
        for namespace in [
            GraphNamespace::Tenant("acme".into()),
            GraphNamespace::Tenant("globex".into()),
            GraphNamespace::AdminCrossTenant,
        ] {
            let edges: usize = expected
                .iter()
                .flat_map(|part| &part.groups)
                .filter(|group| group.namespace == namespace)
                .flat_map(|group| &group.outgoing)
                .map(Vec::len)
                .sum();
            assert_eq!(edges, 5_000);
        }
    }

    #[test]
    fn partition_rejects_cross_part_duplicate_and_invalid_ids_before_emitting() {
        let nid = Nid::from_parts(1, 1).unwrap();
        let valid = DeltaGroupInput {
            namespace: GraphNamespace::Tenant("acme".into()),
            edges: (1..=5_000).map(|id| edge(id, nid, nid)).collect(),
        };
        let mut cases = vec![Vec::new(), vec![valid.clone(), valid.clone()]];
        for bad in [
            valid.edges[0],
            DeltaEdgeInput {
                source_nid: Nid::UNASSIGNED,
                ..edge(5_001, nid, nid)
            },
            DeltaEdgeInput {
                type_id: TypeId::from_raw(0),
                ..edge(5_001, nid, nid)
            },
        ] {
            cases.push(vec![
                valid.clone(),
                DeltaGroupInput {
                    namespace: GraphNamespace::AdminCrossTenant,
                    edges: vec![bad],
                },
            ]);
        }
        cases.push(vec![DeltaGroupInput {
            edges: Vec::new(),
            ..valid
        }]);
        for case in cases {
            assert!(
                TopologyDelta::build_partitioned(71, case, |_| {
                    panic!("invalid identities reached the emitter");
                })
                .is_err()
            );
        }
    }

    #[test]
    fn partition_propagates_emitter_failure_without_emitting_the_remainder() {
        let nid = Nid::from_parts(1, 1).unwrap();
        let mut calls = 0;
        let result = TopologyDelta::build_partitioned(
            71,
            vec![DeltaGroupInput {
                namespace: GraphNamespace::AdminCrossTenant,
                edges: (1..=10_000).map(|id| edge(id, nid, nid)).collect(),
            }],
            |_| {
                calls += 1;
                Err(invalid("test emitter failure"))
            },
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("test emitter failure")
        );
        assert_eq!(calls, 1);
    }
}
