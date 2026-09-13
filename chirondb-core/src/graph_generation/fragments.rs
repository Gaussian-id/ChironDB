//! Manifest-bound physical adjacency rows and incremental directory publication.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use super::*;
use crate::{
    checkpoint::{GraphFragmentBinding, GraphFragmentCatalog, GraphFragmentSource},
    graph::{GraphNamespace, Nid},
    graph_fragdir::{FragmentDirectory, FragmentGroupInput, FragmentReference, FragmentRowInput},
    graph_group::NamespaceDescriptor,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum FragmentLocation {
    Base(usize),
    Delta(usize),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct FragmentRow {
    pub(crate) location: FragmentLocation,
    pub(crate) row_hint: u32,
}

pub(super) fn bind(
    manifest: &SegmentsManifest,
    bases: &[GraphBaseSegment],
    deltas: &[GraphRun<OpenedTopologyDelta>],
) -> Result<HashMap<u64, FragmentLocation>> {
    let graph = manifest.graph.as_ref().expect("graph generation");
    let Some(catalog) = &graph.fragment_catalog else {
        return Ok(HashMap::new());
    };
    let sources: HashMap<_, _> = bases
        .iter()
        .enumerate()
        .map(|(i, base)| {
            (
                GraphFragmentSource::Base {
                    id: base.id.clone(),
                },
                FragmentLocation::Base(i),
            )
        })
        .chain(graph.topology_deltas.iter().enumerate().map(|(i, run)| {
            (
                GraphFragmentSource::Delta { id: run.id.clone() },
                FragmentLocation::Delta(i),
            )
        }))
        .collect();
    debug_assert_eq!(deltas.len(), graph.topology_deltas.len());
    catalog
        .bindings
        .iter()
        .map(|binding| {
            let location = sources.get(&binding.source).copied().ok_or_else(|| {
                corrupt(
                    Path::new("fragment_catalog"),
                    "fragment binding has no opened source",
                )
            })?;
            Ok((binding.fragment_id, location))
        })
        .collect()
}

impl GraphGeneration {
    fn row_namespaces(&self, source: FragmentLocation) -> &[NamespaceDescriptor] {
        match source {
            FragmentLocation::Base(i) => self.bases[i].adjacency.namespaces(),
            FragmentLocation::Delta(i) => self.deltas[i].reader.namespaces(),
        }
    }

    fn row_nid(&self, source: FragmentLocation, group: usize, row: u32) -> Result<Nid> {
        match source {
            FragmentLocation::Base(i) => {
                self.bases[i]
                    .adjacency
                    .row_nid(&self.bases[i].nids, group, row)
            }
            FragmentLocation::Delta(i) => self.deltas[i].reader.row_nid(group, row),
        }
    }

    pub(super) fn validate_fragments(&self, collection: &Path) -> Result<()> {
        if matches!(
            self.manifest
                .graph
                .as_ref()
                .expect("graph")
                .fragment_directory,
            FragmentDirectoryManifest::Absent
        ) {
            return Ok(());
        }
        // Compressed row coverage detects omissions as well as bad references,
        // without retaining another full Nid/reference map after admission.
        let mut covered: HashMap<(u64, GraphNamespace), roaring::RoaringBitmap> = HashMap::new();
        for directory in &self.fragments {
            for group in 0..directory.reader.group_count() {
                let group = directory.reader.read_group(&directory.path, group)?;
                for row in group.rows {
                    for reference in row.fragments {
                        let location = self
                            .fragment_bindings
                            .get(&reference.fragment_id)
                            .copied()
                            .ok_or_else(|| {
                                corrupt(&directory.path, "unbound directory fragment ID")
                            })?;
                        let group_index = self
                            .row_namespaces(location)
                            .iter()
                            .position(|g| g.namespace == group.namespace)
                            .ok_or_else(|| {
                                corrupt(&directory.path, "fragment reference crosses namespace")
                            })?;
                        if reference.row_hint
                            >= self.row_namespaces(location)[group_index].row_count
                        {
                            return Err(corrupt(
                                &directory.path,
                                "fragment row hint is out of bounds",
                            ));
                        }
                        if self.row_nid(location, group_index, reference.row_hint)? != row.nid {
                            return Err(corrupt(
                                &directory.path,
                                "fragment row hint disagrees with Nid",
                            ));
                        }
                        if !covered
                            .entry((reference.fragment_id, group.namespace.clone()))
                            .or_default()
                            .insert(reference.row_hint)
                        {
                            return Err(corrupt(
                                &directory.path,
                                "duplicate directory reference across runs",
                            ));
                        }
                    }
                }
            }
        }
        for (&id, &source) in &self.fragment_bindings {
            for group in self.row_namespaces(source) {
                let count = covered
                    .get(&(id, group.namespace.clone()))
                    .map_or(0, |rows| rows.len());
                if count != u64::from(group.row_count) {
                    return Err(corrupt(
                        collection,
                        "fragment directory omits physical adjacency rows",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Physical rows for one authorized namespace, tied to this generation pin.
    /// Absence probes row-identity columns exactly; present-but-corrupt is never
    /// treated as absence. Traversal/edge visibility remains the caller's layer.
    pub(crate) fn fragment_rows(
        &self,
        namespace: &GraphNamespace,
        nid: Nid,
    ) -> Result<Vec<FragmentRow>> {
        let mut rows = BTreeSet::new();
        if matches!(
            self.manifest
                .graph
                .as_ref()
                .expect("graph")
                .fragment_directory,
            FragmentDirectoryManifest::Present { .. }
        ) {
            for directory in &self.fragments {
                if let Some(references) =
                    directory.reader.lookup(&directory.path, namespace, nid)?
                {
                    for reference in references {
                        let location = self
                            .fragment_bindings
                            .get(&reference.fragment_id)
                            .copied()
                            .ok_or_else(|| {
                                corrupt(&directory.path, "unbound directory fragment ID")
                            })?;
                        rows.insert(FragmentRow {
                            location,
                            row_hint: reference.row_hint,
                        });
                    }
                }
            }
        } else {
            for (i, base) in self.bases.iter().enumerate() {
                if let Some(row_hint) = base.adjacency.find_row(&base.nids, namespace, nid)? {
                    rows.insert(FragmentRow {
                        location: FragmentLocation::Base(i),
                        row_hint,
                    });
                }
            }
            for (i, delta) in self.deltas.iter().enumerate() {
                if let Some(row_hint) = delta.reader.find_row(namespace, nid)? {
                    rows.insert(FragmentRow {
                        location: FragmentLocation::Delta(i),
                        row_hint,
                    });
                }
            }
        }
        Ok(rows.into_iter().collect())
    }
}

pub(super) fn validate_transition(
    collection: &Path,
    expected: Option<&SegmentsManifest>,
    candidate: &SegmentsManifest,
) -> Result<()> {
    let previous_graph = expected.and_then(|m| m.graph.as_ref());
    let Some(previous) = previous_graph.and_then(|g| g.fragment_catalog.as_ref()) else {
        return Ok(());
    };
    let next = candidate
        .graph
        .as_ref()
        .and_then(|g| g.fragment_catalog.as_ref())
        .ok_or_else(|| corrupt(collection, "fragment catalog downgrade"))?;
    if next.high_watermark < previous.high_watermark {
        return Err(corrupt(
            collection,
            "fragment identity high watermark regressed",
        ));
    }
    let old_ids: HashMap<_, _> = previous
        .bindings
        .iter()
        .map(|b| (b.fragment_id, &b.source))
        .collect();
    let old_sources: HashMap<_, _> = previous
        .bindings
        .iter()
        .map(|b| (&b.source, b.fragment_id))
        .collect();
    let old_deltas: HashMap<_, _> = previous_graph
        .unwrap()
        .topology_deltas
        .iter()
        .map(|run| (&run.id, run))
        .collect();
    let next_deltas: HashMap<_, _> = candidate
        .graph
        .as_ref()
        .unwrap()
        .topology_deltas
        .iter()
        .map(|run| (&run.id, run))
        .collect();
    for binding in &next.bindings {
        if let Some(source) = old_ids.get(&binding.fragment_id) {
            if **source != binding.source {
                return Err(corrupt(
                    collection,
                    "fragment ID was rebound to another file",
                ));
            }
        } else if binding.fragment_id <= previous.high_watermark {
            return Err(corrupt(collection, "retired fragment ID was reused"));
        }
        if old_sources
            .get(&binding.source)
            .is_some_and(|id| *id != binding.fragment_id)
        {
            return Err(corrupt(
                collection,
                "installed fragment file changed identity",
            ));
        }
        if let GraphFragmentSource::Delta { id } = &binding.source
            && let Some(old) = old_deltas.get(id)
            && next_deltas.get(id) != Some(old)
        {
            return Err(corrupt(collection, "installed fragment descriptor changed"));
        }
    }
    Ok(())
}

/// First directory bootstraps existing physical rows once. Thereafter append
/// only new fragment references; source removals/new epochs require a new base.
pub(crate) fn build_directory(
    collection: &Path,
    expected: Option<&SegmentsManifest>,
    candidate: &mut SegmentsManifest,
) -> Result<()> {
    let graph = candidate.graph.as_mut().expect("graph seal");
    let previous = expected.and_then(|m| m.graph.as_ref());
    let prior_catalog = previous.and_then(|g| g.fragment_catalog.as_ref());
    let mut high_watermark = prior_catalog.map_or(0, |c| c.high_watermark);
    let old_sources: HashMap<_, _> = prior_catalog
        .into_iter()
        .flat_map(|c| &c.bindings)
        .map(|b| (&b.source, b.fragment_id))
        .collect();
    let sources: Vec<_> = graph
        .base_segments
        .iter()
        .map(|id| GraphFragmentSource::Base { id: id.clone() })
        .chain(
            graph
                .topology_deltas
                .iter()
                .map(|run| GraphFragmentSource::Delta { id: run.id.clone() }),
        )
        .collect();
    let selected: HashSet<_> = sources.iter().collect();
    let incremental = previous.is_some_and(|p| {
        p.epoch == graph.epoch
            && matches!(
                p.fragment_directory,
                FragmentDirectoryManifest::Present { .. }
            )
    }) && prior_catalog
        .is_some_and(|c| c.bindings.iter().all(|b| selected.contains(&b.source)));
    let mut bindings = Vec::with_capacity(sources.len());
    let mut groups: HashMap<GraphNamespace, BTreeMap<Nid, Vec<FragmentReference>>> = HashMap::new();
    let deltas: HashMap<_, _> = graph
        .topology_deltas
        .iter()
        .map(|run| (run.id.as_str(), run))
        .collect();
    for source in sources {
        let existing = old_sources.get(&source).copied();
        let fragment_id = if let Some(id) = existing {
            id
        } else {
            high_watermark = high_watermark
                .checked_add(1)
                .ok_or_else(|| corrupt(collection, "fragment identity space exhausted"))?;
            high_watermark
        };
        let binding = GraphFragmentBinding {
            fragment_id,
            source,
        };
        if !incremental || existing.is_none() {
            for group in source_rows(collection, &deltas, &binding)? {
                let rows = groups.entry(group.namespace).or_default();
                for row in group.rows {
                    rows.entry(row.nid).or_default().extend(row.fragments);
                }
            }
        }
        bindings.push(binding);
    }
    bindings.sort_unstable_by_key(|b| b.fragment_id);
    graph.fragment_catalog = Some(GraphFragmentCatalog {
        high_watermark,
        bindings,
    });
    graph.fragment_directory = if incremental {
        previous
            .expect("incremental base")
            .fragment_directory
            .clone()
    } else {
        FragmentDirectoryManifest::Absent
    };
    if groups.is_empty() {
        return Ok(());
    }
    let id = format!("g{}-l{}", candidate.generation, graph.graph_batch_watermark);
    let path = artifact_path(collection, ArtifactFamily::Fragments, &id)?;
    fs::create_dir_all(path.parent().expect("artifact parent"))?;
    let kind = if incremental {
        FragmentDirectoryRunKind::Overlay
    } else {
        FragmentDirectoryRunKind::Base
    };
    graph_fragdir::write(
        &path,
        &FragmentDirectory::build(
            kind,
            true,
            groups
                .into_iter()
                .map(|(namespace, rows)| FragmentGroupInput {
                    namespace,
                    rows: rows
                        .into_iter()
                        .map(|(nid, fragments)| FragmentRowInput { nid, fragments })
                        .collect(),
                })
                .collect(),
        )?,
    )?;
    let file = PersistentFile::open(&path)?;
    let descriptor = GraphRunDescriptor {
        id,
        first_lsn: if incremental {
            previous.expect("incremental base").graph_batch_watermark
        } else {
            0
        },
        last_lsn: graph
            .graph_batch_watermark
            .checked_sub(1)
            .ok_or_else(|| corrupt(collection, "empty fragment publication cut"))?,
        crc32: file.crc32(0..file.len())?,
    };
    match &mut graph.fragment_directory {
        FragmentDirectoryManifest::Absent => {
            graph.fragment_directory = FragmentDirectoryManifest::Present {
                base: descriptor,
                overlays: Vec::new(),
            }
        }
        FragmentDirectoryManifest::Present { overlays, .. } => overlays.push(descriptor),
    }
    Ok(())
}

fn source_rows(
    collection: &Path,
    deltas: &HashMap<&str, &GraphRunDescriptor>,
    binding: &GraphFragmentBinding,
) -> Result<Vec<FragmentGroupInput>> {
    let mut files = BTreeSet::new();
    let mut groups = Vec::new();
    let mut append = |namespace: &GraphNamespace,
                      count: u32,
                      read: &mut dyn FnMut(u32) -> Result<Nid>|
     -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        let rows = (0..count)
            .map(|row_hint| {
                Ok(FragmentRowInput {
                    nid: read(row_hint)?,
                    fragments: vec![FragmentReference {
                        fragment_id: binding.fragment_id,
                        row_hint,
                    }],
                })
            })
            .collect::<Result<_>>()?;
        groups.push(FragmentGroupInput {
            namespace: namespace.clone(),
            rows,
        });
        Ok(())
    };
    match &binding.source {
        GraphFragmentSource::Base { id } => {
            let (dir, marker) = checked_segment(collection, id, &mut files)?;
            if !marker.has_graph() {
                return Err(corrupt(&dir, "fragment base lacks graph peers"));
            }
            let nids = graph_nid::open(&dir.join(graph_nid::NID_FILE))?;
            let adjacency = graph_edge::open(&dir.join(graph_edge::EDGE_FILE), &nids)?;
            for (i, group) in adjacency.namespaces().iter().enumerate() {
                append(&group.namespace, group.row_count, &mut |row| {
                    adjacency.row_nid(&nids, i, row)
                })?;
            }
        }
        GraphFragmentSource::Delta { id } => {
            let descriptor = deltas.get(id.as_str()).expect("selected delta");
            let path = checked_run(collection, ArtifactFamily::Topology, descriptor, &mut files)?;
            let delta = graph_tdelta::open(&path, descriptor.last_lsn)?;
            for (i, group) in delta.namespaces().iter().enumerate() {
                append(&group.namespace, group.row_count, &mut |row| {
                    delta.row_nid(i, row)
                })?;
            }
        }
    }
    Ok(groups)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_generation::tests::{descriptor, fixture};
    use tempfile::TempDir;

    fn nid(id: u64) -> Nid {
        Nid::from_parts(1, id).unwrap()
    }

    #[test]
    fn bound_rows_and_absent_fallback_match_in_the_exact_namespace() {
        let temp = TempDir::new().unwrap();
        let (manifest, _store) = fixture(temp.path());
        let pinned = GraphGeneration::load_candidate(temp.path(), manifest.clone()).unwrap();
        let mut absent = manifest;
        absent.graph.as_mut().unwrap().fragment_directory = FragmentDirectoryManifest::Absent;
        absent.graph.as_mut().unwrap().fragment_catalog = None;
        let fallback = GraphGeneration::load_candidate(temp.path(), absent.clone()).unwrap();
        build_directory(temp.path(), None, &mut absent).unwrap();
        let bootstrapped = GraphGeneration::load_candidate(temp.path(), absent.clone()).unwrap();
        // No topology change: retain the original directory, with no empty overlay.
        let mut unchanged = absent.clone();
        unchanged.generation += 1;
        build_directory(temp.path(), Some(&absent), &mut unchanged).unwrap();
        assert_eq!(unchanged.graph, absent.graph);
        let tenant = GraphNamespace::Tenant("acme".into());
        for (row_hint, id) in [(0, 1), (1, 2)] {
            let expected = vec![
                FragmentRow {
                    location: FragmentLocation::Base(0),
                    row_hint,
                },
                FragmentRow {
                    location: FragmentLocation::Delta(0),
                    row_hint,
                },
            ];
            for generation in [&pinned, &fallback, &bootstrapped] {
                assert_eq!(
                    generation.fragment_rows(&tenant, nid(id)).unwrap(),
                    expected
                );
                assert!(
                    generation
                        .fragment_rows(&GraphNamespace::Tenant("other".into()), nid(id))
                        .unwrap()
                        .is_empty()
                );
                assert!(
                    generation
                        .fragment_rows(&GraphNamespace::AdminCrossTenant, nid(id))
                        .unwrap()
                        .is_empty()
                );
                assert!(
                    generation
                        .fragment_rows(&tenant, nid(99))
                        .unwrap()
                        .is_empty()
                );
            }
        }
    }

    #[test]
    fn valid_crc_directories_reject_bad_bindings_hints_namespaces_and_omissions() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path();
        let (manifest, _store) = fixture(dir);
        for case in 0..6 {
            let mut rows: Vec<_> = (0..2)
                .map(|row_hint| FragmentRowInput {
                    nid: nid(u64::from(row_hint) + 1),
                    fragments: vec![FragmentReference {
                        fragment_id: 1,
                        row_hint,
                    }],
                })
                .collect();
            let mut namespace = GraphNamespace::Tenant("acme".into());
            let expected_error = match case {
                0 => {
                    rows[0].fragments[0].fragment_id = 99;
                    "unbound directory fragment ID"
                }
                1 => {
                    rows[0].fragments[0].row_hint = 1;
                    "fragment row hint disagrees with Nid"
                }
                2 => {
                    rows[0].fragments[0].row_hint = 2;
                    "fragment row hint is out of bounds"
                }
                3 => {
                    namespace = GraphNamespace::AdminCrossTenant;
                    "fragment reference crosses namespace"
                }
                4 => {
                    rows.pop();
                    "fragment directory omits physical adjacency rows"
                }
                _ => "duplicate directory reference across runs",
            };
            let id = format!("bad-{case}");
            let path = artifact_path(dir, ArtifactFamily::Fragments, &id).unwrap();
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            graph_fragdir::write(
                &path,
                &FragmentDirectory::build(
                    if case == 5 {
                        FragmentDirectoryRunKind::Overlay
                    } else {
                        FragmentDirectoryRunKind::Base
                    },
                    true,
                    vec![FragmentGroupInput { namespace, rows }],
                )
                .unwrap(),
            )
            .unwrap();
            let mut candidate = manifest.clone();
            let FragmentDirectoryManifest::Present { base, overlays } =
                &mut candidate.graph.as_mut().unwrap().fragment_directory
            else {
                unreachable!()
            };
            if case == 5 {
                overlays[0] = descriptor(dir, ArtifactFamily::Fragments, &id, 11, 20);
            } else {
                *base = descriptor(dir, ArtifactFamily::Fragments, &id, 0, 10);
            }
            let error = GraphGeneration::load_candidate(dir, candidate)
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected_error), "case {case}: {error}");
        }
    }

    #[test]
    fn fragment_identity_cannot_regress_rebind_or_reuse_retired_ids() {
        let temp = TempDir::new().unwrap();
        let (mut previous, _store) = fixture(temp.path());
        previous
            .graph
            .as_mut()
            .unwrap()
            .fragment_catalog
            .as_mut()
            .unwrap()
            .high_watermark = 3;
        let catalog = previous
            .graph
            .as_ref()
            .unwrap()
            .fragment_catalog
            .as_ref()
            .unwrap()
            .clone();
        let mut next = previous.clone();
        validate_transition(temp.path(), Some(&previous), &next).unwrap();
        for case in 0..6 {
            let mut invalid = previous.clone();
            let graph = invalid.graph.as_mut().unwrap();
            let bindings = graph.fragment_catalog.as_mut().unwrap();
            match case {
                0 => bindings.high_watermark = 2,
                1 => {
                    bindings.bindings[0].source = GraphFragmentSource::Base {
                        id: "replacement".into(),
                    }
                }
                2 => {
                    bindings.high_watermark = 4;
                    bindings.bindings[0].fragment_id = 4;
                }
                3 => bindings.bindings.push(GraphFragmentBinding {
                    fragment_id: 3,
                    source: GraphFragmentSource::Delta { id: "new".into() },
                }),
                4 => graph.fragment_catalog = None,
                _ => graph.topology_deltas[0].crc32 ^= 1,
            }
            assert!(
                validate_transition(temp.path(), Some(&previous), &invalid).is_err(),
                "{case}"
            );
        }
        // Retire all files but retain the high watermark, including across epochs.
        next.graph
            .as_mut()
            .unwrap()
            .fragment_catalog
            .as_mut()
            .unwrap()
            .bindings
            .clear();
        validate_transition(temp.path(), Some(&previous), &next).unwrap();
        let mut replacement = next.clone();
        replacement.graph.as_mut().unwrap().fragment_catalog = Some(catalog.clone());
        assert!(validate_transition(temp.path(), Some(&next), &replacement).is_err());
        replacement.graph.as_mut().unwrap().fragment_catalog = Some(GraphFragmentCatalog {
            high_watermark: 4,
            bindings: vec![GraphFragmentBinding {
                fragment_id: 4,
                source: catalog.bindings[0].source.clone(),
            }],
        });
        validate_transition(temp.path(), Some(&next), &replacement).unwrap();
        // A pre-binding generation upgrades without inventing array-position IDs.
        previous.graph.as_mut().unwrap().fragment_catalog = None;
        validate_transition(temp.path(), Some(&previous), &replacement).unwrap();
    }
}
