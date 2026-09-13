//! Only dirty documents are mutable. Sealed properties keep their checked pin.

use std::borrow::Cow;

use super::*;

impl MutableGraphState {
    pub(crate) fn edge_properties(&self, edge_id: EdgeId) -> Result<Option<Cow<'_, Value>>> {
        if !self.has_live_edge(edge_id)? {
            return Ok(None);
        }
        self.stored_properties(edge_id).map(Some)
    }

    pub(crate) fn has_mutable_properties(&self, edge_id: EdgeId) -> bool {
        self.property_tail.contains_key(&edge_id)
    }

    pub(super) fn stored_properties(&self, edge_id: EdgeId) -> Result<Cow<'_, Value>> {
        if let Some(properties) = self.property_tail.get(&edge_id) {
            return Ok(Cow::Borrowed(properties));
        }
        self.sealed_properties
            .read(edge_id)?
            .map(Cow::Owned)
            .ok_or_else(|| {
                GaussError::InvalidRequest("sealed graph edge has no property row".into())
            })
    }

    pub(super) fn hydrate_stored_edge(&self, edge: &StoredEdge) -> Result<MutableEdge> {
        Ok(MutableEdge {
            edge_id: edge.edge_id,
            source: edge.source,
            target: edge.target,
            type_id: edge.type_id,
            namespace: edge.namespace.clone(),
            properties: self.stored_properties(edge.edge_id)?.into_owned(),
        })
    }

    /// Resolve MERGE against the pinned base plus current tail before appending
    /// WAL. The persisted batch keeps the original operation; its prepared apply
    /// uses a complete replacement and performs no property I/O after the WAL.
    pub(crate) fn prepare_property_mutations(
        &self,
        mutations: &[EdgeMutation],
    ) -> Result<Vec<EdgeMutation>> {
        mutations
            .iter()
            .enumerate()
            .map(|(item_index, mutation)| {
                let EdgeMutation::Properties(patch) = mutation else {
                    return Ok(mutation.clone());
                };
                let mut prepared = patch.clone();
                if patch.mode == EdgePropertyMode::Merge {
                    let mut document = self
                        .edge_properties(patch.edge_id)?
                        .ok_or_else(|| edge_not_found(patch.edge_id, item_index))?
                        .into_owned();
                    let object = document
                        .as_object_mut()
                        .expect("validated property document");
                    for (key, value) in patch.properties.as_object().expect("validated patch") {
                        object.insert(key.clone(), value.clone());
                    }
                    prepared.properties = document;
                    prepared.mode = EdgePropertyMode::Replace;
                }
                validate_property_document(&prepared.properties, item_index)?;
                Ok(EdgeMutation::Properties(prepared))
            })
            .collect()
    }

    pub(super) fn attach_sealed_properties(
        &mut self,
        pin: crate::graph_generation::properties::SealedProperties,
    ) {
        self.sealed_properties = pin;
        self.property_tail
            .retain(|id, _| self.persist_changes.properties.contains_key(id));
    }

    #[cfg(test)]
    pub(crate) fn edge(&self, edge_id: EdgeId) -> Option<MutableEdge> {
        if !self.edge_visible(edge_id) {
            return None;
        }
        if let Some(edge) = self.edges.get(&edge_id) {
            return Some(self.hydrate_stored_edge(edge).unwrap());
        }
        self.stored_edges().find(|edge| edge.edge_id == edge_id)
    }

    #[cfg(test)]
    pub(crate) fn stored_edges(&self) -> impl Iterator<Item = MutableEdge> + '_ {
        // Test-only full oracle; production edge-addressed requests never scan topology.
        let mut edges = BTreeMap::new();
        if let Some(generation) = &self.sealed_adjacency {
            generation
                .visit_topology(|namespace, edge| {
                    edges.insert(
                        edge.edge_id,
                        StoredEdge {
                            edge_id: edge.edge_id,
                            source: edge.source,
                            target: edge.target,
                            type_id: edge.type_id,
                            namespace: namespace.clone(),
                            properties: (),
                        },
                    );
                    Ok(())
                })
                .unwrap();
        }
        edges
            .into_values()
            .map(|edge| self.hydrate_stored_edge(&edge).unwrap())
            .chain(
                self.edges
                    .values()
                    .map(|edge| self.hydrate_stored_edge(edge).unwrap()),
            )
    }

    #[cfg(test)]
    pub(crate) fn unsealed_property_documents(&self) -> usize {
        self.property_tail.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{graph::EdgePropertyMutation, graph_generation::GraphGeneration};
    use serde_json::json;

    #[test]
    fn sealed_property_apply_does_not_read_namespace_or_topology() {
        let temp = tempfile::tempdir().unwrap();
        let (manifest, _overlay) = crate::graph_generation::tests::fixture(temp.path());
        let generation = GraphGeneration::load_candidate(temp.path(), manifest).unwrap();
        let mut graph = MutableGraphState::new(GraphEpoch::INITIAL);
        graph.attach_sealed_adjacency(std::sync::Arc::new(generation));
        let id = EdgeId::from_parts(1, 1).unwrap();
        assert!(graph.edges.is_empty());
        assert_eq!(
            graph.edge_namespace(id).unwrap(),
            Some(&GraphNamespace::Tenant("acme".into()))
        );
        let original = graph.edge_properties(id).unwrap().unwrap().into_owned();
        let prepared = graph
            .prepare_property_mutations(&[EdgeMutation::Properties(EdgePropertyMutation {
                edge_id: id,
                mode: EdgePropertyMode::Merge,
                properties: json!({"added":true}),
            })])
            .unwrap();
        graph.sealed_namespaces = Default::default();
        graph.sealed_properties = Default::default();
        assert!(graph.edge_namespace(id).unwrap().is_none());
        graph.apply_validated_edge_mutations(&prepared);
        assert!(graph.edges.is_empty());
        let mut expected = original;
        expected
            .as_object_mut()
            .unwrap()
            .insert("added".into(), json!(true));
        assert_eq!(graph.property_tail.get(&id), Some(&expected));
    }

    #[test]
    fn sealed_property_preparation_is_fallible_and_apply_needs_no_reader() {
        let temp = tempfile::tempdir().unwrap();
        let (manifest, _overlay) = crate::graph_generation::tests::fixture(temp.path());
        let generation = GraphGeneration::load_candidate(temp.path(), manifest).unwrap();
        let id = EdgeId::from_parts(1, 1).unwrap();
        let mut graph = MutableGraphState::new(GraphEpoch::INITIAL);
        graph.apply_validated_edge_mutations(&[EdgeMutation::Relate(RelateMutation {
            edge_id: id,
            source: Nid::from_parts(1, 1).unwrap(),
            target: Nid::from_parts(1, 2).unwrap(),
            type_id: TypeId::from_raw(1),
            namespace: GraphNamespace::Tenant("acme".into()),
            properties: json!({"not_retained":true}),
        })]);
        graph.attach_sealed_properties(generation.property_pin());
        drop(generation);
        assert_eq!(graph.unsealed_property_documents(), 0);
        let original = graph.edge_properties(id).unwrap().unwrap().into_owned();
        assert_eq!(original["name"], "fixture");
        let patch = vec![EdgeMutation::Properties(EdgePropertyMutation {
            edge_id: id,
            mode: EdgePropertyMode::Merge,
            properties: json!({"added":true,"optional":null}),
        })];
        let prepared = graph.prepare_property_mutations(&patch).unwrap();
        assert_eq!(graph.unsealed_property_documents(), 0);
        assert_eq!(
            graph.edge_properties(id).unwrap().unwrap().as_ref(),
            &original
        );
        assert!(
            matches!(&patch[0], EdgeMutation::Properties(p) if p.mode == EdgePropertyMode::Merge)
        );
        // Model a missing/corrupt property authority. A new preparation fails,
        // but the already prepared application cannot do another fallible read.
        graph.sealed_properties = Default::default();
        assert!(graph.prepare_property_mutations(&patch).is_err());
        assert_eq!(graph.unsealed_property_documents(), 0);
        assert_eq!(graph.live_edge_count(), 1);
        graph.apply_validated_edge_mutations(&prepared);
        assert_eq!(graph.unsealed_property_documents(), 1);
        assert_eq!(
            graph.edge_properties(id).unwrap().unwrap().as_ref(),
            &json!({"name":"fixture","optional":null,"added":true})
        );
        graph.edge_tombstones.insert(id.raw());
        assert!(graph.edge_properties(id).unwrap().is_none());
    }
}
