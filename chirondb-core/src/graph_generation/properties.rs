//! Shared property readers, independent of recovered state (no generation cycle).

use std::{path::PathBuf, sync::Arc};

use crate::{Result, graph::EdgeId, graph_edgeprop::OpenedEdgeProperties};

#[derive(Clone, Default)]
pub(crate) struct SealedProperties {
    // Lookup precedence: newest collection run first, then segment peers.
    readers: Vec<(PathBuf, Arc<OpenedEdgeProperties>)>,
}

impl std::fmt::Debug for SealedProperties {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedProperties")
            .field("readers", &self.readers.len())
            .finish()
    }
}

impl SealedProperties {
    pub(crate) fn read(&self, edge_id: EdgeId) -> Result<Option<serde_json::Value>> {
        for (path, reader) in &self.readers {
            if let Some(row) = reader.find_edge(path, edge_id)? {
                return reader
                    .read_properties(path, row)
                    .map(serde_json::Value::Object)
                    .map(Some);
            }
        }
        Ok(None)
    }
}

impl super::GraphGeneration {
    pub(crate) fn property_pin(&self) -> SealedProperties {
        SealedProperties {
            readers: self
                .properties
                .iter()
                .rev()
                .map(|run| (run.path.clone(), Arc::clone(&run.reader)))
                .chain(self.bases.iter().map(|base| {
                    (
                        base.dir.join(crate::graph_edgeprop::EDGE_PROPERTY_FILE),
                        Arc::clone(&base.properties),
                    )
                }))
                .collect(),
        }
    }
}
