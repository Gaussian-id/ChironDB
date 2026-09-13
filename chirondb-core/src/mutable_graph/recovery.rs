//! Versioned recovery authority accompanying an immutable graph generation.
//! Topology, edge existence/properties and visibility stay in their G1 files;
//! this catalog stores only the authority that those files cannot reconstruct.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::*;
use crate::{
    graph::{GraphEpoch, MAX_GRAPH_BATCH_BYTES},
    graph_artifact::{self, ArtifactSpec, SectionPayload},
    graph_generation::GraphGeneration,
    graph_lifecycle::GraphLifecycleState,
    wal::{GraphBatch, GraphTypeConfiguration},
};

pub(crate) mod topology;

pub(crate) const FILE: &str = "catalog.gdx";
// Enabled catalogs remain byte-compatible (flags=0). Older readers reject
// this formerly reserved bit instead of reopening a disabled epoch as enabled.
const FLAG_DISABLED: u32 = 1;
const SPEC: ArtifactSpec = ArtifactSpec {
    magic: b"GAUSGC01",
    allowed_flags: FLAG_DISABLED,
    required_sections: &[1, 2],
    optional_sections: &[],
    max_file_len: u64::MAX,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    collection: String,
    graph_epoch: GraphEpoch,
    covered_lsn: u64,
    edge_rows: u64,
    ledger_keys: u64,
    edge_tombstones: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Record {
    Live {
        point_id: String,
        nid: Nid,
    },
    Retired {
        nid: Nid,
    },
    Type {
        definition: GraphTypeConfiguration,
    },
    Session {
        id: String,
        opening_lsn: u64,
        status: u8,
    },
    Pending {
        opening_lsn: u64,
        bind: GraphDeferredBind,
    },
    Idempotency {
        result: GraphIdempotencyState,
    },
}

impl Record {
    fn key(&self) -> (u8, String) {
        match self {
            Self::Live { point_id, .. } => (0, point_id.clone()),
            Self::Retired { nid } => (1, format!("{:020}", nid.raw())),
            Self::Type { definition } => (2, format!("{:010}", definition.type_id.raw())),
            Self::Session { id, .. } => (3, id.clone()),
            Self::Pending { bind, .. } => (4, format!("{:020}", bind.edge_id.raw())),
            Self::Idempotency { result } => (5, result.key.clone()),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct GraphRecoveryControl {
    enabled: bool,
    metadata: Metadata,
    resolver: PointIncarnationResolver,
    /// Only types, deferred state and idempotency are populated here.
    control: MutableGraphState,
}

pub(crate) struct RecoveredGraph {
    pub(crate) lifecycle: GraphLifecycleState,
    pub(crate) resolver: PointIncarnationResolver,
    pub(crate) mutable: MutableGraphState,
}

impl GraphRecoveryControl {
    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Sparse bindings for pre-graph segments. Untouched points require no
    /// catalog entry and have no graph edges until a WAL assignment.
    pub(crate) fn live_nid(&self, point_id: &str) -> Option<Nid> {
        self.resolver.live_nid(point_id)
    }

    pub(crate) fn validate_points(
        &self,
        points: &HashMap<Nid, (String, Option<String>)>,
    ) -> Result<()> {
        if points.len() != self.resolver.live_len()
            || self
                .resolver
                .live_bindings()
                .any(|(id, nid)| points.get(&nid).is_none_or(|(stored, _)| stored != id))
        {
            return Err(invalid(
                "checkpoint resolver disagrees with visible vector identities",
            ));
        }
        Ok(())
    }

    pub(crate) fn capture(
        collection: &str,
        covered_lsn: u64,
        resolver: &PointIncarnationResolver,
        graph: &MutableGraphState,
        enabled: bool,
    ) -> Result<Self> {
        let mut control = MutableGraphState::new(graph.epoch);
        control.types = graph.types.clone();
        control.deferred_sessions = graph.deferred_sessions.clone();
        control.pending_edges = graph.pending_edges.clone();
        control.idempotency = graph.idempotency.clone();
        let snapshot = Self {
            enabled,
            metadata: Metadata {
                collection: collection.into(),
                graph_epoch: graph.epoch,
                covered_lsn,
                edge_rows: graph.stored_topology_count(),
                ledger_keys: graph.stored_edge_count(),
                edge_tombstones: graph.edge_tombstones.len(),
            },
            resolver: resolver.clone(),
            control,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Capture control authority after compaction has physically removed old
    /// topology, ledger keys, and visibility tombstones. Retry records whose
    /// EdgeIds no longer exist are safe to retire at this durable WAL cut.
    pub(crate) fn capture_compacted(
        collection: &str,
        covered_lsn: u64,
        resolver: &PointIncarnationResolver,
        graph: &MutableGraphState,
        enabled: bool,
        edge_rows: u64,
        ledger: &std::collections::HashSet<EdgeId>,
    ) -> Result<Self> {
        let mut control = MutableGraphState::new(graph.epoch);
        if enabled {
            control.types = graph.types.clone();
            control.deferred_sessions = graph.deferred_sessions.clone();
            control.pending_edges = graph.pending_edges.clone();
            control.idempotency = graph
                .idempotency
                .iter()
                .filter(|(_, result)| result.edge_ids.iter().all(|id| ledger.contains(id)))
                .map(|(key, result)| (key.clone(), result.clone()))
                .collect();
        }
        if control.pending_edges.keys().any(|id| !ledger.contains(id)) {
            return Err(invalid(
                "compaction ledger omitted an active deferred EdgeId",
            ));
        }
        let snapshot = Self {
            enabled,
            metadata: Metadata {
                collection: collection.into(),
                graph_epoch: graph.epoch,
                covered_lsn,
                edge_rows,
                ledger_keys: ledger.len() as u64,
                edge_tombstones: 0,
            },
            resolver: resolver.clone(),
            control,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn records(&self) -> Vec<Record> {
        let mut records = Vec::new();
        records.extend(self.resolver.live_bindings().map(|(id, nid)| Record::Live {
            point_id: id.into(),
            nid,
        }));
        records.extend(
            self.resolver
                .retired_nids()
                .map(|nid| Record::Retired { nid }),
        );
        records.extend(
            self.control
                .types
                .definitions()
                .map(|definition| Record::Type {
                    definition: GraphTypeConfiguration {
                        type_id: definition.type_id,
                        name: definition.name.clone(),
                        weight_property: definition.weight_property.clone(),
                    },
                }),
        );
        records.extend(self.control.deferred_sessions.iter().map(|(id, session)| {
            Record::Session {
                id: id.clone(),
                opening_lsn: session.opening_lsn,
                status: match session.status {
                    DeferredSessionStatus::Open => 0,
                    DeferredSessionStatus::Committed => 1,
                    DeferredSessionStatus::Aborted => 2,
                },
            }
        }));
        records.extend(
            self.control
                .pending_edges
                .values()
                .map(|pending| Record::Pending {
                    opening_lsn: pending.opening_lsn,
                    bind: GraphDeferredBind {
                        session_id: pending.session_id.clone(),
                        edge_id: pending.edge_id,
                        source_point_id: pending.source_point_id.clone(),
                        target_point_id: pending.target_point_id.clone(),
                        source_nid: pending.source_nid,
                        target_nid: pending.target_nid,
                        type_id: pending.type_id,
                        namespace: pending.namespace.clone(),
                        properties: pending.properties.clone(),
                    },
                }),
        );
        records.extend(
            self.control
                .idempotency
                .values()
                .cloned()
                .map(|result| Record::Idempotency { result }),
        );
        records.sort_by_cached_key(Record::key);
        records
    }

    fn validate(&self) -> Result<()> {
        if !self.enabled
            && (self.metadata.edge_rows != 0
                || self.metadata.ledger_keys != 0
                || self.metadata.edge_tombstones != 0
                || self.control.types.len() != 0
                || !self.control.deferred_sessions.is_empty()
                || !self.control.pending_edges.is_empty()
                || !self.control.idempotency.is_empty())
        {
            return Err(invalid(
                "disabled catalog must contain only point identities",
            ));
        }
        if self.metadata.collection.is_empty()
            || self.metadata.collection.len() > 1024
            || self.metadata.graph_epoch.raw() == 0
            || self.control.epoch != self.metadata.graph_epoch
        {
            return Err(invalid("invalid recovery catalog identity"));
        }
        GraphLifecycleState::from_checkpoint(self.metadata.graph_epoch, self.enabled)?;
        PointIncarnationResolver::from_checkpoint(
            self.resolver
                .live_bindings()
                .map(|(id, nid)| (id.into(), nid))
                .collect(),
            self.resolver.retired_nids().collect(),
        )?;
        for (id, session) in &self.control.deferred_sessions {
            if id.is_empty() || id.len() > 1024 || session.opening_lsn > self.metadata.covered_lsn {
                return Err(invalid("invalid deferred checkpoint session"));
            }
        }
        for pending in self.control.pending_edges.values() {
            let Some(session) = self.control.deferred_sessions.get(&pending.session_id) else {
                return Err(invalid("pending edge has no checkpoint session"));
            };
            if session.status != DeferredSessionStatus::Open
                || session.opening_lsn != pending.opening_lsn
                || (pending.source_nid.is_some() && pending.target_nid.is_some())
                || self.control.types.get(pending.type_id).is_none()
            {
                return Err(invalid(
                    "pending edge disagrees with its checkpoint session/type",
                ));
            }
            GraphBatch {
                graph_epoch: self.metadata.graph_epoch,
                deferred_binds: vec![GraphDeferredBind {
                    session_id: pending.session_id.clone(),
                    edge_id: pending.edge_id,
                    source_point_id: pending.source_point_id.clone(),
                    target_point_id: pending.target_point_id.clone(),
                    source_nid: pending.source_nid,
                    target_nid: pending.target_nid,
                    type_id: pending.type_id,
                    namespace: pending.namespace.clone(),
                    properties: pending.properties.clone(),
                }],
                ..GraphBatch::default()
            }
            .validate()?;
            for (point_id, nid) in [
                (&pending.source_point_id, pending.source_nid),
                (&pending.target_point_id, pending.target_nid),
            ] {
                // A point created outside this deferred session remains
                // unbound even when its public ID is now live.
                if let Some(nid) = nid
                    && self.resolver.live_nid(point_id) != Some(nid)
                    && !self.resolver.is_retired(nid)
                {
                    return Err(invalid(
                        "pending checkpoint endpoint is not a known incarnation",
                    ));
                }
            }
        }
        for result in self.control.idempotency.values() {
            result.validate_checkpoint()?;
        }
        Ok(())
    }

    pub(crate) fn write(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let metadata = serde_json::to_vec(&self.metadata)?;
        if metadata.len() > 4096 {
            return Err(invalid("recovery metadata exceeds fixed length cap"));
        }
        let records = self.records();
        let mut bytes = Vec::new();
        for record in &records {
            let encoded = serde_json::to_vec(record)?;
            if encoded.len() > MAX_GRAPH_BATCH_BYTES {
                return Err(invalid("recovery catalog record exceeds fixed cap"));
            }
            bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&encoded);
        }
        graph_artifact::write(
            path,
            SPEC,
            if self.enabled { 0 } else { FLAG_DISABLED },
            &[
                SectionPayload {
                    id: 1,
                    elem_count: 1,
                    bytes: &metadata,
                },
                SectionPayload {
                    id: 2,
                    elem_count: records.len() as u64,
                    bytes: &bytes,
                },
            ],
        )
    }

    pub(crate) fn open(
        path: &Path,
        collection: &str,
        epoch: GraphEpoch,
        covered_lsn: u64,
    ) -> Result<Self> {
        let artifact = graph_artifact::open(path, SPEC)?;
        let metadata_section = artifact.section(1).expect("required metadata section");
        if metadata_section.elem_count != 1 || metadata_section.length > 4096 {
            return Err(corrupt(path, "invalid recovery metadata size/count"));
        }
        let metadata: Metadata = serde_json::from_slice(&artifact.read_section(1)?)
            .map_err(|error| corrupt(path, &format!("invalid recovery metadata: {error}")))?;
        if metadata.collection != collection
            || metadata.graph_epoch != epoch
            || metadata.covered_lsn != covered_lsn
        {
            return Err(corrupt(
                path,
                "recovery catalog identity disagrees with manifest",
            ));
        }
        let section = artifact.section(2).expect("required records section");
        if section.elem_count > (section.length / 4) as u64 {
            return Err(corrupt(
                path,
                "recovery record count exceeds section bounds",
            ));
        }
        let mut live = Vec::new();
        let mut retired = Vec::new();
        let mut control = MutableGraphState::new(epoch);
        let mut position = 0usize;
        let mut previous = None;
        for _ in 0..section.elem_count {
            let header_end = position
                .checked_add(4)
                .filter(|end| *end <= section.length)
                .ok_or_else(|| corrupt(path, "truncated recovery record header"))?;
            let length = u32::from_le_bytes(
                artifact
                    .read_section_range(2, position..header_end)?
                    .as_ref()
                    .try_into()
                    .expect("four-byte length"),
            ) as usize;
            if length == 0 || length > MAX_GRAPH_BATCH_BYTES {
                return Err(corrupt(path, "recovery record exceeds fixed length cap"));
            }
            let end = header_end
                .checked_add(length)
                .filter(|end| *end <= section.length)
                .ok_or_else(|| corrupt(path, "recovery record crosses section bounds"))?;
            let record: Record =
                serde_json::from_slice(&artifact.read_section_range(2, header_end..end)?)
                    .map_err(|error| corrupt(path, &format!("invalid recovery record: {error}")))?;
            let key = record.key();
            if previous.as_ref().is_some_and(|previous| previous >= &key) {
                return Err(corrupt(
                    path,
                    "recovery records are unordered or duplicated",
                ));
            }
            previous = Some(key);
            match record {
                Record::Live { point_id, nid } => live.push((point_id, nid)),
                Record::Retired { nid } => retired.push(nid),
                Record::Type { definition } => control
                    .types
                    .configure(
                        definition.type_id,
                        definition.name,
                        definition.weight_property,
                    )
                    .map_err(|error| corrupt(path, &error.to_string()))?,
                Record::Session {
                    id,
                    opening_lsn,
                    status,
                } => {
                    let status = match status {
                        0 => DeferredSessionStatus::Open,
                        1 => DeferredSessionStatus::Committed,
                        2 => DeferredSessionStatus::Aborted,
                        _ => return Err(corrupt(path, "unknown deferred checkpoint status")),
                    };
                    control.deferred_sessions.insert(
                        id,
                        DeferredSession {
                            opening_lsn,
                            status,
                        },
                    );
                }
                Record::Pending { opening_lsn, bind } => {
                    let pending = PendingEdge {
                        session_id: bind.session_id,
                        opening_lsn,
                        edge_id: bind.edge_id,
                        source_point_id: bind.source_point_id,
                        target_point_id: bind.target_point_id,
                        source_nid: bind.source_nid,
                        target_nid: bind.target_nid,
                        type_id: bind.type_id,
                        namespace: bind.namespace,
                        properties: bind.properties,
                    };
                    control.pending_edges.insert(pending.edge_id, pending);
                }
                Record::Idempotency { result } => {
                    control.idempotency.insert(result.key.clone(), result);
                }
            }
            position = end;
        }
        if position != section.length {
            return Err(corrupt(path, "unowned trailing recovery bytes"));
        }
        let resolver = PointIncarnationResolver::from_checkpoint(live, retired)
            .map_err(|error| corrupt(path, &error.to_string()))?;
        let snapshot = Self {
            enabled: artifact.flags() & FLAG_DISABLED == 0,
            metadata,
            resolver,
            control,
        };
        snapshot
            .validate()
            .map_err(|error| corrupt(path, &error.to_string()))?;
        Ok(snapshot)
    }

    /// Rebuild indexes from the selected artifacts; no historical GraphBatch
    /// replay or synthetic mutation order is used to recover deferred state.
    pub(crate) fn restore(
        &self,
        generation: &GraphGeneration,
        tenant_for_nid: impl Fn(Nid) -> Option<String>,
    ) -> Result<RecoveredGraph> {
        let graph = generation
            .manifest
            .graph
            .as_ref()
            .ok_or_else(|| invalid("recovery requires graph manifest"))?;
        if graph.epoch != self.metadata.graph_epoch
            || graph.graph_batch_watermark != self.metadata.covered_lsn
        {
            return Err(invalid("recovery control and artifact generation disagree"));
        }
        if !self.enabled
            && (!generation.bases.is_empty()
                || !generation.deltas.is_empty()
                || !generation.fragments.is_empty())
        {
            return Err(invalid(
                "disabled catalog cannot select active graph fragments",
            ));
        }
        let mut restored = self.control.clone();
        // Capture() does not duplicate this derived reverse index.
        restored.pending_by_endpoint.clear();
        for pending in self.control.pending_edges.values() {
            restored.index_pending_edge(pending);
        }
        let mut topology = topology::TopologySort::new();
        generation.visit_topology(|namespace, edge| {
            // The derived label must agree with every physical occurrence,
            // including both directions and repeated fragments. Do not put
            // variable-length namespace strings in every scratch record.
            if generation.edge_namespaces.lookup(edge.edge_id)? != Some(namespace) {
                return Err(invalid(
                    "recovered topology namespace disagrees with ledger pin",
                ));
            }
            topology.push(edge)
        })?;
        let mut edge_rows = 0_u64;
        let mut live_edges = 0_u64;
        topology.visit_unique(|edge| {
            let crate::graph_group::AdjacencyEdge {
                edge_id,
                source,
                target,
                type_id,
                local_base: _,
            } = edge;
            let namespace = generation
                .edge_namespaces
                .lookup(edge_id)?
                .ok_or_else(|| invalid("recovered topology is absent from ledger"))?;
            if restored.pending_edges.contains_key(&edge_id)
                || restored.types.get(type_id).is_none()
            {
                return Err(invalid(
                    "recovered edge conflicts with pending state or type catalog",
                ));
            }
            for nid in [source, target] {
                if self.resolver.live_point_id(nid).is_none() && !self.resolver.is_retired(nid) {
                    return Err(invalid(
                        "recovered edge has an unknown endpoint incarnation",
                    ));
                }
            }
            let properties = generation
                .edge_properties(edge_id)?
                .ok_or_else(|| invalid("recovered edge has no property row"))?;
            let relate = RelateMutation {
                edge_id,
                source,
                target,
                type_id,
                namespace: namespace.clone(),
                properties: Value::Object(properties),
            };
            GraphBatch {
                graph_epoch: graph.epoch,
                edge_mutations: vec![EdgeMutation::Relate(relate.clone())],
                ..GraphBatch::default()
            }
            .validate()?;
            if self.resolver.live_point_id(source).is_some()
                && self.resolver.live_point_id(target).is_some()
            {
                restored.validate_relate(
                    &self.resolver,
                    &relate,
                    &tenant_for_nid,
                    &restored.types,
                    false,
                    0,
                )?;
            }
            // Validate one complete document and release it. No synthetic
            // mutation, topology map, adjacency index or ledger copy is built.
            edge_rows = edge_rows
                .checked_add(1)
                .ok_or_else(|| invalid("recovered topology count overflow"))?;
            if !generation.overlay.edge_tombstones().contains(edge_id.raw()) {
                live_edges = live_edges
                    .checked_add(1)
                    .ok_or_else(|| invalid("recovered live-edge count overflow"))?;
            }
            Ok(())
        })?;
        restored.attach_sealed_ledger(generation.ledger.clone());
        restored.sealed_namespaces = generation.edge_namespaces.clone();
        restored.edge_tombstones = generation.overlay.edge_tombstones().clone();
        for id in restored.pending_edges.keys() {
            if !restored.contains_edge_id(*id)? || restored.edge_tombstones.contains(id.raw()) {
                return Err(invalid("pending recovery EdgeId is absent or tombstoned"));
            }
        }
        for result in restored.idempotency.values() {
            for id in &result.edge_ids {
                if !restored.contains_edge_id(*id)? {
                    return Err(invalid(
                        "idempotency result references an absent ledger key",
                    ));
                }
            }
        }
        for id in restored.sealed_ledger.keys()? {
            let id = id?;
            if restored.sealed_namespaces.lookup(id)?.is_none()
                && !restored.pending_edges.contains_key(&id)
                && !restored.edge_tombstones.contains(id.raw())
            {
                return Err(invalid(
                    "live ledger key has neither topology nor pending state",
                ));
            }
        }
        if edge_rows != self.metadata.edge_rows
            || edge_rows != restored.stored_topology_count()
            || restored.stored_edge_count() != self.metadata.ledger_keys
            || restored.edge_tombstones.len() != self.metadata.edge_tombstones
        {
            return Err(invalid(
                "recovery catalog counts disagree with selected graph artifacts",
            ));
        }
        restored.live_edges = live_edges;
        restored.attach_sealed_properties(generation.property_pin());
        Ok(RecoveredGraph {
            lifecycle: GraphLifecycleState::from_checkpoint(graph.epoch, self.enabled)?,
            resolver: self.resolver.clone(),
            mutable: restored,
        })
    }
}

fn invalid(message: &str) -> GaussError {
    GaussError::InvalidRequest(format!("invalid graph recovery: {message}"))
}
fn corrupt(path: &Path, message: &str) -> GaussError {
    GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: message.into(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        checkpoint::SegmentsManifest,
        encryption,
        graph::UnrelateMutation,
        graph_edgeid::EdgeLedgerRunKind,
        graph_generation::{ArtifactFamily, artifact_path, tests as fixtures},
    };
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde_json::json;
    use std::{env, fs, path::PathBuf, process::Command};
    use tempfile::TempDir;

    fn nid(id: u64) -> Nid {
        Nid::from_parts(1, id).unwrap()
    }
    fn edge(id: u64) -> EdgeId {
        EdgeId::from_parts(1, id).unwrap()
    }

    fn deferred(
        graph: &mut MutableGraphState,
        resolver: &PointIncarnationResolver,
        lsn: u64,
        creates: &[GraphDeferredBind],
        sessions: &[GraphDeferredSessionMutation],
    ) {
        let plan = graph
            .plan_deferred(
                resolver,
                DeferredMutationInput {
                    record_lsn: lsn,
                    assignments: &HashSet::new(),
                    creates,
                    endpoint_binds: &[],
                    session_mutations: sessions,
                },
                graph.types(),
            )
            .unwrap();
        graph.apply_deferred_plan(plan);
    }

    fn control() -> GraphRecoveryControl {
        let mut resolver = PointIncarnationResolver::default();
        for (point, id) in [("p0", 1), ("p1", 2), ("old", 9)] {
            resolver.bind_live(point.into(), nid(id)).unwrap();
        }
        let mut graph = MutableGraphState::new(GraphEpoch::INITIAL);
        graph
            .types_mut()
            .configure(TypeId::from_raw(1), "knows".into(), None)
            .unwrap();
        for id in [1, 2] {
            graph
                .apply_edge_mutations(
                    &resolver,
                    &[EdgeMutation::Relate(RelateMutation {
                        edge_id: edge(id),
                        source: nid(1),
                        target: nid(2),
                        type_id: TypeId::from_raw(1),
                        namespace: GraphNamespace::Tenant("acme".into()),
                        properties: json!({"name":"fixture","optional":null}),
                    })],
                    |_| Some("acme".into()),
                )
                .unwrap();
        }
        graph
            .apply_edge_mutations(
                &resolver,
                &[EdgeMutation::Unrelate(UnrelateMutation {
                    edge_id: edge(1),
                })],
                |_| Some("acme".into()),
            )
            .unwrap();
        for (session, id, source, source_id, target) in [
            ("open", 3, "p0", 1, "future"),
            ("aborted", 4, "p0", 1, "never"),
            ("retired", 5, "old", 9, "later"),
        ] {
            deferred(
                &mut graph,
                &resolver,
                11,
                &[GraphDeferredBind {
                    session_id: session.into(),
                    edge_id: edge(id),
                    source_point_id: source.into(),
                    target_point_id: target.into(),
                    source_nid: Some(nid(source_id)),
                    target_nid: None,
                    type_id: TypeId::from_raw(1),
                    namespace: GraphNamespace::Tenant("acme".into()),
                    properties: json!({"pending":true}),
                }],
                &[GraphDeferredSessionMutation::Open {
                    session_id: session.into(),
                }],
            );
        }
        deferred(
            &mut graph,
            &resolver,
            12,
            &[],
            &[GraphDeferredSessionMutation::Abort {
                session_id: "aborted".into(),
            }],
        );
        deferred(
            &mut graph,
            &resolver,
            13,
            &[],
            &[GraphDeferredSessionMutation::Open {
                session_id: "committed".into(),
            }],
        );
        deferred(
            &mut graph,
            &resolver,
            14,
            &[],
            &[GraphDeferredSessionMutation::Commit {
                session_id: "committed".into(),
            }],
        );
        resolver.retire("old");
        graph.apply_validated_idempotency(Some(&GraphIdempotencyState {
            key: "retry".into(),
            request_sha256: [7; 32],
            created_at_unix_ms: 1,
            expires_at_unix_ms: 2,
            edge_ids: vec![edge(3)],
        }));
        GraphRecoveryControl::capture("docs", 20, &resolver, &graph, true).unwrap()
    }

    fn candidate(dir: &Path, control: &GraphRecoveryControl) -> SegmentsManifest {
        let (mut manifest, mut overlay) = fixtures::fixture(dir);
        let graph = manifest.graph.as_mut().unwrap();
        graph.edge_ledger.runs = vec![fixtures::ledger(
            dir,
            "recovery-keys",
            EdgeLedgerRunKind::Delta,
            11,
            20,
            vec![edge(2), edge(3), edge(4), edge(5)],
        )];
        overlay
            .replace_edges(&RoaringTreemap::from_iter([edge(1).raw(), edge(4).raw()]))
            .unwrap();
        graph.overlay_version = overlay.stage_pending().unwrap().version();
        let path = artifact_path(dir, ArtifactFamily::Recovery, "control-1").unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        control.write(&path).unwrap();
        graph.version = 2;
        graph.graph_batch_watermark = control.metadata.covered_lsn;
        graph.recovery = Some(fixtures::descriptor(
            dir,
            ArtifactFamily::Recovery,
            "control-1",
            0,
            control.metadata.covered_lsn,
        ));
        manifest
    }

    fn large_recovery_without_topology_map(dir: &Path) {
        use crate::{
            graph_edgeprop::{self, EdgePropertyInput, EdgePropertyTable},
            graph_tdelta::{self, DeltaEdgeInput, DeltaGroupInput, TopologyDelta},
        };
        // Both directions plus the repeated base EdgeId force the real recovery
        // sorter to spill beyond its 16,384-record buffer in both modes.
        const COUNT: u64 = 9_000;
        let mut control = control();
        control.control.pending_edges.clear();
        control.control.deferred_sessions.clear();
        control.control.idempotency.clear();
        control.metadata.edge_rows = COUNT;
        control.metadata.ledger_keys = COUNT;
        let mut manifest = candidate(dir, &control);
        let graph = manifest.graph.as_mut().unwrap();
        graph.fragment_directory = crate::checkpoint::FragmentDirectoryManifest::Absent;
        graph.fragment_catalog = None;
        graph.edge_ledger.runs = vec![fixtures::ledger(
            dir,
            "bulk-keys",
            EdgeLedgerRunKind::Delta,
            11,
            20,
            (2..=COUNT).map(edge).collect(),
        )];
        graph.topology_deltas.clear();
        for part in 0..2 {
            let id = format!("bulk-{part}");
            let first_lsn = 11 + 5 * part;
            let path = artifact_path(dir, ArtifactFamily::Topology, &id).unwrap();
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            graph_tdelta::write(
                &path,
                &TopologyDelta::build(
                    first_lsn,
                    vec![DeltaGroupInput {
                        namespace: GraphNamespace::Tenant("acme".into()),
                        edges: (1 + part * (COUNT / 2)..=(part + 1) * (COUNT / 2))
                            .map(|id| DeltaEdgeInput {
                                edge_id: edge(id),
                                // Bound tagged-neighbor bytes (including its
                                // offset table) per directional fragment.
                                source_nid: nid(if id % 2 == 1 { 1 } else { 2 }),
                                target_nid: nid(if id % 2 == 1 { 2 } else { 1 }),
                                type_id: TypeId::from_raw(1),
                            })
                            .collect(),
                    }],
                )
                .unwrap(),
            )
            .unwrap();
            graph.topology_deltas.push(fixtures::descriptor(
                dir,
                ArtifactFamily::Topology,
                &id,
                first_lsn,
                first_lsn + 4,
            ));
        }
        let path = artifact_path(dir, ArtifactFamily::Properties, "delta-1").unwrap();
        graph_edgeprop::write(
            &path,
            &EdgePropertyTable::build(
                (1..=COUNT)
                    .map(|id| EdgePropertyInput {
                        edge_id: edge(id),
                        properties: json!({"checkpoint":id}).as_object().unwrap().clone(),
                    })
                    .collect(),
            )
            .unwrap(),
        )
        .unwrap();
        graph.edge_properties.runs = vec![fixtures::descriptor(
            dir,
            ArtifactFamily::Properties,
            "delta-1",
            11,
            20,
        )];
        let generation = GraphGeneration::load_candidate(dir, manifest).unwrap();
        let recovered = generation.recovered.as_ref().unwrap();
        assert_eq!(recovered.mutable.unsealed_topology_rows(), 0);
        assert_eq!(recovered.mutable.unsealed_property_documents(), 0);
        assert_eq!(recovered.mutable.unsealed_ledger_keys(), 0);
        assert_eq!(recovered.mutable.stored_topology_count(), COUNT);
        assert_eq!(recovered.mutable.stored_edge_count(), COUNT);
        assert_eq!(recovered.mutable.live_edge_count(), COUNT - 2);
        assert_eq!(
            recovered
                .mutable
                .edge_properties(edge(COUNT))
                .unwrap()
                .unwrap()["checkpoint"],
            COUNT
        );
        assert!(
            recovered
                .mutable
                .edge_properties(edge(1))
                .unwrap()
                .is_none()
        );
        assert!(
            recovered
                .mutable
                .edge_properties(edge(4))
                .unwrap()
                .is_none()
        );
        assert!(recovered.mutable.persist_changes.topology.is_empty());
        assert!(recovered.mutable.persist_changes.properties.is_empty());
    }

    pub(crate) fn candidate_at(dir: &Path, watermark: u64) -> SegmentsManifest {
        let mut control = control();
        control.metadata.covered_lsn = watermark;
        candidate(dir, &control)
    }

    pub(crate) fn legacy_candidate_at(dir: &Path, watermark: u64) -> SegmentsManifest {
        use crate::{
            graph_tdelta::{self, DeltaEdgeInput, DeltaGroupInput, TopologyDelta},
            seal,
        };
        let mut manifest = candidate_at(dir, watermark);
        let source = seal::V4Store::open_graph_base(&dir.join("searchers/sg-1")).unwrap();
        let mut points = (0..source.len())
            .map(|i| source.get_ordinal(i).unwrap())
            .collect::<Vec<_>>();
        let mut untouched = points[0].clone();
        untouched.id = "untouched".into();
        untouched.vector[0] = 8.0;
        points.push(untouched);
        seal::build_segment(
            &points[..],
            &dir.join("searchers/legacy-1"),
            seal::SealConfig {
                vector_dim: 4,
                metric: crate::DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: seal::SealIndexKind::Algorithm2,
                base_lsn: 0,
                end_lsn: 10,
            },
        )
        .unwrap();
        let path = artifact_path(dir, ArtifactFamily::Topology, "catalog-edges").unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        graph_tdelta::write(
            &path,
            &TopologyDelta::build(
                0,
                vec![DeltaGroupInput {
                    namespace: GraphNamespace::Tenant("acme".into()),
                    edges: [1, 2]
                        .into_iter()
                        .map(|id| DeltaEdgeInput {
                            source_nid: nid(1),
                            target_nid: nid(2),
                            edge_id: edge(id),
                            type_id: TypeId::from_raw(1),
                        })
                        .collect(),
                }],
            )
            .unwrap(),
        )
        .unwrap();
        manifest.segments = vec!["legacy-1".into()];
        let graph = manifest.graph.as_mut().unwrap();
        graph.base_segments.clear();
        graph.catalog_overlay_generation = Some(manifest.generation);
        graph.topology_deltas = vec![fixtures::descriptor(
            dir,
            ArtifactFamily::Topology,
            "catalog-edges",
            0,
            watermark,
        )];
        graph.fragment_directory = crate::checkpoint::FragmentDirectoryManifest::Absent;
        graph.fragment_catalog = None;
        manifest
    }

    #[test]
    fn disabled_catalog_flags_are_fail_closed_and_authority_is_identity_only() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(FILE);
        let epoch = GraphEpoch::from_raw(2).unwrap();
        let mut resolver = PointIncarnationResolver::default();
        resolver.bind_live("keep".into(), nid(1)).unwrap();
        resolver.bind_live("retired".into(), nid(2)).unwrap();
        resolver.retire("retired");
        let disabled = GraphRecoveryControl::capture(
            "docs",
            40,
            &resolver,
            &MutableGraphState::new(epoch),
            false,
        )
        .unwrap();
        disabled.write(&path).unwrap();
        let opened = GraphRecoveryControl::open(&path, "docs", epoch, 40).unwrap();
        assert!(!opened.is_enabled());
        assert_eq!(opened.live_nid("keep"), Some(nid(1)));
        assert!(opened.resolver.is_retired(nid(2)));
        assert!(
            graph_artifact::open(
                &path,
                ArtifactSpec {
                    allowed_flags: 0,
                    ..SPEC
                }
            )
            .is_err(),
            "older enabled-only reader must reject the new flag"
        );
        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        assert_eq!(artifact.flags(), FLAG_DISABLED);
        let metadata = artifact.read_section(1).unwrap();
        let records = artifact.read_section(2).unwrap();
        for flags in [0, 2, 3] {
            graph_artifact::write(
                &path,
                ArtifactSpec {
                    allowed_flags: 3,
                    ..SPEC
                },
                flags,
                &[
                    SectionPayload {
                        id: 1,
                        elem_count: 1,
                        bytes: &metadata,
                    },
                    SectionPayload {
                        id: 2,
                        elem_count: 2,
                        bytes: &records,
                    },
                ],
            )
            .unwrap();
            assert!(
                GraphRecoveryControl::open(&path, "docs", epoch, 40).is_err(),
                "flags={flags}"
            );
        }
        let active = control();
        for case in 0..7 {
            let mut invalid = disabled.clone();
            match case {
                0 => invalid.metadata.edge_rows = 1,
                1 => invalid.metadata.ledger_keys = 1,
                2 => invalid.metadata.edge_tombstones = 1,
                3 => invalid.control.types = active.control.types.clone(),
                4 => invalid.control.deferred_sessions = active.control.deferred_sessions.clone(),
                5 => invalid.control.pending_edges = active.control.pending_edges.clone(),
                _ => invalid.control.idempotency = active.control.idempotency.clone(),
            }
            assert!(
                invalid.write(&path).is_err(),
                "disabled authority case {case}"
            );
        }
        active.write(&path).unwrap();
        assert_eq!(graph_artifact::open(&path, SPEC).unwrap().flags(), 0);
        assert!(
            GraphRecoveryControl::open(&path, "docs", GraphEpoch::INITIAL, 20)
                .unwrap()
                .is_enabled()
        );
    }

    #[test]
    fn recovery_roundtrip_and_tail_plaintext_and_encrypted() {
        const MODE: &str = "CHIRONDB_GRAPH_CONTROL_TEST_MODE";
        const ROOT: &str = "CHIRONDB_GRAPH_CONTROL_TEST_ROOT";
        const TEST: &str =
            "mutable_graph::recovery::tests::recovery_roundtrip_and_tail_plaintext_and_encrypted";
        let Some(mode) = env::var_os(MODE) else {
            for mode in ["plaintext", "encrypted"] {
                let root = TempDir::new().unwrap();
                assert!(
                    Command::new(env::current_exe().unwrap())
                        .args(["--exact", TEST, "--nocapture"])
                        .env(MODE, mode)
                        .env(ROOT, root.path())
                        .status()
                        .unwrap()
                        .success()
                );
            }
            return;
        };
        let root = PathBuf::from(env::var_os(ROOT).unwrap());
        let encrypted = mode == "encrypted";
        if encrypted {
            let keyring = root.join("keyring.json");
            fs::write(&keyring,json!({"version":1,"active_key_id":"recovery-test","keys":[{"id":"recovery-test","key_base64":STANDARD.encode([89;32])}]}).to_string()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
            }
            encryption::install_process_keyring(encryption::Keyring::load(&keyring).unwrap(), true)
                .unwrap();
        }
        let dir = root.join("docs");
        let control = control();
        let manifest = candidate(&dir, &control);
        let path = artifact_path(&dir, ArtifactFamily::Recovery, "control-1").unwrap();
        assert_eq!(
            fs::read(&path).unwrap().starts_with(encryption::MAGIC),
            encrypted
        );
        GraphGeneration::publish(&dir, None, manifest).unwrap();
        let mut generation = GraphGeneration::open(&dir).unwrap().unwrap();
        assert!(
            control
                .restore(&generation, |_| Some("wrong-tenant".into()))
                .is_err()
        );
        let mut downgrade = (*generation.manifest).clone();
        downgrade.generation += 1;
        let graph = downgrade.graph.as_mut().unwrap();
        graph.version = 1;
        graph.recovery = None;
        graph.overlay_version += 1;
        let downgrade_error = GraphGeneration::publish(&dir, Some(&generation.manifest), downgrade)
            .err()
            .unwrap();
        assert!(downgrade_error.to_string().contains("graph format"));
        let mut recovered = generation.recovered.take().unwrap();
        assert!(recovered.lifecycle.is_enabled());
        assert_eq!(recovered.lifecycle.epoch(), Some(GraphEpoch::INITIAL));
        assert_eq!(recovered.resolver.live_nid("p0"), Some(nid(1)));
        assert!(recovered.resolver.is_retired(nid(9)));
        assert!(recovered.resolver.bind_live("old".into(), nid(9)).is_err());
        assert_eq!(
            recovered.mutable.types().resolve_name("knows"),
            Some(TypeId::from_raw(1))
        );
        assert_eq!(recovered.mutable.unsealed_topology_rows(), 0);
        assert_eq!(recovered.mutable.stored_topology_count(), 2);
        assert_eq!(recovered.mutable.unsealed_property_documents(), 0);
        assert_eq!(recovered.mutable.stored_edge_count(), 5);
        assert_eq!(recovered.mutable.live_edge_count(), 1);
        assert_eq!(recovered.mutable.unsealed_ledger_keys(), 0);
        assert!(recovered.mutable.persist_changes.topology.is_empty());
        assert!(recovered.mutable.persist_changes.properties.is_empty());
        // Production attaches the immutable pin before replay/traversal. The
        // recovery result itself no longer owns full topology records.
        recovered
            .mutable
            .attach_sealed_adjacency(std::sync::Arc::new(generation));
        for id in 1..=5 {
            assert!(recovered.mutable.contains_edge_id(edge(id)).unwrap());
        }
        assert!(!recovered.mutable.contains_edge_id(edge(6)).unwrap());
        // Live, tombstoned, pending and aborted identities all remain reserved
        // even though none of them is copied into the mutable ledger.
        for id in 1..=5 {
            let refused = recovered.mutable.plan_deferred(
                &recovered.resolver,
                DeferredMutationInput {
                    record_lsn: 21,
                    assignments: &HashSet::new(),
                    creates: &[GraphDeferredBind {
                        session_id: "open".into(),
                        edge_id: edge(id),
                        source_point_id: "p0".into(),
                        target_point_id: "future".into(),
                        source_nid: Some(nid(1)),
                        target_nid: None,
                        type_id: TypeId::from_raw(1),
                        namespace: GraphNamespace::Tenant("acme".into()),
                        properties: json!({}),
                    }],
                    endpoint_binds: &[],
                    session_mutations: &[],
                },
                recovered.mutable.types(),
            );
            let error = refused
                .err()
                .expect("sealed EdgeId cannot be allocated again");
            assert!(error.to_string().contains("stable ledger"), "{error}");
        }
        assert_eq!(recovered.mutable.unsealed_ledger_keys(), 0);
        assert!(recovered.mutable.edge(edge(1)).is_none());
        assert_eq!(
            recovered.mutable.edge(edge(2)).unwrap().properties,
            json!({"name":"fixture","optional":null})
        );
        assert_eq!(
            recovered.mutable.idempotency("retry"),
            control.control.idempotency("retry")
        );
        assert!(recovered.mutable.deferred_session_is_committed("committed"));
        assert!(recovered.mutable.deferred_session_is_aborted("aborted"));
        assert_eq!(recovered.mutable.pending_edge_count(), 2);
        assert_eq!(
            recovered
                .mutable
                .pending_binding_count("future", "open", 11),
            1
        );
        assert_eq!(
            recovered.mutable.pending_edges[&edge(5)].source_nid,
            Some(nid(9))
        );
        // A fresh incarnation cannot overwrite the already-bound retired Nid.
        recovered.resolver.bind_live("old".into(), nid(10)).unwrap();
        assert_eq!(
            recovered.mutable.pending_edges[&edge(5)].source_nid,
            Some(nid(9))
        );
        recovered
            .resolver
            .bind_live("future".into(), nid(6))
            .unwrap();
        let plan = recovered
            .mutable
            .plan_deferred(
                &recovered.resolver,
                DeferredMutationInput {
                    record_lsn: 21,
                    assignments: &HashSet::from([("future".into(), nid(6))]),
                    creates: &[],
                    endpoint_binds: &[GraphEdgeBind {
                        session_id: "open".into(),
                        edge_id: edge(3),
                        endpoint: GraphDeferredEndpoint::Target,
                        point_id: "future".into(),
                        nid: nid(6),
                    }],
                    session_mutations: &[],
                },
                recovered.mutable.types(),
            )
            .unwrap();
        recovered
            .mutable
            .validate_edge_mutations_with_types_and_promotions(
                &recovered.resolver,
                plan.promoted(),
                |_| Some("acme".into()),
                recovered.mutable.types(),
                &HashSet::from([edge(3)]),
            )
            .unwrap();
        recovered
            .mutable
            .apply_validated_edge_mutations(plan.promoted());
        recovered.mutable.apply_deferred_plan(plan);
        deferred(
            &mut recovered.mutable,
            &recovered.resolver,
            22,
            &[],
            &[GraphDeferredSessionMutation::Commit {
                session_id: "open".into(),
            }],
        );
        assert!(recovered.mutable.deferred_session_is_committed("open"));
        assert_eq!(
            recovered.mutable.stored_edge_count(),
            5,
            "promotion must not duplicate a sealed pending key"
        );
        assert_eq!(recovered.mutable.unsealed_ledger_keys(), 0);
        assert_eq!(recovered.mutable.edge(edge(3)).unwrap().target, nid(6));
        assert_eq!(
            recovered
                .mutable
                .pending_binding_count("future", "open", 11),
            0
        );
        recovered
            .lifecycle
            .apply_advance(GraphEpoch::from_raw(2).unwrap(), false)
            .unwrap();
        assert_eq!(recovered.lifecycle.next_epoch().unwrap().raw(), 3);
        assert!(
            crate::seal::V4Store::open(&dir.join("searchers/sg-1")).is_err(),
            "public vector-only loader remains guarded"
        );
        assert!(
            !dir.join("wal").exists(),
            "recovery used artifacts, not a WAL fixture"
        );
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 0x80;
        fs::write(&path, bytes).unwrap();
        assert!(
            GraphGeneration::open(&dir).is_err(),
            "corrupt recovery authority must not fall back to vector-only state"
        );
        super::topology::tests::exercise_sort();
        large_recovery_without_topology_map(&root.join("large/docs"));
    }

    #[test]
    fn recovery_reconciles_exact_topology_across_base_and_delta() {
        use crate::graph_tdelta::{self, DeltaEdgeInput, DeltaGroupInput, TopologyDelta};
        let root = TempDir::new().unwrap();
        for case in 0..5 {
            let dir = root.path().join(case.to_string()).join("docs");
            let mut control = control();
            control
                .control
                .types
                .configure(TypeId::from_raw(2), "other".into(), None)
                .unwrap();
            let mut manifest = candidate(&dir, &control);
            let mut duplicate = DeltaEdgeInput {
                edge_id: edge(1),
                source_nid: nid(1),
                target_nid: nid(2),
                type_id: TypeId::from_raw(1),
            };
            match case {
                1 => duplicate.source_nid = nid(2),
                2 => duplicate.target_nid = nid(1),
                3 => duplicate.type_id = TypeId::from_raw(2),
                _ => {}
            }
            let mut groups = vec![DeltaGroupInput {
                namespace: GraphNamespace::Tenant("acme".into()),
                edges: vec![DeltaEdgeInput {
                    edge_id: edge(2),
                    source_nid: nid(1),
                    target_nid: nid(2),
                    type_id: TypeId::from_raw(1),
                }],
            }];
            if case == 4 {
                groups.push(DeltaGroupInput {
                    namespace: GraphNamespace::Tenant("other".into()),
                    edges: vec![duplicate],
                });
            } else {
                groups[0].edges.push(duplicate);
            }
            let path = artifact_path(&dir, ArtifactFamily::Topology, "delta-1").unwrap();
            graph_tdelta::write(&path, &TopologyDelta::build(11, groups).unwrap()).unwrap();
            let graph = manifest.graph.as_mut().unwrap();
            graph.fragment_directory = crate::checkpoint::FragmentDirectoryManifest::Absent;
            graph.fragment_catalog = None;
            graph.topology_deltas = vec![fixtures::descriptor(
                &dir,
                ArtifactFamily::Topology,
                "delta-1",
                11,
                20,
            )];
            let result = GraphGeneration::publish(&dir, None, manifest);
            if case == 0 {
                let generation = result.unwrap();
                let recovered = generation.recovered.as_ref().unwrap();
                assert_eq!(recovered.mutable.stored_topology_count(), 2);
                assert_eq!(recovered.mutable.unsealed_topology_rows(), 0);
            } else {
                let error = result.unwrap_err().to_string();
                assert!(
                    error.contains(if case == 4 {
                        "multiple namespaces"
                    } else {
                        "fragments disagree"
                    }),
                    "case {case}: {error}"
                );
                assert!(
                    crate::checkpoint::read_segments_manifest(&dir)
                        .unwrap()
                        .is_none()
                );
            }
        }
    }

    #[test]
    fn recovery_rejects_cross_file_identity_and_control_mismatches() {
        let root = TempDir::new().unwrap();
        for case in 0..9 {
            let dir = root.path().join(case.to_string()).join("docs");
            let mut control = control();
            match case {
                0 => {
                    control.resolver.retire("p1");
                }
                1 => {
                    control.metadata.edge_rows += 1;
                }
                2 => {
                    control
                        .control
                        .idempotency
                        .get_mut("retry")
                        .unwrap()
                        .edge_ids = vec![edge(99)];
                }
                3 => {
                    let mut pending = control.control.pending_edges.remove(&edge(3)).unwrap();
                    pending.edge_id = edge(4);
                    control.control.pending_edges.insert(edge(4), pending);
                }
                4 => {
                    control
                        .control
                        .types
                        .configure(TypeId::from_raw(2), "other".into(), None)
                        .unwrap();
                    control.control.types.by_id.remove(&TypeId::from_raw(1));
                }
                _ => {}
            }
            // A missing pending-edge type is refused before writing.
            if case == 4 {
                assert!(control.validate().is_err());
                continue;
            }
            let mut manifest = candidate(&dir, &control);
            match case {
                5 => {
                    manifest
                        .graph
                        .as_mut()
                        .unwrap()
                        .recovery
                        .as_mut()
                        .unwrap()
                        .last_lsn = 19;
                }
                6 => {
                    manifest.graph.as_mut().unwrap().recovery = None;
                }
                7 => {
                    manifest.graph.as_mut().unwrap().version = 1;
                }
                8 => {
                    manifest
                        .graph
                        .as_mut()
                        .unwrap()
                        .recovery
                        .as_mut()
                        .unwrap()
                        .id = "missing".into();
                }
                _ => {}
            }
            assert!(
                GraphGeneration::publish(&dir, None, manifest).is_err(),
                "case {case}"
            );
            assert!(
                crate::checkpoint::read_segments_manifest(&dir)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn recovery_catalog_rejects_malformed_records_and_metadata() {
        let root = TempDir::new().unwrap();
        let path = root.path().join(FILE);
        let control = control();
        control.write(&path).unwrap();
        assert!(GraphRecoveryControl::open(&path, "elsewhere", GraphEpoch::INITIAL, 20).is_err());
        assert!(
            GraphRecoveryControl::open(&path, "docs", GraphEpoch::from_raw(2).unwrap(), 20)
                .is_err()
        );
        assert!(GraphRecoveryControl::open(&path, "docs", GraphEpoch::INITIAL, 19).is_err());
        let metadata = serde_json::to_vec(&control.metadata).unwrap();
        let live = serde_json::to_vec(&Record::Live {
            point_id: "p0".into(),
            nid: nid(1),
        })
        .unwrap();
        let mut framed = (live.len() as u32).to_le_bytes().to_vec();
        framed.extend_from_slice(&live);
        let mut duplicate = framed.clone();
        duplicate.extend_from_slice(&framed);
        let invalid = br#"{"kind":"live","point_id":"p0","nid":0,"extra":true}"#;
        let mut unknown = (invalid.len() as u32).to_le_bytes().to_vec();
        unknown.extend_from_slice(invalid);
        for (count, bytes) in [
            (2, framed.clone()),
            (2, duplicate),
            (0, framed),
            (1, u32::MAX.to_le_bytes().to_vec()),
            (1, unknown),
        ] {
            graph_artifact::write(
                &path,
                SPEC,
                0,
                &[
                    SectionPayload {
                        id: 1,
                        elem_count: 1,
                        bytes: &metadata,
                    },
                    SectionPayload {
                        id: 2,
                        elem_count: count,
                        bytes: &bytes,
                    },
                ],
            )
            .unwrap();
            assert!(GraphRecoveryControl::open(&path, "docs", GraphEpoch::INITIAL, 20).is_err());
        }
        assert!(
            PointIncarnationResolver::from_checkpoint(vec![("p".into(), Nid::UNASSIGNED)], vec![])
                .is_err()
        );
        assert!(
            PointIncarnationResolver::from_checkpoint(vec![("p".into(), nid(1))], vec![nid(1)])
                .is_err()
        );
        assert!(PointIncarnationResolver::from_checkpoint(vec![], vec![nid(1), nid(1)]).is_err());
        let mut outside_session = control.clone();
        outside_session
            .resolver
            .bind_live("future".into(), nid(11))
            .unwrap();
        outside_session.write(&path).unwrap();
        let reopened = GraphRecoveryControl::open(&path, "docs", GraphEpoch::INITIAL, 20).unwrap();
        assert_eq!(reopened.control.pending_edges[&edge(3)].target_nid, None);
    }
}
