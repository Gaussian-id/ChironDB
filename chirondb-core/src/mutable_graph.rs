#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "activated by the following GraphBatch execution slice"
    )
)]

use std::collections::{BTreeMap, HashMap, HashSet};

pub(crate) mod adjacency;
mod ledger;
mod properties;
pub(crate) mod recovery;
pub(crate) mod seal;

use roaring::RoaringTreemap;
use serde_json::Value;

use crate::{
    GaussError, GraphError, GraphErrorCode, Result,
    graph::{
        EdgeId, EdgeMutation, EdgePropertyMode, GraphEpoch, GraphNamespace,
        MAX_EDGE_PROPERTY_BYTES, MAX_GRAPH_CATALOG_NAME_BYTES, Nid, RelateMutation, TypeId,
    },
    graph_resolver::PointIncarnationResolver,
    wal::{
        GraphDeferredBind, GraphDeferredEndpoint, GraphDeferredSessionMutation, GraphEdgeBind,
        GraphIdempotencyState,
    },
};

const DEFAULT_GRAPH_NAMESPACE: &str = "@chiron:default";

/// One collection-global edge-type definition. Segment-local remaps are a G1
/// storage concern and never alter this identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EdgeTypeDefinition {
    pub(crate) type_id: TypeId,
    pub(crate) name: String,
    pub(crate) weight_property: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct GraphTypeCatalog {
    by_id: BTreeMap<TypeId, EdgeTypeDefinition>,
    by_name: HashMap<String, TypeId>,
}

impl GraphTypeCatalog {
    pub(crate) fn configure(
        &mut self,
        type_id: TypeId,
        name: String,
        weight_property: Option<String>,
    ) -> Result<()> {
        validate_type_id(type_id)?;
        validate_catalog_name("edge type", &name)?;
        if let Some(weight_property) = weight_property.as_deref() {
            validate_catalog_name("weight property", weight_property)?;
        }
        if let Some(existing) = self.by_id.get(&type_id)
            && existing.name != name
        {
            return Err(invalid_catalog(
                "a TypeId cannot be remapped to another name",
            ));
        }
        if let Some(existing) = self.by_name.get(&name)
            && *existing != type_id
        {
            return Err(invalid_catalog(
                "an edge type name cannot identify two TypeIds",
            ));
        }

        self.by_name.insert(name.clone(), type_id);
        self.by_id.insert(
            type_id,
            EdgeTypeDefinition {
                type_id,
                name,
                weight_property,
            },
        );
        Ok(())
    }

    pub(crate) fn get(&self, type_id: TypeId) -> Option<&EdgeTypeDefinition> {
        self.by_id.get(&type_id)
    }

    pub(crate) fn resolve_name(&self, name: &str) -> Option<TypeId> {
        self.by_name.get(name).copied()
    }

    pub(crate) fn len(&self) -> usize {
        self.by_id.len()
    }

    pub(crate) fn definitions(&self) -> impl Iterator<Item = &EdgeTypeDefinition> {
        self.by_id.values()
    }

    pub(crate) fn next_type_id(&self) -> Result<TypeId> {
        let next = self
            .by_id
            .last_key_value()
            .map_or(1, |(type_id, _)| type_id.raw().saturating_add(1));
        if next == 0 || self.by_id.contains_key(&TypeId::from_raw(next)) {
            return Err(GraphError::new(
                GraphErrorCode::AllocatorExhausted,
                "edge type identifier space is exhausted",
            )
            .into());
        }
        Ok(TypeId::from_raw(next))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GraphEdge<P> {
    pub(crate) edge_id: EdgeId,
    pub(crate) source: Nid,
    pub(crate) target: Nid,
    pub(crate) type_id: TypeId,
    pub(crate) namespace: GraphNamespace,
    pub(crate) properties: P,
}

pub(crate) type MutableEdge = GraphEdge<Value>;
pub(crate) type StoredEdge = GraphEdge<()>;

#[derive(Clone, Debug, Default)]
struct NamespaceAdjacency {
    outgoing: HashMap<Nid, Vec<EdgeId>>,
    incoming: HashMap<Nid, Vec<EdgeId>>,
}

impl NamespaceAdjacency {
    fn insert<P>(&mut self, edge: &GraphEdge<P>) {
        self.outgoing
            .entry(edge.source)
            .or_default()
            .push(edge.edge_id);
        self.incoming
            .entry(edge.target)
            .or_default()
            .push(edge.edge_id);
    }

    fn outgoing(&self, nid: Nid) -> &[EdgeId] {
        self.outgoing.get(&nid).map_or(&[], Vec::as_slice)
    }

    fn incoming(&self, nid: Nid) -> &[EdgeId] {
        self.incoming.get(&nid).map_or(&[], Vec::as_slice)
    }
}

/// Tenant-local and admin-only topology are held in distinct maps. A scoped
/// traversal therefore cannot discover an admin namespace by iterating tenant
/// rows, and high-cardinality tenants allocate only when they own an edge.
#[derive(Clone, Debug, Default)]
struct MutableAdjacency {
    tenants: HashMap<String, NamespaceAdjacency>,
    admin_cross_tenant: NamespaceAdjacency,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeferredSessionStatus {
    Open,
    Committed,
    Aborted,
}

#[derive(Clone, Debug)]
struct DeferredSession {
    opening_lsn: u64,
    status: DeferredSessionStatus,
}

#[derive(Clone, Debug)]
struct PendingEdge {
    session_id: String,
    opening_lsn: u64,
    edge_id: EdgeId,
    source_point_id: String,
    target_point_id: String,
    source_nid: Option<Nid>,
    target_nid: Option<Nid>,
    type_id: TypeId,
    namespace: GraphNamespace,
    properties: Value,
}

#[derive(Default)]
pub(crate) struct DeferredMutationPlan {
    session_updates: HashMap<String, DeferredSession>,
    pending_updates: BTreeMap<EdgeId, Option<PendingEdge>>,
    created_edge_ids: HashSet<EdgeId>,
    aborted_edge_ids: Vec<EdgeId>,
    promoted: Vec<EdgeMutation>,
}

impl DeferredMutationPlan {
    pub(crate) fn promoted(&self) -> &[EdgeMutation] {
        &self.promoted
    }
}

pub(crate) struct DeferredMutationInput<'a> {
    pub(crate) record_lsn: u64,
    pub(crate) assignments: &'a HashSet<(String, Nid)>,
    pub(crate) creates: &'a [GraphDeferredBind],
    pub(crate) endpoint_binds: &'a [GraphEdgeBind],
    pub(crate) session_mutations: &'a [GraphDeferredSessionMutation],
}

impl MutableAdjacency {
    fn insert<P>(&mut self, edge: &GraphEdge<P>) {
        match &edge.namespace {
            GraphNamespace::Tenant(tenant) => {
                self.tenants.entry(tenant.clone()).or_default().insert(edge);
            }
            GraphNamespace::AdminCrossTenant => self.admin_cross_tenant.insert(edge),
        }
    }

    fn namespace(&self, namespace: &GraphNamespace) -> Option<&NamespaceAdjacency> {
        match namespace {
            GraphNamespace::Tenant(tenant) => self.tenants.get(tenant),
            GraphNamespace::AdminCrossTenant => Some(&self.admin_cross_tenant),
        }
    }
}

/// Graph control and mutable tail. Once attached, sealed adjacency is read from
/// a generation pin and only unsealed topology keeps mutable adjacency rows.
/// Sealed properties are read lazily; only unsealed documents are retained.
/// Only unsealed topology rows and property documents are retained after pinning.
/// Namespace labels are derived from checked artifacts. The ledger is pinned;
/// only unsealed existence keys are retained in the mutable bitmap.
/// Removals add visibility tombstones until compaction reclaims physical rows.
#[derive(Clone, Debug)]
pub(crate) struct MutableGraphState {
    epoch: GraphEpoch,
    types: GraphTypeCatalog,
    /// Unsealed stable EdgeIds, including pending/aborted deferred edges.
    edge_ids: RoaringTreemap,
    sealed_ledger: crate::graph_generation::ledger::SealedLedger,
    edges: BTreeMap<EdgeId, StoredEdge>,
    property_tail: BTreeMap<EdgeId, Value>,
    sealed_namespaces: crate::graph_generation::namespaces::SealedNamespaces,
    sealed_properties: crate::graph_generation::properties::SealedProperties,
    live_edges: u64,
    edge_tombstones: RoaringTreemap,
    adjacency: MutableAdjacency,
    sealed_adjacency: Option<std::sync::Arc<crate::graph_generation::GraphGeneration>>,
    deferred_sessions: HashMap<String, DeferredSession>,
    pending_edges: BTreeMap<EdgeId, PendingEdge>,
    /// Missing endpoints are addressed by the exact durable session window,
    /// so point creation can discover bind work without scanning all pending
    /// edges or capturing an incarnation from another window.
    pending_by_endpoint: BTreeMap<(String, String, u64), Vec<(EdgeId, GraphDeferredEndpoint)>>,
    /// Durable retry results for this graph epoch. Expired entries remain
    /// until a later checkpoint/compaction proves their source WAL cannot be
    /// replayed; G0 must never evict them from wall-clock time alone.
    idempotency: HashMap<String, GraphIdempotencyState>,
    persist_changes: seal::PersistChanges,
}

impl MutableGraphState {
    pub(crate) fn new(epoch: GraphEpoch) -> Self {
        Self {
            epoch,
            types: GraphTypeCatalog::default(),
            edge_ids: RoaringTreemap::new(),
            sealed_ledger: Default::default(),
            edges: BTreeMap::new(),
            property_tail: BTreeMap::new(),
            sealed_namespaces: Default::default(),
            sealed_properties: Default::default(),
            live_edges: 0,
            edge_tombstones: RoaringTreemap::new(),
            adjacency: MutableAdjacency::default(),
            sealed_adjacency: None,
            deferred_sessions: HashMap::new(),
            pending_edges: BTreeMap::new(),
            pending_by_endpoint: BTreeMap::new(),
            idempotency: HashMap::new(),
            persist_changes: seal::PersistChanges::default(),
        }
    }

    pub(crate) fn compaction_pending_edge_ids(&self) -> impl Iterator<Item = EdgeId> + '_ {
        self.pending_edges.keys().copied()
    }

    pub(crate) fn install_compaction_tail_tombstones(&mut self, tail: RoaringTreemap) {
        self.edge_tombstones = tail;
    }

    pub(crate) fn epoch(&self) -> GraphEpoch {
        self.epoch
    }

    pub(crate) fn types(&self) -> &GraphTypeCatalog {
        &self.types
    }

    pub(crate) fn types_mut(&mut self) -> &mut GraphTypeCatalog {
        &mut self.types
    }

    pub(crate) fn replace_types(&mut self, types: GraphTypeCatalog) {
        self.types = types;
    }

    pub(crate) fn edge_namespace(&self, edge_id: EdgeId) -> Result<Option<&GraphNamespace>> {
        if !self.edge_visible(edge_id) {
            Ok(None)
        } else if let Some(edge) = self.edges.get(&edge_id) {
            Ok(Some(&edge.namespace))
        } else {
            self.sealed_namespaces.lookup(edge_id)
        }
    }

    fn has_live_edge(&self, edge_id: EdgeId) -> Result<bool> {
        self.edge_namespace(edge_id)
            .map(|namespace| namespace.is_some())
    }

    pub(crate) fn stored_topology_count(&self) -> u64 {
        self.sealed_namespaces.len() + self.edges.len() as u64
    }

    /// Visibility only, not an existence check. Adjacency supplies checked
    /// identities; edge-addressed callers must separately verify existence.
    pub(crate) fn edge_visible(&self, edge_id: EdgeId) -> bool {
        !self.edge_tombstones.contains(edge_id.raw())
    }

    pub(crate) fn live_edge_count(&self) -> u64 {
        self.live_edges
    }

    pub(crate) fn stored_edge_count(&self) -> u64 {
        self.sealed_ledger.len() + self.edge_ids.len()
    }

    pub(crate) fn tombstone_count(&self) -> u64 {
        self.edge_tombstones.len()
    }

    pub(crate) fn edge_tombstones(&self) -> &RoaringTreemap {
        &self.edge_tombstones
    }

    /// Frozen unsealed topology for the graph-compaction input. Sealed rows
    /// stay behind the generation pin; pending deferred identities have no
    /// topology and are deliberately absent.
    pub(crate) fn compaction_topology(
        &self,
    ) -> impl Iterator<Item = (GraphNamespace, crate::graph_group::AdjacencyEdge)> + '_ {
        self.edges.values().map(|edge| {
            (
                edge.namespace.clone(),
                crate::graph_group::AdjacencyEdge {
                    edge_id: edge.edge_id,
                    source: edge.source,
                    target: edge.target,
                    type_id: edge.type_id,
                    local_base: None,
                },
            )
        })
    }

    pub(crate) fn idempotency(&self, key: &str) -> Option<&GraphIdempotencyState> {
        self.idempotency.get(key)
    }

    pub(crate) fn idempotency_len(&self) -> usize {
        self.idempotency.len()
    }

    pub(crate) fn deferred_opening_lsn(&self, session_id: &str) -> Option<u64> {
        self.deferred_sessions
            .get(session_id)
            .map(|session| session.opening_lsn)
    }

    pub(crate) fn deferred_session_is_committed(&self, session_id: &str) -> bool {
        self.deferred_sessions
            .get(session_id)
            .is_some_and(|session| session.status == DeferredSessionStatus::Committed)
    }

    pub(crate) fn deferred_session_is_open(&self, session_id: &str) -> bool {
        self.deferred_sessions
            .get(session_id)
            .is_some_and(|session| session.status == DeferredSessionStatus::Open)
    }

    pub(crate) fn deferred_session_is_aborted(&self, session_id: &str) -> bool {
        self.deferred_sessions
            .get(session_id)
            .is_some_and(|session| session.status == DeferredSessionStatus::Aborted)
    }

    pub(crate) fn pending_edge_count(&self) -> usize {
        self.pending_edges.len()
    }

    pub(crate) fn pending_binding_count(
        &self,
        point_id: &str,
        session_id: &str,
        opening_lsn: u64,
    ) -> usize {
        self.pending_by_endpoint
            .get(&(point_id.to_string(), session_id.to_string(), opening_lsn))
            .map_or(0, Vec::len)
    }

    pub(crate) fn pending_bindings(
        &self,
        point_id: &str,
        session_id: &str,
        opening_lsn: u64,
    ) -> Vec<(EdgeId, GraphDeferredEndpoint)> {
        self.pending_by_endpoint
            .get(&(point_id.to_string(), session_id.to_string(), opening_lsn))
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn pending_edge_count_for_session(&self, session_id: &str) -> usize {
        self.pending_edges
            .values()
            .filter(|pending| pending.session_id == session_id)
            .count()
    }

    pub(crate) fn validate_idempotency(&self, entry: Option<&GraphIdempotencyState>) -> Result<()> {
        let Some(entry) = entry else {
            return Ok(());
        };
        if let Some(existing) = self.idempotency.get(&entry.key)
            && existing != entry
        {
            return Err(GaussError::InvalidRequest(format!(
                "idempotency key '{}' is already bound to another graph request in epoch {}",
                entry.key,
                self.epoch.raw()
            )));
        }
        Ok(())
    }

    pub(crate) fn apply_validated_idempotency(&mut self, entry: Option<&GraphIdempotencyState>) {
        if let Some(entry) = entry {
            self.idempotency
                .entry(entry.key.clone())
                .or_insert_with(|| entry.clone());
        }
    }

    pub(crate) fn plan_deferred(
        &self,
        resolver: &PointIncarnationResolver,
        input: DeferredMutationInput<'_>,
        types: &GraphTypeCatalog,
    ) -> Result<DeferredMutationPlan> {
        let DeferredMutationInput {
            record_lsn,
            assignments,
            creates,
            endpoint_binds,
            session_mutations,
        } = input;
        let mut plan = DeferredMutationPlan::default();
        let mut terminal_mutations = Vec::new();

        for mutation in session_mutations {
            match mutation {
                GraphDeferredSessionMutation::Open { session_id } => {
                    if self.deferred_sessions.contains_key(session_id) {
                        return Err(invalid_deferred(format!(
                            "deferred session '{session_id}' already exists"
                        )));
                    }
                    plan.session_updates.insert(
                        session_id.clone(),
                        DeferredSession {
                            opening_lsn: record_lsn,
                            status: DeferredSessionStatus::Open,
                        },
                    );
                }
                GraphDeferredSessionMutation::Commit { session_id }
                | GraphDeferredSessionMutation::Abort { session_id } => {
                    let Some(session) = self.deferred_sessions.get(session_id) else {
                        return Err(GraphError::new(
                            GraphErrorCode::DeferredSessionNotFound,
                            format!("deferred session '{session_id}' does not exist"),
                        )
                        .into());
                    };
                    if session.status != DeferredSessionStatus::Open {
                        return Err(invalid_deferred(format!(
                            "deferred session '{session_id}' is not open"
                        )));
                    }
                    terminal_mutations.push(mutation);
                }
            }
        }

        let session_is_open =
            |session_id: &str, updates: &HashMap<String, DeferredSession>| -> bool {
                updates
                    .get(session_id)
                    .or_else(|| self.deferred_sessions.get(session_id))
                    .is_some_and(|session| session.status == DeferredSessionStatus::Open)
            };

        for (item_index, create) in creates.iter().enumerate() {
            if !session_is_open(&create.session_id, &plan.session_updates) {
                return Err(GraphError::new(
                    GraphErrorCode::DeferredSessionNotFound,
                    format!("deferred session '{}' is not open", create.session_id),
                )
                .with_item_index(item_index)
                .into());
            }
            if self.contains_edge_id(create.edge_id)?
                || plan.created_edge_ids.contains(&create.edge_id)
            {
                return Err(invalid_deferred_item(
                    item_index,
                    "EdgeId already exists in the stable ledger",
                ));
            }
            if types.get(create.type_id).is_none() {
                return Err(GraphError::new(
                    GraphErrorCode::TypeNotFound,
                    format!("edge type {} is not configured", create.type_id.raw()),
                )
                .with_item_index(item_index)
                .into());
            }
            validate_property_document(&create.properties, item_index)?;
            validate_deferred_endpoint(
                resolver,
                &create.source_point_id,
                create.source_nid,
                item_index,
            )?;
            validate_deferred_endpoint(
                resolver,
                &create.target_point_id,
                create.target_nid,
                item_index,
            )?;
            let opening_lsn = plan
                .session_updates
                .get(&create.session_id)
                .or_else(|| self.deferred_sessions.get(&create.session_id))
                .expect("validated open deferred session exists")
                .opening_lsn;
            plan.created_edge_ids.insert(create.edge_id);
            plan.pending_updates.insert(
                create.edge_id,
                Some(PendingEdge {
                    session_id: create.session_id.clone(),
                    opening_lsn,
                    edge_id: create.edge_id,
                    source_point_id: create.source_point_id.clone(),
                    target_point_id: create.target_point_id.clone(),
                    source_nid: create.source_nid,
                    target_nid: create.target_nid,
                    type_id: create.type_id,
                    namespace: create.namespace.clone(),
                    properties: create.properties.clone(),
                }),
            );
        }

        for (item_index, bind) in endpoint_binds.iter().enumerate() {
            if !session_is_open(&bind.session_id, &plan.session_updates) {
                return Err(GraphError::new(
                    GraphErrorCode::DeferredSessionNotFound,
                    format!("deferred session '{}' is not open", bind.session_id),
                )
                .with_item_index(item_index)
                .into());
            }
            let mut pending = match plan.pending_updates.get(&bind.edge_id) {
                Some(Some(pending)) => pending.clone(),
                Some(None) => {
                    return Err(invalid_deferred_item(
                        item_index,
                        "deferred edge is already fully bound",
                    ));
                }
                None => self
                    .pending_edges
                    .get(&bind.edge_id)
                    .cloned()
                    .ok_or_else(|| {
                        invalid_deferred_item(item_index, "pending EdgeId does not exist")
                    })?,
            };
            if pending.session_id != bind.session_id {
                return Err(invalid_deferred_item(
                    item_index,
                    "pending EdgeId belongs to another deferred session",
                ));
            }
            if !assignments.contains(&(bind.point_id.clone(), bind.nid))
                || resolver.live_nid(&bind.point_id) != Some(bind.nid)
            {
                return Err(invalid_deferred_item(
                    item_index,
                    "EdgeBind must name the exact Nid assigned in the same GraphBatch",
                ));
            }
            match bind.endpoint {
                GraphDeferredEndpoint::Source => {
                    if pending.source_point_id != bind.point_id || pending.source_nid.is_some() {
                        return Err(invalid_deferred_item(
                            item_index,
                            "source binding is immutable or names the wrong point",
                        ));
                    }
                    pending.source_nid = Some(bind.nid);
                }
                GraphDeferredEndpoint::Target => {
                    if pending.target_point_id != bind.point_id || pending.target_nid.is_some() {
                        return Err(invalid_deferred_item(
                            item_index,
                            "target binding is immutable or names the wrong point",
                        ));
                    }
                    pending.target_nid = Some(bind.nid);
                }
            }
            plan.pending_updates.insert(bind.edge_id, Some(pending));
        }

        for update in plan.pending_updates.values_mut() {
            let Some(pending) = update.as_ref() else {
                continue;
            };
            if let (Some(source), Some(target)) = (pending.source_nid, pending.target_nid) {
                plan.promoted.push(EdgeMutation::Relate(RelateMutation {
                    edge_id: pending.edge_id,
                    source,
                    target,
                    type_id: pending.type_id,
                    namespace: pending.namespace.clone(),
                    properties: pending.properties.clone(),
                }));
                *update = None;
            }
        }

        for mutation in terminal_mutations {
            let (session_id, next_status) = match mutation {
                GraphDeferredSessionMutation::Commit { session_id } => {
                    let offenders = projected_unbound_endpoints(
                        &self.pending_edges,
                        &plan.pending_updates,
                        session_id,
                    );
                    if !offenders.is_empty() {
                        return Err(GraphError::new(
                            GraphErrorCode::DeferredEndpointsRemain,
                            format!(
                                "deferred session '{session_id}' has {} unbound endpoints: {offenders:?}",
                                offenders.len()
                            ),
                        )
                        .into());
                    }
                    (session_id, DeferredSessionStatus::Committed)
                }
                GraphDeferredSessionMutation::Abort { session_id } => {
                    let mut abort_ids = self
                        .pending_edges
                        .values()
                        .filter(|pending| pending.session_id == *session_id)
                        .map(|pending| pending.edge_id)
                        .collect::<HashSet<_>>();
                    abort_ids.extend(
                        plan.pending_updates
                            .values()
                            .filter_map(Option::as_ref)
                            .filter(|pending| pending.session_id == *session_id)
                            .map(|pending| pending.edge_id),
                    );
                    for edge_id in abort_ids {
                        if plan
                            .pending_updates
                            .get(&edge_id)
                            .is_some_and(Option::is_none)
                        {
                            continue;
                        }
                        plan.pending_updates.insert(edge_id, None);
                        plan.aborted_edge_ids.push(edge_id);
                    }
                    (session_id, DeferredSessionStatus::Aborted)
                }
                GraphDeferredSessionMutation::Open { .. } => unreachable!(),
            };
            let opening_lsn = self
                .deferred_sessions
                .get(session_id)
                .expect("validated terminal session exists")
                .opening_lsn;
            plan.session_updates.insert(
                session_id.clone(),
                DeferredSession {
                    opening_lsn,
                    status: next_status,
                },
            );
        }

        Ok(plan)
    }

    pub(crate) fn apply_deferred_plan(&mut self, plan: DeferredMutationPlan) {
        for edge_id in plan.created_edge_ids {
            self.edge_ids.insert(edge_id.raw());
        }
        for (session_id, session) in plan.session_updates {
            self.deferred_sessions.insert(session_id, session);
        }
        for (edge_id, pending) in plan.pending_updates {
            if let Some(previous) = self.pending_edges.remove(&edge_id) {
                self.unindex_pending_edge(&previous);
            }
            if let Some(pending) = pending {
                self.index_pending_edge(&pending);
                self.pending_edges.insert(edge_id, pending);
            }
        }
        for edge_id in plan.aborted_edge_ids {
            self.edge_tombstones.insert(edge_id.raw());
        }
    }

    fn index_pending_edge(&mut self, pending: &PendingEdge) {
        for (point_id, endpoint, missing) in [
            (
                &pending.source_point_id,
                GraphDeferredEndpoint::Source,
                pending.source_nid.is_none(),
            ),
            (
                &pending.target_point_id,
                GraphDeferredEndpoint::Target,
                pending.target_nid.is_none(),
            ),
        ] {
            if missing {
                self.pending_by_endpoint
                    .entry((
                        point_id.clone(),
                        pending.session_id.clone(),
                        pending.opening_lsn,
                    ))
                    .or_default()
                    .push((pending.edge_id, endpoint));
            }
        }
    }

    fn unindex_pending_edge(&mut self, pending: &PendingEdge) {
        for point_id in [&pending.source_point_id, &pending.target_point_id] {
            let key = (
                point_id.clone(),
                pending.session_id.clone(),
                pending.opening_lsn,
            );
            let remove_key = if let Some(entries) = self.pending_by_endpoint.get_mut(&key) {
                entries.retain(|(edge_id, _)| *edge_id != pending.edge_id);
                entries.is_empty()
            } else {
                false
            };
            if remove_key {
                self.pending_by_endpoint.remove(&key);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn outgoing(&self, namespace: &GraphNamespace, nid: Nid) -> Vec<EdgeId> {
        self.edge_candidates(namespace, nid, false)
            .unwrap()
            .filter_map(|step| step.unwrap().edge())
            .filter(|edge| edge.source == nid)
            .map(|edge| edge.edge_id)
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn incoming(&self, namespace: &GraphNamespace, nid: Nid) -> Vec<EdgeId> {
        self.edge_candidates(namespace, nid, true)
            .unwrap()
            .filter_map(|step| step.unwrap().edge())
            .filter(|edge| edge.target == nid)
            .map(|edge| edge.edge_id)
            .collect()
    }

    pub(crate) fn has_live_incident_edge_excluding(
        &self,
        nid: Nid,
        tenant: Option<&str>,
        removed: &HashSet<EdgeId>,
    ) -> Result<bool> {
        for namespace in self.incident_namespaces(tenant) {
            for incoming in [false, true] {
                for step in self.edge_candidates(&namespace, nid, incoming)? {
                    let Some(edge) = step?.edge() else {
                        continue;
                    };
                    if !removed.contains(&edge.edge_id)
                        && self.edge_visible(edge.edge_id)
                        && (edge.source == nid || edge.target == nid)
                    {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    pub(crate) fn live_incident_edge_ids(
        &self,
        nid: Nid,
        tenant: &str,
        resolver: &PointIncarnationResolver,
    ) -> Result<HashSet<EdgeId>> {
        let mut ids = HashSet::new();
        for namespace in self.incident_namespaces(Some(tenant)) {
            for incoming in [false, true] {
                for step in self.edge_candidates(&namespace, nid, incoming)? {
                    let Some(edge) = step?.edge() else {
                        continue;
                    };
                    if self.edge_visible(edge.edge_id)
                        && (edge.source == nid || edge.target == nid)
                        && resolver.live_point_id(edge.source).is_some()
                        && resolver.live_point_id(edge.target).is_some()
                    {
                        ids.insert(edge.edge_id);
                    }
                }
            }
        }
        Ok(ids)
    }

    /// Validate the complete mutation set before changing the ledger,
    /// adjacency, tombstones, or properties. The commit pass is infallible,
    /// preserving one GraphBatch all-or-nothing publication boundary without
    /// cloning the whole graph.
    pub(crate) fn apply_edge_mutations<F>(
        &mut self,
        resolver: &PointIncarnationResolver,
        mutations: &[EdgeMutation],
        tenant_for_nid: F,
    ) -> Result<()>
    where
        F: Fn(Nid) -> Option<String>,
    {
        self.validate_edge_mutations_with_types(resolver, mutations, tenant_for_nid, &self.types)?;
        let prepared = self.prepare_property_mutations(mutations)?;
        self.apply_validated_edge_mutations(&prepared);
        Ok(())
    }

    pub(crate) fn validate_edge_mutations_with_types<F>(
        &self,
        resolver: &PointIncarnationResolver,
        mutations: &[EdgeMutation],
        tenant_for_nid: F,
        types: &GraphTypeCatalog,
    ) -> Result<()>
    where
        F: Fn(Nid) -> Option<String>,
    {
        self.validate_edge_mutations_with_types_and_promotions(
            resolver,
            mutations,
            tenant_for_nid,
            types,
            &HashSet::new(),
        )
    }

    pub(crate) fn validate_edge_mutations_with_types_and_promotions<F>(
        &self,
        resolver: &PointIncarnationResolver,
        mutations: &[EdgeMutation],
        tenant_for_nid: F,
        types: &GraphTypeCatalog,
        promoted_pending_ids: &HashSet<EdgeId>,
    ) -> Result<()>
    where
        F: Fn(Nid) -> Option<String>,
    {
        let mut seen = HashSet::with_capacity(mutations.len());
        for (item_index, mutation) in mutations.iter().enumerate() {
            let edge_id = mutation_edge_id(mutation);
            if !seen.insert(edge_id) {
                return Err(invalid_edge_item(
                    item_index,
                    "one EdgeId is mutated more than once",
                ));
            }
            match mutation {
                EdgeMutation::Relate(relate) => self.validate_relate(
                    resolver,
                    relate,
                    &tenant_for_nid,
                    types,
                    promoted_pending_ids.contains(&relate.edge_id),
                    item_index,
                )?,
                EdgeMutation::Unrelate(unrelate) => {
                    if !self.has_live_edge(unrelate.edge_id)? {
                        return Err(edge_not_found(unrelate.edge_id, item_index));
                    }
                }
                EdgeMutation::Properties(properties) => {
                    if !self.has_live_edge(properties.edge_id)? {
                        return Err(edge_not_found(properties.edge_id, item_index));
                    }
                    validate_property_document(&properties.properties, item_index)?;
                }
            }
        }

        Ok(())
    }

    pub(crate) fn apply_validated_edge_mutations(&mut self, mutations: &[EdgeMutation]) {
        for mutation in mutations {
            match mutation {
                EdgeMutation::Relate(relate) => {
                    let edge = StoredEdge {
                        edge_id: relate.edge_id,
                        source: relate.source,
                        target: relate.target,
                        type_id: relate.type_id,
                        namespace: relate.namespace.clone(),
                        properties: (),
                    };
                    self.adjacency.insert(&edge);
                    // A promoted pending edge already owns a stable key, which
                    // may now live only in the immutable ledger. No disk read
                    // is allowed in this post-WAL application pass.
                    if !self.pending_edges.contains_key(&edge.edge_id) {
                        self.edge_ids.insert(edge.edge_id.raw());
                    }
                    self.edges.insert(edge.edge_id, edge);
                    self.property_tail
                        .insert(relate.edge_id, relate.properties.clone());
                    self.live_edges = self
                        .live_edges
                        .checked_add(1)
                        .expect("validated graph live-edge count overflow");
                }
                EdgeMutation::Unrelate(unrelate) => {
                    self.edge_tombstones.insert(unrelate.edge_id.raw());
                    self.live_edges = self
                        .live_edges
                        .checked_sub(1)
                        .expect("validated graph live-edge count underflow");
                }
                EdgeMutation::Properties(properties) => match properties.mode {
                    EdgePropertyMode::Replace => {
                        self.property_tail
                            .insert(properties.edge_id, properties.properties.clone());
                    }
                    EdgePropertyMode::Merge => {
                        let target = self
                            .property_tail
                            .get_mut(&properties.edge_id)
                            .expect("sealed property merge was prepared before WAL")
                            .as_object_mut()
                            .expect("validated edge property document");
                        for (key, value) in properties
                            .properties
                            .as_object()
                            .expect("validated property patch")
                        {
                            target.insert(key.clone(), value.clone());
                        }
                    }
                },
            }
        }
    }

    fn validate_relate<F>(
        &self,
        resolver: &PointIncarnationResolver,
        relate: &RelateMutation,
        tenant_for_nid: &F,
        types: &GraphTypeCatalog,
        promoting_pending: bool,
        item_index: usize,
    ) -> Result<()>
    where
        F: Fn(Nid) -> Option<String>,
    {
        validate_edge_id(relate.edge_id, item_index)?;
        if !promoting_pending && self.contains_edge_id(relate.edge_id)? {
            return Err(invalid_edge_item(
                item_index,
                "EdgeId already exists in the stable ledger",
            ));
        }
        if types.get(relate.type_id).is_none() {
            return Err(GraphError::new(
                GraphErrorCode::TypeNotFound,
                format!("edge type {} is not configured", relate.type_id.raw()),
            )
            .with_item_index(item_index)
            .into());
        }
        for nid in [relate.source, relate.target] {
            if resolver.live_point_id(nid).is_none() {
                return Err(GraphError::new(
                    GraphErrorCode::EndpointNotFound,
                    format!("endpoint Nid {} is not live", nid.raw()),
                )
                .with_item_index(item_index)
                .into());
            }
        }
        let source_tenant = tenant_for_nid(relate.source);
        let target_tenant = tenant_for_nid(relate.target);
        match &relate.namespace {
            GraphNamespace::Tenant(tenant)
                if source_tenant.as_deref().unwrap_or(DEFAULT_GRAPH_NAMESPACE)
                    != tenant.as_str()
                    || target_tenant.as_deref().unwrap_or(DEFAULT_GRAPH_NAMESPACE)
                        != tenant.as_str() =>
            {
                return Err(invalid_edge_item(
                    item_index,
                    "tenant-local edge endpoints must belong to its physical namespace",
                ));
            }
            GraphNamespace::AdminCrossTenant
                if source_tenant.is_none()
                    || target_tenant.is_none()
                    || source_tenant == target_tenant =>
            {
                return Err(invalid_edge_item(
                    item_index,
                    "admin cross-tenant edge endpoints must belong to different named tenants",
                ));
            }
            GraphNamespace::Tenant(_) | GraphNamespace::AdminCrossTenant => {}
        }
        validate_property_document(&relate.properties, item_index)
    }
}

fn validate_deferred_endpoint(
    resolver: &PointIncarnationResolver,
    point_id: &str,
    recorded_nid: Option<Nid>,
    item_index: usize,
) -> Result<()> {
    let live_nid = resolver.live_nid(point_id);
    if live_nid != recorded_nid {
        return Err(invalid_deferred_item(
            item_index,
            "pending edge must record the exact live Nid or None for an absent endpoint",
        ));
    }
    Ok(())
}

fn projected_unbound_endpoints(
    current: &BTreeMap<EdgeId, PendingEdge>,
    updates: &BTreeMap<EdgeId, Option<PendingEdge>>,
    session_id: &str,
) -> std::collections::BTreeSet<String> {
    let mut offenders = std::collections::BTreeSet::new();
    for (edge_id, pending) in current {
        let projected = match updates.get(edge_id) {
            Some(Some(projected)) => Some(projected),
            Some(None) => None,
            None => Some(pending),
        };
        if let Some(projected) = projected
            && projected.session_id == session_id
        {
            if projected.source_nid.is_none() {
                offenders.insert(projected.source_point_id.clone());
            }
            if projected.target_nid.is_none() {
                offenders.insert(projected.target_point_id.clone());
            }
        }
    }
    for (edge_id, pending) in updates {
        if current.contains_key(edge_id) {
            continue;
        }
        if let Some(pending) = pending
            && pending.session_id == session_id
        {
            if pending.source_nid.is_none() {
                offenders.insert(pending.source_point_id.clone());
            }
            if pending.target_nid.is_none() {
                offenders.insert(pending.target_point_id.clone());
            }
        }
    }
    offenders
}

fn mutation_edge_id(mutation: &EdgeMutation) -> EdgeId {
    match mutation {
        EdgeMutation::Relate(relate) => relate.edge_id,
        EdgeMutation::Unrelate(unrelate) => unrelate.edge_id,
        EdgeMutation::Properties(properties) => properties.edge_id,
    }
}

fn validate_type_id(type_id: TypeId) -> Result<()> {
    if type_id.raw() == 0 {
        return Err(invalid_catalog("TypeId=0 is reserved"));
    }
    Ok(())
}

fn validate_catalog_name(label: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_GRAPH_CATALOG_NAME_BYTES {
        return Err(invalid_catalog(format!(
            "{label} must contain 1..={MAX_GRAPH_CATALOG_NAME_BYTES} UTF-8 bytes"
        )));
    }
    Ok(())
}

fn validate_edge_id(edge_id: EdgeId, item_index: usize) -> Result<()> {
    if EdgeId::from_parts(edge_id.epoch(), edge_id.counter()) != Some(edge_id) {
        return Err(invalid_edge_item(item_index, "invalid EdgeId"));
    }
    Ok(())
}

fn validate_property_document(properties: &Value, item_index: usize) -> Result<()> {
    if !properties.is_object() {
        return Err(invalid_edge_item(
            item_index,
            "edge properties must be a JSON object",
        ));
    }
    let bytes = serde_json::to_vec(properties)?.len();
    if bytes > MAX_EDGE_PROPERTY_BYTES {
        return Err(GraphError::new(
            GraphErrorCode::PropertyTooLarge,
            format!("edge properties are {bytes} bytes; maximum is {MAX_EDGE_PROPERTY_BYTES}"),
        )
        .with_item_index(item_index)
        .into());
    }
    Ok(())
}

fn edge_not_found(edge_id: EdgeId, item_index: usize) -> GaussError {
    GraphError::new(
        GraphErrorCode::EdgeNotFound,
        format!("EdgeId {} is not live", edge_id.raw()),
    )
    .with_item_index(item_index)
    .into()
}

fn invalid_edge_item(item_index: usize, message: impl Into<String>) -> GaussError {
    GaussError::InvalidRequest(format!(
        "invalid graph edge mutation at index {item_index}: {}",
        message.into()
    ))
}

fn invalid_deferred_item(item_index: usize, message: impl Into<String>) -> GaussError {
    GaussError::InvalidRequest(format!(
        "invalid deferred edge mutation at index {item_index}: {}",
        message.into()
    ))
}

fn invalid_deferred(message: impl Into<String>) -> GaussError {
    GaussError::InvalidRequest(format!(
        "invalid deferred graph session: {}",
        message.into()
    ))
}

fn invalid_catalog(message: impl Into<String>) -> GaussError {
    GaussError::InvalidRequest(format!("invalid graph type catalog: {}", message.into()))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::graph::{EdgePropertyMutation, UnrelateMutation};

    fn nid(counter: u64) -> Nid {
        Nid::from_parts(7, counter).unwrap()
    }

    fn edge_id(counter: u64) -> EdgeId {
        EdgeId::from_parts(7, counter).unwrap()
    }

    fn type_id(raw: u32) -> TypeId {
        TypeId::from_raw(raw)
    }

    fn resolver() -> PointIncarnationResolver {
        let mut resolver = PointIncarnationResolver::default();
        resolver.bind_live("a".to_string(), nid(1)).unwrap();
        resolver.bind_live("b".to_string(), nid(2)).unwrap();
        resolver.bind_live("c".to_string(), nid(3)).unwrap();
        resolver
    }

    fn relate(
        edge_id: EdgeId,
        source: Nid,
        target: Nid,
        namespace: GraphNamespace,
    ) -> EdgeMutation {
        EdgeMutation::Relate(RelateMutation {
            edge_id,
            source,
            target,
            type_id: type_id(1),
            namespace,
            properties: json!({"kind": "citation", "year": 2026}),
        })
    }

    fn configured_state() -> MutableGraphState {
        let mut state = MutableGraphState::new(GraphEpoch::INITIAL);
        state
            .types_mut()
            .configure(type_id(1), "CITES".to_string(), None)
            .unwrap();
        state
    }

    fn tenant_for_nid(nid: Nid) -> Option<String> {
        match nid {
            value if value == self::nid(1) || value == self::nid(2) => Some("acme".to_string()),
            value if value == self::nid(3) => Some("globex".to_string()),
            _ => None,
        }
    }

    #[test]
    fn type_catalog_is_collection_global_and_rejects_identity_conflicts() {
        let mut catalog = GraphTypeCatalog::default();
        catalog
            .configure(type_id(1), "CITES".to_string(), None)
            .unwrap();
        catalog
            .configure(
                type_id(1),
                "CITES".to_string(),
                Some("confidence".to_string()),
            )
            .unwrap();
        assert_eq!(catalog.resolve_name("CITES"), Some(type_id(1)));
        assert_eq!(
            catalog.get(type_id(1)).unwrap().weight_property.as_deref(),
            Some("confidence")
        );
        assert_eq!(catalog.len(), 1);
        assert!(
            catalog
                .configure(type_id(1), "MENTIONS".to_string(), None)
                .is_err()
        );
        assert!(
            catalog
                .configure(type_id(2), "CITES".to_string(), None)
                .is_err()
        );
        assert!(
            catalog
                .configure(type_id(0), "INVALID".to_string(), None)
                .is_err()
        );
    }

    #[test]
    fn mutable_ledger_supports_multi_edges_and_self_loops_in_both_directions() {
        let resolver = resolver();
        let mut state = configured_state();
        let tenant = GraphNamespace::Tenant("acme".to_string());
        assert_eq!(state.epoch(), GraphEpoch::INITIAL);
        assert_eq!(state.types().len(), 1);
        state
            .apply_edge_mutations(
                &resolver,
                &[
                    relate(edge_id(1), nid(1), nid(2), tenant.clone()),
                    relate(edge_id(2), nid(1), nid(2), tenant.clone()),
                    relate(edge_id(3), nid(1), nid(1), tenant.clone()),
                ],
                tenant_for_nid,
            )
            .unwrap();

        assert_eq!(state.live_edge_count(), 3);
        assert_eq!(
            state.outgoing(&tenant, nid(1)),
            &[edge_id(1), edge_id(2), edge_id(3)]
        );
        assert_eq!(state.incoming(&tenant, nid(2)), &[edge_id(1), edge_id(2)]);
        assert_eq!(state.incoming(&tenant, nid(1)), &[edge_id(3)]);
        assert_eq!(state.edge(edge_id(2)).unwrap().type_id, type_id(1));
    }

    #[test]
    fn tenant_and_admin_adjacency_are_physically_separate() {
        let resolver = resolver();
        let mut state = configured_state();
        let tenant = GraphNamespace::Tenant("acme".to_string());
        state
            .apply_edge_mutations(
                &resolver,
                &[
                    relate(edge_id(1), nid(1), nid(2), tenant.clone()),
                    relate(edge_id(2), nid(1), nid(3), GraphNamespace::AdminCrossTenant),
                ],
                tenant_for_nid,
            )
            .unwrap();

        assert_eq!(state.outgoing(&tenant, nid(1)), &[edge_id(1)]);
        assert_eq!(
            state.outgoing(&GraphNamespace::AdminCrossTenant, nid(1)),
            &[edge_id(2)]
        );
        assert!(
            state
                .outgoing(&GraphNamespace::Tenant("globex".to_string()), nid(1))
                .is_empty()
        );
    }

    #[test]
    fn strict_endpoint_and_tenant_validation_publish_no_batch_prefix() {
        let resolver = resolver();
        let mut state = configured_state();
        let tenant = GraphNamespace::Tenant("acme".to_string());
        let mutations = [
            relate(edge_id(1), nid(1), nid(2), tenant.clone()),
            relate(edge_id(2), nid(1), nid(99), tenant.clone()),
        ];
        let error = state
            .apply_edge_mutations(&resolver, &mutations, tenant_for_nid)
            .unwrap_err();
        assert!(error.to_string().contains("graph.endpoint_not_found"));
        assert_eq!(state.live_edge_count(), 0);
        assert!(state.outgoing(&tenant, nid(1)).is_empty());

        let error = state
            .apply_edge_mutations(
                &resolver,
                &[relate(edge_id(3), nid(1), nid(3), tenant.clone())],
                tenant_for_nid,
            )
            .unwrap_err();
        assert!(error.to_string().contains("physical namespace"));
        assert_eq!(state.live_edge_count(), 0);
    }

    #[test]
    fn unrelate_is_o1_visibility_and_properties_never_recreate_an_edge() {
        let resolver = resolver();
        let mut state = configured_state();
        let tenant = GraphNamespace::Tenant("acme".to_string());
        state
            .apply_edge_mutations(
                &resolver,
                &[relate(edge_id(1), nid(1), nid(2), tenant.clone())],
                tenant_for_nid,
            )
            .unwrap();
        state
            .apply_edge_mutations(
                &resolver,
                &[EdgeMutation::Properties(EdgePropertyMutation {
                    edge_id: edge_id(1),
                    mode: EdgePropertyMode::Merge,
                    properties: json!({"year": 2027, "reviewed": true}),
                })],
                tenant_for_nid,
            )
            .unwrap();
        assert_eq!(state.edge(edge_id(1)).unwrap().properties["year"], 2027);
        assert_eq!(state.edge(edge_id(1)).unwrap().properties["reviewed"], true);

        state
            .apply_edge_mutations(
                &resolver,
                &[EdgeMutation::Unrelate(UnrelateMutation {
                    edge_id: edge_id(1),
                })],
                tenant_for_nid,
            )
            .unwrap();
        assert_eq!(state.live_edge_count(), 0);
        assert_eq!(state.stored_edge_count(), 1);
        assert_eq!(state.tombstone_count(), 1);
        assert_eq!(state.outgoing(&tenant, nid(1)), &[edge_id(1)]);
        assert!(state.edge(edge_id(1)).is_none());

        let error = state
            .apply_edge_mutations(
                &resolver,
                &[EdgeMutation::Properties(EdgePropertyMutation {
                    edge_id: edge_id(1),
                    mode: EdgePropertyMode::Replace,
                    properties: json!({"must": "not recreate"}),
                })],
                tenant_for_nid,
            )
            .unwrap_err();
        assert!(error.to_string().contains("graph.edge_not_found"));
        assert!(state.edge(edge_id(1)).is_none());
    }
}
