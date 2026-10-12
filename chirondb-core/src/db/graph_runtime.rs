//! G0 graph lifecycle orchestration and lazy point-handle migration.
//!
//! Durable state remains `GraphEpochAdvance` plus bounded `GraphBatch`
//! assignments. There is deliberately no second progress file: recovery
//! derives pending work from the collection resolver reconstructed from WAL.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    num::NonZeroU64,
    sync::atomic::AtomicBool,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};

use crate::{GaussError, Point, Result, transaction_journal::TransactionAudit, wal::WalEntry};

use super::{
    Collection, Db, GraphBatchCommitReceipt, audit_context, build_admission, insert_sparse_point,
    remove_sparse_point,
};

/// Keep lazy migration below the fixed 16 MiB GraphBatch cap even when every
/// point ID uses the public 1 KiB maximum.
pub(super) const GRAPH_HANDLE_BACKFILL_BATCH: usize = 1024;
const GRAPH_IDEMPOTENCY_TTL_MS: u64 = 24 * 60 * 60 * 1000;
const DEFAULT_GRAPH_NAMESPACE: &str = "@chiron:default";
// Conservative v1 policy: any visible incident edge requires the explicit
// flag. This is engine-owned, avoids a customer tuning knob, and cannot reveal
// degree because the refusal and successful result carry no count.
const GRAPH_DELETE_ACK_DEGREE_THRESHOLD: usize = 0;

pub(super) struct MultiModelGraphMutations {
    pub points: Vec<Point>,
    pub point_deletes: Vec<String>,
    pub relations: Vec<crate::graph::RelateRequest>,
    pub edge_deletes: Vec<crate::graph::EdgeToken>,
    pub edge_updates: Vec<(crate::graph::EdgeToken, crate::graph::UpdateEdgeRequest)>,
}

impl Collection {
    pub(super) fn graph_backfill_pending(&self) -> bool {
        if !self.graph_lifecycle.is_enabled() {
            return false;
        }
        let Some(resolver) = self.graph_resolver.as_ref() else {
            return !self.id_index.is_empty();
        };
        self.id_index
            .keys()
            .any(|point_id| resolver.live_nid(point_id).is_none())
    }
}

impl Db {
    pub(super) fn build_multimodel_graph_batch_locked(
        &self,
        collection: &Collection,
        mutations: MultiModelGraphMutations,
        scope: &crate::tenant::TenantScope,
    ) -> Result<(crate::wal::GraphBatch, Vec<crate::graph::EdgeToken>)> {
        let MultiModelGraphMutations {
            mut points,
            point_deletes,
            relations,
            edge_deletes,
            edge_updates,
        } = mutations;
        if points.is_empty()
            && point_deletes.is_empty()
            && relations.is_empty()
            && edge_deletes.is_empty()
            && edge_updates.is_empty()
        {
            return Err(GaussError::InvalidRequest(
                "multi-model transaction requires a vector or graph mutation".to_string(),
            ));
        }
        if !points.is_empty() && !point_deletes.is_empty() {
            return Err(GaussError::InvalidRequest(
                "multi-model transaction accepts one vector mutation kind".to_string(),
            ));
        }
        let mutable = active_mutable_graph(collection)?;
        let graph_epoch = mutable.epoch();
        let enforcement = self.tenant_enforcement();
        let mut staged_points = BTreeMap::new();
        for point in &mut points {
            scope.stamp_payload(enforcement, &mut point.payload)?;
            if staged_points
                .insert(point.id.clone(), point.clone())
                .is_some()
            {
                return Err(GaussError::InvalidRequest(format!(
                    "multi-model UPSERT contains duplicate point ID '{}'",
                    point.id
                )));
            }
        }
        let resolver = collection.graph_resolver.as_ref().ok_or_else(|| {
            GaussError::InvalidRequest(
                "enabled graph lifecycle has no point incarnation resolver".to_string(),
            )
        })?;
        let mut deleted_points = BTreeSet::new();
        for point_id in point_deletes {
            validate_public_graph_key("point ID", &point_id)?;
            if !deleted_points.insert(point_id.clone()) {
                return Err(GaussError::InvalidRequest(format!(
                    "multi-model DELETE contains duplicate point ID '{point_id}'"
                )));
            }
            let point = collection
                .try_resolve(&point_id)?
                .ok_or_else(endpoint_not_found)?;
            scope
                .may_write_payload(enforcement, &point.payload)
                .map_err(|_| endpoint_not_found())?;
        }
        let mut endpoint_ids = staged_points.keys().cloned().collect::<BTreeSet<_>>();
        endpoint_ids.extend(deleted_points.iter().cloned());
        for relation in &relations {
            validate_public_graph_key("source point ID", &relation.source_point_id)?;
            validate_public_graph_key("target point ID", &relation.target_point_id)?;
            validate_public_catalog_name("edge type", &relation.edge_type)?;
            validate_public_properties(&relation.properties)?;
            if relation.idempotency_key.is_some() {
                return Err(GaussError::InvalidRequest(
                    "per-edge idempotency keys are not supported inside a multi-model transaction; use the transaction idempotency_key"
                        .to_string(),
                ));
            }
            endpoint_ids.insert(relation.source_point_id.clone());
            endpoint_ids.insert(relation.target_point_id.clone());
            if deleted_points.contains(&relation.source_point_id)
                || deleted_points.contains(&relation.target_point_id)
            {
                return Err(GaussError::InvalidRequest(
                    "a related endpoint cannot be deleted in the same transaction".to_string(),
                ));
            }
        }
        for point_id in &endpoint_ids {
            if !staged_points.contains_key(point_id) && !collection.id_index.contains_key(point_id)
            {
                return Err(endpoint_not_found());
            }
        }
        let missing = endpoint_ids
            .iter()
            .filter(|point_id| resolver.live_nid(point_id).is_none())
            .count();
        let mut allocated = NonZeroU64::new(missing as u64)
            .map(|count| self.graph_identity.allocate_nids(count))
            .transpose()?
            .into_iter()
            .flat_map(|range| range.nids());
        let mut point_nids = BTreeMap::new();
        let mut handle_assignments = Vec::with_capacity(missing);
        for point_id in endpoint_ids {
            let nid = match resolver.live_nid(&point_id) {
                Some(nid) => nid,
                None => {
                    let nid = allocated
                        .next()
                        .expect("allocated the exact number of missing Nids");
                    handle_assignments.push(crate::wal::GraphHandleAssignment {
                        point_id: point_id.clone(),
                        nid,
                    });
                    nid
                }
            };
            point_nids.insert(point_id, nid);
        }
        debug_assert!(allocated.next().is_none());

        let endpoint = |point_id: &str| -> Result<ResolvedGraphEndpoint> {
            if let Some(point) = staged_points.get(point_id) {
                scope
                    .may_write_payload(enforcement, &point.payload)
                    .map_err(|_| endpoint_not_found())?;
                return Ok(ResolvedGraphEndpoint {
                    tenant: point
                        .payload
                        .get(crate::tenant::TENANT_FIELD)
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or(DEFAULT_GRAPH_NAMESPACE)
                        .to_string(),
                });
            }
            resolve_graph_endpoint(collection, point_id, scope, enforcement)
        };
        let mut explicit_edge_ids = HashSet::new();
        let mut edge_mutations = Vec::with_capacity(
            relations
                .len()
                .saturating_add(edge_deletes.len())
                .saturating_add(edge_updates.len()),
        );
        for token in edge_deletes {
            let edge_id = crate::edge_token::decode(self.graph_database_id(), &token)?;
            if !explicit_edge_ids.insert(edge_id) {
                return Err(GaussError::InvalidRequest(
                    "multi-model graph mutation contains a duplicate edge token".to_string(),
                ));
            }
            let namespace = mutable
                .edge_namespace(edge_id)?
                .ok_or_else(endpoint_not_found)?;
            authorize_edge_mutation(namespace, scope, enforcement)?;
            edge_mutations.push(crate::graph::EdgeMutation::Unrelate(
                crate::graph::UnrelateMutation { edge_id },
            ));
        }
        for (token, update) in edge_updates {
            validate_public_properties(&update.properties)?;
            let edge_id = crate::edge_token::decode(self.graph_database_id(), &token)?;
            if !explicit_edge_ids.insert(edge_id) {
                return Err(GaussError::InvalidRequest(
                    "multi-model graph mutation contains a duplicate edge token".to_string(),
                ));
            }
            let namespace = mutable
                .edge_namespace(edge_id)?
                .ok_or_else(endpoint_not_found)?;
            authorize_edge_mutation(namespace, scope, enforcement)?;
            edge_mutations.push(crate::graph::EdgeMutation::Properties(
                crate::graph::EdgePropertyMutation {
                    edge_id,
                    mode: update.mode,
                    properties: update.properties,
                },
            ));
        }
        let edge_range = NonZeroU64::new(relations.len() as u64)
            .map(|count| self.graph_identity.allocate_edge_ids(count))
            .transpose()?;
        let mut edge_ids = edge_range.into_iter().flat_map(|range| range.edge_ids());
        let mut edge_tokens = Vec::with_capacity(relations.len());
        for relation in relations {
            let source = endpoint(&relation.source_point_id)?;
            let target = endpoint(&relation.target_point_id)?;
            let namespace = relation_namespace(&source, &target, relation.scope, scope)?;
            let type_id = mutable
                .types()
                .resolve_name(&relation.edge_type)
                .ok_or_else(|| {
                    crate::graph::GraphError::new(
                        crate::graph::GraphErrorCode::TypeNotFound,
                        format!("edge type '{}' is not configured", relation.edge_type),
                    )
                })?;
            let edge_id = edge_ids
                .next()
                .expect("allocated the exact number of EdgeIds");
            edge_mutations.push(crate::graph::EdgeMutation::Relate(
                crate::graph::RelateMutation {
                    edge_id,
                    source: point_nids[&relation.source_point_id],
                    target: point_nids[&relation.target_point_id],
                    type_id,
                    namespace,
                    properties: relation.properties,
                },
            ));
            edge_tokens.push(crate::edge_token::encode(
                self.graph_database_id(),
                edge_id,
            )?);
        }
        debug_assert!(edge_ids.next().is_none());
        let mut point_mutations = staged_points
            .into_values()
            .map(|point| crate::wal::GraphPointMutation::Upsert { point })
            .collect::<Vec<_>>();
        point_mutations.extend(deleted_points.into_iter().map(|point_id| {
            crate::wal::GraphPointMutation::Delete {
                nid: point_nids[&point_id],
                point_id,
            }
        }));
        let batch = crate::wal::GraphBatch {
            graph_epoch,
            point_mutations,
            handle_assignments,
            edge_mutations,
            ..crate::wal::GraphBatch::default()
        };
        batch.validate()?;
        Ok((batch, edge_tokens))
    }

    /// Route an ordinary point UPSERT through GraphBatch while graph is
    /// enabled. Duplicate IDs retain the legacy last-write-wins result, but
    /// only the final value is encoded because GraphBatch forbids ambiguous
    /// repeated mutations inside one atomic request.
    pub(super) fn commit_graph_point_upserts_locked(
        &self,
        collection: &mut Collection,
        points: Vec<Point>,
        wait: bool,
    ) -> Result<GraphBatchCommitReceipt> {
        self.commit_graph_point_upserts_with_session_locked(collection, points, wait, None)
            .map(|(receipt, _)| receipt)
    }

    pub(super) fn commit_graph_point_upserts_with_session_locked(
        &self,
        collection: &mut Collection,
        points: Vec<Point>,
        wait: bool,
        deferred_session_id: Option<&str>,
    ) -> Result<(GraphBatchCommitReceipt, usize)> {
        self.commit_graph_point_upserts_with_security_locked(
            collection,
            points,
            wait,
            deferred_session_id,
            None,
            None,
        )
    }

    pub(super) fn commit_graph_point_upserts_with_security_locked(
        &self,
        collection: &mut Collection,
        points: Vec<Point>,
        wait: bool,
        deferred_session_id: Option<&str>,
        security: Option<crate::security::SecurityDelta>,
        decision: Option<(&crate::audit::AuditContext, &std::sync::atomic::AtomicBool)>,
    ) -> Result<(GraphBatchCommitReceipt, usize)> {
        debug_assert!(!points.is_empty());
        let mut seen = HashSet::with_capacity(points.len());
        let mut points = points
            .into_iter()
            .rev()
            .filter(|point| seen.insert(point.id.clone()))
            .collect::<Vec<_>>();
        points.reverse();

        let old_points = points
            .iter()
            .map(|point| {
                collection
                    .try_resolve(&point.id)
                    .map(|point| point.map(std::borrow::Cow::into_owned))
            })
            .collect::<Result<Vec<_>>>()?;
        let resolver = collection.graph_resolver.as_ref().ok_or_else(|| {
            GaussError::InvalidRequest(
                "enabled graph lifecycle has no point incarnation resolver".to_string(),
            )
        })?;
        let pending_bindings = if let Some(session_id) = deferred_session_id {
            let mutable = active_mutable_graph(collection)?;
            if !mutable.deferred_session_is_open(session_id) {
                return Err(crate::graph::GraphError::new(
                    crate::graph::GraphErrorCode::DeferredSessionNotFound,
                    "deferred graph session does not exist or is not open",
                )
                .into());
            }
            let opening_lsn = mutable
                .deferred_opening_lsn(session_id)
                .expect("validated deferred session has opening LSN");
            points
                .iter()
                .zip(&old_points)
                .filter(|(_, old_point)| old_point.is_none())
                .flat_map(|(point, _)| {
                    mutable
                        .pending_bindings(&point.id, session_id, opening_lsn)
                        .into_iter()
                        .map(|(edge_id, endpoint)| (point.id.clone(), edge_id, endpoint))
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        if pending_bindings.len() > crate::graph::MAX_GRAPH_EDGES_PER_BATCH {
            return Err(GaussError::InvalidRequest(format!(
                "{} deferred endpoint binds exceed fixed limit {}",
                pending_bindings.len(),
                crate::graph::MAX_GRAPH_EDGES_PER_BATCH
            )));
        }
        let missing = points
            .iter()
            .filter(|point| resolver.live_nid(&point.id).is_none())
            .map(|point| point.id.clone())
            .collect::<Vec<_>>();
        let handle_assignments = if let Some(count) = NonZeroU64::new(missing.len() as u64) {
            missing
                .into_iter()
                .zip(self.graph_identity.allocate_nids(count)?.nids())
                .map(|(point_id, nid)| crate::wal::GraphHandleAssignment { point_id, nid })
                .collect()
        } else {
            Vec::new()
        };
        let assigned_nids = handle_assignments
            .iter()
            .map(|assignment| (assignment.point_id.as_str(), assignment.nid))
            .collect::<HashMap<_, _>>();
        let edge_binds = pending_bindings
            .iter()
            .map(|(point_id, edge_id, endpoint)| {
                Ok(crate::wal::GraphEdgeBind {
                    session_id: deferred_session_id
                        .expect("pending binds require deferred session")
                        .to_string(),
                    edge_id: *edge_id,
                    endpoint: *endpoint,
                    point_id: point_id.clone(),
                    nid: assigned_nids.get(point_id.as_str()).copied().ok_or_else(|| {
                        GaussError::InvalidRequest(
                            "deferred endpoint must be created as a fresh incarnation in its session"
                                .to_string(),
                        )
                    })?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let graph_epoch = collection
            .graph_lifecycle
            .epoch()
            .expect("enabled graph lifecycle has an epoch");
        let h2qg_present_before = collection.streamer.hnsw.is_some();
        let rabitq_present_before = collection.rabitq.is_some();
        let vamana_present_before = collection.vamana.is_some();
        let ivf_present_before = collection.ivf.is_some();
        let vector_dim = collection.config.vector_dim;
        let receipt = self.commit_graph_batch_security_locked(
            collection,
            crate::wal::GraphBatch {
                graph_epoch,
                point_mutations: points
                    .iter()
                    .cloned()
                    .map(|point| crate::wal::GraphPointMutation::Upsert { point })
                    .collect(),
                handle_assignments,
                edge_binds,
                ..crate::wal::GraphBatch::default()
            },
            wait,
            security,
            decision,
        )?;

        for (point, old_point) in points.iter().zip(old_points) {
            if let Some(old_point) = old_point {
                remove_sparse_point(&mut collection.sparse_index, &old_point);
            }
            insert_sparse_point(&mut collection.sparse_index, point);
            if h2qg_present_before
                && let Some(h2qg) = collection.streamer.hnsw.as_mut()
                && !h2qg.contains(&point.id)
            {
                let _ = h2qg.insert_point(point, vector_dim);
            }
            if rabitq_present_before && let Some(index) = collection.rabitq.as_mut() {
                use crate::index::IndexBackend;
                if !IndexBackend::contains(index, &point.id) {
                    let _ = IndexBackend::insert_point(index, point, vector_dim);
                }
            }
            if vamana_present_before && let Some(index) = collection.vamana.as_mut() {
                use crate::index::IndexBackend;
                if !IndexBackend::contains(index, &point.id) {
                    let _ = IndexBackend::insert_point(index, point, vector_dim);
                }
            }
            if ivf_present_before && let Some(index) = collection.ivf.as_mut() {
                use crate::index::IndexBackend;
                if !IndexBackend::contains(index, &point.id) {
                    let _ = IndexBackend::insert_point(index, point, vector_dim);
                }
            }
        }
        collection.hnsw_dirty = true;
        Ok((receipt, pending_bindings.len()))
    }

    /// Retire every currently live requested point through one GraphBatch.
    /// Missing and duplicate IDs keep the legacy idempotent delete result and
    /// therefore do not create invalid duplicate/missing graph mutations.
    pub(super) fn validate_graph_delete_ack_locked(
        collection: &Collection,
        ids: &[String],
        acknowledged: bool,
    ) -> Result<()> {
        if acknowledged || !collection.graph_lifecycle.is_enabled() {
            return Ok(());
        }
        let mutable = active_mutable_graph(collection)?;
        let resolver = collection
            .graph_resolver
            .as_ref()
            .ok_or_else(|| GaussError::InvalidRequest("graph resolver is unavailable".into()))?;
        for id in ids {
            if let (Some(nid), Some(point)) = (resolver.live_nid(id), collection.try_resolve(id)?) {
                let tenant = point
                    .payload
                    .get(crate::tenant::TENANT_FIELD)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(DEFAULT_GRAPH_NAMESPACE);
                if mutable.live_incident_edge_ids(nid, tenant, resolver)?.len()
                    > GRAPH_DELETE_ACK_DEGREE_THRESHOLD
                {
                    return Err(crate::graph::GraphError::new(
                        crate::graph::GraphErrorCode::EdgesExist,
                        "point deletion requires the WITH EDGES acknowledgement",
                    )
                    .into());
                }
            }
        }
        Ok(())
    }

    pub(super) fn commit_graph_point_deletes_locked(
        &self,
        collection: &mut Collection,
        ids: &[String],
        with_edges_acknowledged: bool,
    ) -> Result<(Option<GraphBatchCommitReceipt>, usize, usize)> {
        self.commit_graph_point_deletes_with_security_locked(
            collection,
            ids,
            with_edges_acknowledged,
            None,
            None,
        )
    }

    pub(super) fn commit_graph_point_deletes_with_security_locked(
        &self,
        collection: &mut Collection,
        ids: &[String],
        with_edges_acknowledged: bool,
        security: Option<crate::security::SecurityDelta>,
        decision: Option<(&crate::audit::AuditContext, &std::sync::atomic::AtomicBool)>,
    ) -> Result<(Option<GraphBatchCommitReceipt>, usize, usize)> {
        Self::validate_graph_delete_ack_locked(collection, ids, with_edges_acknowledged)?;
        let mut seen = HashSet::with_capacity(ids.len());
        let live_ids = ids
            .iter()
            .filter(|id| seen.insert((*id).clone()) && collection.id_index.contains_key(*id))
            .cloned()
            .collect::<Vec<_>>();
        if live_ids.is_empty() {
            return Ok((None, 0, 0));
        }

        let old_points = live_ids
            .iter()
            .filter_map(|id| collection.try_resolve(id).transpose())
            .map(|point| point.map(std::borrow::Cow::into_owned))
            .collect::<Result<Vec<_>>>()?;
        if old_points.len() != live_ids.len() {
            return Err(GaussError::InvalidRequest(
                "live point index could not resolve every graph delete".to_string(),
            ));
        }
        let resolver = collection.graph_resolver.as_ref().ok_or_else(|| {
            GaussError::InvalidRequest(
                "enabled graph lifecycle has no point incarnation resolver".to_string(),
            )
        })?;
        let current_nids = live_ids
            .iter()
            .map(|id| resolver.live_nid(id))
            .collect::<Vec<_>>();
        let mutable = active_mutable_graph(collection)?;
        let incident_by_node = current_nids
            .iter()
            .zip(&old_points)
            .filter_map(|(nid, point)| {
                nid.map(|nid| {
                    let tenant = point
                        .payload
                        .get(crate::tenant::TENANT_FIELD)
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or(DEFAULT_GRAPH_NAMESPACE);
                    mutable.live_incident_edge_ids(nid, tenant, resolver)
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let orphaned_edges = incident_by_node
            .into_iter()
            .flatten()
            .collect::<HashSet<_>>()
            .len();
        let missing_count = current_nids.iter().filter(|nid| nid.is_none()).count();
        let mut allocated = NonZeroU64::new(missing_count as u64)
            .map(|count| self.graph_identity.allocate_nids(count))
            .transpose()?
            .into_iter()
            .flat_map(|range| range.nids());
        let mut handle_assignments = Vec::with_capacity(missing_count);
        let mut mutations = Vec::with_capacity(live_ids.len());
        for (point_id, current_nid) in live_ids.iter().cloned().zip(current_nids) {
            let nid = match current_nid {
                Some(nid) => nid,
                None => {
                    let nid = allocated.next().expect("allocated exact missing Nid count");
                    handle_assignments.push(crate::wal::GraphHandleAssignment {
                        point_id: point_id.clone(),
                        nid,
                    });
                    nid
                }
            };
            mutations.push(crate::wal::GraphPointMutation::Delete { point_id, nid });
        }
        debug_assert!(allocated.next().is_none());
        let graph_epoch = collection
            .graph_lifecycle
            .epoch()
            .expect("enabled graph lifecycle has an epoch");
        let receipt = self.commit_graph_batch_security_locked(
            collection,
            crate::wal::GraphBatch {
                graph_epoch,
                point_mutations: mutations,
                handle_assignments,
                ..crate::wal::GraphBatch::default()
            },
            true,
            security,
            decision,
        )?;

        for point in &old_points {
            remove_sparse_point(&mut collection.sparse_index, point);
            if let Some(h2qg) = collection.streamer.hnsw.as_mut() {
                h2qg.remove_from_indexed(&point.id);
            }
            for named in collection.streamer.named_hnsw.values_mut() {
                named.remove_from_indexed(&point.id);
            }
        }
        collection.hnsw_dirty = true;
        Ok((Some(receipt), live_ids.len(), orphaned_edges))
    }

    pub fn traverse_scoped(
        &self,
        collection_name: &str,
        request: crate::graph::GraphTraverseRequest,
        scope: &crate::tenant::TenantScope,
    ) -> Result<crate::graph::GraphTraversalResult> {
        self.traverse_cancellable_scoped(
            collection_name,
            request,
            scope,
            self.build_lifecycle.cancellation(),
        )
    }

    /// Traverse a protected graph using physical storage identities internally
    /// and expose only public identities authorized by the bound policy
    /// snapshot. Node filters use Query-authorized payload projection. Edge
    /// properties inherit GraphRead visibility from both endpoints.
    pub fn traverse_authorized(
        &self,
        context: &crate::security::AccessContext,
        request: crate::graph::GraphTraverseRequest,
        cancelled: &AtomicBool,
    ) -> Result<crate::security::AuthorizedOutput<crate::graph::GraphTraversalResult>> {
        self.traverse_query_authorized(
            context,
            crate::graph::GraphTraversalQueryRequest {
                traversal: request,
                returns: crate::graph::GraphTraversalReturn::Nodes,
                limit: None,
                with_payload: false,
            },
            cancelled,
        )?
        .map(|result| {
            let crate::graph::GraphTraversalRows::Nodes(nodes) = result.result else {
                unreachable!("node materialization requested")
            };
            crate::graph::GraphTraversalResult {
                nodes: nodes
                    .into_iter()
                    .map(|node| crate::graph::GraphTraversalNode {
                        point_id: node.id,
                        depth: node.depth,
                    })
                    .collect(),
                stats: result.stats,
                truncation: result.truncation,
                warnings: result.warnings,
                graph_epoch: result.graph_epoch,
            }
        })
    }

    /// Protected nodes, edges and simple paths share endpoint visibility,
    /// field projection, admission, cancellation and publication fencing.
    pub fn traverse_query_authorized(
        &self,
        context: &crate::security::AccessContext,
        mut query: crate::graph::GraphTraversalQueryRequest,
        cancelled: &AtomicBool,
    ) -> Result<crate::security::AuthorizedOutput<crate::graph::GraphTraversalQueryResult>> {
        if context.action() != crate::security::Action::GraphRead {
            return Err(crate::security::SecurityError::Forbidden.into());
        }
        if query.returns == crate::graph::GraphTraversalReturn::Paths && query.limit.is_none() {
            return Err(GaussError::InvalidRequest(
                "graph path traversal requires an explicit limit".into(),
            ));
        }
        let request = &mut query.traversal;
        validate_traversal_request(request)?;
        // Validate protected predicate syntax and encoded size before admission.
        for filter in [request.node_filter.as_ref(), request.edge_filter.as_ref()]
            .into_iter()
            .flatten()
        {
            crate::security::SecurityFilter::compile(filter.clone())?;
        }
        request.budget.max_time_ms = request.budget.max_time_ms.min(30_000);
        request.budget = crate::graph_admission::resolve_default_memory(request.budget);
        context.publication_permit()?;
        for anchor in &mut request.anchors {
            *anchor = context.authorize(anchor)?.storage_id.to_string();
        }
        let budget = request.budget.validate()?;
        let coll = self.get_coll_authorized(context)?;
        {
            let collection = coll.read();
            active_mutable_graph(&collection)?;
        }
        // Protected storage derives tenancy from the authority binding rather
        // than the legacy payload tenant stamp. Resource authorization below
        // remains the only visibility filter for this path.
        let scope = crate::tenant::TenantScope::system();
        let _permit =
            crate::graph_admission::acquire(context.collection(), &scope, budget, cancelled)?;
        // Keep response hydration within the same admitted reservation while
        // traversal retains its captured visits/edges/paths. Charge before
        // cloning JSON; the 64x estimate includes tree/map/string overhead.
        let output_limit = (budget.max_memory_bytes / 4).min(64 * 1024 * 1024);
        query.traversal.budget.max_memory_bytes = budget.max_memory_bytes - output_limit;
        let _lifecycle = self.lifecycle_gate.read();
        let collection = coll.read();
        let visibility = collection.overlay_read_state();
        let result = super::graph_retrieval::traverse_query_locked(
            &collection,
            &visibility,
            &query,
            &scope,
            self.tenant_enforcement(),
            cancelled,
            super::graph_retrieval::GraphQueryIdentity {
                database_id: self.graph_database_id(),
                authorization: Some(context),
                output_limit,
                output_bytes: Default::default(),
            },
        )?;
        context.publication_permit()?;
        crate::security::storage::serialized_len(&result, 8 * 1024 * 1024)?;
        Ok(crate::security::AuthorizedOutput::new(
            context.clone(),
            result,
        ))
    }

    /// Exact mutable-graph BFS with request-timeout/client-disconnect
    /// cancellation. Admission is acquired before the collection read lock;
    /// G0 then pins that lock for the complete traversal snapshot.
    pub fn traverse_cancellable_scoped(
        &self,
        collection_name: &str,
        mut request: crate::graph::GraphTraverseRequest,
        scope: &crate::tenant::TenantScope,
        cancelled: &AtomicBool,
    ) -> Result<crate::graph::GraphTraversalResult> {
        request.budget = crate::graph_admission::resolve_default_memory(request.budget);
        validate_traversal_request(&request)?;
        let budget = request.budget.validate()?;
        let coll = self.get_coll(collection_name)?;
        {
            let collection = coll.read();
            active_mutable_graph(&collection)?;
        }
        let _permit = crate::graph_admission::acquire(collection_name, scope, budget, cancelled)?;
        let _lifecycle = self.lifecycle_gate.read();
        let collection = coll.read();
        let enforcement = self.tenant_enforcement();
        let visibility = collection.overlay_read_state();
        let expansion = super::graph_retrieval::expand_constraint_locked(
            &collection,
            &visibility,
            &request,
            None,
            scope,
            enforcement,
            cancelled,
        )?;
        let mut warnings = Vec::new();
        if expansion.traversal.truncation.is_some() {
            warnings.push(crate::graph::GraphWarning::ResultTruncated);
        }
        if expansion.backfill_pending {
            warnings.push(crate::graph::GraphWarning::HandleBackfillInProgress);
        }
        crate::observability::observe_graph_traversal(
            &expansion.traversal.stats,
            expansion.traversal.truncation,
        );
        Ok(crate::graph::GraphTraversalResult {
            nodes: expansion.nodes,
            stats: expansion.traversal.stats,
            truncation: expansion.traversal.truncation,
            warnings,
            graph_epoch: expansion.graph_epoch,
        })
    }

    pub fn traverse_query_scoped(
        &self,
        collection_name: &str,
        request: crate::graph::GraphTraversalQueryRequest,
        scope: &crate::tenant::TenantScope,
    ) -> Result<crate::graph::GraphTraversalQueryResult> {
        self.traverse_query_cancellable_scoped(
            collection_name,
            request,
            scope,
            self.build_lifecycle.cancellation(),
        )
    }

    /// Exact pure traversal with one pinned vector/graph read state for all
    /// three materialization shapes.
    pub fn traverse_query_cancellable_scoped(
        &self,
        collection_name: &str,
        mut request: crate::graph::GraphTraversalQueryRequest,
        scope: &crate::tenant::TenantScope,
        cancelled: &AtomicBool,
    ) -> Result<crate::graph::GraphTraversalQueryResult> {
        request.traversal.budget =
            crate::graph_admission::resolve_default_memory(request.traversal.budget);
        validate_traversal_request(&request.traversal)?;
        if request.returns == crate::graph::GraphTraversalReturn::Paths && request.limit.is_none() {
            return Err(GaussError::InvalidRequest(
                "graph path traversal requires an explicit limit".to_string(),
            ));
        }
        let budget = request.traversal.budget.validate()?;
        let coll = self.get_coll(collection_name)?;
        {
            let collection = coll.read();
            active_mutable_graph(&collection)?;
        }
        let _permit = crate::graph_admission::acquire(collection_name, scope, budget, cancelled)?;
        let _lifecycle = self.lifecycle_gate.read();
        let collection = coll.read();
        let enforcement = self.tenant_enforcement();
        let visibility = collection.overlay_read_state();
        super::graph_retrieval::traverse_query_locked(
            &collection,
            &visibility,
            &request,
            scope,
            enforcement,
            cancelled,
            super::graph_retrieval::GraphQueryIdentity {
                database_id: self.graph_database_id(),
                authorization: None,
                output_limit: 0,
                output_bytes: Default::default(),
            },
        )
    }

    /// Return collection-global edge types without exposing internal TypeId.
    pub fn list_edge_types_scoped(
        &self,
        collection_name: &str,
        _scope: &crate::tenant::TenantScope,
    ) -> Result<Vec<crate::graph::GraphEdgeType>> {
        let _lifecycle = self.lifecycle_gate.read();
        let coll = self.get_coll(collection_name)?;
        let collection = coll.read();
        let mutable = active_mutable_graph(&collection)?;
        Ok(mutable
            .types()
            .definitions()
            .map(|definition| crate::graph::GraphEdgeType {
                name: definition.name.clone(),
                weight_property: definition.weight_property.clone(),
            })
            .collect())
    }

    /// Open one explicit deferred bulk-load window. The generated session
    /// token is public, while its opening LSN remains durable mutable state.
    pub fn open_deferred_graph_session_scoped(
        &self,
        collection_name: &str,
        wait: bool,
        scope: &crate::tenant::TenantScope,
    ) -> Result<crate::graph::GraphDeferredSessionResult> {
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let audit_operation = self.audit_operation_with_context(
            "graph_deferred_open",
            Some(collection_name),
            audit_context(scope),
        )?;
        let coll = self.get_coll(collection_name)?;
        let mut collection = coll.write();
        let mutable = active_mutable_graph(&collection)?;
        let graph_epoch = mutable.epoch();
        let session_id = loop {
            let candidate = uuid::Uuid::new_v4().simple().to_string();
            if mutable.deferred_opening_lsn(&candidate).is_none() {
                break candidate;
            }
        };
        let receipt = self.commit_graph_batch_locked(
            &mut collection,
            crate::wal::GraphBatch {
                graph_epoch,
                deferred_sessions: vec![crate::wal::GraphDeferredSessionMutation::Open {
                    session_id: session_id.clone(),
                    owner: Some(scope.session_owner()),
                }],
                ..crate::wal::GraphBatch::default()
            },
            wait,
        )?;
        let receipt = public_receipt(receipt, false);
        drop(collection);
        self.finish_committed_legacy_audit(
            audit_operation,
            serde_json::json!({
                "graph_epoch": receipt.graph_epoch.raw(),
                "operation_lsn": receipt.operation_lsn,
                "wait": wait,
                "state": "open",
            }),
        );
        self.refresh_metrics();
        Ok(crate::graph::GraphDeferredSessionResult {
            session_id: crate::graph::GraphDeferredSessionId::from_encoded(session_id),
            state: crate::graph::GraphDeferredSessionState::Open,
            receipt,
        })
    }

    /// Create or update points inside an explicit deferred window. Only a
    /// fresh absent->present transition in this call may emit EdgeBind rows.
    pub fn upsert_deferred_scoped(
        &self,
        collection_name: &str,
        session_id: &crate::graph::GraphDeferredSessionId,
        mut points: Vec<Point>,
        wait: bool,
        scope: &crate::tenant::TenantScope,
    ) -> Result<crate::graph::GraphDeferredUpsertResult> {
        validate_deferred_session_id(session_id)?;
        if points.is_empty() {
            return Err(GaussError::InvalidRequest(
                "deferred graph UPSERT requires at least one point".to_string(),
            ));
        }
        let enforcement = self.tenant_enforcement();
        for point in &mut points {
            scope.stamp_payload(enforcement, &mut point.payload)?;
        }
        let receipt = self.upsert_wait_unguarded(
            collection_name,
            points,
            wait,
            super::MutationContext::scoped(scope),
            None,
            Some(session_id),
        )?;
        let graph_epoch = receipt.graph_epoch.ok_or_else(|| {
            crate::graph::GraphError::new(
                crate::graph::GraphErrorCode::GraphDisabled,
                "graph is not enabled for this collection",
            )
        })?;
        Ok(crate::graph::GraphDeferredUpsertResult {
            total_points: receipt.total,
            bound_endpoints: receipt.graph_bound_endpoints,
            receipt: crate::graph::GraphMutationReceipt {
                graph_epoch,
                operation_lsn: Some(receipt.operation_lsn),
                durable: true,
                replayed: false,
            },
        })
    }

    /// Explicit deferred RELATE. Present endpoints bind immediately; absent
    /// endpoints stay invisible until a session-aware UPSERT creates them.
    pub fn relate_deferred_scoped(
        &self,
        collection_name: &str,
        session_id: &crate::graph::GraphDeferredSessionId,
        request: crate::graph::RelateRequest,
        wait: bool,
        scope: &crate::tenant::TenantScope,
    ) -> Result<crate::graph::RelateResult> {
        validate_deferred_session_id(session_id)?;
        validate_public_graph_key("source point ID", &request.source_point_id)?;
        validate_public_graph_key("target point ID", &request.target_point_id)?;
        validate_public_catalog_name("edge type", &request.edge_type)?;
        if let Some(key) = request.idempotency_key.as_deref() {
            validate_public_graph_key("idempotency key", key)?;
        }
        validate_public_properties(&request.properties)?;
        let request_sha256: [u8; 32] =
            Sha256::digest(serde_json::to_vec(&(session_id, &request))?).into();

        let scoped_key = request
            .idempotency_key
            .as_deref()
            .map(|key| scoped_idempotency_key(scope, collection_name, "deferred_relate", key))
            .transpose()?;

        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let audit_operation = self.audit_operation_with_context(
            "graph_deferred_relate",
            Some(collection_name),
            audit_context(scope),
        )?;
        let coll = self.get_coll(collection_name)?;
        let mut collection = coll.write();
        let graph_epoch = active_mutable_graph(&collection)?.epoch();

        active_mutable_graph(&collection)?.authorize_deferred_owner(session_id.as_str(), scope)?;
        let enforcement = self.tenant_enforcement();
        let source = resolve_graph_endpoint_optional(
            &collection,
            &request.source_point_id,
            scope,
            enforcement,
        )?;
        let target = resolve_graph_endpoint_optional(
            &collection,
            &request.target_point_id,
            scope,
            enforcement,
        )?;
        deferred_relation_namespace(source.as_ref(), target.as_ref(), request.scope, scope)?;
        if let Some(key) = scoped_key.as_deref()
            && let Some(existing) = active_mutable_graph(&collection)?.idempotency(key)
        {
            if current_unix_ms()? >= existing.expires_at_unix_ms {
                return Err(GaussError::InvalidRequest(
                    "idempotency result expired".into(),
                ));
            }
            if existing.request_sha256 != request_sha256 {
                return Err(GaussError::InvalidRequest(format!(
                    "idempotency key '{key}' is already bound to another graph request in epoch {}",
                    graph_epoch.raw()
                )));
            }
            let [edge_id] = existing.edge_ids.as_slice() else {
                return Err(GaussError::InvalidRequest(
                    "durable deferred RELATE idempotency result is not singular".to_string(),
                ));
            };
            let mutable = active_mutable_graph(&collection)?;
            let namespace = mutable
                .edge_namespace(*edge_id)?
                .or_else(|| mutable.pending_edge_namespace(*edge_id, session_id.as_str()))
                .ok_or_else(edge_not_found)?;
            authorize_edge_mutation(namespace, scope, enforcement)?;
            if wait && let Err(error) = collection.wal.sync() {
                self.mark_durability_degraded("graph_deferred_relate_retry_sync", &error);
                return Err(error);
            }
            let edge_id = crate::edge_token::encode(self.graph_database_id(), *edge_id)?;
            let receipt = crate::graph::GraphMutationReceipt {
                graph_epoch,
                operation_lsn: None,
                durable: wait,
                replayed: true,
            };
            drop(collection);
            self.finish_committed_legacy_audit(
                audit_operation,
                serde_json::json!({
                        "graph_epoch": graph_epoch.raw(),
                        "operation_lsn": null,
                        "wait": wait,
                        "edge_count": 1,
                        "idempotency_replay": true,
                }),
            );
            self.refresh_metrics();
            return Ok(crate::graph::RelateResult { edge_id, receipt });
        }

        let mutable = active_mutable_graph(&collection)?;
        if !mutable.deferred_session_is_open(session_id.as_str()) {
            return Err(deferred_session_not_found());
        }
        let type_id = mutable
            .types()
            .resolve_name(&request.edge_type)
            .ok_or_else(|| {
                crate::graph::GraphError::new(
                    crate::graph::GraphErrorCode::TypeNotFound,
                    format!("edge type '{}' is not configured", request.edge_type),
                )
            })?;
        let namespace =
            deferred_relation_namespace(source.as_ref(), target.as_ref(), request.scope, scope)?;

        let resolver = collection.graph_resolver.as_ref().ok_or_else(|| {
            GaussError::InvalidRequest(
                "enabled graph lifecycle has no point incarnation resolver".to_string(),
            )
        })?;
        let mut endpoint_nids = HashMap::with_capacity(2);
        for (point_id, exists) in [
            (&request.source_point_id, source.is_some()),
            (&request.target_point_id, target.is_some()),
        ] {
            if exists && !endpoint_nids.contains_key(point_id) {
                endpoint_nids.insert(point_id.clone(), resolver.live_nid(point_id));
            }
        }
        let missing_handles = endpoint_nids.values().filter(|nid| nid.is_none()).count();
        let mut allocated = NonZeroU64::new(missing_handles as u64)
            .map(|count| self.graph_identity.allocate_nids(count))
            .transpose()?
            .into_iter()
            .flat_map(|range| range.nids());
        let mut handle_assignments = Vec::with_capacity(missing_handles);
        for (point_id, nid) in &mut endpoint_nids {
            if nid.is_none() {
                let allocated_nid = allocated
                    .next()
                    .expect("allocated exact endpoint Nid count");
                *nid = Some(allocated_nid);
                handle_assignments.push(crate::wal::GraphHandleAssignment {
                    point_id: point_id.clone(),
                    nid: allocated_nid,
                });
            }
        }
        debug_assert!(allocated.next().is_none());
        let source_nid = endpoint_nids
            .get(&request.source_point_id)
            .copied()
            .flatten();
        let target_nid = endpoint_nids
            .get(&request.target_point_id)
            .copied()
            .flatten();
        let edge_id = self
            .graph_identity
            .allocate_edge_ids(NonZeroU64::new(1).expect("one edge is non-zero"))?
            .edge_ids()
            .next()
            .expect("one EdgeId was allocated");
        let idempotency = if let Some(key) = scoped_key.as_ref() {
            let now = current_unix_ms()?;
            Some(crate::wal::GraphIdempotencyState {
                key: key.clone(),
                request_sha256,
                created_at_unix_ms: now,
                expires_at_unix_ms: now.checked_add(GRAPH_IDEMPOTENCY_TTL_MS).ok_or_else(|| {
                    GaussError::InvalidRequest("idempotency expiry overflow".to_string())
                })?,
                edge_ids: vec![edge_id],
            })
        } else {
            None
        };
        let pending_endpoints =
            usize::from(source_nid.is_none()) + usize::from(target_nid.is_none());
        let receipt = self.commit_graph_batch_locked(
            &mut collection,
            crate::wal::GraphBatch {
                graph_epoch,
                handle_assignments,
                deferred_binds: vec![crate::wal::GraphDeferredBind {
                    session_id: session_id.as_str().to_string(),
                    edge_id,
                    source_point_id: request.source_point_id,
                    target_point_id: request.target_point_id,
                    source_nid,
                    target_nid,
                    type_id,
                    namespace,
                    properties: request.properties,
                }],
                idempotency,
                ..crate::wal::GraphBatch::default()
            },
            wait,
        )?;
        let receipt = public_receipt(receipt, false);
        let edge_id = crate::edge_token::encode(self.graph_database_id(), edge_id)?;
        drop(collection);
        self.finish_committed_legacy_audit(
            audit_operation,
            serde_json::json!({
                "graph_epoch": receipt.graph_epoch.raw(),
                "operation_lsn": receipt.operation_lsn,
                "wait": wait,
                "edge_count": 1,
                "pending_endpoints": pending_endpoints,
                "idempotency_key_present": request.idempotency_key.is_some(),
                "idempotency_replay": false,
            }),
        );
        self.refresh_metrics();
        Ok(crate::graph::RelateResult { edge_id, receipt })
    }

    pub fn commit_deferred_graph_session_scoped(
        &self,
        collection_name: &str,
        session_id: &crate::graph::GraphDeferredSessionId,
        wait: bool,
        scope: &crate::tenant::TenantScope,
    ) -> Result<crate::graph::GraphDeferredSessionResult> {
        self.finish_deferred_graph_session_scoped(
            collection_name,
            session_id,
            crate::graph::GraphDeferredSessionState::Committed,
            wait,
            scope,
        )
    }

    pub fn abort_deferred_graph_session_scoped(
        &self,
        collection_name: &str,
        session_id: &crate::graph::GraphDeferredSessionId,
        wait: bool,
        scope: &crate::tenant::TenantScope,
    ) -> Result<crate::graph::GraphDeferredSessionResult> {
        self.finish_deferred_graph_session_scoped(
            collection_name,
            session_id,
            crate::graph::GraphDeferredSessionState::Aborted,
            wait,
            scope,
        )
    }

    fn finish_deferred_graph_session_scoped(
        &self,
        collection_name: &str,
        session_id: &crate::graph::GraphDeferredSessionId,
        target: crate::graph::GraphDeferredSessionState,
        wait: bool,
        scope: &crate::tenant::TenantScope,
    ) -> Result<crate::graph::GraphDeferredSessionResult> {
        validate_deferred_session_id(session_id)?;
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let audit_name = match target {
            crate::graph::GraphDeferredSessionState::Committed => "graph_deferred_commit",
            crate::graph::GraphDeferredSessionState::Aborted => "graph_deferred_abort",
            crate::graph::GraphDeferredSessionState::Open => {
                return Err(GaussError::InvalidRequest(
                    "open is not a deferred-session terminal state".to_string(),
                ));
            }
        };
        let audit_operation = self.audit_operation_with_context(
            audit_name,
            Some(collection_name),
            audit_context(scope),
        )?;
        let coll = self.get_coll(collection_name)?;
        let mut collection = coll.write();
        let mutable = active_mutable_graph(&collection)?;
        let graph_epoch = mutable.epoch();
        mutable.authorize_deferred_owner(session_id.as_str(), scope)?;
        let already_target = match target {
            crate::graph::GraphDeferredSessionState::Committed => {
                mutable.deferred_session_is_committed(session_id.as_str())
            }
            crate::graph::GraphDeferredSessionState::Aborted => {
                mutable.deferred_session_is_aborted(session_id.as_str())
            }
            crate::graph::GraphDeferredSessionState::Open => false,
        };
        let session_exists = mutable.deferred_opening_lsn(session_id.as_str()).is_some();
        if !session_exists {
            return Err(deferred_session_not_found());
        }
        if already_target {
            if wait && let Err(error) = collection.wal.sync() {
                self.mark_durability_degraded("graph_deferred_retry_sync", &error);
                return Err(error);
            }
            let receipt = crate::graph::GraphMutationReceipt {
                graph_epoch,
                operation_lsn: None,
                durable: wait,
                replayed: true,
            };
            drop(collection);
            self.finish_committed_legacy_audit(
                audit_operation,
                serde_json::json!({
                        "graph_epoch": graph_epoch.raw(),
                        "operation_lsn": null,
                        "wait": wait,
                        "state": target,
                        "replayed": true,
                }),
            );
            self.refresh_metrics();
            return Ok(crate::graph::GraphDeferredSessionResult {
                session_id: session_id.clone(),
                state: target,
                receipt,
            });
        }
        if !mutable.deferred_session_is_open(session_id.as_str()) {
            return Err(GaussError::InvalidRequest(
                "deferred graph session is already in another terminal state".to_string(),
            ));
        }
        let pending_edges = mutable.pending_edge_count_for_session(session_id.as_str());
        let session_mutation = match target {
            crate::graph::GraphDeferredSessionState::Committed => {
                crate::wal::GraphDeferredSessionMutation::Commit {
                    session_id: session_id.as_str().to_string(),
                }
            }
            crate::graph::GraphDeferredSessionState::Aborted => {
                crate::wal::GraphDeferredSessionMutation::Abort {
                    session_id: session_id.as_str().to_string(),
                }
            }
            crate::graph::GraphDeferredSessionState::Open => unreachable!(),
        };
        let receipt = self.commit_graph_batch_locked(
            &mut collection,
            crate::wal::GraphBatch {
                graph_epoch,
                deferred_sessions: vec![session_mutation],
                ..crate::wal::GraphBatch::default()
            },
            wait,
        )?;
        let receipt = public_receipt(receipt, false);
        drop(collection);
        self.finish_committed_legacy_audit(
            audit_operation,
            serde_json::json!({
                "graph_epoch": receipt.graph_epoch.raw(),
                "operation_lsn": receipt.operation_lsn,
                "wait": wait,
                "state": target,
                "pending_edges_before": pending_edges,
                "replayed": false,
            }),
        );
        self.refresh_metrics();
        Ok(crate::graph::GraphDeferredSessionResult {
            session_id: session_id.clone(),
            state: target,
            receipt,
        })
    }

    /// Configure one collection-global edge type through a single GraphBatch.
    /// The public contract is name-based; TypeId never leaves the core.
    pub fn configure_edge_type_scoped(
        &self,
        collection_name: &str,
        request: crate::graph::ConfigureEdgeTypeRequest,
        wait: bool,
        scope: &crate::tenant::TenantScope,
    ) -> Result<crate::graph::ConfigureEdgeTypeResult> {
        validate_public_catalog_name("edge type", &request.name)?;
        if let Some(weight_property) = request.weight_property.as_deref() {
            validate_public_catalog_name("weight property", weight_property)?;
        }
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let audit_operation = self.audit_operation_with_context(
            "graph_type_configure",
            Some(collection_name),
            audit_context(scope),
        )?;
        let coll = self.get_coll(collection_name)?;
        let mut collection = coll.write();
        let mutable = active_mutable_graph(&collection)?;
        let graph_epoch = mutable.epoch();
        let type_id = mutable
            .types()
            .resolve_name(&request.name)
            .map_or_else(|| mutable.types().next_type_id(), Ok)?;
        let unchanged = mutable.types().get(type_id).is_some_and(|existing| {
            existing.name == request.name && existing.weight_property == request.weight_property
        });
        let receipt = if unchanged {
            if wait && let Err(error) = collection.wal.sync() {
                self.mark_durability_degraded("graph_type_sync", &error);
                return Err(error);
            }
            crate::graph::GraphMutationReceipt {
                graph_epoch,
                operation_lsn: None,
                durable: wait,
                replayed: true,
            }
        } else {
            let receipt = self.commit_graph_batch_locked(
                &mut collection,
                crate::wal::GraphBatch {
                    graph_epoch,
                    type_configurations: vec![crate::wal::GraphTypeConfiguration {
                        type_id,
                        name: request.name.clone(),
                        weight_property: request.weight_property.clone(),
                    }],
                    ..crate::wal::GraphBatch::default()
                },
                wait,
            )?;
            public_receipt(receipt, false)
        };
        drop(collection);
        self.finish_committed_legacy_audit(
            audit_operation,
            serde_json::json!({
                "graph_epoch": receipt.graph_epoch.raw(),
                "operation_lsn": receipt.operation_lsn,
                "wait": wait,
                "changed": !unchanged,
            }),
        );
        self.refresh_metrics();
        Ok(crate::graph::ConfigureEdgeTypeResult {
            edge_type: crate::graph::GraphEdgeType {
                name: request.name,
                weight_property: request.weight_property,
            },
            receipt,
            changed: !unchanged,
        })
    }

    /// Create one strict-endpoint edge and return only its opaque token.
    pub fn relate_scoped(
        &self,
        collection_name: &str,
        request: crate::graph::RelateRequest,
        wait: bool,
        scope: &crate::tenant::TenantScope,
    ) -> Result<crate::graph::RelateResult> {
        validate_public_graph_key("source point ID", &request.source_point_id)?;
        validate_public_graph_key("target point ID", &request.target_point_id)?;
        validate_public_catalog_name("edge type", &request.edge_type)?;
        if let Some(key) = request.idempotency_key.as_deref() {
            validate_public_graph_key("idempotency key", key)?;
        }
        validate_public_properties(&request.properties)?;
        let request_sha256: [u8; 32] = Sha256::digest(serde_json::to_vec(&request)?).into();

        let scoped_key = request
            .idempotency_key
            .as_deref()
            .map(|key| scoped_idempotency_key(scope, collection_name, "relate", key))
            .transpose()?;

        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let audit_operation = self.audit_operation_with_context(
            "graph_relate",
            Some(collection_name),
            audit_context(scope),
        )?;
        let coll = self.get_coll(collection_name)?;
        let mut collection = coll.write();
        let graph_epoch = active_mutable_graph(&collection)?.epoch();

        let enforcement = self.tenant_enforcement();
        let source =
            resolve_graph_endpoint(&collection, &request.source_point_id, scope, enforcement)?;
        let target =
            resolve_graph_endpoint(&collection, &request.target_point_id, scope, enforcement)?;
        relation_namespace(&source, &target, request.scope, scope)?;
        if let Some(key) = scoped_key.as_deref()
            && let Some(existing) = active_mutable_graph(&collection)?.idempotency(key)
        {
            if current_unix_ms()? >= existing.expires_at_unix_ms {
                return Err(GaussError::InvalidRequest(
                    "idempotency result expired".into(),
                ));
            }
            if existing.request_sha256 != request_sha256 {
                return Err(GaussError::InvalidRequest(format!(
                    "idempotency key '{key}' is already bound to another graph request in epoch {}",
                    graph_epoch.raw()
                )));
            }
            let [edge_id] = existing.edge_ids.as_slice() else {
                return Err(GaussError::InvalidRequest(
                    "durable RELATE idempotency result is not singular".to_string(),
                ));
            };
            let mutable = active_mutable_graph(&collection)?;
            let namespace = mutable
                .edge_namespace(*edge_id)?
                .ok_or_else(edge_not_found)?;
            authorize_edge_mutation(namespace, scope, enforcement)?;
            if wait && let Err(error) = collection.wal.sync() {
                self.mark_durability_degraded("graph_relate_retry_sync", &error);
                return Err(error);
            }
            let edge_id = crate::edge_token::encode(self.graph_database_id(), *edge_id)?;
            let receipt = crate::graph::GraphMutationReceipt {
                graph_epoch,
                operation_lsn: None,
                durable: wait,
                replayed: true,
            };
            drop(collection);
            self.finish_committed_legacy_audit(
                audit_operation,
                serde_json::json!({
                        "graph_epoch": graph_epoch.raw(),
                        "operation_lsn": null,
                        "wait": wait,
                        "edge_count": 1,
                        "idempotency_replay": true,
                }),
            );
            self.refresh_metrics();
            return Ok(crate::graph::RelateResult { edge_id, receipt });
        }

        let type_id = active_mutable_graph(&collection)?
            .types()
            .resolve_name(&request.edge_type)
            .ok_or_else(|| {
                crate::graph::GraphError::new(
                    crate::graph::GraphErrorCode::TypeNotFound,
                    format!("edge type '{}' is not configured", request.edge_type),
                )
            })?;
        let namespace = relation_namespace(&source, &target, request.scope, scope)?;

        let resolver = collection.graph_resolver.as_ref().ok_or_else(|| {
            GaussError::InvalidRequest(
                "enabled graph lifecycle has no point incarnation resolver".to_string(),
            )
        })?;
        let mut endpoint_nids = HashMap::with_capacity(2);
        for point_id in [&request.source_point_id, &request.target_point_id] {
            if endpoint_nids.contains_key(point_id) {
                continue;
            }
            endpoint_nids.insert(point_id.clone(), resolver.live_nid(point_id));
        }
        let missing = endpoint_nids.values().filter(|nid| nid.is_none()).count();
        let mut allocated = NonZeroU64::new(missing as u64)
            .map(|count| self.graph_identity.allocate_nids(count))
            .transpose()?
            .into_iter()
            .flat_map(|range| range.nids());
        let mut handle_assignments = Vec::with_capacity(missing);
        for (point_id, nid) in &mut endpoint_nids {
            if nid.is_none() {
                let allocated_nid = allocated
                    .next()
                    .expect("allocated exact endpoint Nid count");
                *nid = Some(allocated_nid);
                handle_assignments.push(crate::wal::GraphHandleAssignment {
                    point_id: point_id.clone(),
                    nid: allocated_nid,
                });
            }
        }
        debug_assert!(allocated.next().is_none());
        let source_nid =
            endpoint_nids[&request.source_point_id].expect("strict source endpoint has a Nid");
        let target_nid =
            endpoint_nids[&request.target_point_id].expect("strict target endpoint has a Nid");
        let edge_id = self
            .graph_identity
            .allocate_edge_ids(NonZeroU64::new(1).expect("one edge is non-zero"))?
            .edge_ids()
            .next()
            .expect("one EdgeId was allocated");
        let idempotency = if let Some(key) = scoped_key.as_ref() {
            let now = current_unix_ms()?;
            Some(crate::wal::GraphIdempotencyState {
                key: key.clone(),
                request_sha256,
                created_at_unix_ms: now,
                expires_at_unix_ms: now.checked_add(GRAPH_IDEMPOTENCY_TTL_MS).ok_or_else(|| {
                    GaussError::InvalidRequest("idempotency expiry overflow".to_string())
                })?,
                edge_ids: vec![edge_id],
            })
        } else {
            None
        };
        let receipt = self.commit_graph_batch_locked(
            &mut collection,
            crate::wal::GraphBatch {
                graph_epoch,
                handle_assignments,
                edge_mutations: vec![crate::graph::EdgeMutation::Relate(
                    crate::graph::RelateMutation {
                        edge_id,
                        source: source_nid,
                        target: target_nid,
                        type_id,
                        namespace,
                        properties: request.properties,
                    },
                )],
                idempotency,
                ..crate::wal::GraphBatch::default()
            },
            wait,
        )?;
        let public_receipt = public_receipt(receipt, false);
        let token = crate::edge_token::encode(self.graph_database_id(), edge_id)?;
        drop(collection);
        self.finish_committed_legacy_audit(
            audit_operation,
            serde_json::json!({
                "graph_epoch": public_receipt.graph_epoch.raw(),
                "operation_lsn": public_receipt.operation_lsn,
                "wait": wait,
                "edge_count": 1,
                "idempotency_key_present": request.idempotency_key.is_some(),
                "idempotency_replay": false,
            }),
        );
        self.refresh_metrics();
        Ok(crate::graph::RelateResult {
            edge_id: token,
            receipt: public_receipt,
        })
    }

    pub fn unrelate_scoped(
        &self,
        collection_name: &str,
        edge_token: &crate::graph::EdgeToken,
        wait: bool,
        scope: &crate::tenant::TenantScope,
    ) -> Result<crate::graph::GraphMutationReceipt> {
        self.unrelate_many_scoped(
            collection_name,
            std::slice::from_ref(edge_token),
            wait,
            scope,
        )
        .map(|(receipt, _)| receipt)
    }

    /// Remove one bounded list of edges as one GraphBatch publication.
    ///
    /// Every token, edge existence check, namespace authorization, and batch
    /// limit is validated before WAL append. A failure therefore removes none
    /// of the requested edges, which is the statement-level atomicity required
    /// by ChironQL `UNRELATE ... EDGE <list>`.
    pub fn unrelate_many_scoped(
        &self,
        collection_name: &str,
        edge_tokens: &[crate::graph::EdgeToken],
        wait: bool,
        scope: &crate::tenant::TenantScope,
    ) -> Result<(crate::graph::GraphMutationReceipt, usize)> {
        if edge_tokens.is_empty() {
            return Err(GaussError::InvalidRequest(
                "UNRELATE needs at least one edge token".to_string(),
            ));
        }
        if edge_tokens.len() > crate::graph::MAX_GRAPH_EDGES_PER_BATCH {
            return Err(GaussError::InvalidRequest(format!(
                "{} edge operations exceed fixed limit {}",
                edge_tokens.len(),
                crate::graph::MAX_GRAPH_EDGES_PER_BATCH
            )));
        }

        let mut seen = HashSet::with_capacity(edge_tokens.len());
        let edge_ids = edge_tokens
            .iter()
            .map(|token| crate::edge_token::decode(self.graph_database_id(), token))
            .collect::<Result<Vec<_>>>()?;
        if edge_ids.iter().any(|edge_id| !seen.insert(*edge_id)) {
            return Err(GaussError::InvalidRequest(
                "UNRELATE cannot contain duplicate edge tokens".to_string(),
            ));
        }

        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let audit_operation = self.audit_operation_with_context(
            "graph_unrelate",
            Some(collection_name),
            audit_context(scope),
        )?;
        let coll = self.get_coll(collection_name)?;
        let mut collection = coll.write();
        let mutable = active_mutable_graph(&collection)?;
        for edge_id in &edge_ids {
            let namespace = mutable
                .edge_namespace(*edge_id)?
                .ok_or_else(edge_not_found)?;
            authorize_edge_mutation(namespace, scope, self.tenant_enforcement())?;
        }
        let graph_epoch = mutable.epoch();
        let edge_count = edge_ids.len();
        let receipt = self.commit_graph_batch_locked(
            &mut collection,
            crate::wal::GraphBatch {
                graph_epoch,
                edge_mutations: edge_ids
                    .into_iter()
                    .map(|edge_id| {
                        crate::graph::EdgeMutation::Unrelate(crate::graph::UnrelateMutation {
                            edge_id,
                        })
                    })
                    .collect(),
                ..crate::wal::GraphBatch::default()
            },
            wait,
        )?;
        let receipt = public_receipt(receipt, false);
        drop(collection);
        self.finish_committed_legacy_audit(
            audit_operation,
            serde_json::json!({
                "graph_epoch": receipt.graph_epoch.raw(),
                "operation_lsn": receipt.operation_lsn,
                "wait": wait,
                "edge_count": edge_count,
            }),
        );
        self.refresh_metrics();
        Ok((receipt, edge_count))
    }

    pub fn update_edge_scoped(
        &self,
        collection_name: &str,
        edge_token: &crate::graph::EdgeToken,
        request: crate::graph::UpdateEdgeRequest,
        wait: bool,
        scope: &crate::tenant::TenantScope,
    ) -> Result<crate::graph::GraphMutationReceipt> {
        validate_public_properties(&request.properties)?;
        let edge_id = crate::edge_token::decode(self.graph_database_id(), edge_token)?;
        self.mutate_existing_edge_scoped(
            collection_name,
            edge_id,
            crate::graph::EdgeMutation::Properties(crate::graph::EdgePropertyMutation {
                edge_id,
                mode: request.mode,
                properties: request.properties,
            }),
            "graph_edge_update",
            wait,
            scope,
        )
    }

    fn mutate_existing_edge_scoped(
        &self,
        collection_name: &str,
        edge_id: crate::graph::EdgeId,
        mutation: crate::graph::EdgeMutation,
        audit_name: &str,
        wait: bool,
        scope: &crate::tenant::TenantScope,
    ) -> Result<crate::graph::GraphMutationReceipt> {
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let audit_operation = self.audit_operation_with_context(
            audit_name,
            Some(collection_name),
            audit_context(scope),
        )?;
        let coll = self.get_coll(collection_name)?;
        let mut collection = coll.write();
        let mutable = active_mutable_graph(&collection)?;
        let namespace = mutable
            .edge_namespace(edge_id)?
            .ok_or_else(edge_not_found)?;
        authorize_edge_mutation(namespace, scope, self.tenant_enforcement())?;
        let graph_epoch = mutable.epoch();
        let receipt = self.commit_graph_batch_locked(
            &mut collection,
            crate::wal::GraphBatch {
                graph_epoch,
                edge_mutations: vec![mutation],
                ..crate::wal::GraphBatch::default()
            },
            wait,
        )?;
        let receipt = public_receipt(receipt, false);
        drop(collection);
        self.finish_committed_legacy_audit(
            audit_operation,
            serde_json::json!({
                "graph_epoch": receipt.graph_epoch.raw(),
                "operation_lsn": receipt.operation_lsn,
                "wait": wait,
                "edge_count": 1,
            }),
        );
        self.refresh_metrics();
        Ok(receipt)
    }

    /// Internal lifecycle boundary. Network protocols remain closed until
    /// graph-specific authorization and point-mutation integration land.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "used by the following scoped graph API slice")
    )]
    pub fn set_graph_lifecycle_scoped(
        &self,
        collection_name: &str,
        enabled: bool,
        wait: bool,
        scope: &crate::tenant::TenantScope,
    ) -> Result<crate::graph::GraphLifecycleResult> {
        const PUBLICATION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

        let lifecycle_guard = self.lifecycle_gate.write();
        self.ensure_storage_mutations_available()?;
        let admission_guard = self.maintenance_barrier.read();
        let operation = if enabled {
            "graph_enable"
        } else {
            "graph_drop"
        };
        let audit_operation = self.audit_operation_with_context(
            operation,
            Some(collection_name),
            audit_context(scope),
        )?;
        let coll = self.get_coll(collection_name)?;

        // A lifecycle epoch cannot be inserted into the middle of a vector
        // generation publication. Holding the exclusive lifecycle gate stops
        // new vector mutations while the already-started builder retires.
        let deadline = std::time::Instant::now() + PUBLICATION_IDLE_TIMEOUT;
        loop {
            let collection = coll.read();
            if collection.sealing.is_none() && !collection.generation_build_in_flight {
                break;
            }
            drop(collection);
            if std::time::Instant::now() >= deadline {
                return Err(GaussError::ResourceExhausted(format!(
                    "timed out waiting to change graph lifecycle for collection '{collection_name}'"
                )));
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let mut collection = coll.write();
        let receipt = if collection.graph_lifecycle.is_enabled() == enabled {
            // An idempotent wait=true retry upgrades an earlier asynchronous
            // lifecycle record (and any preceding backfill) to stable storage
            // without manufacturing another graph epoch.
            if wait && let Err(error) = collection.wal.sync() {
                self.mark_durability_degraded("graph_lifecycle_sync", &error);
                return Err(error);
            }
            crate::graph::GraphLifecycleResult {
                enabled,
                graph_epoch: collection.graph_lifecycle.epoch(),
                operation_lsn: None,
                durable: wait,
                transitioned: false,
                backfill_in_progress: collection.graph_backfill_pending(),
            }
        } else {
            let epoch = collection.graph_lifecycle.next_epoch()?;
            let mut staged_lifecycle = collection.graph_lifecycle;
            staged_lifecycle.apply_advance(epoch, enabled)?;
            let (transaction, operation_lsn) = self.commit_collection_transaction(
                collection_name,
                &mut collection,
                WalEntry::GraphEpochAdvance { epoch, enabled },
                TransactionAudit::mutation(
                    operation,
                    Some(collection_name),
                    &audit_context(scope),
                    serde_json::json!({
                        "enabled": enabled,
                        "graph_epoch": epoch.raw(),
                        "wait_requested": wait,
                    }),
                ),
            )?;

            collection.graph_lifecycle = staged_lifecycle;
            if enabled && collection.graph_resolver.is_none() {
                collection.graph_resolver =
                    Some(crate::graph_resolver::PointIncarnationResolver::default());
            }
            collection.graph_mutable =
                enabled.then(|| crate::mutable_graph::MutableGraphState::new(epoch));
            let empty_edges = roaring::RoaringTreemap::new();
            if let Err(error) = collection
                .overlays
                .replace_edges(&empty_edges)
                .and_then(|_| collection.overlays.publish_pending())
            {
                self.mark_durability_degraded("graph_lifecycle_overlay", &error);
            }
            self.project_transaction_audit(&transaction);
            crate::graph::GraphLifecycleResult {
                enabled,
                graph_epoch: Some(epoch),
                operation_lsn: Some(operation_lsn),
                durable: true,
                transitioned: true,
                backfill_in_progress: collection.graph_backfill_pending(),
            }
        };
        drop(collection);

        self.finish_committed_legacy_audit(
            audit_operation,
            serde_json::json!({
                "enabled": enabled,
                "graph_epoch": receipt.graph_epoch.map(crate::graph::GraphEpoch::raw),
                "operation_lsn": receipt.operation_lsn,
                "wait": wait,
                "transitioned": receipt.transitioned,
                "backfill_in_progress": receipt.backfill_in_progress,
            }),
        );
        drop(admission_guard);
        drop(lifecycle_guard);

        if enabled && receipt.backfill_in_progress {
            self.start_graph_handle_backfill(collection_name);
        }
        self.refresh_metrics();
        Ok(receipt)
    }

    pub(super) fn resume_graph_handle_backfills(&self) {
        let collections = self
            .inner
            .read()
            .collections
            .iter()
            .filter(|(_, collection)| collection.read().graph_backfill_pending())
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        for collection in collections {
            self.start_graph_handle_backfill(&collection);
        }
    }

    /// Internal maintenance lookup, also valid for protected generations.
    /// Content-facing APIs must continue to use get_coll_authorized.
    fn graph_backfill_collection(
        &self,
        name: &str,
    ) -> Result<std::sync::Arc<parking_lot::RwLock<Collection>>> {
        self.inner
            .read()
            .collections
            .get(name)
            .cloned()
            .ok_or_else(|| GaussError::CollectionNotFound(name.into()))
    }

    pub(super) fn start_graph_handle_backfill(&self, collection_name: &str) {
        let Ok(coll) = self.graph_backfill_collection(collection_name) else {
            return;
        };
        {
            let mut collection = coll.write();
            if collection.graph_backfill_in_flight || !collection.graph_backfill_pending() {
                return;
            }
            collection.graph_backfill_in_flight = true;
        }

        let Some(task_guard) = self.build_lifecycle.register() else {
            coll.write().graph_backfill_in_flight = false;
            return;
        };
        let db = self.clone();
        let collection_name = collection_name.to_string();
        build_admission::BUILD_POOL.spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                db.run_graph_handle_backfill(&collection_name)
            }));
            if let Ok(coll) = db.graph_backfill_collection(&collection_name) {
                coll.write().graph_backfill_in_flight = false;
            }
            match outcome {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::error!(%error, collection = %collection_name, "graph handle backfill stopped")
                }
                Err(_) => {
                    tracing::error!(collection = %collection_name, "graph handle backfill panicked")
                }
            }
            // Avoid the last Db clone waiting for the task guard owned by its
            // own stack frame during Drop.
            drop(task_guard);
            drop(db);
        });
    }

    fn run_graph_handle_backfill(&self, collection_name: &str) -> Result<()> {
        loop {
            if self.build_lifecycle.is_cancelled() {
                return Ok(());
            }
            if self.backfill_graph_handles_once(collection_name)? {
                return Ok(());
            }
            std::thread::yield_now();
        }
    }

    /// Returns true when no legacy point remained unassigned in the locked
    /// collection snapshot. Each successful call appends exactly one bounded
    /// GraphBatch and fsyncs it before exposing the assignments.
    fn backfill_graph_handles_once(&self, collection_name: &str) -> Result<bool> {
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let coll = self.graph_backfill_collection(collection_name)?;
        let mut collection = coll.write();
        if !collection.graph_lifecycle.is_enabled() {
            return Ok(true);
        }
        let resolver = collection.graph_resolver.as_ref().ok_or_else(|| {
            GaussError::InvalidRequest(
                "enabled graph lifecycle has no point incarnation resolver".to_string(),
            )
        })?;
        let mut point_ids = collection
            .id_index
            .keys()
            .filter(|point_id| resolver.live_nid(point_id).is_none())
            .take(GRAPH_HANDLE_BACKFILL_BATCH + 1)
            .cloned()
            .collect::<Vec<_>>();
        if point_ids.is_empty() {
            return Ok(true);
        }
        let has_more = point_ids.len() > GRAPH_HANDLE_BACKFILL_BATCH;
        point_ids.truncate(GRAPH_HANDLE_BACKFILL_BATCH);
        let audit_operation = self.audit_operation_with_context(
            "graph_handle_backfill",
            Some(collection_name),
            audit_context(&crate::tenant::TenantScope::system()),
        )?;
        let count = NonZeroU64::new(point_ids.len() as u64)
            .expect("a non-empty backfill batch has a non-zero size");
        let assignments = point_ids
            .into_iter()
            .zip(self.graph_identity.allocate_nids(count)?.nids())
            .map(|(point_id, nid)| crate::wal::GraphHandleAssignment { point_id, nid })
            .collect::<Vec<_>>();
        let graph_epoch = collection
            .graph_lifecycle
            .epoch()
            .expect("enabled graph lifecycle has an epoch");
        let assignment_count = assignments.len();
        let batch = crate::wal::GraphBatch {
            graph_epoch,
            handle_assignments: assignments,
            ..crate::wal::GraphBatch::default()
        };
        let receipt = if let Some(authority) = collection.security.clone() {
            authority.graph_backfill_with_commit(|security| {
                self.commit_graph_batch_audited_locked(
                    &mut collection,
                    batch,
                    true,
                    Some(security),
                    &crate::audit::AuditContext {
                        principal_id: "system".into(),
                        tenant_id: None,
                        transport: "graph-handle-backfill".into(),
                        request_id: None,
                    },
                    None,
                )
            })?
        } else {
            self.commit_graph_batch_locked(&mut collection, batch, true)?
        };
        drop(collection);
        self.finish_committed_legacy_audit(
            audit_operation,
            serde_json::json!({
                "graph_epoch": graph_epoch.raw(),
                "operation_lsn": receipt.operation_lsn,
                "handle_assignments": assignment_count,
                "remaining": has_more,
            }),
        );
        self.refresh_metrics();
        Ok(!has_more)
    }
}

#[derive(Clone)]
struct ResolvedGraphEndpoint {
    tenant: String,
}

pub(super) fn active_mutable_graph(
    collection: &Collection,
) -> Result<&crate::mutable_graph::MutableGraphState> {
    if !collection.graph_lifecycle.is_enabled() {
        return Err(crate::graph::GraphError::new(
            crate::graph::GraphErrorCode::GraphDisabled,
            "graph is not enabled for this collection",
        )
        .into());
    }
    collection.graph_mutable.as_ref().ok_or_else(|| {
        GaussError::InvalidRequest("enabled graph lifecycle has no mutable graph state".to_string())
    })
}

fn resolve_graph_endpoint(
    collection: &Collection,
    point_id: &str,
    scope: &crate::tenant::TenantScope,
    enforcement: crate::tenant::TenantEnforcement,
) -> Result<ResolvedGraphEndpoint> {
    let point = collection
        .try_resolve(point_id)?
        .ok_or_else(endpoint_not_found)?;
    if scope
        .may_write_payload(enforcement, &point.payload)
        .is_err()
    {
        return Err(endpoint_not_found());
    }
    let tenant = point
        .payload
        .get(crate::tenant::TENANT_FIELD)
        .and_then(serde_json::Value::as_str)
        .unwrap_or(DEFAULT_GRAPH_NAMESPACE)
        .to_string();
    Ok(ResolvedGraphEndpoint { tenant })
}

fn resolve_graph_endpoint_optional(
    collection: &Collection,
    point_id: &str,
    scope: &crate::tenant::TenantScope,
    enforcement: crate::tenant::TenantEnforcement,
) -> Result<Option<ResolvedGraphEndpoint>> {
    let Some(point) = collection.try_resolve(point_id)? else {
        return Ok(None);
    };
    if scope
        .may_write_payload(enforcement, &point.payload)
        .is_err()
    {
        return Err(endpoint_not_found());
    }
    let tenant = point
        .payload
        .get(crate::tenant::TENANT_FIELD)
        .and_then(serde_json::Value::as_str)
        .unwrap_or(DEFAULT_GRAPH_NAMESPACE)
        .to_string();
    Ok(Some(ResolvedGraphEndpoint { tenant }))
}

fn relation_namespace(
    source: &ResolvedGraphEndpoint,
    target: &ResolvedGraphEndpoint,
    requested: crate::graph::GraphRelationScope,
    scope: &crate::tenant::TenantScope,
) -> Result<crate::graph::GraphNamespace> {
    match requested {
        crate::graph::GraphRelationScope::Local if source.tenant == target.tenant => {
            Ok(crate::graph::GraphNamespace::Tenant(source.tenant.clone()))
        }
        crate::graph::GraphRelationScope::Local => Err(GaussError::InvalidRequest(
            "cross-tenant RELATE requires the explicit admin_cross_tenant scope".to_string(),
        )),
        crate::graph::GraphRelationScope::AdminCrossTenant
            if !scope.is_system() && !scope.can_cross_write() =>
        {
            Err(GaussError::InvalidRequest(
                "admin_cross_tenant RELATE requires tenant:cross_write".to_string(),
            ))
        }
        crate::graph::GraphRelationScope::AdminCrossTenant if source.tenant == target.tenant => {
            Err(GaussError::InvalidRequest(
                "admin_cross_tenant RELATE requires endpoints from different tenants".to_string(),
            ))
        }
        crate::graph::GraphRelationScope::AdminCrossTenant => {
            Ok(crate::graph::GraphNamespace::AdminCrossTenant)
        }
    }
}

fn deferred_relation_namespace(
    source: Option<&ResolvedGraphEndpoint>,
    target: Option<&ResolvedGraphEndpoint>,
    requested: crate::graph::GraphRelationScope,
    scope: &crate::tenant::TenantScope,
) -> Result<crate::graph::GraphNamespace> {
    if let (Some(source), Some(target)) = (source, target) {
        return relation_namespace(source, target, requested, scope);
    }
    match requested {
        crate::graph::GraphRelationScope::Local => {
            let tenant = source
                .or(target)
                .map(|endpoint| endpoint.tenant.as_str())
                .or_else(|| scope.tenant_id())
                .unwrap_or(DEFAULT_GRAPH_NAMESPACE);
            Ok(crate::graph::GraphNamespace::Tenant(tenant.to_string()))
        }
        crate::graph::GraphRelationScope::AdminCrossTenant
            if !scope.is_system() && !scope.can_cross_write() =>
        {
            Err(GaussError::InvalidRequest(
                "admin_cross_tenant RELATE requires tenant:cross_write".to_string(),
            ))
        }
        crate::graph::GraphRelationScope::AdminCrossTenant => {
            Ok(crate::graph::GraphNamespace::AdminCrossTenant)
        }
    }
}

fn authorize_edge_mutation(
    namespace: &crate::graph::GraphNamespace,
    scope: &crate::tenant::TenantScope,
    enforcement: crate::tenant::TenantEnforcement,
) -> Result<()> {
    if !enforcement.blocks() || scope.is_system() {
        return Ok(());
    }
    let authorized = match namespace {
        crate::graph::GraphNamespace::Tenant(tenant) => {
            scope.can_cross_write() || scope.tenant_id() == Some(tenant.as_str())
        }
        crate::graph::GraphNamespace::AdminCrossTenant => scope.can_cross_write(),
    };
    if authorized {
        Ok(())
    } else {
        Err(edge_not_found())
    }
}

fn public_receipt(
    receipt: GraphBatchCommitReceipt,
    replayed: bool,
) -> crate::graph::GraphMutationReceipt {
    crate::graph::GraphMutationReceipt {
        graph_epoch: receipt.graph_epoch,
        operation_lsn: Some(receipt.operation_lsn),
        durable: receipt.durable,
        replayed,
    }
}

fn validate_public_graph_key(label: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 1024 {
        return Err(GaussError::InvalidRequest(format!(
            "{label} must contain 1..=1024 UTF-8 bytes"
        )));
    }
    Ok(())
}

pub(super) fn validate_traversal_request(
    request: &crate::graph::GraphTraverseRequest,
) -> Result<()> {
    if request.anchors.is_empty() {
        return Err(GaussError::InvalidRequest(
            "graph traversal requires at least one anchor".to_string(),
        ));
    }
    if request.anchors.len() > crate::graph::MAX_GRAPH_ANCHORS {
        return Err(crate::graph::GraphError::new(
            crate::graph::GraphErrorCode::TooManyAnchors,
            format!(
                "graph traversal has {} anchors; maximum is {}",
                request.anchors.len(),
                crate::graph::MAX_GRAPH_ANCHORS
            ),
        )
        .into());
    }
    if request.edge_types.len() > crate::graph::MAX_GRAPH_TYPES_PER_CLAUSE {
        return Err(crate::graph::GraphError::new(
            crate::graph::GraphErrorCode::TooManyTypes,
            format!(
                "graph traversal has {} edge types; maximum is {}",
                request.edge_types.len(),
                crate::graph::MAX_GRAPH_TYPES_PER_CLAUSE
            ),
        )
        .into());
    }
    for point_id in &request.anchors {
        validate_public_graph_key("anchor point id", point_id)?;
    }
    for edge_type in &request.edge_types {
        validate_public_catalog_name("edge type", edge_type)?;
    }
    for filter in [request.node_filter.as_ref(), request.edge_filter.as_ref()]
        .into_iter()
        .flatten()
    {
        filter.validate_complexity().map_err(|message| {
            GaussError::InvalidRequest(format!("invalid graph traversal filter: {message}"))
        })?;
    }
    Ok(())
}

fn validate_deferred_session_id(session_id: &crate::graph::GraphDeferredSessionId) -> Result<()> {
    let value = session_id.as_str();
    let canonical = uuid::Uuid::parse_str(value)
        .ok()
        .map(|parsed| parsed.simple().to_string());
    if value.len() != 32 || canonical.as_deref() != Some(value) {
        return Err(deferred_session_not_found());
    }
    Ok(())
}

pub(super) fn validate_public_catalog_name(label: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > crate::graph::MAX_GRAPH_CATALOG_NAME_BYTES {
        return Err(GaussError::InvalidRequest(format!(
            "{label} must contain 1..={} UTF-8 bytes",
            crate::graph::MAX_GRAPH_CATALOG_NAME_BYTES
        )));
    }
    Ok(())
}

fn validate_public_properties(properties: &serde_json::Value) -> Result<()> {
    if !properties.is_object() {
        return Err(GaussError::InvalidRequest(
            "edge properties must be a JSON object".to_string(),
        ));
    }
    let bytes = serde_json::to_vec(properties)?.len();
    if bytes > crate::graph::MAX_EDGE_PROPERTY_BYTES {
        return Err(crate::graph::GraphError::new(
            crate::graph::GraphErrorCode::PropertyTooLarge,
            format!(
                "edge properties are {bytes} bytes; maximum is {}",
                crate::graph::MAX_EDGE_PROPERTY_BYTES
            ),
        )
        .into());
    }
    Ok(())
}

fn current_unix_ms() -> Result<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GaussError::InvalidRequest("system clock precedes UNIX epoch".to_string()))?
        .as_millis();
    u64::try_from(millis)
        .map_err(|_| GaussError::InvalidRequest("system clock exceeds u64 millis".to_string()))
}

fn endpoint_not_found() -> GaussError {
    crate::graph::GraphError::new(
        crate::graph::GraphErrorCode::EndpointNotFound,
        "one or more graph endpoints are unavailable",
    )
    .into()
}

fn edge_not_found() -> GaussError {
    crate::graph::GraphError::new(
        crate::graph::GraphErrorCode::EdgeNotFound,
        "edge does not exist or is not visible to this principal",
    )
    .into()
}

fn deferred_session_not_found() -> GaussError {
    crate::graph::GraphError::new(
        crate::graph::GraphErrorCode::DeferredSessionNotFound,
        "deferred graph session does not exist or is not visible",
    )
    .into()
}

fn scoped_idempotency_key(
    scope: &crate::tenant::TenantScope,
    collection: &str,
    operation: &str,
    key: &str,
) -> Result<String> {
    let encoded = serde_json::to_vec(&(scope.session_owner(), collection, operation, key))?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        Sha256::digest(encoded),
    ))
}
