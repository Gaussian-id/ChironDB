use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::RwLock;

use crate::model::{SearchHit, SearchRequest, SearchResponse};
use crate::placement::{ClusterNode, assign_shards};

/// The role this node plays in the cluster topology.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    /// Handles all roles (default standalone mode).
    #[default]
    All,
    /// Receives client requests, routes to coordinator.
    Ingress,
    /// Plans queries, fans out to engine nodes.
    Coordinator,
    /// Holds data and executes queries.
    Engine,
}

/// Configuration for running in cluster mode.
#[derive(Clone, Debug)]
pub struct ClusterConfig {
    pub node_id: u64,
    pub node_role: NodeRole,
    pub listen_raft: std::net::SocketAddr,
    pub peers: Vec<ClusterNode>,
}

/// A handle to the running cluster.  None when in standalone mode.
#[derive(Clone)]
pub struct ClusterHandle {
    pub config: ClusterConfig,
    is_leader: Arc<AtomicBool>,
    leader_addr: Arc<RwLock<Option<String>>>,
}

impl ClusterHandle {
    pub fn new(config: ClusterConfig) -> Self {
        Self {
            config,
            is_leader: Arc::new(AtomicBool::new(false)),
            leader_addr: Arc::new(RwLock::new(None)),
        }
    }

    /// Returns whether this node is the current Raft leader.
    pub fn is_leader(&self) -> bool {
        self.is_leader.load(Ordering::Acquire)
    }

    /// Sets the current leader address (called when Raft elects a new leader).
    /// Pass `None` to indicate no known leader.
    pub fn set_leader(&self, addr: Option<String>) {
        let is_self = addr
            .as_deref()
            .map(|a| a == self.config.listen_raft.to_string())
            .unwrap_or(false);
        self.is_leader.store(is_self, Ordering::Release);
        *self.leader_addr.write() = addr;
    }

    /// Returns the address to forward writes to.
    /// `None` means this node is the leader (or standalone) and should handle the request locally.
    pub fn forward_to(&self) -> Option<String> {
        if self.is_leader() {
            return None;
        }
        self.leader_addr.read().clone()
    }

    /// Compute shard assignment for a collection.
    pub fn shard_assignment(
        &self,
        collection: &str,
        shard_count: u32,
        replicas: u32,
    ) -> HashMap<u32, Vec<u64>> {
        assign_shards(collection, shard_count, &self.config.peers, replicas)
    }

    // --- Row 16: disaggregated topology helpers ---

    /// True if this node should accept and serve client HTTP/gRPC requests.
    pub fn accepts_client_traffic(&self) -> bool {
        matches!(
            self.config.node_role,
            NodeRole::All | NodeRole::Ingress | NodeRole::Coordinator
        )
    }

    /// True if this node holds vector data.
    pub fn holds_data(&self) -> bool {
        matches!(self.config.node_role, NodeRole::All | NodeRole::Engine)
    }

    /// True if this node participates in query planning/coordination.
    pub fn is_coordinator(&self) -> bool {
        matches!(self.config.node_role, NodeRole::All | NodeRole::Coordinator)
    }
}

// --- Row 55: distributed straggler cancellation ---

/// A stub shard search client.  In production this would be a gRPC client;
/// here we use a trait so tests can inject deterministic fakes.
pub trait ShardClient: Send + 'static {
    fn search(
        self,
        request: SearchRequest,
    ) -> impl std::future::Future<Output = crate::error::Result<SearchResponse>> + Send;
}

const REPLICA_HEDGE_BUDGET_DIVISOR: u64 = 10;

fn replica_hedge_delay_ms(budget_ms: u64) -> u64 {
    budget_ms.div_ceil(REPLICA_HEDGE_BUDGET_DIVISOR).max(1)
}

struct HedgedReplicaSet<C> {
    replicas: Vec<C>,
    hedge_delay: std::time::Duration,
}

impl<C: ShardClient> ShardClient for HedgedReplicaSet<C> {
    async fn search(self, request: SearchRequest) -> crate::error::Result<SearchResponse> {
        use std::collections::VecDeque;
        use tokio::task::JoinSet;

        let mut replicas = self.replicas.into_iter();
        let Some(primary) = replicas.next() else {
            return Err(crate::error::GaussError::InvalidRequest(
                "replicated shard has no readable replicas".to_string(),
            ));
        };
        let mut followers = replicas.collect::<VecDeque<_>>();
        let mut tasks = JoinSet::new();
        spawn_replica_search(&mut tasks, primary, &request);
        let hedge = tokio::time::sleep(self.hedge_delay);
        tokio::pin!(hedge);
        let mut hedge_launched = false;
        let mut last_error = "all replica searches failed".to_string();

        loop {
            if tasks.is_empty() {
                let Some(follower) = followers.pop_front() else {
                    return Err(crate::error::GaussError::InvalidRequest(format!(
                        "replicated shard search failed: {last_error}"
                    )));
                };
                spawn_replica_search(&mut tasks, follower, &request);
                hedge_launched = true;
            }

            tokio::select! {
                _ = &mut hedge, if !hedge_launched && !followers.is_empty() => {
                    if let Some(follower) = followers.pop_front() {
                        spawn_replica_search(&mut tasks, follower, &request);
                    }
                    hedge_launched = true;
                }
                result = tasks.join_next() => {
                    match result {
                        Some(Ok(Ok(response))) => {
                            tasks.abort_all();
                            return Ok(response);
                        }
                        Some(Ok(Err(error))) => {
                            last_error = error.to_string();
                            if let Some(follower) = followers.pop_front() {
                                spawn_replica_search(&mut tasks, follower, &request);
                                hedge_launched = true;
                            }
                        }
                        Some(Err(error)) => {
                            last_error = error.to_string();
                            if let Some(follower) = followers.pop_front() {
                                spawn_replica_search(&mut tasks, follower, &request);
                                hedge_launched = true;
                            }
                        }
                        None => {}
                    }
                }
            }
        }
    }
}

fn spawn_replica_search<C: ShardClient>(
    tasks: &mut tokio::task::JoinSet<crate::error::Result<SearchResponse>>,
    replica: C,
    request: &SearchRequest,
) {
    let request = request.clone();
    tasks.spawn(async move { replica.search(request).await });
}

/// Fan out over logical shards whose entries contain in-sync replicas.
///
/// The first replica starts immediately. If it has not completed after 10% of
/// the query budget, one follower is hedged in parallel. Additional followers
/// are reserved for error failover. The first successful response wins and
/// unfinished replicas are cancelled. This keeps the ordinary
/// one-client-per-shard path unchanged while giving replicated collections a
/// structural tail-latency defense with at most 2x healthy-path requests.
pub async fn fan_out_search_replicated<C: ShardClient>(
    replica_sets: Vec<Vec<C>>,
    request: SearchRequest,
    budget_ms: u64,
) -> SearchResponse {
    let hedge_delay_ms = replica_hedge_delay_ms(budget_ms);
    let shards = replica_sets
        .into_iter()
        .map(|replicas| HedgedReplicaSet {
            replicas,
            hedge_delay: std::time::Duration::from_millis(hedge_delay_ms),
        })
        .collect();
    fan_out_search(shards, request, budget_ms).await
}

/// Fan out a search to multiple shard holders; cancel stragglers after `budget_ms`.
///
/// Results from shards that respond within the budget are merged and returned.
/// `degraded` is set to `true` when at least one shard timed out.
pub async fn fan_out_search<C: ShardClient>(
    shard_clients: Vec<C>,
    request: SearchRequest,
    budget_ms: u64,
) -> SearchResponse {
    use tokio::task::JoinSet;
    use tokio::time::{Duration, timeout};

    if shard_clients.is_empty() {
        return SearchResponse {
            hits: vec![],
            degraded: false,
            searched: 0,
            elapsed_ms: 0,
            graph: None,
        };
    }

    let start = std::time::Instant::now();
    let budget = Duration::from_millis(budget_ms);

    // Collect shards in completion order. Waiting on handles in submission
    // order lets one straggler hide a fast shard that has already finished.
    let mut tasks = JoinSet::new();
    for client in shard_clients {
        let req = request.clone();
        tasks.spawn(async move { client.search(req).await });
    }

    let mut all_hits: Vec<SearchHit> = Vec::new();
    let mut total_searched: usize = 0;
    let mut degraded = false;

    while !tasks.is_empty() {
        let remaining = budget.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            degraded = true;
            tasks.abort_all();
            break;
        }
        match timeout(remaining, tasks.join_next()).await {
            Ok(Some(Ok(Ok(resp)))) => {
                degraded |= resp.degraded;
                total_searched += resp.searched;
                all_hits.extend(resp.hits);
            }
            Ok(Some(Ok(Err(_)))) => {
                // shard returned an error — treat as degraded
                degraded = true;
            }
            Ok(Some(Err(_))) => {
                // task panicked
                degraded = true;
            }
            Ok(None) => break,
            Err(_) => {
                // The budget applies to the whole fan-out. Abort unfinished
                // shard futures so timed-out work cannot continue detached.
                degraded = true;
                tasks.abort_all();
                break;
            }
        }
    }

    // Merge: sort by score descending, keep top-k
    let k = request.k;
    all_hits.sort_unstable_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    all_hits.truncate(k);

    SearchResponse {
        hits: all_hits,
        degraded,
        searched: total_searched,
        elapsed_ms: start.elapsed().as_millis(),
        graph: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SearchHit;
    use crate::placement::ClusterNode;
    use serde_json::json;
    use std::sync::atomic::AtomicUsize;

    fn make_config(role: NodeRole) -> ClusterConfig {
        ClusterConfig {
            node_id: 1,
            node_role: role,
            listen_raft: "127.0.0.1:7410".parse().unwrap(),
            peers: vec![ClusterNode {
                id: 1,
                addr: "127.0.0.1:7401".to_string(),
                zone: None,
            }],
        }
    }

    #[test]
    fn topology_roles_are_correct() {
        let all = ClusterHandle::new(make_config(NodeRole::All));
        assert!(all.accepts_client_traffic());
        assert!(all.holds_data());
        assert!(all.is_coordinator());

        let ingress = ClusterHandle::new(make_config(NodeRole::Ingress));
        assert!(ingress.accepts_client_traffic());
        assert!(!ingress.holds_data());
        assert!(!ingress.is_coordinator());

        let coord = ClusterHandle::new(make_config(NodeRole::Coordinator));
        assert!(coord.accepts_client_traffic());
        assert!(!coord.holds_data());
        assert!(coord.is_coordinator());

        let engine = ClusterHandle::new(make_config(NodeRole::Engine));
        assert!(!engine.accepts_client_traffic());
        assert!(engine.holds_data());
        assert!(!engine.is_coordinator());
    }

    #[test]
    fn set_leader_updates_forward_to() {
        let handle = ClusterHandle::new(make_config(NodeRole::All));
        // Initially no leader
        assert!(handle.forward_to().is_none());
        // Set a remote leader
        handle.set_leader(Some("10.0.0.2:7410".to_string()));
        assert!(!handle.is_leader());
        assert_eq!(handle.forward_to(), Some("10.0.0.2:7410".to_string()));
        // Elect this node as leader
        handle.set_leader(Some("127.0.0.1:7410".to_string()));
        assert!(handle.is_leader());
        assert!(handle.forward_to().is_none());
    }

    struct FakeShard {
        hits: Vec<SearchHit>,
        delay_ms: u64,
    }

    impl ShardClient for FakeShard {
        async fn search(self, req: SearchRequest) -> crate::error::Result<SearchResponse> {
            if self.delay_ms > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(self.delay_ms)).await;
            }
            Ok(SearchResponse {
                hits: self.hits,
                degraded: false,
                searched: req.k,
                elapsed_ms: self.delay_ms as u128,
                graph: None,
            })
        }
    }

    #[tokio::test]
    async fn replicated_fan_out_hedges_a_slow_primary() {
        let replicas = vec![vec![
            FakeShard {
                hits: vec![SearchHit {
                    id: "primary".into(),
                    score: 1.0,
                    payload: json!({}),
                }],
                delay_ms: 500,
            },
            FakeShard {
                hits: vec![SearchHit {
                    id: "follower".into(),
                    score: 1.0,
                    payload: json!({}),
                }],
                delay_ms: 0,
            },
        ]];
        let req = SearchRequest {
            graph: None,
            vector: vec![1.0],
            vector_name: None,
            k: 10,
            filter: None,
            budget_ms: None,
            consistency: None,
            ef_search: None,
            recall_target: None,
            with_payload: None,
        };

        let resp = fan_out_search_replicated(replicas, req, 100).await;

        assert!(!resp.degraded);
        assert_eq!(resp.hits.len(), 1);
        assert_eq!(resp.hits[0].id, "follower");
        assert!(resp.elapsed_ms < 100);
    }

    struct CountingShard {
        calls: Arc<AtomicUsize>,
        id: &'static str,
        delay_ms: u64,
    }

    impl ShardClient for CountingShard {
        async fn search(self, req: SearchRequest) -> crate::error::Result<SearchResponse> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            if self.delay_ms > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(self.delay_ms)).await;
            }
            Ok(SearchResponse {
                hits: vec![SearchHit {
                    id: self.id.into(),
                    score: 1.0,
                    payload: json!({}),
                }],
                degraded: false,
                searched: req.k,
                elapsed_ms: self.delay_ms as u128,
                graph: None,
            })
        }
    }

    #[tokio::test]
    async fn replicated_fan_out_does_not_launch_follower_for_fast_primary() {
        let primary_calls = Arc::new(AtomicUsize::new(0));
        let follower_calls = Arc::new(AtomicUsize::new(0));
        let replicas = vec![vec![
            CountingShard {
                calls: Arc::clone(&primary_calls),
                id: "primary",
                delay_ms: 0,
            },
            CountingShard {
                calls: Arc::clone(&follower_calls),
                id: "follower",
                delay_ms: 0,
            },
        ]];
        let req = SearchRequest {
            graph: None,
            vector: vec![1.0],
            vector_name: None,
            k: 10,
            filter: None,
            budget_ms: None,
            consistency: None,
            ef_search: None,
            recall_target: None,
            with_payload: None,
        };

        let resp = fan_out_search_replicated(replicas, req, 100).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

        assert!(!resp.degraded);
        assert_eq!(resp.hits[0].id, "primary");
        assert_eq!(primary_calls.load(Ordering::Acquire), 1);
        assert_eq!(follower_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn replicated_fan_out_launches_only_one_healthy_path_follower() {
        let primary_calls = Arc::new(AtomicUsize::new(0));
        let hedge_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let replicas = vec![vec![
            CountingShard {
                calls: Arc::clone(&primary_calls),
                id: "primary",
                delay_ms: 500,
            },
            CountingShard {
                calls: Arc::clone(&hedge_calls),
                id: "hedge",
                delay_ms: 0,
            },
            CountingShard {
                calls: Arc::clone(&fallback_calls),
                id: "fallback",
                delay_ms: 0,
            },
        ]];
        let req = SearchRequest {
            graph: None,
            vector: vec![1.0],
            vector_name: None,
            k: 10,
            filter: None,
            budget_ms: None,
            consistency: None,
            ef_search: None,
            recall_target: None,
            with_payload: None,
        };

        let resp = fan_out_search_replicated(replicas, req, 100).await;

        assert!(!resp.degraded);
        assert_eq!(resp.hits[0].id, "hedge");
        assert_eq!(primary_calls.load(Ordering::Acquire), 1);
        assert_eq!(hedge_calls.load(Ordering::Acquire), 1);
        assert_eq!(fallback_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn fan_out_merges_and_sorts() {
        let shards: Vec<FakeShard> = vec![
            FakeShard {
                hits: vec![
                    SearchHit {
                        id: "a".into(),
                        score: 0.9,
                        payload: json!({}),
                    },
                    SearchHit {
                        id: "b".into(),
                        score: 0.5,
                        payload: json!({}),
                    },
                ],
                delay_ms: 0,
            },
            FakeShard {
                hits: vec![
                    SearchHit {
                        id: "c".into(),
                        score: 0.8,
                        payload: json!({}),
                    },
                    SearchHit {
                        id: "d".into(),
                        score: 0.3,
                        payload: json!({}),
                    },
                ],
                delay_ms: 0,
            },
        ];
        let req = SearchRequest {
            graph: None,
            vector: vec![1.0, 0.0],
            vector_name: None,
            k: 3,
            filter: None,
            budget_ms: None,
            consistency: None,
            ef_search: None,
            recall_target: None,
            with_payload: None,
        };
        let resp = fan_out_search(shards, req, 1000).await;
        assert!(!resp.degraded);
        assert_eq!(resp.hits.len(), 3);
        assert_eq!(resp.hits[0].id, "a");
        assert_eq!(resp.hits[1].id, "c");
        assert_eq!(resp.hits[2].id, "b");
    }

    #[tokio::test]
    async fn fan_out_marks_degraded_on_timeout() {
        let shards: Vec<FakeShard> = vec![
            FakeShard {
                hits: vec![SearchHit {
                    id: "fast".into(),
                    score: 1.0,
                    payload: json!({}),
                }],
                delay_ms: 0,
            },
            FakeShard {
                hits: vec![],
                delay_ms: 500, // will time out
            },
        ];
        let req = SearchRequest {
            graph: None,
            vector: vec![1.0],
            vector_name: None,
            k: 10,
            filter: None,
            budget_ms: None,
            consistency: None,
            ef_search: None,
            recall_target: None,
            with_payload: None,
        };
        let resp = fan_out_search(shards, req, 50).await;
        assert!(resp.degraded);
        // The fast shard's result should still be present
        assert_eq!(resp.hits.len(), 1);
        assert_eq!(resp.hits[0].id, "fast");
    }

    #[tokio::test]
    async fn fan_out_collects_fast_shard_even_when_straggler_was_submitted_first() {
        let shards = vec![
            FakeShard {
                hits: vec![],
                delay_ms: 500,
            },
            FakeShard {
                hits: vec![SearchHit {
                    id: "fast".into(),
                    score: 1.0,
                    payload: json!({}),
                }],
                delay_ms: 0,
            },
        ];
        let req = SearchRequest {
            graph: None,
            vector: vec![1.0],
            vector_name: None,
            k: 10,
            filter: None,
            budget_ms: None,
            consistency: None,
            ef_search: None,
            recall_target: None,
            with_payload: None,
        };

        let resp = fan_out_search(shards, req, 50).await;

        assert!(resp.degraded);
        assert_eq!(resp.hits.len(), 1);
        assert_eq!(resp.hits[0].id, "fast");
    }

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    struct CancelAwareShard {
        dropped: Arc<AtomicBool>,
    }

    impl ShardClient for CancelAwareShard {
        async fn search(self, _req: SearchRequest) -> crate::error::Result<SearchResponse> {
            let _drop_flag = DropFlag(self.dropped);
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            unreachable!("the shard future must be cancelled at the coordinator budget")
        }
    }

    #[tokio::test]
    async fn fan_out_aborts_timed_out_shard_future() {
        let dropped = Arc::new(AtomicBool::new(false));
        let req = SearchRequest {
            graph: None,
            vector: vec![1.0],
            vector_name: None,
            k: 10,
            filter: None,
            budget_ms: None,
            consistency: None,
            ef_search: None,
            recall_target: None,
            with_payload: None,
        };

        let resp = fan_out_search(
            vec![CancelAwareShard {
                dropped: Arc::clone(&dropped),
            }],
            req,
            10,
        )
        .await;
        tokio::task::yield_now().await;

        assert!(resp.degraded);
        assert!(dropped.load(Ordering::Acquire));
    }

    struct DegradedShard;

    impl ShardClient for DegradedShard {
        async fn search(self, _req: SearchRequest) -> crate::error::Result<SearchResponse> {
            Ok(SearchResponse {
                hits: vec![],
                degraded: true,
                searched: 1,
                elapsed_ms: 1,
                graph: None,
            })
        }
    }

    #[tokio::test]
    async fn fan_out_propagates_shard_degraded_flag() {
        let req = SearchRequest {
            graph: None,
            vector: vec![1.0],
            vector_name: None,
            k: 10,
            filter: None,
            budget_ms: None,
            consistency: None,
            ef_search: None,
            recall_target: None,
            with_payload: None,
        };

        let resp = fan_out_search(vec![DegradedShard], req, 100).await;

        assert!(resp.degraded);
        assert_eq!(resp.searched, 1);
    }
}
