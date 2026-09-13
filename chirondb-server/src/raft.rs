use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::{
    sync::{RwLock, mpsc, oneshot},
    time::{Instant, sleep_until},
};

use crate::model::{CollectionConfig, PayloadType};

pub mod raft_proto {
    tonic::include_proto!("raft.v1");
}

pub type NodeId = u64;
pub type Term = u64;
pub type LogIndex = u64;

// ── Commands ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CatalogCommand {
    CreateCollection {
        config: CollectionConfig,
    },
    DeleteCollection {
        name: String,
    },
    UpdatePayloadSchema {
        collection: String,
        schema: HashMap<String, PayloadType>,
    },
    Noop,
}

impl PartialEq for CatalogCommand {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Noop, Self::Noop) => true,
            (Self::DeleteCollection { name: a }, Self::DeleteCollection { name: b }) => a == b,
            // For collection configs and schema, compare via serialized form
            (a, b) => serde_json::to_string(a).ok() == serde_json::to_string(b).ok(),
        }
    }
}

// ── Log entry ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RaftLogEntry {
    pub term: Term,
    pub index: LogIndex,
    pub command: CatalogCommand,
}

// ── Peer info ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct NodeInfo {
    pub id: NodeId,
    pub addr: String,
}

// ── Raft config ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct RaftConfig {
    pub node_id: NodeId,
    pub peers: Vec<NodeInfo>,
    pub election_timeout_min_ms: u64,
    pub election_timeout_max_ms: u64,
    pub heartbeat_interval_ms: u64,
    pub data_dir: PathBuf,
}

impl Default for RaftConfig {
    fn default() -> Self {
        Self {
            node_id: 1,
            peers: Vec::new(),
            election_timeout_min_ms: 150,
            election_timeout_max_ms: 300,
            heartbeat_interval_ms: 50,
            data_dir: PathBuf::from("data"),
        }
    }
}

// ── Persistent state ─────────────────────────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RaftPersistentState {
    pub current_term: Term,
    pub voted_for: Option<NodeId>,
}

impl RaftPersistentState {
    pub fn load(path: &Path) -> Self {
        if !path.exists() {
            return Self::default();
        }
        crate::encryption::read_persistent(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(bytes) = serde_json::to_vec(self)
            && let Err(error) = crate::encryption::atomic_write_persistent(
                path,
                crate::encryption::FileType::Raft,
                &bytes,
            )
        {
            tracing::error!(%error, path = %path.display(), "failed to persist Raft state");
        }
    }
}

// ── Catalog state machine ────────────────────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CatalogStateMachine {
    pub collections: HashMap<String, CollectionConfig>,
    pub last_applied: LogIndex,
}

impl CatalogStateMachine {
    pub fn apply(&mut self, entry: &RaftLogEntry) {
        match &entry.command {
            CatalogCommand::CreateCollection { config } => {
                self.collections.insert(config.name.clone(), config.clone());
            }
            CatalogCommand::DeleteCollection { name } => {
                self.collections.remove(name);
            }
            CatalogCommand::UpdatePayloadSchema { collection, schema } => {
                if let Some(cfg) = self.collections.get_mut(collection) {
                    cfg.payload_schema = schema.clone();
                }
            }
            CatalogCommand::Noop => {}
        }
        self.last_applied = entry.index;
    }

    pub fn snapshot(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn restore(data: &[u8]) -> Self {
        serde_json::from_slice(data).unwrap_or_default()
    }
}

// ── Role ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum RaftRole {
    Follower { leader_id: Option<NodeId> },
    Candidate,
    Leader,
}

// ── RPC types (internal, not proto) ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AppendEntriesReq {
    pub term: Term,
    pub leader_id: NodeId,
    pub prev_log_index: LogIndex,
    pub prev_log_term: Term,
    pub entries: Vec<RaftLogEntry>,
    pub leader_commit: LogIndex,
}

#[derive(Debug, Clone, Copy)]
pub struct AppendEntriesResp {
    pub term: Term,
    pub success: bool,
    pub conflict_index: LogIndex,
    pub conflict_term: Term,
}

#[derive(Debug, Clone, Copy)]
pub struct RequestVoteReq {
    pub term: Term,
    pub candidate_id: NodeId,
    pub last_log_index: LogIndex,
    pub last_log_term: Term,
}

#[derive(Debug, Clone, Copy)]
pub struct RequestVoteResp {
    pub term: Term,
    pub vote_granted: bool,
}

// ── Raft event channel ───────────────────────────────────────────────────────

pub enum RaftInput {
    AppendEntries {
        req: AppendEntriesReq,
        tx: oneshot::Sender<AppendEntriesResp>,
    },
    RequestVote {
        req: RequestVoteReq,
        tx: oneshot::Sender<RequestVoteResp>,
    },
    Propose {
        cmd: CatalogCommand,
        tx: oneshot::Sender<Result<(), String>>,
    },
    ElectionTimeout,
    HeartbeatTick,
    ApplyCommitted,
}

// ── RaftNode ─────────────────────────────────────────────────────────────────

struct RaftNode {
    config: RaftConfig,
    state: RaftPersistentState,
    log: Vec<RaftLogEntry>,
    commit_index: LogIndex,
    role: RaftRole,
    votes_received: HashSet<NodeId>,
    // Leader-only
    next_index: HashMap<NodeId, LogIndex>,
    match_index: HashMap<NodeId, LogIndex>,
    // Pending proposals waiting for commit (leader-only)
    // Maps log index -> sender
    pending: HashMap<LogIndex, oneshot::Sender<Result<(), String>>>,
}

impl RaftNode {
    fn new(config: RaftConfig, data_dir: &Path) -> Self {
        let state = RaftPersistentState::load(&data_dir.join("raft_state.json"));
        let log = Self::load_log(&data_dir.join("raft_log.json"));
        let commit_index = log.last().map(|e| e.index).unwrap_or(0);
        Self {
            config,
            state,
            log,
            commit_index,
            role: RaftRole::Follower { leader_id: None },
            votes_received: HashSet::new(),
            next_index: HashMap::new(),
            match_index: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    fn save_state(&self) {
        self.state
            .save(&self.config.data_dir.join("raft_state.json"));
    }

    fn save_log(&self) {
        if let Some(parent) = self.config.data_dir.as_path().parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(bytes) = serde_json::to_vec(&self.log) {
            let path = self.config.data_dir.join("raft_log.json");
            if let Err(error) = crate::encryption::atomic_write_persistent(
                &path,
                crate::encryption::FileType::Raft,
                &bytes,
            ) {
                tracing::error!(%error, path = %path.display(), "failed to persist Raft log");
            }
        }
    }

    fn load_log(path: &Path) -> Vec<RaftLogEntry> {
        if !path.exists() {
            return Vec::new();
        }
        crate::encryption::read_persistent(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    fn last_log_index(&self) -> LogIndex {
        self.log.last().map(|e| e.index).unwrap_or(0)
    }

    fn last_log_term(&self) -> Term {
        self.log.last().map(|e| e.term).unwrap_or(0)
    }

    fn log_term_at(&self, index: LogIndex) -> Term {
        if index == 0 {
            return 0;
        }
        self.log
            .iter()
            .find(|e| e.index == index)
            .map(|e| e.term)
            .unwrap_or(0)
    }

    /// Returns true if this candidate's log is at least as up-to-date as ours.
    fn is_candidate_log_ok(&self, last_index: LogIndex, last_term: Term) -> bool {
        if last_term != self.last_log_term() {
            last_term > self.last_log_term()
        } else {
            last_index >= self.last_log_index()
        }
    }

    fn quorum_size(&self) -> usize {
        // peers + self
        let n = self.config.peers.len() + 1;
        n / 2 + 1
    }

    fn become_follower(&mut self, term: Term) {
        self.state.current_term = term;
        self.state.voted_for = None;
        self.role = RaftRole::Follower { leader_id: None };
        self.votes_received.clear();
        self.save_state();
    }

    fn become_leader(&mut self) {
        let next = self.last_log_index() + 1;
        self.next_index = self.config.peers.iter().map(|p| (p.id, next)).collect();
        self.match_index = self.config.peers.iter().map(|p| (p.id, 0)).collect();
        self.role = RaftRole::Leader;
        // Append Noop entry
        let noop_index = self.last_log_index() + 1;
        let noop = RaftLogEntry {
            term: self.state.current_term,
            index: noop_index,
            command: CatalogCommand::Noop,
        };
        self.log.push(noop);
        self.save_log();
    }

    fn try_advance_commit(&mut self) {
        // Find highest index where a majority have match_index >= that index.
        let mut n = self.last_log_index();
        while n > self.commit_index {
            if self.log_term_at(n) == self.state.current_term {
                let acks = self.match_index.values().filter(|&&m| m >= n).count() + 1; // +1 for self
                if acks >= self.quorum_size() {
                    self.commit_index = n;
                    break;
                }
            }
            n = n.saturating_sub(1);
        }
    }

    fn notify_committed_proposals(&mut self) {
        let committed = self.commit_index;
        let indices: Vec<LogIndex> = self
            .pending
            .keys()
            .copied()
            .filter(|&idx| idx <= committed)
            .collect();
        for idx in indices {
            if let Some(tx) = self.pending.remove(&idx) {
                let _ = tx.send(Ok(()));
            }
        }
    }

    fn handle_append_entries(&mut self, req: AppendEntriesReq) -> AppendEntriesResp {
        // Reject stale term
        if req.term < self.state.current_term {
            return AppendEntriesResp {
                term: self.state.current_term,
                success: false,
                conflict_index: 0,
                conflict_term: 0,
            };
        }
        // Discovered newer term or valid leader heartbeat
        if req.term > self.state.current_term {
            self.become_follower(req.term);
        } else {
            self.role = RaftRole::Follower {
                leader_id: Some(req.leader_id),
            };
        }

        // Check prev_log consistency
        if req.prev_log_index > 0 {
            let our_term = self.log_term_at(req.prev_log_index);
            if our_term == 0 {
                // We don't have prev_log_index
                return AppendEntriesResp {
                    term: self.state.current_term,
                    success: false,
                    conflict_index: self.last_log_index() + 1,
                    conflict_term: 0,
                };
            }
            if our_term != req.prev_log_term {
                // Conflict: find first index of the conflicting term
                let conflict_term = our_term;
                let conflict_index = self
                    .log
                    .iter()
                    .find(|e| e.term == conflict_term)
                    .map(|e| e.index)
                    .unwrap_or(req.prev_log_index);
                // Truncate conflicting entries
                self.log.retain(|e| e.index < req.prev_log_index);
                self.save_log();
                return AppendEntriesResp {
                    term: self.state.current_term,
                    success: false,
                    conflict_index,
                    conflict_term,
                };
            }
        }

        // Truncate conflicting entries and append new ones
        for entry in &req.entries {
            let existing_term = self.log_term_at(entry.index);
            if existing_term != 0 && existing_term != entry.term {
                // Conflict at this index — truncate from here
                self.log.retain(|e| e.index < entry.index);
            }
            if self.log_term_at(entry.index) == 0 {
                self.log.push(entry.clone());
            }
        }
        if !req.entries.is_empty() {
            self.save_log();
        }

        // Advance commit_index
        if req.leader_commit > self.commit_index {
            self.commit_index = req.leader_commit.min(self.last_log_index());
        }

        AppendEntriesResp {
            term: self.state.current_term,
            success: true,
            conflict_index: 0,
            conflict_term: 0,
        }
    }

    fn handle_request_vote(&mut self, req: RequestVoteReq) -> RequestVoteResp {
        if req.term < self.state.current_term {
            return RequestVoteResp {
                term: self.state.current_term,
                vote_granted: false,
            };
        }
        if req.term > self.state.current_term {
            self.become_follower(req.term);
        }
        let already_voted_for_other = self
            .state
            .voted_for
            .map(|v| v != req.candidate_id)
            .unwrap_or(false);
        let grant = !already_voted_for_other
            && self.is_candidate_log_ok(req.last_log_index, req.last_log_term);
        if grant {
            self.state.voted_for = Some(req.candidate_id);
            self.save_state();
        }
        RequestVoteResp {
            term: self.state.current_term,
            vote_granted: grant,
        }
    }

    fn handle_propose(&mut self, cmd: CatalogCommand, tx: oneshot::Sender<Result<(), String>>) {
        match &self.role {
            RaftRole::Leader => {
                let index = self.last_log_index() + 1;
                self.log.push(RaftLogEntry {
                    term: self.state.current_term,
                    index,
                    command: cmd,
                });
                self.save_log();
                self.pending.insert(index, tx);
            }
            _ => {
                let _ = tx.send(Err("not leader".to_string()));
            }
        }
    }
}

// ── Peer RPC helpers ─────────────────────────────────────────────────────────

async fn send_request_vote(
    addr: &str,
    req: raft_proto::RequestVoteRequest,
) -> Option<raft_proto::RequestVoteResponse> {
    let endpoint = format!("http://{addr}");
    let mut client = raft_proto::raft_service_client::RaftServiceClient::connect(endpoint)
        .await
        .ok()?;
    client.request_vote(req).await.ok().map(|r| r.into_inner())
}

async fn send_append_entries(
    addr: &str,
    req: raft_proto::AppendEntriesRequest,
) -> Option<raft_proto::AppendEntriesResponse> {
    let endpoint = format!("http://{addr}");
    let mut client = raft_proto::raft_service_client::RaftServiceClient::connect(endpoint)
        .await
        .ok()?;
    client
        .append_entries(req)
        .await
        .ok()
        .map(|r| r.into_inner())
}

fn to_proto_entry(e: &RaftLogEntry) -> raft_proto::LogEntry {
    raft_proto::LogEntry {
        term: e.term,
        index: e.index,
        data: serde_json::to_vec(&e.command).unwrap_or_default(),
    }
}

// ── Event loop ───────────────────────────────────────────────────────────────

pub async fn run_raft(
    config: RaftConfig,
    state_machine: Arc<RwLock<CatalogStateMachine>>,
    mut rx: mpsc::Receiver<RaftInput>,
) {
    let data_dir = config.data_dir.clone();
    let _ = std::fs::create_dir_all(&data_dir);

    let mut node = RaftNode::new(config.clone(), &data_dir);

    let election_timeout_min = Duration::from_millis(config.election_timeout_min_ms);
    let election_timeout_max = Duration::from_millis(config.election_timeout_max_ms);
    let heartbeat_interval = Duration::from_millis(config.heartbeat_interval_ms);

    // Random election timeout using a simple LCG seeded by node_id
    let election_timeout = {
        let range = config.election_timeout_max_ms - config.election_timeout_min_ms;
        let jitter = (config.node_id * 6364136223846793005 + 1442695040888963407) % range;
        election_timeout_min + Duration::from_millis(jitter)
    };
    let _ = (election_timeout_min, election_timeout_max); // suppress unused

    let mut next_election = Instant::now() + election_timeout;
    let mut next_heartbeat = Instant::now() + heartbeat_interval;

    loop {
        // Determine how long until the next scheduled event
        let now = Instant::now();
        let deadline = match node.role {
            RaftRole::Leader => next_heartbeat,
            _ => next_election,
        };
        let timeout_fut = sleep_until(deadline);
        tokio::pin!(timeout_fut);

        tokio::select! {
            _ = &mut timeout_fut => {
                match node.role {
                    RaftRole::Leader => {
                        // Heartbeat tick
                        next_heartbeat = Instant::now() + heartbeat_interval;
                        send_heartbeats_to_peers(&mut node).await;
                    }
                    _ => {
                        // Election timeout
                        start_election(&mut node, state_machine.clone()).await;
                        let range = config.election_timeout_max_ms - config.election_timeout_min_ms;
                        let jitter = (node.state.current_term * 6364136223846793005 + 1442695040888963407) % range;
                        next_election = Instant::now() + election_timeout_min + Duration::from_millis(jitter);
                    }
                }
            }

            msg = rx.recv() => {
                let Some(input) = msg else { break };
                match input {
                    RaftInput::AppendEntries { req, tx } => {
                        // Reset election timer on valid heartbeat
                        let resp = node.handle_append_entries(req);
                        if resp.success || matches!(node.role, RaftRole::Follower { .. }) {
                            let range = config.election_timeout_max_ms - config.election_timeout_min_ms;
                            let jitter = (node.state.current_term * 6364136223846793005 + 1442695040888963407) % range;
                            next_election = Instant::now() + election_timeout_min + Duration::from_millis(jitter);
                        }
                        let _ = tx.send(resp);
                        apply_committed(&mut node, &state_machine).await;
                    }
                    RaftInput::RequestVote { req, tx } => {
                        let resp = node.handle_request_vote(req);
                        let _ = tx.send(resp);
                    }
                    RaftInput::Propose { cmd, tx } => {
                        node.handle_propose(cmd, tx);
                        if matches!(node.role, RaftRole::Leader) {
                            send_heartbeats_to_peers(&mut node).await;
                            node.try_advance_commit();
                            node.notify_committed_proposals();
                            apply_committed(&mut node, &state_machine).await;
                        }
                    }
                    RaftInput::ElectionTimeout => {
                        start_election(&mut node, state_machine.clone()).await;
                    }
                    RaftInput::HeartbeatTick => {
                        if matches!(node.role, RaftRole::Leader) {
                            send_heartbeats_to_peers(&mut node).await;
                        }
                    }
                    RaftInput::ApplyCommitted => {
                        apply_committed(&mut node, &state_machine).await;
                    }
                }
            }
        }
        let _ = now; // suppress warning
    }
}

async fn apply_committed(node: &mut RaftNode, state_machine: &Arc<RwLock<CatalogStateMachine>>) {
    let mut sm = state_machine.write().await;
    while sm.last_applied < node.commit_index {
        let next = sm.last_applied + 1;
        if let Some(entry) = node.log.iter().find(|e| e.index == next) {
            sm.apply(&entry.clone());
        } else {
            break;
        }
    }
    node.notify_committed_proposals();
}

async fn start_election(node: &mut RaftNode, state_machine: Arc<RwLock<CatalogStateMachine>>) {
    node.state.current_term += 1;
    node.state.voted_for = Some(node.config.node_id);
    node.role = RaftRole::Candidate;
    node.votes_received.clear();
    node.votes_received.insert(node.config.node_id);
    node.save_state();

    let term = node.state.current_term;
    let candidate_id = node.config.node_id;
    let last_log_index = node.last_log_index();
    let last_log_term = node.last_log_term();

    let peers: Vec<NodeInfo> = node.config.peers.clone();
    let mut vote_futures = Vec::new();
    for peer in &peers {
        let addr = peer.addr.clone();
        let req = raft_proto::RequestVoteRequest {
            term,
            candidate_id,
            last_log_index,
            last_log_term,
        };
        vote_futures.push(async move { (peer.id, send_request_vote(&addr, req).await) });
    }

    let results = futures_util::future::join_all(vote_futures).await;
    let quorum = node.quorum_size();
    for (peer_id, resp) in results {
        let Some(resp) = resp else { continue };
        if resp.term > node.state.current_term {
            node.become_follower(resp.term);
            return;
        }
        if resp.vote_granted && node.state.current_term == term {
            node.votes_received.insert(peer_id);
        }
    }

    if node.votes_received.len() >= quorum {
        node.become_leader();
        send_heartbeats_to_peers(node).await;
        node.try_advance_commit();
        node.notify_committed_proposals();
        apply_committed(node, &state_machine).await;
    }
}

async fn send_heartbeats_to_peers(node: &mut RaftNode) {
    let peers: Vec<NodeInfo> = node.config.peers.clone();
    let term = node.state.current_term;
    let leader_id = node.config.node_id;
    let commit_index = node.commit_index;

    let mut futs = Vec::new();
    for peer in &peers {
        let next = *node.next_index.get(&peer.id).unwrap_or(&1);
        let prev_log_index = next.saturating_sub(1);
        let prev_log_term = node.log_term_at(prev_log_index);
        let entries: Vec<raft_proto::LogEntry> = node
            .log
            .iter()
            .filter(|e| e.index >= next)
            .map(to_proto_entry)
            .collect();
        let addr = peer.addr.clone();
        let peer_id = peer.id;
        let req = raft_proto::AppendEntriesRequest {
            term,
            leader_id,
            prev_log_index,
            prev_log_term,
            entries,
            leader_commit: commit_index,
        };
        futs.push(async move { (peer_id, send_append_entries(&addr, req).await) });
    }

    let results = futures_util::future::join_all(futs).await;
    for (peer_id, resp) in results {
        let Some(resp) = resp else { continue };
        if resp.term > node.state.current_term {
            node.become_follower(resp.term);
            return;
        }
        if resp.success {
            // Update match_index / next_index
            let last_sent = node.log.last().map(|e| e.index).unwrap_or(0);
            node.match_index.insert(peer_id, last_sent);
            node.next_index.insert(peer_id, last_sent + 1);
        } else if resp.conflict_index > 0 {
            node.next_index.insert(peer_id, resp.conflict_index);
        } else {
            let cur = *node.next_index.get(&peer_id).unwrap_or(&1);
            node.next_index
                .insert(peer_id, cur.saturating_sub(1).max(1));
        }
    }

    node.try_advance_commit();
}

// ── futures_util shim (join_all without adding a dep) ────────────────────────
mod futures_util {
    pub mod future {
        pub async fn join_all<F, T>(futs: Vec<F>) -> Vec<T>
        where
            F: std::future::Future<Output = T>,
        {
            let mut results = Vec::with_capacity(futs.len());
            for fut in futs {
                results.push(fut.await);
            }
            results
        }
    }
}

// ── Handle exposed to the rest of the system ─────────────────────────────────

#[derive(Clone)]
pub struct RaftHandle {
    tx: mpsc::Sender<RaftInput>,
    state_machine: Arc<RwLock<CatalogStateMachine>>,
}

impl RaftHandle {
    pub fn new(
        tx: mpsc::Sender<RaftInput>,
        state_machine: Arc<RwLock<CatalogStateMachine>>,
    ) -> Self {
        Self { tx, state_machine }
    }

    /// Propose a catalog command. Blocks until committed or returns error.
    pub async fn propose(&self, cmd: CatalogCommand) -> Result<(), String> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(RaftInput::Propose { cmd, tx: resp_tx })
            .await
            .map_err(|_| "raft channel closed".to_string())?;
        resp_rx.await.map_err(|_| "raft loop gone".to_string())?
    }

    /// Get the current committed catalog (read from state machine).
    pub async fn read_catalog(&self) -> CatalogStateMachine {
        let sm = self.state_machine.read().await;
        // CatalogStateMachine doesn't derive Clone; reconstruct via snapshot
        CatalogStateMachine::restore(&sm.snapshot())
    }

    /// Handle an incoming AppendEntries RPC.
    pub async fn append_entries(&self, req: AppendEntriesReq) -> AppendEntriesResp {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(RaftInput::AppendEntries { req, tx })
            .await
            .is_err()
        {
            return AppendEntriesResp {
                term: 0,
                success: false,
                conflict_index: 0,
                conflict_term: 0,
            };
        }
        rx.await.unwrap_or(AppendEntriesResp {
            term: 0,
            success: false,
            conflict_index: 0,
            conflict_term: 0,
        })
    }

    /// Handle an incoming RequestVote RPC.
    pub async fn request_vote(&self, req: RequestVoteReq) -> RequestVoteResp {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(RaftInput::RequestVote { req, tx })
            .await
            .is_err()
        {
            return RequestVoteResp {
                term: 0,
                vote_granted: false,
            };
        }
        rx.await.unwrap_or(RequestVoteResp {
            term: 0,
            vote_granted: false,
        })
    }

    pub fn state_machine(&self) -> Arc<RwLock<CatalogStateMachine>> {
        Arc::clone(&self.state_machine)
    }
}

/// Convenience: spawn a Raft node and return a handle to it.
pub fn spawn_raft(config: RaftConfig) -> RaftHandle {
    let (tx, rx) = mpsc::channel(256);
    let state_machine = Arc::new(RwLock::new(CatalogStateMachine::default()));
    let sm_clone = Arc::clone(&state_machine);
    let handle = RaftHandle::new(tx, state_machine);
    tokio::spawn(run_raft(config, sm_clone, rx));
    handle
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn catalog_command_serialization_roundtrip() {
        let cmd = CatalogCommand::CreateCollection {
            config: CollectionConfig {
                name: "test".to_string(),
                vector_dim: 4,
                metric: crate::DistanceMetric::Cosine,
                shards: 1,
                replicas: 1,
                quantization: None,
                payload_schema: HashMap::new(),
                named_vector_dims: HashMap::new(),
                hnsw_m: None,
                hnsw_ef_construction: None,
                hnsw_ef_search: None,
                recall_sla: None,
                index_kind: None,
                streamer_max_bytes: 0,
            },
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let back: CatalogCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(cmd, back);
    }

    #[test]
    fn noop_roundtrip() {
        let cmd = CatalogCommand::Noop;
        let json = serde_json::to_string(&cmd).unwrap();
        let back: CatalogCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(cmd, back);
    }

    #[test]
    fn state_machine_apply_create_and_delete() {
        let mut sm = CatalogStateMachine::default();
        let config = CollectionConfig {
            name: "docs".to_string(),
            vector_dim: 128,
            metric: crate::DistanceMetric::Cosine,
            shards: 1,
            replicas: 1,
            quantization: None,
            payload_schema: HashMap::new(),
            named_vector_dims: HashMap::new(),
            hnsw_m: None,
            hnsw_ef_construction: None,
            hnsw_ef_search: None,
            recall_sla: None,
            index_kind: None,
            streamer_max_bytes: 0,
        };
        sm.apply(&RaftLogEntry {
            term: 1,
            index: 1,
            command: CatalogCommand::CreateCollection {
                config: config.clone(),
            },
        });
        assert_eq!(sm.last_applied, 1);
        assert!(sm.collections.contains_key("docs"));

        sm.apply(&RaftLogEntry {
            term: 1,
            index: 2,
            command: CatalogCommand::DeleteCollection {
                name: "docs".to_string(),
            },
        });
        assert_eq!(sm.last_applied, 2);
        assert!(!sm.collections.contains_key("docs"));
    }

    #[test]
    fn state_machine_snapshot_restore() {
        let mut sm = CatalogStateMachine::default();
        sm.apply(&RaftLogEntry {
            term: 1,
            index: 1,
            command: CatalogCommand::CreateCollection {
                config: CollectionConfig {
                    name: "snap".to_string(),
                    vector_dim: 8,
                    metric: crate::DistanceMetric::Dot,
                    shards: 2,
                    replicas: 1,
                    quantization: None,
                    payload_schema: HashMap::new(),
                    named_vector_dims: HashMap::new(),
                    hnsw_m: None,
                    hnsw_ef_construction: None,
                    hnsw_ef_search: None,
                    recall_sla: None,
                    index_kind: None,
                    streamer_max_bytes: 0,
                },
            },
        });
        let bytes = sm.snapshot();
        let restored = CatalogStateMachine::restore(&bytes);
        assert!(restored.collections.contains_key("snap"));
        assert_eq!(restored.last_applied, 1);
    }

    #[test]
    fn persistent_state_save_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("raft_state.json");
        let state = RaftPersistentState {
            current_term: 7,
            voted_for: Some(3),
        };
        state.save(&path);
        let loaded = RaftPersistentState::load(&path);
        assert_eq!(loaded.current_term, 7);
        assert_eq!(loaded.voted_for, Some(3));
    }

    #[test]
    fn persistent_state_defaults_when_missing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("no_file.json");
        let loaded = RaftPersistentState::load(&path);
        assert_eq!(loaded.current_term, 0);
        assert_eq!(loaded.voted_for, None);
    }
}
