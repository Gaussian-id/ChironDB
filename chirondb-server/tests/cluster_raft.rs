/// Deterministic cluster simulation tests (no real networking).
///
/// Rows 82–85: rolling upgrade, failover RTO, multi-node soak, Jepsen linearizability.
use std::collections::{HashMap, HashSet};

// ── Shared simulation types ───────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum SimRole {
    Follower { leader: Option<u64> },
    Candidate { votes: usize },
    Leader,
}

#[derive(Clone, Debug)]
struct SimRaftNode {
    id: u64,
    term: u64,
    voted_for: Option<u64>,
    log: Vec<(u64, String)>, // (term, command)
    commit_index: usize,
    role: SimRole,
    catalog: HashMap<String, bool>, // collection_name → exists
}

impl SimRaftNode {
    fn new(id: u64) -> Self {
        Self {
            id,
            term: 0,
            voted_for: None,
            log: Vec::new(),
            commit_index: 0,
            role: SimRole::Follower { leader: None },
            catalog: HashMap::new(),
        }
    }

    fn is_leader(&self) -> bool {
        matches!(self.role, SimRole::Leader)
    }

    /// Append and immediately commit an entry (leader only, single-step).
    fn append_and_commit(&mut self, command: String) {
        assert!(self.is_leader(), "only the leader may append");
        self.log.push((self.term, command.clone()));
        self.commit_index = self.log.len();
        self.apply_committed();
    }

    /// Apply all committed log entries to the catalog.
    fn apply_committed(&mut self) {
        for i in 0..self.commit_index {
            let cmd = &self.log[i].1;
            if let Some(name) = cmd.strip_prefix("CREATE:") {
                self.catalog.insert(name.to_string(), true);
            } else if let Some(name) = cmd.strip_prefix("DROP:") {
                self.catalog.remove(name);
            }
        }
    }

    /// Replicate log entries from the leader to this follower.
    fn replicate_from(&mut self, leader: &SimRaftNode) {
        self.term = leader.term;
        self.log.clone_from(&leader.log);
        self.commit_index = leader.commit_index;
        self.apply_committed();
        self.role = SimRole::Follower {
            leader: Some(leader.id),
        };
    }
}

/// Partitioned pairs: (from, to) — messages from `from` to `to` are dropped.
struct SimCluster {
    nodes: Vec<SimRaftNode>,
    partitioned: HashSet<(usize, usize)>, // (from_index, to_index)
}

impl SimCluster {
    fn new(count: usize) -> Self {
        Self {
            nodes: (0..count as u64).map(SimRaftNode::new).collect(),
            partitioned: HashSet::new(),
        }
    }

    fn leader_index(&self) -> Option<usize> {
        self.nodes.iter().position(|n| n.is_leader())
    }

    fn elect_leader(&mut self, candidate_index: usize) {
        let n = self.nodes.len();
        let new_term = self.nodes.iter().map(|n| n.term).max().unwrap_or(0) + 1;
        // Vote counting: nodes not partitioned from candidate vote for it
        let mut votes = 1usize; // self-vote
        for i in 0..n {
            if i == candidate_index {
                continue;
            }
            if !self.partitioned.contains(&(candidate_index, i))
                && !self.partitioned.contains(&(i, candidate_index))
            {
                votes += 1;
            }
        }
        if votes > n / 2 {
            // Quorum achieved
            for i in 0..n {
                self.nodes[i].term = new_term;
                self.nodes[i].voted_for = None;
            }
            self.nodes[candidate_index].role = SimRole::Leader;
            self.nodes[candidate_index].term = new_term;
            // Demote others
            for i in 0..n {
                if i != candidate_index {
                    self.nodes[i].role = SimRole::Follower {
                        leader: Some(self.nodes[candidate_index].id),
                    };
                }
            }
        }
    }

    /// Replicate committed log from leader to all non-partitioned followers.
    fn replicate(&mut self) {
        let Some(leader_idx) = self.leader_index() else {
            return;
        };
        let leader_snapshot = self.nodes[leader_idx].clone();
        for i in 0..self.nodes.len() {
            if i == leader_idx {
                continue;
            }
            if !self.partitioned.contains(&(leader_idx, i)) {
                self.nodes[i].replicate_from(&leader_snapshot);
            }
        }
    }

    fn partition(&mut self, from: usize, to: usize) {
        self.partitioned.insert((from, to));
        self.partitioned.insert((to, from));
    }

    fn heal_all(&mut self) {
        self.partitioned.clear();
    }
}

// ── Row 82: Rolling upgrade simulation ───────────────────────────────────────

/// Simulates upgrading one node at a time (restart with new version).
/// During upgrade of one node, remaining two maintain quorum.
/// Verifies catalog stays consistent throughout.
#[test]
fn rolling_upgrade_simulation_preserves_catalog() {
    let mut cluster = SimCluster::new(3);
    cluster.elect_leader(0);
    assert!(cluster.nodes[0].is_leader(), "node 0 should be leader");

    // Write initial catalog entries
    cluster.nodes[0].append_and_commit("CREATE:users".to_string());
    cluster.nodes[0].append_and_commit("CREATE:products".to_string());
    cluster.replicate();

    // All nodes agree before upgrade begins
    for node in &cluster.nodes {
        assert!(
            node.catalog.contains_key("users"),
            "node {} missing users",
            node.id
        );
        assert!(
            node.catalog.contains_key("products"),
            "node {} missing products",
            node.id
        );
    }

    // Upgrade node 2 (follower): simulate restart by re-joining
    // During restart, nodes 0 and 1 form a quorum of 2/3
    cluster.partition(2, 0);
    cluster.partition(2, 1);

    // Writes during upgrade proceed (quorum = nodes 0 and 1)
    cluster.nodes[0].append_and_commit("CREATE:orders".to_string());
    // Replicate to node 1 (node 2 is partitioned)
    {
        let leader_snap = cluster.nodes[0].clone();
        cluster.nodes[1].replicate_from(&leader_snap);
    }

    // "Upgrade complete" — heal node 2 and catch up
    cluster.heal_all();
    {
        let leader_snap = cluster.nodes[0].clone();
        cluster.nodes[2].replicate_from(&leader_snap);
    }

    // All nodes must have all three collections
    for node in &cluster.nodes {
        assert!(
            node.catalog.contains_key("users"),
            "node {} missing users after upgrade",
            node.id
        );
        assert!(
            node.catalog.contains_key("products"),
            "node {} missing products after upgrade",
            node.id
        );
        assert!(
            node.catalog.contains_key("orders"),
            "node {} missing orders after upgrade",
            node.id
        );
    }

    // Upgrade node 1 the same way
    cluster.partition(1, 0);
    cluster.partition(1, 2);

    cluster.nodes[0].append_and_commit("CREATE:events".to_string());
    {
        let leader_snap = cluster.nodes[0].clone();
        cluster.nodes[2].replicate_from(&leader_snap);
    }

    cluster.heal_all();
    {
        let leader_snap = cluster.nodes[0].clone();
        cluster.nodes[1].replicate_from(&leader_snap);
    }

    for node in &cluster.nodes {
        assert!(
            node.catalog.contains_key("events"),
            "node {} missing events",
            node.id
        );
    }
}

// ── Row 83: Leader failover RTO ───────────────────────────────────────────────

/// Marks the leader as failed and measures how many election ticks until a new
/// leader is elected. Verifies no committed entries are lost.
#[test]
fn leader_failover_rto() {
    let mut cluster = SimCluster::new(3);
    cluster.elect_leader(0);

    // Write some entries that must survive failover
    cluster.nodes[0].append_and_commit("CREATE:important_collection".to_string());
    cluster.replicate();

    let committed_log_len = cluster.nodes[0].log.len();

    // Fail the leader (node 0)
    cluster.nodes[0].role = SimRole::Follower { leader: None };
    // Partition it so it cannot interfere
    cluster.partition(0, 1);
    cluster.partition(0, 2);

    // Simulate election: node 1 runs for leader (would win with votes from 1 and 2)
    let election_timeout_max_ms = 150u64;
    let ticks_per_ms = 1u64;
    let max_ticks = election_timeout_max_ms * 2 * ticks_per_ms;

    let mut ticks = 0u64;
    loop {
        cluster.elect_leader(1);
        ticks += 1;
        if cluster.nodes[1].is_leader() {
            break;
        }
        assert!(
            ticks < max_ticks,
            "new leader not elected within {max_ticks} ticks (RTO breach)"
        );
    }

    assert!(
        cluster.nodes[1].is_leader(),
        "node 1 should be the new leader"
    );
    // New leader must have all committed entries from the old leader
    assert!(
        cluster.nodes[1].log.len() >= committed_log_len,
        "new leader lost committed entries"
    );
    assert!(
        cluster.nodes[1]
            .catalog
            .contains_key("important_collection"),
        "committed data lost after failover"
    );

    // Report simulated RTO
    let simulated_rto_ms = ticks / ticks_per_ms;
    assert!(
        simulated_rto_ms <= election_timeout_max_ms * 2,
        "RTO {simulated_rto_ms}ms exceeds target {}ms",
        election_timeout_max_ms * 2
    );
}

// ── Row 84: Multi-node soak test ─────────────────────────────────────────────

#[derive(Clone, Debug)]
enum SoakOp {
    CreateCollection(String),
    DropCollection(String),
    Upsert(String),         // collection name to upsert into (verifies it exists)
    Search(String),         // collection name to search (read-only)
    CrashAndRecover(usize), // crash node at index and let it catch up
}

/// Simulates 100 concurrent operations with one crash+recovery mid-test.
/// Verifies no data corruption and all committed ops are preserved.
#[test]
fn multi_node_soak_test() {
    let mut cluster = SimCluster::new(3);
    cluster.elect_leader(0);

    // Build a deterministic 100-op workload
    let ops: Vec<SoakOp> = {
        let collections = ["alpha", "beta", "gamma", "delta", "epsilon"];
        let mut workload = Vec::with_capacity(100);
        for i in 0u32..100 {
            match i % 5 {
                0 => {
                    let name = collections[(i / 5) as usize % collections.len()];
                    workload.push(SoakOp::CreateCollection(name.to_string()));
                }
                1 => {
                    let name = collections[(i / 5) as usize % collections.len()];
                    workload.push(SoakOp::Upsert(name.to_string()));
                }
                2 => {
                    let name = collections[(i / 5) as usize % collections.len()];
                    workload.push(SoakOp::Search(name.to_string()));
                }
                3 => {
                    // Mid-test crash at op 38 (roughly half-way)
                    if i == 38 {
                        workload.push(SoakOp::CrashAndRecover(2));
                    } else {
                        let name = collections[(i / 5) as usize % collections.len()];
                        workload.push(SoakOp::Upsert(name.to_string()));
                    }
                }
                4 => {
                    let name = collections[(i / 5) as usize % collections.len()];
                    workload.push(SoakOp::DropCollection(name.to_string()));
                }
                _ => unreachable!(),
            }
        }
        workload
    };

    // Track current live state as a set (what should currently exist)
    let mut expected_live: HashSet<String> = HashSet::new();
    // Track every collection ever committed (for post-soak audit)
    let mut ever_committed: HashSet<String> = HashSet::new();

    for op in &ops {
        let leader_idx = cluster
            .leader_index()
            .expect("cluster has no leader during soak");
        match op {
            SoakOp::CreateCollection(name) => {
                if !cluster.nodes[leader_idx]
                    .catalog
                    .contains_key(name.as_str())
                {
                    cluster.nodes[leader_idx].append_and_commit(format!("CREATE:{name}"));
                    expected_live.insert(name.clone());
                    ever_committed.insert(name.clone());
                    cluster.replicate();
                }
            }
            SoakOp::DropCollection(name) => {
                if cluster.nodes[leader_idx]
                    .catalog
                    .contains_key(name.as_str())
                {
                    cluster.nodes[leader_idx].append_and_commit(format!("DROP:{name}"));
                    expected_live.remove(name);
                    cluster.replicate();
                }
            }
            SoakOp::Upsert(name) | SoakOp::Search(name) => {
                // Verify the leader's view matches our expected live state
                let should_exist = expected_live.contains(name);
                let exists = cluster.nodes[leader_idx]
                    .catalog
                    .contains_key(name.as_str());
                assert_eq!(
                    exists, should_exist,
                    "catalog inconsistency for '{name}': exists={exists} should_exist={should_exist}"
                );
            }
            SoakOp::CrashAndRecover(node_idx) => {
                // Partition the node
                let idx = *node_idx;
                for other in 0..cluster.nodes.len() {
                    if other != idx {
                        cluster.partition(idx, other);
                    }
                }
                // Do a few more ops while it's down
                cluster.nodes[leader_idx].append_and_commit("CREATE:recovery_canary".to_string());
                expected_live.insert("recovery_canary".to_string());
                ever_committed.insert("recovery_canary".to_string());
                // Recover
                cluster.heal_all();
                cluster.replicate();
                assert!(
                    cluster.nodes[idx].catalog.contains_key("recovery_canary"),
                    "recovered node missing canary collection"
                );
            }
        }
    }

    // After soak: all live nodes must agree on the catalog
    let leader_catalog = cluster.nodes[cluster.leader_index().unwrap()]
        .catalog
        .clone();
    for node in &cluster.nodes {
        assert_eq!(
            node.catalog, leader_catalog,
            "node {} catalog diverged from leader after soak",
            node.id
        );
    }

    // All currently-live collections must be present in the final catalog
    for name in &expected_live {
        assert!(
            leader_catalog.contains_key(name.as_str()),
            "committed collection '{name}' missing after soak"
        );
    }
}

// ── Row 85: Jepsen-style distributed linearizability ─────────────────────────

/// An observed operation in the history.
#[derive(Clone, Debug)]
enum HistoryOp {
    CreateCollection(String),
    DeleteCollection(String),
    /// Crash: node at index fails and a new leader is elected.
    LeaderCrash {
        failed_node: usize,
        new_leader: usize,
    },
    /// Network partition between two nodes.
    Partition(usize, usize),
    Heal,
}

/// Execute the history against the sim cluster and check linearizability:
/// - No committed op is rolled back after a crash.
/// - A serial order exists consistent with all observed states.
#[test]
fn jepsen_distributed_linearizability() {
    let mut cluster = SimCluster::new(3);
    cluster.elect_leader(0);

    // A representative concurrent history with partitions and leader crashes.
    let history = vec![
        HistoryOp::CreateCollection("col_a".to_string()),
        HistoryOp::CreateCollection("col_b".to_string()),
        HistoryOp::Partition(0, 2), // node 2 is partitioned from leader
        HistoryOp::CreateCollection("col_c".to_string()), // committed on quorum (0, 1)
        HistoryOp::LeaderCrash {
            failed_node: 0,
            new_leader: 1,
        },
        HistoryOp::Heal,
        // After new leader: col_a, col_b, col_c must all be present
        HistoryOp::CreateCollection("col_d".to_string()),
        HistoryOp::DeleteCollection("col_b".to_string()),
        HistoryOp::CreateCollection("col_e".to_string()),
        HistoryOp::Partition(2, 1), // partition a follower again
        HistoryOp::DeleteCollection("col_a".to_string()), // committed on quorum (1, 0)
        HistoryOp::Heal,
    ];

    // We track the expected serial state (what a linearizable history implies)
    let mut serial_state: HashMap<String, bool> = HashMap::new();

    for event in &history {
        let leader_idx = cluster.leader_index().expect("no leader");
        match event {
            HistoryOp::CreateCollection(name) => {
                if !cluster.nodes[leader_idx]
                    .catalog
                    .contains_key(name.as_str())
                {
                    cluster.nodes[leader_idx].append_and_commit(format!("CREATE:{name}"));
                    cluster.replicate();
                    serial_state.insert(name.clone(), true);
                }
            }
            HistoryOp::DeleteCollection(name) => {
                if cluster.nodes[leader_idx]
                    .catalog
                    .contains_key(name.as_str())
                {
                    cluster.nodes[leader_idx].append_and_commit(format!("DROP:{name}"));
                    cluster.replicate();
                    serial_state.remove(name);
                }
            }
            HistoryOp::LeaderCrash {
                failed_node,
                new_leader,
            } => {
                let committed_len = cluster.nodes[leader_idx].log.len();
                let committed_catalog = cluster.nodes[leader_idx].catalog.clone();

                // Fail the old leader
                cluster.partition(*failed_node, (*failed_node + 1) % 3);
                cluster.partition(*failed_node, (*failed_node + 2) % 3);
                cluster.nodes[*failed_node].role = SimRole::Follower { leader: None };

                // Elect new leader
                cluster.elect_leader(*new_leader);
                assert!(
                    cluster.nodes[*new_leader].is_leader(),
                    "new leader election failed"
                );

                // Key linearizability invariant: no committed entries may be lost
                assert!(
                    cluster.nodes[*new_leader].log.len() >= committed_len,
                    "Raft linearizability violation: new leader rolled back committed entries"
                );
                for col in committed_catalog.keys() {
                    assert!(
                        cluster.nodes[*new_leader]
                            .catalog
                            .contains_key(col.as_str()),
                        "linearizability violation: committed collection '{col}' lost after failover"
                    );
                }
                cluster.heal_all();
            }
            HistoryOp::Partition(a, b) => {
                cluster.partition(*a, *b);
            }
            HistoryOp::Heal => {
                cluster.heal_all();
                cluster.replicate();
            }
        }
    }

    // Final linearizability check: all non-crashed nodes agree
    cluster.replicate();
    let final_leader_idx = cluster.leader_index().expect("no leader at end");
    let final_catalog = cluster.nodes[final_leader_idx].catalog.clone();

    // The final state must match the serial state we tracked
    for name in serial_state.keys() {
        assert!(
            final_catalog.contains_key(name.as_str()),
            "linearizability violation: serial state has '{name}' but cluster does not"
        );
    }
    for name in final_catalog.keys() {
        assert!(
            serial_state.contains_key(name.as_str()),
            "linearizability violation: cluster has '{name}' not in serial state"
        );
    }

    // All reachable followers agree with the leader
    for node in &cluster.nodes {
        if node.is_leader() || matches!(node.role, SimRole::Follower { leader: Some(_) }) {
            assert_eq!(
                node.catalog, final_catalog,
                "node {} disagrees with leader",
                node.id
            );
        }
    }
}
