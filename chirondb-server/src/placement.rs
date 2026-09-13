use std::collections::HashMap;
use std::hash::{Hash, Hasher};

/// A node in the cluster.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ClusterNode {
    pub id: u64,
    pub addr: String,         // "host:port"
    pub zone: Option<String>, // availability zone for affinity
}

/// Assigns shards to nodes using rendezvous (HRW) hashing.
/// Returns a map from shard_index → node_ids (ordered: primary first).
pub fn assign_shards(
    collection: &str,
    shard_count: u32,
    nodes: &[ClusterNode],
    replicas: u32,
) -> HashMap<u32, Vec<u64>> {
    let replicas = replicas as usize;
    let mut assignment = HashMap::with_capacity(shard_count as usize);
    for shard in 0..shard_count {
        let mut scored: Vec<(u64, u64)> = nodes
            .iter()
            .map(|node| {
                let score = hrw_score(collection, shard, node.id);
                (score, node.id)
            })
            .collect();
        // Sort descending by score; break ties by node id for stability
        scored.sort_unstable_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        let picked: Vec<u64> = scored
            .into_iter()
            .take(replicas.min(nodes.len()))
            .map(|(_, id)| id)
            .collect();
        assignment.insert(shard, picked);
    }
    assignment
}

/// Returns the primary node (first replica) for a given shard.
pub fn primary_for_shard(shard: u32, assignment: &HashMap<u32, Vec<u64>>) -> Option<u64> {
    assignment
        .get(&shard)
        .and_then(|replicas| replicas.first().copied())
}

/// A shard migration step produced by rebalancing.
pub struct ShardMigration {
    pub shard: u32,
    pub from_node: u64,
    pub to_node: u64,
}

/// Given a change in cluster membership, returns the minimal migration plan.
pub fn compute_rebalance(
    collection: &str,
    shard_count: u32,
    old_nodes: &[ClusterNode],
    new_nodes: &[ClusterNode],
    replicas: u32,
) -> Vec<ShardMigration> {
    let old_assignment = assign_shards(collection, shard_count, old_nodes, replicas);
    let new_assignment = assign_shards(collection, shard_count, new_nodes, replicas);

    let mut migrations = Vec::new();
    for shard in 0..shard_count {
        let old_replicas = old_assignment.get(&shard).cloned().unwrap_or_default();
        let new_replicas = new_assignment.get(&shard).cloned().unwrap_or_default();
        // Nodes that need to gain this shard
        let added: Vec<u64> = new_replicas
            .iter()
            .filter(|id| !old_replicas.contains(id))
            .copied()
            .collect();
        // Nodes that need to lose this shard
        let removed: Vec<u64> = old_replicas
            .iter()
            .filter(|id| !new_replicas.contains(id))
            .copied()
            .collect();
        // Pair up removals with additions (1-to-1 migration)
        for (from_node, to_node) in removed.into_iter().zip(added) {
            migrations.push(ShardMigration {
                shard,
                from_node,
                to_node,
            });
        }
    }
    migrations
}

/// Compute a rendezvous score for (collection, shard, node_id).
/// Uses DefaultHasher with a manual mixing strategy to produce distinct seeds.
fn hrw_score(collection: &str, shard: u32, node_id: u64) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    collection.hash(&mut hasher);
    shard.hash(&mut hasher);
    node_id.hash(&mut hasher);
    // Mix in a second pass seeded by node_id to reduce correlation
    let first = hasher.finish();
    let mut hasher2 = DefaultHasher::new();
    first.hash(&mut hasher2);
    node_id.hash(&mut hasher2);
    hasher2.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_nodes(ids: &[u64]) -> Vec<ClusterNode> {
        ids.iter()
            .map(|&id| ClusterNode {
                id,
                addr: format!("127.0.0.1:{}", 7400 + id),
                zone: None,
            })
            .collect()
    }

    #[test]
    fn rendezvous_is_deterministic() {
        let nodes = make_nodes(&[1, 2, 3]);
        let a = assign_shards("my_collection", 8, &nodes, 2);
        let b = assign_shards("my_collection", 8, &nodes, 2);
        assert_eq!(a, b);
    }

    #[test]
    fn rendezvous_rebalance_minimizes_moves() {
        let old_nodes = make_nodes(&[1, 2, 3]);
        let new_nodes = make_nodes(&[1, 2, 3, 4]);
        let shard_count = 12u32;
        let replicas = 1u32;
        let migrations = compute_rebalance("col", shard_count, &old_nodes, &new_nodes, replicas);
        // Adding 1 node to a 3-node cluster: ~1/4 of shards should migrate (≈3 shards)
        // Allow some slack: must be ≤ ceil(shard_count / old_node_count) * 2
        assert!(
            migrations.len() <= (shard_count / 3 + 2) as usize,
            "too many migrations: {}",
            migrations.len()
        );
        // Must also be > 0 (the new node must receive something)
        assert!(!migrations.is_empty(), "new node received no shards");
    }

    #[test]
    fn primary_for_shard_returns_first_replica() {
        let nodes = make_nodes(&[10, 20, 30]);
        let assignment = assign_shards("col", 4, &nodes, 3);
        for shard in 0..4u32 {
            let primary = primary_for_shard(shard, &assignment);
            let expected = assignment[&shard].first().copied();
            assert_eq!(primary, expected);
        }
    }
}
