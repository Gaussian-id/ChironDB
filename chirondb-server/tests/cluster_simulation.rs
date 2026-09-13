use std::collections::BTreeMap;

#[derive(Clone, Debug)]
struct Operation {
    lsn: u64,
    key: &'static str,
    value: &'static str,
}

#[derive(Clone, Debug, Default)]
struct SimNode {
    log: Vec<Operation>,
    applied: BTreeMap<&'static str, &'static str>,
    applied_lsn: u64,
}

impl SimNode {
    fn receive(&mut self, operation: Operation) {
        if self
            .log
            .iter()
            .any(|existing| existing.lsn == operation.lsn)
        {
            return;
        }
        self.log.push(operation);
    }

    fn apply_ordered_prefix(&mut self) {
        self.log.sort_by_key(|operation| operation.lsn);
        let mut next_lsn = self.applied_lsn + 1;
        for operation in &self.log {
            if operation.lsn <= self.applied_lsn {
                continue;
            }
            if operation.lsn != next_lsn {
                break;
            }
            self.applied.insert(operation.key, operation.value);
            self.applied_lsn = operation.lsn;
            next_lsn += 1;
        }
    }
}

#[derive(Clone, Debug)]
enum Event {
    Propose(Operation),
    Deliver { node: usize, lsn: u64 },
    Heal,
    Partition(usize),
}

#[derive(Debug)]
struct SimCluster {
    leader_log: Vec<Operation>,
    nodes: Vec<SimNode>,
    partitioned: Vec<bool>,
}

impl SimCluster {
    fn new(nodes: usize) -> Self {
        Self {
            leader_log: Vec::new(),
            nodes: vec![SimNode::default(); nodes],
            partitioned: vec![false; nodes],
        }
    }

    fn run(&mut self, events: &[Event]) {
        for event in events {
            match event {
                Event::Propose(operation) => self.leader_log.push(operation.clone()),
                Event::Deliver { node, lsn } => {
                    if !self.partitioned[*node]
                        && let Some(operation) = self.leader_log.iter().find(|op| op.lsn == *lsn)
                    {
                        self.nodes[*node].receive(operation.clone());
                    }
                }
                Event::Heal => self.partitioned.fill(false),
                Event::Partition(node) => self.partitioned[*node] = true,
            }
            for node in &mut self.nodes {
                node.apply_ordered_prefix();
            }
        }
    }

    fn catch_up_all(&mut self) {
        for node_index in 0..self.nodes.len() {
            self.partitioned[node_index] = false;
            for operation in self.leader_log.clone() {
                self.nodes[node_index].receive(operation);
            }
            self.nodes[node_index].apply_ordered_prefix();
        }
    }
}

#[test]
fn deterministic_cluster_log_simulation_handles_drop_reorder_and_partition() {
    let mut cluster = SimCluster::new(3);
    cluster.run(&[
        Event::Propose(Operation {
            lsn: 1,
            key: "a",
            value: "1",
        }),
        Event::Propose(Operation {
            lsn: 2,
            key: "b",
            value: "2",
        }),
        Event::Partition(2),
        Event::Deliver { node: 0, lsn: 2 },
        Event::Deliver { node: 1, lsn: 1 },
        Event::Deliver { node: 0, lsn: 1 },
        Event::Deliver { node: 1, lsn: 2 },
        Event::Deliver { node: 2, lsn: 1 },
        Event::Heal,
        Event::Deliver { node: 2, lsn: 1 },
        Event::Deliver { node: 2, lsn: 2 },
    ]);

    assert_eq!(cluster.nodes[0].applied.get("a"), Some(&"1"));
    assert_eq!(cluster.nodes[0].applied.get("b"), Some(&"2"));
    assert_eq!(cluster.nodes[1].applied, cluster.nodes[0].applied);
    assert_eq!(cluster.nodes[2].applied, cluster.nodes[0].applied);

    cluster.run(&[
        Event::Propose(Operation {
            lsn: 3,
            key: "c",
            value: "3",
        }),
        Event::Deliver { node: 2, lsn: 3 },
        Event::Deliver { node: 0, lsn: 3 },
    ]);
    assert_eq!(cluster.nodes[1].applied.get("c"), None);

    cluster.catch_up_all();
    let expected = cluster.nodes[0].applied.clone();
    assert!(cluster.nodes.iter().all(|node| node.applied == expected));
    assert_eq!(expected.get("c"), Some(&"3"));
}
