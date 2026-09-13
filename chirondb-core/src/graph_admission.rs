//! Process-wide admission control for graph traversal.
//!
//! A traversal reserves its declared memory and cold-byte allowances before
//! expansion. The two resources are accounted independently, while tenant and
//! collection fair shares prevent one noisy scope from consuming every permit.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        Condvar, LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use std::fs;

use crate::{
    GaussError, Result,
    graph::{GraphError, GraphErrorCode, TraversalBudget},
    tenant::TenantScope,
};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const FALLBACK_BYTES_PER_CORE: u64 = 256 * MIB;
const MIN_FALLBACK_CAPACITY: u64 = GIB;
const MAX_PROCESS_CAPACITY: u64 = 4 * GIB;
const WAIT_SLICE: Duration = Duration::from_millis(5);
const ADMISSION_TIMEOUT: Duration = Duration::from_millis(50);
const RETRY_AFTER_MS: u64 = 100;

static PROCESS_POOL: LazyLock<GraphAdmissionPool> = LazyLock::new(|| {
    let memory_capacity = process_memory_capacity();
    let cold_capacity = (memory_capacity / 4).max(1);
    GraphAdmissionPool::new(memory_capacity, cold_capacity, ADMISSION_TIMEOUT, true)
});

/// Reserves all aggregate resources required by one traversal.
pub(crate) fn acquire(
    collection: &str,
    scope: &TenantScope,
    budget: TraversalBudget,
    cancelled: &AtomicBool,
) -> Result<GraphAdmissionPermit<'static>> {
    let budget = budget.validate()?;
    PROCESS_POOL.acquire(
        collection,
        TenantKey::from_scope(scope),
        budget.max_memory_bytes,
        budget.cold.map_or(0, |cold| cold.max_bytes),
        cancelled,
    )
}

fn process_memory_capacity() -> u64 {
    if let Some(limit) = cgroup_memory_limit() {
        return (limit / 2).clamp(1, MAX_PROCESS_CAPACITY);
    }

    let workers = std::thread::available_parallelism()
        .map(|workers| workers.get() as u64)
        .unwrap_or(1);
    workers
        .saturating_mul(FALLBACK_BYTES_PER_CORE)
        .clamp(MIN_FALLBACK_CAPACITY, MAX_PROCESS_CAPACITY)
}

#[cfg(target_os = "linux")]
fn cgroup_memory_limit() -> Option<u64> {
    const LIMIT_PATHS: [&str; 2] = [
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ];
    LIMIT_PATHS.into_iter().find_map(|path| {
        let value = fs::read_to_string(path).ok()?;
        let limit = value.trim().parse::<u64>().ok()?;
        // Cgroup v1 commonly reports an enormous sentinel when no limit is
        // configured. Treat it as absent and use the host-derived fallback.
        (limit > 0 && limit < (1_u64 << 60)).then_some(limit)
    })
}

#[cfg(not(target_os = "linux"))]
fn cgroup_memory_limit() -> Option<u64> {
    None
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum TenantKey {
    Named(String),
    Unscoped,
}

impl TenantKey {
    fn from_scope(scope: &TenantScope) -> Self {
        scope
            .tenant_id()
            .map_or(Self::Unscoped, |tenant| Self::Named(tenant.to_owned()))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Reservation {
    memory: u64,
    cold: u64,
}

#[derive(Debug)]
struct Waiter {
    ticket: u64,
    tenant: TenantKey,
    collection: String,
    requested: Reservation,
}

#[derive(Debug, Default)]
struct AdmissionState {
    used: Reservation,
    by_tenant: HashMap<TenantKey, Reservation>,
    by_collection: HashMap<String, Reservation>,
    next_ticket: u64,
    queue: VecDeque<Waiter>,
}

struct GraphAdmissionPool {
    capacity: Reservation,
    timeout: Duration,
    state: Mutex<AdmissionState>,
    changed: Condvar,
    emit_metrics: bool,
}

impl GraphAdmissionPool {
    fn new(memory: u64, cold: u64, timeout: Duration, emit_metrics: bool) -> Self {
        Self {
            capacity: Reservation {
                memory: memory.max(1),
                cold: cold.max(1),
            },
            timeout,
            state: Mutex::new(AdmissionState::default()),
            changed: Condvar::new(),
            emit_metrics,
        }
    }

    fn acquire(
        &self,
        collection: &str,
        tenant: TenantKey,
        memory: u64,
        cold: u64,
        cancelled: &AtomicBool,
    ) -> Result<GraphAdmissionPermit<'_>> {
        let requested = Reservation { memory, cold };
        let started = Instant::now();
        if memory == 0 || memory > self.capacity.memory || cold > self.capacity.cold {
            self.observe_rejection("capacity", started);
            return Err(overloaded());
        }

        let mut state = self.lock_state();
        let ticket = state.next_ticket;
        state.next_ticket = state.next_ticket.wrapping_add(1);
        state.queue.push_back(Waiter {
            ticket,
            tenant: tenant.clone(),
            collection: collection.to_owned(),
            requested,
        });
        self.changed.notify_all();

        loop {
            if cancelled.load(Ordering::Acquire) {
                remove_waiter(&mut state.queue, ticket);
                self.changed.notify_all();
                drop(state);
                self.observe_cancellation(started);
                return Err(cancelled_error());
            }

            if let Some(position) = self.first_admissible(&state)
                && state.queue[position].ticket == ticket
            {
                let admitted = state
                    .queue
                    .remove(position)
                    .expect("admissible queue position must exist");
                add_reservation(&mut state.used, admitted.requested);
                add_map_reservation(
                    &mut state.by_tenant,
                    admitted.tenant.clone(),
                    admitted.requested,
                );
                add_map_reservation(
                    &mut state.by_collection,
                    admitted.collection.clone(),
                    admitted.requested,
                );
                let used = state.used;
                self.changed.notify_all();
                drop(state);
                self.observe_admission(started, used);
                return Ok(GraphAdmissionPermit {
                    pool: self,
                    tenant: admitted.tenant,
                    collection: admitted.collection,
                    reserved: admitted.requested,
                });
            }

            let elapsed = started.elapsed();
            if elapsed >= self.timeout {
                remove_waiter(&mut state.queue, ticket);
                self.changed.notify_all();
                drop(state);
                self.observe_rejection("timeout", started);
                return Err(overloaded());
            }
            let remaining = self.timeout.saturating_sub(elapsed).min(WAIT_SLICE);
            let (next, _) = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
        }
    }

    fn first_admissible(&self, state: &AdmissionState) -> Option<usize> {
        state.queue.iter().position(|waiter| {
            fits_total(state.used, waiter.requested, self.capacity)
                && fits_fair_share(
                    waiter,
                    state,
                    &state.by_tenant,
                    self.capacity,
                    |queued| &queued.tenant,
                    |queued| queued.requested,
                )
                && fits_fair_share(
                    waiter,
                    state,
                    &state.by_collection,
                    self.capacity,
                    |queued| &queued.collection,
                    |queued| queued.requested,
                )
        })
    }

    fn release(&self, permit: &GraphAdmissionPermit<'_>) {
        let mut state = self.lock_state();
        subtract_reservation(&mut state.used, permit.reserved);
        subtract_map_reservation(&mut state.by_tenant, &permit.tenant, permit.reserved);
        subtract_map_reservation(
            &mut state.by_collection,
            &permit.collection,
            permit.reserved,
        );
        let used = state.used;
        self.changed.notify_all();
        drop(state);
        self.observe_reserved(used);
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, AdmissionState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn observe_admission(&self, started: Instant, used: Reservation) {
        if self.emit_metrics {
            metrics::histogram!("graph_admission_wait_seconds")
                .record(started.elapsed().as_secs_f64());
            self.observe_reserved(used);
        }
    }

    fn observe_reserved(&self, used: Reservation) {
        if self.emit_metrics {
            metrics::gauge!("graph_pool_bytes_reserved").set(used.memory as f64);
            metrics::gauge!("graph_cold_pool_bytes_reserved").set(used.cold as f64);
        }
    }

    fn observe_rejection(&self, reason: &'static str, started: Instant) {
        if self.emit_metrics {
            metrics::counter!("graph_admission_rejected_total", "reason" => reason).increment(1);
            metrics::histogram!("graph_admission_wait_seconds")
                .record(started.elapsed().as_secs_f64());
        }
    }

    fn observe_cancellation(&self, started: Instant) {
        if self.emit_metrics {
            metrics::counter!("graph_admission_cancelled_total").increment(1);
            metrics::histogram!("graph_admission_wait_seconds")
                .record(started.elapsed().as_secs_f64());
        }
    }
}

pub(crate) struct GraphAdmissionPermit<'a> {
    pool: &'a GraphAdmissionPool,
    tenant: TenantKey,
    collection: String,
    reserved: Reservation,
}

impl Drop for GraphAdmissionPermit<'_> {
    fn drop(&mut self) {
        self.pool.release(self);
    }
}

fn fits_total(used: Reservation, requested: Reservation, capacity: Reservation) -> bool {
    used.memory.saturating_add(requested.memory) <= capacity.memory
        && used.cold.saturating_add(requested.cold) <= capacity.cold
}

fn fits_fair_share<K, FKey, FReservation>(
    waiter: &Waiter,
    state: &AdmissionState,
    in_use: &HashMap<K, Reservation>,
    capacity: Reservation,
    key_of: FKey,
    reservation_of: FReservation,
) -> bool
where
    K: Clone + Eq + std::hash::Hash,
    FKey: Fn(&Waiter) -> &K,
    FReservation: Fn(&Waiter) -> Reservation,
{
    let key = key_of(waiter);
    let current = in_use.get(key).copied().unwrap_or_default();
    resource_within_share(
        current.memory,
        waiter.requested.memory,
        capacity.memory,
        distinct_contenders(state, in_use, &key_of, &reservation_of, true),
    ) && resource_within_share(
        current.cold,
        waiter.requested.cold,
        capacity.cold,
        distinct_contenders(state, in_use, &key_of, &reservation_of, false),
    )
}

fn distinct_contenders<K, FKey, FReservation>(
    state: &AdmissionState,
    in_use: &HashMap<K, Reservation>,
    key_of: &FKey,
    reservation_of: &FReservation,
    memory: bool,
) -> u64
where
    K: Clone + Eq + std::hash::Hash,
    FKey: Fn(&Waiter) -> &K,
    FReservation: Fn(&Waiter) -> Reservation,
{
    let mut keys = HashSet::new();
    for (key, reservation) in in_use {
        let amount = if memory {
            reservation.memory
        } else {
            reservation.cold
        };
        if amount > 0 {
            keys.insert(key.clone());
        }
    }
    for waiter in &state.queue {
        let reservation = reservation_of(waiter);
        let amount = if memory {
            reservation.memory
        } else {
            reservation.cold
        };
        if amount > 0 {
            keys.insert(key_of(waiter).clone());
        }
    }
    keys.len().max(1) as u64
}

fn resource_within_share(current: u64, requested: u64, capacity: u64, contenders: u64) -> bool {
    requested == 0 || current.saturating_add(requested) <= capacity / contenders
}

fn add_reservation(target: &mut Reservation, amount: Reservation) {
    target.memory = target.memory.saturating_add(amount.memory);
    target.cold = target.cold.saturating_add(amount.cold);
}

fn subtract_reservation(target: &mut Reservation, amount: Reservation) {
    target.memory = target
        .memory
        .checked_sub(amount.memory)
        .expect("graph memory reservation underflow");
    target.cold = target
        .cold
        .checked_sub(amount.cold)
        .expect("graph cold reservation underflow");
}

fn add_map_reservation<K: Eq + std::hash::Hash>(
    reservations: &mut HashMap<K, Reservation>,
    key: K,
    amount: Reservation,
) {
    add_reservation(reservations.entry(key).or_default(), amount);
}

fn subtract_map_reservation<K: Eq + std::hash::Hash>(
    reservations: &mut HashMap<K, Reservation>,
    key: &K,
    amount: Reservation,
) {
    let remove = {
        let reservation = reservations
            .get_mut(key)
            .expect("graph reservation key must exist");
        subtract_reservation(reservation, amount);
        *reservation == Reservation::default()
    };
    if remove {
        reservations.remove(key);
    }
}

fn remove_waiter(queue: &mut VecDeque<Waiter>, ticket: u64) {
    if let Some(position) = queue.iter().position(|waiter| waiter.ticket == ticket) {
        queue.remove(position);
    }
}

fn overloaded() -> GaussError {
    GraphError::new(
        GraphErrorCode::Overloaded,
        "graph traversal capacity is temporarily unavailable",
    )
    .with_retry_after_ms(RETRY_AFTER_MS)
    .into()
}

fn cancelled_error() -> GaussError {
    GraphError::new(
        GraphErrorCode::Cancelled,
        "graph traversal was cancelled before admission",
    )
    .into()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Barrier, mpsc},
    };

    use serde_json::json;

    use super::*;
    use crate::{
        graph::{
            ColdTraversalBudget, EdgeId, EdgeMutation, GraphDirection, GraphEpoch, GraphNamespace,
            Nid, RelateMutation, TypeId,
        },
        graph_traversal::{MutableTraversal, exact_bfs},
        mutable_graph::MutableGraphState,
    };

    fn pool(memory: u64, cold: u64) -> GraphAdmissionPool {
        GraphAdmissionPool::new(memory, cold, Duration::from_millis(100), false)
    }

    fn key(name: &str) -> TenantKey {
        TenantKey::Named(name.to_owned())
    }

    fn graph_error(error: GaussError) -> GraphError {
        match error {
            GaussError::Graph(error) => error,
            other => panic!("expected graph error, got {other}"),
        }
    }

    fn result_error<T>(result: Result<T>) -> GraphError {
        match result {
            Err(error) => graph_error(error),
            Ok(_) => panic!("expected graph error"),
        }
    }

    #[test]
    fn aggregate_reservations_never_exceed_either_pool() {
        let pool = pool(100, 20);
        let cancelled = AtomicBool::new(false);
        let first = pool.acquire("c", key("a"), 60, 10, &cancelled).unwrap();
        let second = pool.acquire("c", key("b"), 40, 10, &cancelled).unwrap();

        let state = pool.lock_state();
        assert_eq!(
            state.used,
            Reservation {
                memory: 100,
                cold: 20
            }
        );
        drop(state);
        let error = result_error(pool.acquire("c", key("c"), 1, 0, &cancelled));
        assert_eq!(error.code, GraphErrorCode::Overloaded);
        assert_eq!(error.retry_after_ms, Some(RETRY_AFTER_MS));
        drop((first, second));
        assert_eq!(pool.lock_state().used, Reservation::default());
    }

    #[test]
    fn a_tenant_flood_cannot_head_of_line_block_another_tenant() {
        let pool = Arc::new(pool(100, 100));
        let cancelled = AtomicBool::new(false);
        let blocker = pool.acquire("c", key("a"), 100, 0, &cancelled).unwrap();
        let (order_tx, order_rx) = mpsc::channel();

        let a_pool = Arc::clone(&pool);
        let a_tx = order_tx.clone();
        let a = std::thread::spawn(move || {
            let cancelled = AtomicBool::new(false);
            let _permit = a_pool.acquire("c", key("a"), 60, 0, &cancelled).unwrap();
            a_tx.send("a").unwrap();
        });
        while pool.lock_state().queue.len() != 1 {
            std::thread::yield_now();
        }

        let b_pool = Arc::clone(&pool);
        let b = std::thread::spawn(move || {
            let cancelled = AtomicBool::new(false);
            let _permit = b_pool.acquire("c", key("b"), 40, 0, &cancelled).unwrap();
            order_tx.send("b").unwrap();
        });
        while pool.lock_state().queue.len() != 2 {
            std::thread::yield_now();
        }
        drop(blocker);

        assert_eq!(order_rx.recv_timeout(Duration::from_secs(1)).unwrap(), "b");
        a.join().unwrap();
        b.join().unwrap();
    }

    #[test]
    fn a_collection_flood_cannot_head_of_line_block_another_collection() {
        let pool = Arc::new(pool(100, 100));
        let cancelled = AtomicBool::new(false);
        let blocker = pool
            .acquire("flood", key("tenant"), 100, 0, &cancelled)
            .unwrap();
        let (order_tx, order_rx) = mpsc::channel();

        let flood_pool = Arc::clone(&pool);
        let flood_tx = order_tx.clone();
        let flood = std::thread::spawn(move || {
            let cancelled = AtomicBool::new(false);
            let _permit = flood_pool
                .acquire("flood", key("tenant"), 60, 0, &cancelled)
                .unwrap();
            flood_tx.send("flood").unwrap();
        });
        while pool.lock_state().queue.len() != 1 {
            std::thread::yield_now();
        }

        let fair_pool = Arc::clone(&pool);
        let fair = std::thread::spawn(move || {
            let cancelled = AtomicBool::new(false);
            let _permit = fair_pool
                .acquire("fair", key("tenant"), 40, 0, &cancelled)
                .unwrap();
            order_tx.send("fair").unwrap();
        });
        while pool.lock_state().queue.len() != 2 {
            std::thread::yield_now();
        }
        drop(blocker);

        assert_eq!(
            order_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            "fair"
        );
        flood.join().unwrap();
        fair.join().unwrap();
    }

    #[test]
    fn cancellation_removes_waiter_without_leaking_a_reservation() {
        let pool = Arc::new(pool(10, 10));
        let cancelled = AtomicBool::new(false);
        let blocker = pool.acquire("c", key("a"), 10, 0, &cancelled).unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        let waiter_pool = Arc::clone(&pool);
        let waiter_flag = Arc::clone(&flag);
        let waiter = std::thread::spawn(move || {
            result_error(waiter_pool.acquire("c", key("b"), 5, 0, &waiter_flag))
        });
        while pool.lock_state().queue.len() != 1 {
            std::thread::yield_now();
        }
        flag.store(true, Ordering::Release);
        let error = waiter.join().unwrap();
        assert_eq!(error.code, GraphErrorCode::Cancelled);
        assert!(pool.lock_state().queue.is_empty());
        assert_eq!(pool.lock_state().used.memory, 10);
        drop(blocker);
        assert_eq!(pool.lock_state().used, Reservation::default());
    }

    #[test]
    fn cold_and_memory_exhaustion_are_independent() {
        let cancelled = AtomicBool::new(false);
        let cold_pool = pool(100, 10);
        let cold_blocker = cold_pool
            .acquire("c", key("a"), 10, 10, &cancelled)
            .unwrap();
        let cold_error = result_error(cold_pool.acquire("c", key("b"), 10, 1, &cancelled));
        assert_eq!(cold_error.code, GraphErrorCode::Overloaded);
        drop(cold_blocker);

        let memory_pool = pool(10, 100);
        let memory_blocker = memory_pool
            .acquire("c", key("a"), 10, 1, &cancelled)
            .unwrap();
        let memory_error = result_error(memory_pool.acquire("c", key("b"), 1, 1, &cancelled));
        assert_eq!(memory_error.code, GraphErrorCode::Overloaded);
        drop(memory_blocker);
    }

    #[test]
    fn overload_errors_and_metrics_keys_do_not_expose_fairness_identity() {
        let pool = pool(10, 10);
        let cancelled = AtomicBool::new(false);
        let error = result_error(pool.acquire(
            "secret-collection",
            key("secret-tenant"),
            11,
            0,
            &cancelled,
        ));
        assert_eq!(error.code, GraphErrorCode::Overloaded);
        assert_eq!(error.retry_after_ms, Some(RETRY_AFTER_MS));
        assert!(!error.message.contains("secret-collection"));
        assert!(!error.message.contains("secret-tenant"));
    }

    #[test]
    fn c14_concurrent_hub_traversals_stay_inside_aggregate_reservations() {
        const MIB: u64 = 1024 * 1024;
        const RESERVATION: u64 = 2 * MIB;
        let mut graph = MutableGraphState::new(GraphEpoch::INITIAL);
        graph
            .types_mut()
            .configure(TypeId::from_raw(1), "LINK".to_string(), None)
            .unwrap();
        let center = Nid::from_parts(13, 1).unwrap();
        let namespace = GraphNamespace::Tenant("acme".to_string());
        let edges = (1..=1_000_u64)
            .map(|counter| {
                EdgeMutation::Relate(RelateMutation {
                    edge_id: EdgeId::from_parts(13, counter).unwrap(),
                    source: center,
                    target: Nid::from_parts(13, counter + 1).unwrap(),
                    type_id: TypeId::from_raw(1),
                    namespace: namespace.clone(),
                    properties: json!({}),
                })
            })
            .collect::<Vec<_>>();
        graph.apply_validated_edge_mutations(&edges);
        let payloads = (1..=1_001_u64)
            .map(|counter| {
                (
                    Nid::from_parts(13, counter).unwrap(),
                    json!({"tenant_id": "acme"}),
                )
            })
            .collect::<HashMap<_, _>>();

        let pool = Arc::new(GraphAdmissionPool::new(
            4 * RESERVATION,
            256 * 1024,
            Duration::from_millis(100),
            false,
        ));
        let graph = Arc::new(graph);
        let payloads = Arc::new(payloads);
        let admitted = Arc::new(Barrier::new(5));
        let release = Arc::new(AtomicBool::new(false));
        let mut running = Vec::new();
        for _ in 0..4 {
            let pool = Arc::clone(&pool);
            let graph = Arc::clone(&graph);
            let payloads = Arc::clone(&payloads);
            let admitted = Arc::clone(&admitted);
            let release = Arc::clone(&release);
            running.push(std::thread::spawn(move || {
                let cancelled = AtomicBool::new(false);
                let _permit = pool
                    .acquire(
                        "hub-collection",
                        key("flood-tenant"),
                        RESERVATION,
                        64 * 1024,
                        &cancelled,
                    )
                    .unwrap();
                let result = exact_bfs(MutableTraversal {
                    graph: graph.as_ref(),
                    anchors: vec![center],
                    visible_anchor_count: 1,
                    selected_types: None,
                    direction: GraphDirection::Outgoing,
                    node_filter: None,
                    statement_filter: None,
                    edge_filter: None,
                    budget: TraversalBudget {
                        max_depth: 1,
                        max_frontier: 2_000,
                        max_visited: 2_000,
                        max_edges: 2_000,
                        max_time_ms: 5_000,
                        max_memory_bytes: RESERVATION,
                        cold: Some(ColdTraversalBudget {
                            max_fragments: 1,
                            max_bytes: 64 * 1024,
                        }),
                    },
                    cancelled: &cancelled,
                    payload_for_nid: |nid| payloads.get(&nid).cloned(),
                    namespaces_for_payload: |_| vec![GraphNamespace::Tenant("acme".to_string())],
                })
                .unwrap()
                .result;
                assert_eq!(result.truncation, None);
                assert_eq!(result.visits.len(), 1_000);
                admitted.wait();
                while !release.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
            }));
        }
        admitted.wait();
        assert_eq!(
            pool.lock_state().used,
            Reservation {
                memory: 4 * RESERVATION,
                cold: 256 * 1024,
            }
        );

        let mut refused = Vec::new();
        for index in 0..8 {
            let pool = Arc::clone(&pool);
            refused.push(std::thread::spawn(move || {
                let cancelled = AtomicBool::new(false);
                result_error(pool.acquire(
                    "hub-collection",
                    if index < 6 {
                        key("flood-tenant")
                    } else {
                        key("fair-tenant")
                    },
                    RESERVATION,
                    64 * 1024,
                    &cancelled,
                ))
            }));
        }
        for waiter in refused {
            let error = waiter.join().unwrap();
            assert_eq!(error.code, GraphErrorCode::Overloaded);
            assert_eq!(error.retry_after_ms, Some(RETRY_AFTER_MS));
        }
        assert_eq!(pool.lock_state().used.memory, 4 * RESERVATION);

        release.store(true, Ordering::Release);
        for worker in running {
            worker.join().unwrap();
        }
        assert_eq!(pool.lock_state().used, Reservation::default());
    }
}
