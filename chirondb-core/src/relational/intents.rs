//! Canonically ordered transaction intents.
//!
//! A transaction requests its complete bounded intent set before it owns any
//! key. Granting the set atomically removes hold-and-wait cycles, while the
//! FIFO ticket queue prevents a stream of newer transactions from starving an
//! older conflicting writer.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{GaussError, Result};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct IntentKey(Vec<u8>);

impl IntentKey {
    pub(super) fn row(table_id: u64, row_id: u64) -> Self {
        let mut bytes = Vec::with_capacity(17);
        bytes.push(0);
        bytes.extend_from_slice(&table_id.to_be_bytes());
        bytes.extend_from_slice(&row_id.to_be_bytes());
        Self(bytes)
    }

    pub(super) fn index(index_id: u64, encoded_key: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(9 + encoded_key.len());
        bytes.push(1);
        bytes.extend_from_slice(&index_id.to_be_bytes());
        bytes.extend_from_slice(encoded_key);
        Self(bytes)
    }

    pub(super) fn catalog() -> Self {
        Self(vec![2])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum IntentMode {
    Shared,
    Exclusive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct IntentRequest {
    pub(super) key: IntentKey,
    pub(super) mode: IntentMode,
}

#[derive(Debug, Default)]
struct Holders {
    shared: BTreeSet<u64>,
    exclusive: Option<u64>,
}

#[derive(Debug)]
struct Waiter {
    ticket: u64,
    owner: u64,
    requests: Vec<IntentRequest>,
}

#[derive(Debug, Default)]
struct IntentState {
    holders: BTreeMap<IntentKey, Holders>,
    waiters: VecDeque<Waiter>,
}

#[derive(Debug, Default)]
struct IntentInner {
    state: Mutex<IntentState>,
    changed: Condvar,
    next_owner: AtomicU64,
    next_ticket: AtomicU64,
}

#[derive(Clone, Debug, Default)]
pub(super) struct IntentManager {
    inner: Arc<IntentInner>,
}

impl IntentManager {
    pub(super) fn acquire(
        &self,
        requests: Vec<IntentRequest>,
        timeout: Duration,
    ) -> Result<IntentGuard> {
        let requests = canonicalize(requests);
        let owner = self.inner.next_owner.fetch_add(1, Ordering::Relaxed) + 1;
        if requests.is_empty() {
            return Ok(IntentGuard {
                inner: Arc::clone(&self.inner),
                owner,
                requests,
            });
        }
        let ticket = self.inner.next_ticket.fetch_add(1, Ordering::Relaxed) + 1;
        let deadline = Instant::now() + timeout;
        let mut state =
            self.inner.state.lock().map_err(|_| {
                GaussError::WalUnavailable("relational intent lock poisoned".into())
            })?;
        state.waiters.push_back(Waiter {
            ticket,
            owner,
            requests: requests.clone(),
        });
        loop {
            if let Err(error) = super::check_sql_cancelled() {
                state.waiters.retain(|waiter| waiter.ticket != ticket);
                self.inner.changed.notify_all();
                return Err(error);
            }
            let at_front = state
                .waiters
                .front()
                .is_some_and(|waiter| waiter.ticket == ticket);
            if at_front && available(&state.holders, owner, &requests) {
                let waiter = state
                    .waiters
                    .pop_front()
                    .expect("front waiter exists while granting intents");
                debug_assert_eq!(waiter.owner, owner);
                debug_assert_eq!(waiter.requests, requests);
                grant(&mut state.holders, owner, &requests);
                self.inner.changed.notify_all();
                return Ok(IntentGuard {
                    inner: Arc::clone(&self.inner),
                    owner,
                    requests,
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                state.waiters.retain(|waiter| waiter.ticket != ticket);
                self.inner.changed.notify_all();
                return Err(GaussError::ResourceExhausted(format!(
                    "relational intent wait exceeded {} ms",
                    timeout.as_millis()
                )));
            }
            // Wake periodically so PostgreSQL CancelRequest can interrupt a
            // blocked writer without waiting for the full intent timeout.
            let (next, wait) = self
                .inner
                .changed
                .wait_timeout(state, remaining.min(Duration::from_millis(25)))
                .map_err(|_| {
                    GaussError::WalUnavailable("relational intent lock poisoned".into())
                })?;
            state = next;
            if wait.timed_out() && Instant::now() >= deadline {
                state.waiters.retain(|waiter| waiter.ticket != ticket);
                self.inner.changed.notify_all();
                return Err(GaussError::ResourceExhausted(format!(
                    "relational intent wait exceeded {} ms",
                    timeout.as_millis()
                )));
            }
        }
    }
}

#[derive(Debug)]
pub(super) struct IntentGuard {
    inner: Arc<IntentInner>,
    owner: u64,
    requests: Vec<IntentRequest>,
}

impl Drop for IntentGuard {
    fn drop(&mut self) {
        let Ok(mut state) = self.inner.state.lock() else {
            return;
        };
        for request in &self.requests {
            let remove = if let Some(holders) = state.holders.get_mut(&request.key) {
                match request.mode {
                    IntentMode::Shared => {
                        holders.shared.remove(&self.owner);
                    }
                    IntentMode::Exclusive => {
                        if holders.exclusive == Some(self.owner) {
                            holders.exclusive = None;
                        }
                    }
                }
                holders.shared.is_empty() && holders.exclusive.is_none()
            } else {
                false
            };
            if remove {
                state.holders.remove(&request.key);
            }
        }
        self.inner.changed.notify_all();
    }
}

fn canonicalize(requests: Vec<IntentRequest>) -> Vec<IntentRequest> {
    let mut canonical = BTreeMap::new();
    for request in requests {
        canonical
            .entry(request.key)
            .and_modify(|mode| {
                if request.mode == IntentMode::Exclusive {
                    *mode = IntentMode::Exclusive;
                }
            })
            .or_insert(request.mode);
    }
    canonical
        .into_iter()
        .map(|(key, mode)| IntentRequest { key, mode })
        .collect()
}

fn available(
    holders: &BTreeMap<IntentKey, Holders>,
    owner: u64,
    requests: &[IntentRequest],
) -> bool {
    requests.iter().all(|request| {
        let Some(holders) = holders.get(&request.key) else {
            return true;
        };
        match request.mode {
            IntentMode::Shared => holders.exclusive.is_none_or(|holder| holder == owner),
            IntentMode::Exclusive => {
                holders.exclusive.is_none_or(|holder| holder == owner)
                    && holders.shared.iter().all(|holder| *holder == owner)
            }
        }
    })
}

fn grant(holders: &mut BTreeMap<IntentKey, Holders>, owner: u64, requests: &[IntentRequest]) {
    for request in requests {
        let holders = holders.entry(request.key.clone()).or_default();
        match request.mode {
            IntentMode::Shared => {
                holders.shared.insert(owner);
            }
            IntentMode::Exclusive => holders.exclusive = Some(owner),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier, mpsc},
        thread,
    };

    use super::*;

    fn request(key: u64, mode: IntentMode) -> IntentRequest {
        IntentRequest {
            key: IntentKey::row(1, key),
            mode,
        }
    }

    #[test]
    fn canonicalization_sorts_deduplicates_and_upgrades() {
        let requests = canonicalize(vec![
            request(2, IntentMode::Shared),
            request(1, IntentMode::Shared),
            request(2, IntentMode::Exclusive),
        ]);
        assert_eq!(
            requests,
            vec![
                request(1, IntentMode::Shared),
                request(2, IntentMode::Exclusive),
            ]
        );
    }

    #[test]
    fn cancellation_removes_blocked_waiter_before_timeout() {
        let manager = IntentManager::default();
        let held = manager
            .acquire(
                vec![request(1, IntentMode::Exclusive)],
                Duration::from_secs(1),
            )
            .unwrap();
        let waiting = manager.clone();
        let cancellation = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_cancellation = Arc::clone(&cancellation);
        let worker = thread::spawn(move || {
            super::super::with_sql_cancellation(worker_cancellation, || {
                waiting.acquire(
                    vec![request(1, IntentMode::Exclusive)],
                    Duration::from_secs(1),
                )
            })
        });
        thread::sleep(Duration::from_millis(50));
        cancellation.store(true, Ordering::Release);
        let error = worker
            .join()
            .unwrap()
            .expect_err("cancelled intent waiter must fail");
        assert_eq!(error.to_string(), "invalid request: query canceled");
        drop(held);

        manager
            .acquire(
                vec![request(1, IntentMode::Exclusive)],
                Duration::from_millis(100),
            )
            .expect("cancelled waiter must be removed from the FIFO queue");
    }

    #[test]
    fn conflicting_writer_waits_and_nonconflicting_writer_can_follow() {
        let manager = Arc::new(IntentManager::default());
        let held = manager
            .acquire(
                vec![request(1, IntentMode::Exclusive)],
                Duration::from_secs(1),
            )
            .unwrap();
        let start = Arc::new(Barrier::new(2));
        let (sender, receiver) = mpsc::channel();
        let worker_manager = Arc::clone(&manager);
        let worker_start = Arc::clone(&start);
        let worker = thread::spawn(move || {
            worker_start.wait();
            let _guard = worker_manager
                .acquire(
                    vec![request(1, IntentMode::Exclusive)],
                    Duration::from_secs(1),
                )
                .unwrap();
            sender.send(()).unwrap();
        });
        start.wait();
        assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
        drop(held);
        receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();

        manager
            .acquire(vec![request(1, IntentMode::Shared)], Duration::from_secs(1))
            .unwrap();
        manager
            .acquire(
                vec![request(2, IntentMode::Exclusive)],
                Duration::from_secs(1),
            )
            .unwrap();
    }

    #[test]
    fn timeout_removes_waiter_and_releases_queue() {
        let manager = IntentManager::default();
        let _held = manager
            .acquire(
                vec![request(1, IntentMode::Exclusive)],
                Duration::from_secs(1),
            )
            .unwrap();
        let error = manager
            .acquire(
                vec![request(1, IntentMode::Exclusive)],
                Duration::from_millis(5),
            )
            .unwrap_err();
        assert!(matches!(error, GaussError::ResourceExhausted(_)));
    }
}
