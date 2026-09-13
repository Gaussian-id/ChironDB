use std::sync::{Condvar, LazyLock, Mutex};
use std::{collections::VecDeque, sync::atomic::AtomicBool};

use crate::{GaussError, Result};

const MIB: usize = 1024 * 1024;
const MIN_BUILD_BUDGET: usize = 512 * MIB;
const MAX_BUILD_BUDGET: usize = 4 * 1024 * MIB;
const BUDGET_PER_CORE: usize = 256 * MIB;

fn host_workers() -> usize {
    std::thread::available_parallelism()
        .map(|workers| workers.get())
        .unwrap_or(1)
}

fn build_budget() -> usize {
    host_workers()
        .saturating_mul(BUDGET_PER_CORE)
        .clamp(MIN_BUILD_BUDGET, MAX_BUILD_BUDGET)
}

pub(super) static BUILD_POOL: LazyLock<rayon::ThreadPool> = LazyLock::new(|| {
    // Bound maintenance CPU to at most half the host and four workers. The
    // memory limiter remains the stricter gate for large simultaneous builds,
    // while four workers avoid starvation when many small collections cross
    // the ANN threshold together.
    let threads = host_workers().div_ceil(2).clamp(1, 4);
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(|index| format!("chirondb-build-{index}"))
        .build()
        .expect("failed to build bounded index-build pool")
});

static BUILD_LIMITER: LazyLock<BuildLimiter> = LazyLock::new(|| BuildLimiter::new(build_budget()));

pub(super) fn estimated_build_bytes(points: usize, vector_dim: usize, weight: usize) -> usize {
    let row_bytes = vector_dim
        .saturating_mul(std::mem::size_of::<f32>())
        .saturating_add(320);
    points
        .saturating_mul(row_bytes)
        .saturating_mul(weight.max(1))
}

pub(super) fn acquire(estimated_bytes: usize) -> BuildPermit<'static> {
    BUILD_LIMITER.acquire(estimated_bytes)
}

pub(super) fn acquire_cancellable(
    estimated_bytes: usize,
    cancelled: &AtomicBool,
) -> Result<BuildPermit<'static>> {
    BUILD_LIMITER.acquire_cancellable(estimated_bytes, cancelled)
}

pub(super) fn notify_waiters() {
    BUILD_LIMITER.changed.notify_all();
}

struct BuildLimiter {
    capacity: usize,
    state: Mutex<BuildState>,
    changed: Condvar,
}

struct BuildState {
    available: usize,
    next_ticket: u64,
    queue: VecDeque<u64>,
}

impl BuildLimiter {
    fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            state: Mutex::new(BuildState {
                available: capacity,
                next_ticket: 0,
                queue: VecDeque::new(),
            }),
            changed: Condvar::new(),
        }
    }

    fn acquire(&self, requested: usize) -> BuildPermit<'_> {
        static NEVER_CANCELLED: AtomicBool = AtomicBool::new(false);
        self.acquire_cancellable(requested, &NEVER_CANCELLED)
            .expect("non-cancellable build admission cannot be cancelled")
    }

    fn acquire_cancellable(
        &self,
        requested: usize,
        cancelled: &AtomicBool,
    ) -> Result<BuildPermit<'_>> {
        // A generation larger than the budget runs alone instead of waiting
        // forever for an impossible reservation.
        let reserved = requested.max(1).min(self.capacity);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let ticket = state.next_ticket;
        state.next_ticket = state.next_ticket.wrapping_add(1);
        state.queue.push_back(ticket);
        loop {
            if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                state.queue.retain(|queued| *queued != ticket);
                self.changed.notify_all();
                return Err(GaussError::ResourceExhausted(
                    "background build cancelled during shutdown".to_string(),
                ));
            }
            if state.queue.front() == Some(&ticket) && state.available >= reserved {
                break;
            }
            let (next, _) = self
                .changed
                .wait_timeout(state, std::time::Duration::from_millis(25))
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
        }
        state.available -= reserved;
        let admitted_ticket = state.queue.pop_front();
        debug_assert_eq!(admitted_ticket, Some(ticket));
        self.changed.notify_all();
        Ok(BuildPermit {
            limiter: self,
            reserved,
        })
    }
}

pub(super) struct BuildPermit<'a> {
    limiter: &'a BuildLimiter,
    reserved: usize,
}

impl Drop for BuildPermit<'_> {
    fn drop(&mut self) {
        let mut state = self
            .limiter
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.available = state
            .available
            .saturating_add(self.reserved)
            .min(self.limiter.capacity);
        self.limiter.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::*;

    #[test]
    fn oversized_build_gets_an_exclusive_reservation() {
        let limiter = BuildLimiter::new(8);
        {
            let permit = limiter.acquire(usize::MAX);
            assert_eq!(permit.reserved, 8);
            let state = limiter.state.lock().unwrap();
            assert_eq!(state.available, 0);
            assert!(state.queue.is_empty());
        }
        assert_eq!(limiter.state.lock().unwrap().available, 8);
    }

    #[test]
    fn successful_acquire_dequeues_ticket_in_all_profiles() {
        let limiter = BuildLimiter::new(8);
        let permit = limiter.acquire(1);
        let state = limiter.state.lock().unwrap();
        assert_eq!(state.queue.len(), 0);
        assert_eq!(state.available, 7);
        drop(state);
        drop(permit);
        assert_eq!(limiter.state.lock().unwrap().available, 8);
    }

    #[test]
    fn estimate_saturates_instead_of_wrapping() {
        assert_eq!(estimated_build_bytes(usize::MAX, usize::MAX, 4), usize::MAX);
    }

    #[test]
    fn queued_large_build_is_not_bypassed_by_a_small_build() {
        let limiter = Arc::new(BuildLimiter::new(2));
        let blocker = limiter.acquire(2);
        let (order_tx, order_rx) = std::sync::mpsc::channel();

        let large_limiter = Arc::clone(&limiter);
        let large_tx = order_tx.clone();
        let large = std::thread::spawn(move || {
            let _permit = large_limiter.acquire(2);
            large_tx.send("large").unwrap();
        });
        while limiter.state.lock().unwrap().next_ticket < 2 {
            std::thread::yield_now();
        }

        let small_limiter = Arc::clone(&limiter);
        let small = std::thread::spawn(move || {
            let _permit = small_limiter.acquire(1);
            order_tx.send("small").unwrap();
        });
        drop(blocker);

        assert_eq!(
            order_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            "large"
        );
        large.join().unwrap();
        small.join().unwrap();
    }

    #[test]
    fn cancelled_waiter_leaves_fifo_queue_without_blocking_successor() {
        let limiter = Arc::new(BuildLimiter::new(1));
        let blocker = limiter.acquire(1);
        let cancelled = Arc::new(AtomicBool::new(false));

        let cancelled_limiter = Arc::clone(&limiter);
        let cancelled_flag = Arc::clone(&cancelled);
        let waiter = std::thread::spawn(move || {
            cancelled_limiter
                .acquire_cancellable(1, &cancelled_flag)
                .is_err()
        });
        while limiter.state.lock().unwrap().queue.len() != 1 {
            std::thread::yield_now();
        }
        cancelled.store(true, std::sync::atomic::Ordering::Release);
        limiter.changed.notify_all();
        assert!(waiter.join().unwrap());

        drop(blocker);
        let permit = limiter.acquire(1);
        drop(permit);
        assert!(limiter.state.lock().unwrap().queue.is_empty());
    }
}
