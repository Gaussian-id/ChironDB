use std::{
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

use std::sync::atomic::{AtomicBool, Ordering};

/// Owns every queued/running background index task for one `Db` instance.
///
/// The final `Db` handle closes admission, requests cooperative cancellation,
/// and waits for all registered tasks to run their rollback/cleanup guards.
/// Tasks intentionally keep the data-directory lease separately, so even a
/// timed-out graceful drain cannot allow an unsafe concurrent reopen.
#[derive(Debug)]
pub(super) struct BuildLifecycle {
    cancelled: AtomicBool,
    state: Mutex<BuildLifecycleState>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct BuildLifecycleState {
    active: usize,
}

impl BuildLifecycle {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            cancelled: AtomicBool::new(false),
            state: Mutex::new(BuildLifecycleState::default()),
            changed: Condvar::new(),
        })
    }

    pub(super) fn register(self: &Arc<Self>) -> Option<BuildTaskGuard> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.cancelled.load(Ordering::Acquire) {
            return None;
        }
        state.active = state.active.saturating_add(1);
        Some(BuildTaskGuard {
            lifecycle: Arc::clone(self),
        })
    }

    pub(super) fn cancellation(&self) -> &AtomicBool {
        &self.cancelled
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(super) fn cancel_and_drain(&self, timeout: Duration) -> bool {
        self.cancelled.store(true, Ordering::Release);
        super::build_admission::notify_waiters();

        let deadline = Instant::now() + timeout;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while state.active != 0 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let (next, wait) = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
            if wait.timed_out() && state.active != 0 {
                return false;
            }
        }
        true
    }

    #[cfg(test)]
    pub(super) fn active(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
    }
}

pub(super) struct BuildTaskGuard {
    lifecycle: Arc<BuildLifecycle>,
}

impl Drop for BuildTaskGuard {
    fn drop(&mut self) {
        let mut state = self
            .lifecycle
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active = state.active.saturating_sub(1);
        self.lifecycle.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_closes_admission_and_drain_waits_for_cleanup() {
        let lifecycle = BuildLifecycle::new();
        let guard = lifecycle.register().unwrap();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            drop(guard);
        });

        assert!(lifecycle.cancel_and_drain(Duration::from_secs(1)));
        assert!(lifecycle.is_cancelled());
        assert!(lifecycle.register().is_none());
        worker.join().unwrap();
    }

    #[test]
    fn drain_timeout_does_not_forget_running_task() {
        let lifecycle = BuildLifecycle::new();
        let guard = lifecycle.register().unwrap();
        assert!(!lifecycle.cancel_and_drain(Duration::from_millis(1)));
        assert_eq!(lifecycle.active(), 1);
        drop(guard);
        assert!(lifecycle.cancel_and_drain(Duration::from_secs(1)));
    }
}
