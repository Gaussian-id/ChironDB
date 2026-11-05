//! Bounded fair waiting for HTTP work, retaining the existing active quotas.
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::Notify;

#[derive(Clone, Debug)]
pub(super) struct WorkLimiter {
    state: Arc<Mutex<WorkState>>,
    changed: Arc<Notify>,
    global_limit: usize,
    tenant_limit: usize,
}

#[derive(Debug, Default)]
struct WorkState {
    total: usize,
    per_tenant: HashMap<String, usize>,
    next_ticket: u64,
    waiting: VecDeque<(u64, String)>,
}

#[derive(Debug)]
pub struct WorkPermit {
    state: Arc<Mutex<WorkState>>,
    changed: Arc<Notify>,
    tenant: String,
}

struct Queued {
    limiter: WorkLimiter,
    ticket: u64,
}

impl Default for WorkLimiter {
    fn default() -> Self {
        let global = chirondb_core::resource_profile::current().query_workers;
        Self::new(global, global.div_ceil(4).max(1))
    }
}

impl WorkLimiter {
    fn new(global_limit: usize, tenant_limit: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(WorkState::default())),
            changed: Arc::new(Notify::new()),
            global_limit,
            tenant_limit,
        }
    }

    fn available(&self, state: &WorkState, tenant: &str) -> bool {
        state.total < self.global_limit
            && state.per_tenant.get(tenant).copied().unwrap_or(0) < self.tenant_limit
    }

    fn first_eligible(&self, state: &WorkState) -> Option<u64> {
        state
            .waiting
            .iter()
            .find(|(_, tenant)| self.available(state, tenant))
            .map(|(ticket, _)| *ticket)
    }

    fn admit(&self, state: &mut WorkState, tenant: &str) -> WorkPermit {
        state.total += 1;
        *state.per_tenant.entry(tenant.to_owned()).or_default() += 1;
        WorkPermit {
            state: Arc::clone(&self.state),
            changed: Arc::clone(&self.changed),
            tenant: tenant.to_owned(),
        }
    }

    pub(super) fn try_acquire(&self, tenant: &str) -> Option<WorkPermit> {
        let mut state = self.state.lock().ok()?;
        if !self.available(&state, tenant) || self.first_eligible(&state).is_some() {
            return None;
        }
        Some(self.admit(&mut state, tenant))
    }

    pub(super) async fn acquire(&self, tenant: &str) -> Option<WorkPermit> {
        if let Some(permit) = self.try_acquire(tenant) {
            return Some(permit);
        }
        let ticket = {
            let mut state = self.state.lock().ok()?;
            let capacity = self.global_limit.saturating_mul(8).max(8);
            let tenant_capacity = capacity.div_ceil(4).max(8);
            if state.waiting.len() >= capacity
                || state
                    .waiting
                    .iter()
                    .filter(|(_, owner)| owner == tenant)
                    .count()
                    >= tenant_capacity
            {
                return None;
            }
            let ticket = state.next_ticket;
            state.next_ticket = ticket.checked_add(1)?;
            state.waiting.push_back((ticket, tenant.to_owned()));
            ticket
        };
        let _queued = Queued {
            limiter: self.clone(),
            ticket,
        };
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                // Register before checking state so a released permit cannot
                // be lost between the check and the await.
                changed.as_mut().enable();
                {
                    let mut state = self.state.lock().ok()?;
                    if self.first_eligible(&state) == Some(ticket) {
                        state.waiting.retain(|(id, _)| *id != ticket);
                        let permit = self.admit(&mut state, tenant);
                        self.changed.notify_waiters();
                        return Some(permit);
                    }
                }
                changed.await;
            }
        })
        .await
        .ok()
        .flatten()
    }
}

impl Drop for Queued {
    fn drop(&mut self) {
        if let Ok(mut state) = self.limiter.state.lock() {
            state.waiting.retain(|(ticket, _)| *ticket != self.ticket);
        }
        self.limiter.changed.notify_waiters();
    }
}

impl Drop for WorkPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.total = state.total.saturating_sub(1);
            if let Some(count) = state.per_tenant.get_mut(&self.tenant) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    state.per_tenant.remove(&self.tenant);
                }
            }
        }
        self.changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn queued(limiter: &WorkLimiter, count: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while limiter.state.lock().unwrap().waiting.len() != count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn queued_tenant_keeps_its_quota_without_blocking_another_tenant() {
        let limiter = WorkLimiter::new(4, 1);
        let first = limiter.try_acquire("a").unwrap();
        let pending = {
            let limiter = limiter.clone();
            tokio::spawn(async move { limiter.acquire("a").await })
        };
        queued(&limiter, 1).await;
        assert!(limiter.try_acquire("a").is_none());
        let other = limiter.try_acquire("b").unwrap();
        assert_eq!(limiter.state.lock().unwrap().total, 2);
        drop(first);
        let admitted = pending.await.unwrap().unwrap();
        assert_eq!(limiter.state.lock().unwrap().per_tenant["a"], 1);
        drop((admitted, other));
        assert_eq!(limiter.state.lock().unwrap().total, 0);
    }

    #[tokio::test]
    async fn bounded_queue_releases_canceled_waiters_and_does_not_allow_barging() {
        let limiter = WorkLimiter::new(4, 1);
        let first = limiter.try_acquire("a").unwrap();
        let mut pending = Vec::new();
        for _ in 0..8 {
            let limiter = limiter.clone();
            pending.push(tokio::spawn(async move { limiter.acquire("a").await }));
        }
        queued(&limiter, 8).await;
        assert!(limiter.acquire("a").await.is_none());
        for task in pending {
            task.abort();
            let _ = task.await;
        }
        queued(&limiter, 0).await;
        drop(first);
        assert!(limiter.try_acquire("a").is_some());
    }

    #[tokio::test]
    async fn canceled_request_retains_admission_until_blocking_commit_finishes() {
        let limiter = WorkLimiter::new(4, 1);
        let permit = Arc::new(limiter.try_acquire("a").unwrap());
        let retained = Arc::clone(&permit);
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, finish) = std::sync::mpsc::channel();
        let request = tokio::spawn(async move {
            let _request_permit = permit;
            tokio::task::spawn_blocking(move || {
                let _work = retained;
                entered.send(()).unwrap();
                finish.recv().unwrap();
            })
            .await
        });
        started.await.unwrap();
        request.abort();
        let _ = request.await;
        assert!(limiter.try_acquire("a").is_none());
        release.send(()).unwrap();
        assert!(limiter.acquire("a").await.is_some());
    }
}
