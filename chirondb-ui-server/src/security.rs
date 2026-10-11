//! Local operator session lifecycle. Cancellation follows every active job.
use std::{
    collections::HashMap,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, Notify};
use uuid::Uuid;

const MAX_SESSIONS: usize = 32;
const LOGIN_ATTEMPTS: usize = 5;
const LOGIN_WINDOW: Duration = Duration::from_secs(30);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct Session {
    expires: Instant,
    pub csrf: String,
    closed: AtomicBool,
    active: AtomicUsize,
    changed: Notify,
}

impl Session {
    fn new(ttl: Duration) -> Arc<Self> {
        Arc::new(Self {
            expires: Instant::now() + ttl,
            csrf: random_token(),
            closed: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            changed: Notify::new(),
        })
    }
    pub fn valid(&self) -> bool {
        !self.closed.load(Ordering::SeqCst) && Instant::now() < self.expires
    }
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.changed.notify_waiters();
    }

    async fn cancelled(&self) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self.valid() {
                return;
            }
            tokio::select! { _ = notified => {}, _ = tokio::time::sleep_until(self.expires.into()) => { self.close(); return } }
        }
    }

    pub async fn run<T>(&self, future: impl Future<Output = T>) -> Option<T> {
        if !self.valid() {
            return None;
        }
        self.active.fetch_add(1, Ordering::SeqCst);
        let _lease = Lease(self);
        if !self.valid() {
            return None;
        }
        tokio::select! { biased; _ = self.cancelled() => None, value = future => Some(value) }
    }

    async fn revoke(&self) -> bool {
        self.close();
        tokio::time::timeout(DRAIN_TIMEOUT, async {
            loop {
                let notified = self.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.active.load(Ordering::SeqCst) == 0 {
                    return;
                }
                notified.await;
            }
        })
        .await
        .is_ok()
    }
}

struct Lease<'a>(&'a Session);
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.changed.notify_waiters();
    }
}

#[derive(Default)]
pub struct Sessions {
    values: Mutex<HashMap<String, Arc<Session>>>,
    login_attempts: Mutex<Vec<Instant>>,
}

impl Sessions {
    pub async fn admit_login(&self) -> bool {
        let now = Instant::now();
        let mut attempts = self.login_attempts.lock().await;
        attempts.retain(|at| now.duration_since(*at) < LOGIN_WINDOW);
        if attempts.len() >= LOGIN_ATTEMPTS {
            return false;
        }
        attempts.push(now);
        true
    }
    pub async fn create(&self, ttl: Duration) -> Option<(String, Arc<Session>)> {
        let mut values = self.values.lock().await;
        values.retain(|_, session| {
            if session.valid() {
                true
            } else {
                session.close();
                false
            }
        });
        if values.len() >= MAX_SESSIONS {
            return None;
        }
        let token = loop {
            let token = random_token();
            if !values.contains_key(&token) {
                break token;
            }
        };
        let session = Session::new(ttl);
        values.insert(token.clone(), Arc::clone(&session));
        Some((token, session))
    }
    pub async fn get(&self, token: &str) -> Option<Arc<Session>> {
        if token.len() != 64 {
            return None;
        }
        let mut values = self.values.lock().await;
        let session = values.get(token)?;
        if session.valid() {
            return Some(Arc::clone(session));
        }
        session.close();
        values.remove(token);
        None
    }
    pub async fn revoke(&self, token: &str) -> bool {
        let session = self.values.lock().await.remove(token);
        if let Some(session) = session {
            session.revoke().await
        } else {
            true
        }
    }
}

fn random_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn logout_cancels_active_jobs_and_refuses_old_session() {
        let sessions = Sessions::default();
        let (token, session) = sessions.create(Duration::from_secs(60)).await.unwrap();
        let active = Arc::clone(&session);
        let (started, waiting) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            active
                .run(async {
                    started.send(()).unwrap();
                    std::future::pending::<()>().await
                })
                .await
        });
        waiting.await.unwrap();
        assert!(sessions.revoke(&token).await);
        assert!(task.await.unwrap().is_none());
        assert!(sessions.get(&token).await.is_none());
        assert!(session.run(async { "leak" }).await.is_none());
    }
    #[tokio::test]
    async fn expiry_closes_active_work_and_login_and_sessions_are_bounded() {
        let sessions = Sessions::default();
        for _ in 0..LOGIN_ATTEMPTS {
            assert!(sessions.admit_login().await)
        }
        assert!(!sessions.admit_login().await);
        let (_, expiring) = sessions.create(Duration::from_millis(10)).await.unwrap();
        assert!(expiring.run(std::future::pending::<()>()).await.is_none());
        for _ in 0..MAX_SESSIONS {
            assert!(sessions.create(Duration::from_secs(60)).await.is_some())
        }
        assert!(sessions.create(Duration::from_secs(60)).await.is_none());
    }
}
