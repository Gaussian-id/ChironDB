//! Lifetime attachment for the optional server ML scheduler.
//!
//! Normal Db handles own the scheduler. Its background handle shares engine
//! storage but not this attachment, avoiding a Db -> scheduler -> Db cycle.
use std::{
    any::Any,
    fmt,
    sync::{Arc, Mutex},
    time::Instant,
};

use super::Db;

/// Lifecycle contract for the optional ML service attached to one open Db.
/// A timed-out shutdown must retain its engine lease until its worker exits.
pub trait MlRuntimeService: Any + Send + Sync {
    fn shutdown(&self, deadline: Instant) -> bool;
}

struct Attachment {
    value: Arc<dyn Any + Send + Sync>,
    lifecycle: Arc<dyn MlRuntimeService>,
}

#[derive(Default)]
pub(super) struct MlRuntimeOwner(Mutex<Option<Attachment>>);

impl fmt::Debug for MlRuntimeOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlRuntimeOwner").finish_non_exhaustive()
    }
}

impl MlRuntimeOwner {
    pub(super) fn stop(&self) {
        let owner = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        // Final handle drop may join; never hold the attachment mutex.
        drop(owner);
    }

    pub(super) fn shutdown(&self, deadline: Instant) -> bool {
        let lifecycle = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|owner| Arc::clone(&owner.lifecycle));
        let Some(lifecycle) = lifecycle else {
            return true;
        };
        if !lifecycle.shutdown(deadline) {
            return false;
        }
        let owner = {
            let mut owner = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if owner
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(&owner.lifecycle, &lifecycle))
            {
                owner.take()
            } else {
                None
            }
        };
        drop(owner);
        true
    }
}

impl Db {
    /// Attach one ML scheduler to this opened database, shared by its handles.
    #[doc(hidden)]
    pub fn ml_runtime<T: MlRuntimeService>(&self, create: impl FnOnce() -> T) -> Arc<T> {
        let mut owner = self
            .ml_runtime_owner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(value) = owner.as_ref() {
            return Arc::clone(&value.value)
                .downcast::<T>()
                .expect("one ML runtime type per Db");
        }
        let value = Arc::new(create());
        *owner = Some(Attachment {
            value: value.clone(),
            lifecycle: value.clone(),
        });
        value
    }

    /// Engine lease for the attached scheduler, without owning itself.
    #[doc(hidden)]
    pub fn ml_background_clone(&self) -> Self {
        let mut db = self.clone();
        db.ml_runtime_owner = Arc::new(MlRuntimeOwner::default());
        db
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct Service {
        finished: Arc<AtomicBool>,
        drops: Arc<AtomicUsize>,
        deadline: Arc<Mutex<Option<Instant>>>,
    }
    impl MlRuntimeService for Service {
        fn shutdown(&self, deadline: Instant) -> bool {
            *self.deadline.lock().unwrap() = Some(deadline);
            self.finished.load(Ordering::Acquire)
        }
    }
    impl Drop for Service {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn expired_shutdown_retains_attachment_until_service_finishes() {
        let directory = tempfile::tempdir().unwrap();
        let db = Db::open(directory.path()).unwrap();
        let finished = Arc::new(AtomicBool::new(false));
        let drops = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(Mutex::new(None));
        let value = db.ml_runtime(|| Service {
            finished: finished.clone(),
            drops: drops.clone(),
            deadline: observed.clone(),
        });
        drop(value);
        let deadline = Instant::now();
        assert!(!db.ml_runtime_owner.shutdown(deadline));
        assert_eq!(*observed.lock().unwrap(), Some(deadline));
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert!(db.ml_runtime_owner.0.lock().unwrap().is_some());
        finished.store(true, Ordering::Release);
        assert!(db.ml_runtime_owner.shutdown(deadline));
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert!(db.ml_runtime_owner.0.lock().unwrap().is_none());
    }

    #[test]
    fn database_shutdown_reports_unfinished_ml_background_work() {
        let directory = tempfile::tempdir().unwrap();
        let db = Db::open(directory.path()).unwrap();
        let drops = Arc::new(AtomicUsize::new(0));
        drop(db.ml_runtime(|| Service {
            finished: Arc::new(AtomicBool::new(false)),
            drops: drops.clone(),
            deadline: Arc::new(Mutex::new(None)),
        }));
        let report = db.shutdown(Instant::now());
        assert!(!report.background_drained);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        drop(db);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}
