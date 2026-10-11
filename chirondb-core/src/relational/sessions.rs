//! Short registry leases and independent interactive transaction serialization.
//! Never wait for a session while holding the registry. Expiry only tries idle
//! sessions and releases their snapshots outside the registry lock.
use super::*;
use parking_lot::{Mutex as SessionMutex, MutexGuard};

#[derive(Debug, Default)]
pub(super) struct InteractiveSessions {
    entries: Mutex<HashMap<String, Arc<InteractiveSession>>>,
}

#[derive(Debug)]
pub(super) struct InteractiveSession {
    principal_id: String,
    pub(super) tenant_id: Option<String>,
    transaction: SessionMutex<Option<InteractiveTransaction>>,
}

impl InteractiveSessions {
    pub(super) fn is_empty(&self) -> Result<bool> {
        self.expire()?;
        Ok(self
            .entries
            .lock()
            .map_err(|_| registry_error())?
            .is_empty())
    }

    pub(super) fn insert(
        &self,
        handle: String,
        transaction: InteractiveTransaction,
        owner: &AuditContext,
    ) -> Result<()> {
        self.expire()?;
        let entry = Arc::new(InteractiveSession {
            principal_id: owner.principal_id.clone(),
            tenant_id: owner.tenant_id.clone(),
            transaction: SessionMutex::new(Some(transaction)),
        });
        let mut entries = self.entries.lock().map_err(|_| registry_error())?;
        if entries.len() >= MAX_INTERACTIVE_TRANSACTIONS {
            return Err(GaussError::ResourceExhausted(format!(
                "interactive transaction limit {MAX_INTERACTIVE_TRANSACTIONS} reached"
            )));
        }
        entries.insert(handle, entry);
        Ok(())
    }

    pub(super) fn get(
        &self,
        handle: &str,
        owner: &AuditContext,
    ) -> Result<Arc<InteractiveSession>> {
        self.expire()?;
        let entry = self
            .entries
            .lock()
            .map_err(|_| registry_error())?
            .get(handle)
            .cloned()
            .ok_or_else(|| inactive(handle))?;
        // Immutable ownership is checked before waiting behind another call.
        if entry.principal_id != owner.principal_id || entry.tenant_id != owner.tenant_id {
            return Err(invalid(
                "interactive transaction owner does not match caller",
            ));
        }
        Ok(entry)
    }

    pub(super) fn remove(&self, handle: &str, entry: &Arc<InteractiveSession>) -> Result<()> {
        let mut entries = self.entries.lock().map_err(|_| registry_error())?;
        if entries
            .get(handle)
            .is_some_and(|live| Arc::ptr_eq(live, entry))
        {
            entries.remove(handle);
        }
        Ok(())
    }

    pub(super) fn expire(&self) -> Result<()> {
        let mut retired = Vec::new();
        let now = Instant::now();
        {
            let mut entries = self.entries.lock().map_err(|_| registry_error())?;
            entries.retain(|_, entry| {
                let Some(mut state) = entry.transaction.try_lock() else {
                    return true;
                };
                if state.as_ref().is_none_or(|transaction| {
                    now.saturating_duration_since(transaction.last_activity)
                        >= INTERACTIVE_TRANSACTION_TTL
                }) {
                    if let Some(transaction) = state.take() {
                        retired.push(transaction);
                    }
                    false
                } else {
                    true
                }
            });
        }
        drop(retired);
        Ok(())
    }
}

impl InteractiveSession {
    pub(super) fn lock(
        &self,
        handle: &str,
    ) -> Result<MutexGuard<'_, Option<InteractiveTransaction>>> {
        let deadline = Instant::now() + INTENT_WAIT_TIMEOUT;
        loop {
            check_sql_cancelled()?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(GaussError::ResourceExhausted(
                    "interactive transaction is busy; retry later".into(),
                ));
            }
            if let Some(mut state) = self
                .transaction
                .try_lock_for(remaining.min(SQL_WAIT_CHECK_INTERVAL))
            {
                check_sql_cancelled()?;
                let transaction = state.as_ref().ok_or_else(|| inactive(handle))?;
                if transaction.last_activity.elapsed() >= INTERACTIVE_TRANSACTION_TTL {
                    // Another request may have captured this Arc before expiry.
                    // Clear its private state so it cannot resurrect the handle.
                    let retired = state.take();
                    drop(state);
                    drop(retired);
                    return Err(inactive(handle));
                }
                return Ok(state);
            }
            #[cfg(test)]
            observe_wait();
        }
    }
}

fn inactive(handle: &str) -> GaussError {
    invalid(format!("interactive transaction {handle} is not active"))
}

fn registry_error() -> GaussError {
    invalid("interactive transaction registry lock poisoned")
}

// One-shot, thread-local test notification after entering a real wait. Tests
// can cancel an already-blocked request without sleeps or global failpoints.
#[cfg(test)]
thread_local! {
    static WAIT_OBSERVER: RefCell<Option<std::sync::mpsc::Sender<()>>> = const { RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn observe_wait() {
    WAIT_OBSERVER.with(|observer| {
        if let Some(sender) = observer.borrow_mut().take() {
            let _ = sender.send(());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Barrier, mpsc};

    fn request(sql: &str) -> SqlExecutionRequest {
        SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql: sql.into(),
                parameters: Vec::new(),
            }],
            retry_id: None,
            idempotency_key: None,
        }
    }

    fn fixture() -> (tempfile::TempDir, Arc<RelationalEngine>, AuditContext) {
        let directory = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let engine = RelationalEngine::open(directory.path(), journal).unwrap();
        engine
            .execute(request("CREATE TABLE items (id INTEGER PRIMARY KEY)"))
            .unwrap();
        (directory, engine, AuditContext::embedded())
    }

    fn count(engine: &RelationalEngine, id: usize) -> i64 {
        let result = engine
            .execute(request(&format!(
                "SELECT COUNT(*) FROM items WHERE id = {id}"
            )))
            .unwrap();
        let SqlResult::Rows { rows, .. } = &result.response.results[0] else {
            panic!("count rows")
        };
        let RelationalValue::Integer(value) = rows[0][0] else {
            panic!("integer count")
        };
        value
    }

    #[test]
    fn busy_session_allows_other_session_commit_checkpoint_and_owner_refusal() {
        let (_directory, engine, owner) = fixture();
        let first = engine.begin_interactive(&owner).unwrap();
        let entry = engine.interactive.get(&first.handle, &owner).unwrap();
        let held = entry.lock(&first.handle).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        std::thread::scope(|scope| {
            let engine = &engine;
            let owner = &owner;
            let first = &first;
            let cancelled = &cancelled;
            let (started_tx, started_rx) = mpsc::channel();
            let (first_tx, first_rx) = mpsc::channel();
            scope.spawn(move || {
                WAIT_OBSERVER.with(|observer| *observer.borrow_mut() = Some(started_tx));
                first_tx
                    .send(engine.execute_interactive_cancellable(
                        &first.handle,
                        request("SELECT COUNT(*) FROM items"),
                        owner,
                        cancelled.clone(),
                    ))
                    .unwrap();
            });
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let (other_tx, other_rx) = mpsc::channel();
            scope.spawn(move || {
                let mut foreign = owner.clone();
                foreign.principal_id = "foreign-owner".into();
                let refused = engine.execute_interactive(
                    &first.handle,
                    request("SELECT COUNT(*) FROM items"),
                    &foreign,
                );
                assert!(
                    refused
                        .err()
                        .unwrap()
                        .to_string()
                        .contains("owner does not match")
                );
                let second = engine.begin_interactive(owner).unwrap();
                engine
                    .execute_interactive(
                        &second.handle,
                        request("INSERT INTO items VALUES (1)"),
                        owner,
                    )
                    .unwrap();
                engine.commit_interactive(&second.handle, owner).unwrap();
                engine.checkpoint().unwrap();
                other_tx.send(count(engine, 1)).unwrap();
            });
            let other = other_rx.recv_timeout(Duration::from_secs(5));
            cancelled.store(true, AtomicOrdering::Release);
            let first_result = first_rx.recv_timeout(Duration::from_secs(2));
            drop(held);
            assert_eq!(
                other.unwrap(),
                1,
                "another session must finish while the first remains locked"
            );
            assert_eq!(
                first_result.unwrap().unwrap_err().to_string(),
                "invalid request: query canceled"
            );
        });
        assert_eq!(engine.snapshots.active_count(), 1);
        engine.rollback_interactive(&first.handle, &owner).unwrap();
        assert_eq!(engine.snapshots.active_count(), 0);
    }

    #[test]
    fn cancellation_while_waiting_to_commit_preserves_session_and_retry_identity() {
        let (_directory, engine, owner) = fixture();
        let first = engine.begin_interactive(&owner).unwrap();
        engine
            .execute_interactive(
                &first.handle,
                request("INSERT INTO items VALUES (1)"),
                &owner,
            )
            .unwrap();
        let entry = engine.interactive.get(&first.handle, &owner).unwrap();
        let held = entry.lock(&first.handle).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        std::thread::scope(|scope| {
            let engine = &engine;
            let owner = &owner;
            let first = &first;
            let cancelled = &cancelled;
            let (started_tx, started_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel();
            scope.spawn(move || {
                WAIT_OBSERVER.with(|observer| *observer.borrow_mut() = Some(started_tx));
                done_tx
                    .send(
                        engine
                            .commit_interactive_cancellable(&first.handle, owner, cancelled.clone())
                            .map(|value| value.response),
                    )
                    .unwrap();
            });
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            cancelled.store(true, AtomicOrdering::Release);
            let result = done_rx.recv_timeout(Duration::from_secs(2));
            drop(held);
            assert_eq!(
                result.unwrap().unwrap_err().to_string(),
                "invalid request: query canceled"
            );
        });
        assert_eq!(count(&engine, 1), 0);
        let receipt = engine
            .commit_interactive(&first.handle, &owner)
            .unwrap()
            .response;
        assert_eq!(receipt.transaction_id, first.transaction_id);
        assert_eq!(
            engine
                .commit_interactive(&first.handle, &owner)
                .unwrap()
                .response,
            receipt
        );
        assert_eq!(count(&engine, 1), 1);
        assert_eq!(engine.snapshots.active_count(), 0);
    }

    #[test]
    fn racing_execute_cannot_append_after_commit_freezes_the_session() {
        let (_directory, engine, owner) = fixture();
        for id in 0..32 {
            let first = engine.begin_interactive(&owner).unwrap();
            let barrier = Barrier::new(3);
            let (executed, committed) = std::thread::scope(|scope| {
                let execute = scope.spawn(|| {
                    barrier.wait();
                    engine.execute_interactive(
                        &first.handle,
                        request(&format!("INSERT INTO items VALUES ({id})")),
                        &owner,
                    )
                });
                let commit = scope.spawn(|| {
                    barrier.wait();
                    engine
                        .commit_interactive(&first.handle, &owner)
                        .map(|value| value.response)
                });
                barrier.wait();
                (execute.join().unwrap(), commit.join().unwrap())
            });
            let committed = committed.unwrap();
            if let Err(error) = &executed {
                assert!(error.to_string().contains("is not active"), "{error}");
            }
            assert_eq!(count(&engine, id), i64::from(executed.is_ok()));
            assert_eq!(
                engine
                    .commit_interactive(&first.handle, &owner)
                    .unwrap()
                    .response,
                committed
            );
            assert_eq!(engine.snapshots.active_count(), 0);
        }
    }

    #[test]
    fn racing_commit_and_rollback_have_one_terminal_outcome() {
        let (_directory, engine, owner) = fixture();
        for id in 0..32 {
            let first = engine.begin_interactive(&owner).unwrap();
            engine
                .execute_interactive(
                    &first.handle,
                    request(&format!("INSERT INTO items VALUES ({id})")),
                    &owner,
                )
                .unwrap();
            let barrier = Barrier::new(3);
            let (committed, rolled_back) = std::thread::scope(|scope| {
                let commit = scope.spawn(|| {
                    barrier.wait();
                    engine
                        .commit_interactive(&first.handle, &owner)
                        .map(|value| value.response)
                });
                let rollback = scope.spawn(|| {
                    barrier.wait();
                    engine.rollback_interactive(&first.handle, &owner)
                });
                barrier.wait();
                (commit.join().unwrap(), rollback.join().unwrap())
            });
            assert_ne!(committed.is_ok(), rolled_back.is_ok());
            assert_eq!(count(&engine, id), i64::from(committed.is_ok()));
            assert_eq!(engine.snapshots.active_count(), 0);
        }
    }

    #[test]
    fn expiry_skips_busy_sessions_and_stale_handles_cannot_resurrect_pins() {
        let (_directory, engine, owner) = fixture();
        let first = engine.begin_interactive(&owner).unwrap();
        let entry = engine.interactive.get(&first.handle, &owner).unwrap();
        let mut held = entry.lock(&first.handle).unwrap();
        held.as_mut().unwrap().last_activity =
            Instant::now() - INTERACTIVE_TRANSACTION_TTL - Duration::from_secs(1);
        engine.interactive.expire().unwrap();
        assert_eq!(engine.snapshots.active_count(), 1);
        let second = engine.begin_interactive(&owner).unwrap();
        assert_eq!(engine.snapshots.active_count(), 2);
        drop(held);
        engine.interactive.expire().unwrap();
        assert_eq!(engine.snapshots.active_count(), 1);
        assert!(entry.lock(&first.handle).is_err());
        assert!(
            engine
                .execute_interactive(&first.handle, request("SELECT COUNT(*) FROM items"), &owner)
                .is_err()
        );
        engine.rollback_interactive(&second.handle, &owner).unwrap();
        assert_eq!(engine.snapshots.active_count(), 0);
    }

    #[test]
    fn ordinary_sql_releases_expired_pins_without_another_handle_request() {
        let (_directory, engine, owner) = fixture();
        engine
            .execute(request("INSERT INTO items VALUES (1)"))
            .unwrap();
        let first = engine.begin_interactive(&owner).unwrap();
        engine
            .execute(request("DELETE FROM items WHERE id = 1"))
            .unwrap();
        assert_eq!(engine.snapshots.active_count(), 1);
        assert_eq!(engine.state.read().tables["items"].rows.len(), 1);
        let entry = engine.interactive.get(&first.handle, &owner).unwrap();
        entry
            .lock(&first.handle)
            .unwrap()
            .as_mut()
            .unwrap()
            .last_activity = Instant::now() - INTERACTIVE_TRANSACTION_TTL - Duration::from_secs(1);
        assert_eq!(count(&engine, 1), 0);
        assert_eq!(engine.snapshots.active_count(), 0);
        assert!(engine.state.read().tables["items"].rows.is_empty());
        assert!(entry.lock(&first.handle).is_err());
    }

    #[test]
    fn session_capacity_refusal_releases_the_unpublished_snapshot_pin() {
        let (_directory, engine, owner) = fixture();
        let handles: Vec<_> = (0..MAX_INTERACTIVE_TRANSACTIONS)
            .map(|_| engine.begin_interactive(&owner).unwrap())
            .collect();
        assert!(matches!(
            engine.begin_interactive(&owner),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(
            engine.snapshots.active_count(),
            MAX_INTERACTIVE_TRANSACTIONS
        );
        for handle in handles {
            engine.rollback_interactive(&handle.handle, &owner).unwrap();
        }
        assert_eq!(engine.snapshots.active_count(), 0);
        assert!(engine.interactive.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn admission_wait_observes_cancellation_without_a_capacity_notification() {
        let admission = SqlAdmission {
            capacity: 1,
            reservation: 1,
            used: Mutex::new(0),
            changed: Condvar::new(),
        };
        let held = admission.acquire().unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        std::thread::scope(|scope| {
            let admission = &admission;
            let cancelled = &cancelled;
            let (started_tx, started_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel();
            scope.spawn(move || {
                WAIT_OBSERVER.with(|observer| *observer.borrow_mut() = Some(started_tx));
                let result =
                    with_sql_cancellation(cancelled.clone(), || admission.acquire().map(drop));
                done_tx.send(result).unwrap();
            });
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            cancelled.store(true, AtomicOrdering::Release);
            let result = done_rx.recv_timeout(Duration::from_secs(2));
            assert_eq!(*admission.used.lock().unwrap(), 1);
            drop(held);
            assert_eq!(
                result.unwrap().unwrap_err().to_string(),
                "invalid request: query canceled"
            );
        });
        assert_eq!(*admission.used.lock().unwrap(), 0);
    }
}
