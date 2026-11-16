//! Temporarily quiesce checkpoint publication while Db freezes a content root.
//! Db holds its exclusive lifecycle gate, so no new SQL commit can schedule a
//! worker before this guard restores the previous cancellation state.
use super::*;

pub(crate) struct CheckpointPause {
    engine: Arc<RelationalEngine>,
    was_cancelled: bool,
}

impl RelationalEngine {
    /// Let an active checkpoint install its captured roots before admitting
    /// another write snapshot under overlay pressure. Otherwise a continuous
    /// writer can keep every capture stale until conservative COW reservations
    /// exhaust the retained pool. Reads and durable receipt replay bypass this.
    pub(super) fn wait_for_checkpoint_headroom(&self) -> Result<()> {
        let deadline = Instant::now() + INTENT_WAIT_TIMEOUT;
        loop {
            check_sql_cancelled()?;
            let active = self
                .checkpoint_worker
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|worker| !worker.is_finished());
            if !active
                || self.checkpoint_cancel.load(AtomicOrdering::Acquire)
                || self.state.read().retained_bytes() < memory::flush_threshold()
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(GaussError::ResourceExhausted(
                    "relational checkpoint is still relieving memory pressure; retry after checkpoint"
                        .into(),
                ));
            }
            std::thread::sleep(SQL_WAIT_CHECK_INTERVAL);
        }
    }

    pub(super) fn drain_background_checkpoint(
        &self,
        mut checkpoint: CapturedRelationalCheckpoint,
        flush_threshold: u64,
    ) -> Result<()> {
        loop {
            self.publish_checkpoint(&checkpoint)?;
            let sequence = checkpoint.manifest.sequence;
            // Release captured roots before reserving the next projection.
            drop(checkpoint);
            check_sql_cancelled()?;
            checkpoint = {
                let state = self.state.read();
                if state.sequence <= sequence || state.retained_bytes() < flush_threshold {
                    return Ok(());
                }
                let watermark = self
                    .wal
                    .lock()
                    .map_err(|_| GaussError::WalUnavailable("relational WAL lock poisoned".into()))?
                    .len()?;
                capture_relational_checkpoint(&state, watermark)?
            };
            // A concurrent writer can make the first captured table root stale.
            // Keep draining pressure without requiring another admitted mutation.
        }
    }

    pub(crate) fn pause_checkpoints(self: &Arc<Self>) -> Result<CheckpointPause> {
        self.pause_checkpoints_until(Instant::now() + Duration::from_secs(300))
    }

    pub(crate) fn pause_checkpoints_until(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<CheckpointPause> {
        let guard = CheckpointPause {
            engine: Arc::clone(self),
            was_cancelled: self.checkpoint_cancel.swap(true, AtomicOrdering::AcqRel),
        };
        if !self.cancel_and_drain_checkpoint(deadline) {
            return Err(GaussError::WalUnavailable(
                "timed out quiescing relational checkpoints".into(),
            ));
        }
        Ok(guard)
    }

    pub(crate) fn ensure_restore_idle(&self) -> Result<()> {
        if !self.interactive.is_empty()? {
            return Err(GaussError::InvalidRequest(
                "restore requires all SQL transactions to end".into(),
            ));
        }
        Ok(())
    }
}

impl Drop for CheckpointPause {
    fn drop(&mut self) {
        self.engine
            .checkpoint_cancel
            .store(self.was_cancelled, AtomicOrdering::Release);
    }
}

#[cfg(all(test, feature = "fault-injection"))]
mod tests {
    use super::*;
    use crate::SqlStatementRequest;

    fn request(sql: &str) -> SqlExecutionRequest {
        SqlExecutionRequest {
            statements: vec![SqlStatementRequest {
                sql: sql.into(),
                parameters: vec![],
            }],
            idempotency_key: None,
            retry_id: None,
        }
    }

    fn schedule(engine: &RelationalEngine) {
        let captured = capture_relational_checkpoint(
            &engine.state.read(),
            engine.wal.lock().unwrap().len().unwrap(),
        );
        engine.checkpoint_after_commit(captured, "maintenance-test");
    }

    fn pressured_checkpoint_writer(cancel_pending: bool) {
        let temp = tempfile::tempdir().unwrap();
        memory::with_pool(16 * 1024 * 1024, |pool| {
            let engine =
                RelationalEngine::open(temp.path(), TransactionJournal::open(temp.path()).unwrap())
                    .unwrap();
            engine
                .execute(request(
                    "CREATE TABLE items (id BIGINT PRIMARY KEY, text TEXT)",
                ))
                .unwrap();
            engine.enable_background_checkpoints(Arc::new(()));
            let marker = temp.path().join("marker");
            let release = temp.path().join("release");
            let env = crate::failpoint::test_env(
                "pause:relational_checkpoint.after_segments",
                &marker,
                &release,
            );
            let values = (0..384)
                .map(|id| format!("({id},'{}')", "x".repeat(512)))
                .collect::<Vec<_>>()
                .join(",");
            let mut seed = request(&format!("INSERT INTO items VALUES {values}"));
            seed.idempotency_key = Some("pressure-seed".into());
            let first = engine.execute(seed.clone()).unwrap().response;
            assert!(first.committed, "durable ACK must not wait for checkpoint");
            let deadline = Instant::now() + Duration::from_secs(10);
            while !marker.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            let reached = marker.exists();
            let pressure = engine.state.read().retained_bytes() >= memory::flush_threshold();
            let replay = engine.execute(seed).unwrap().response;
            let read = engine
                .execute(request("SELECT COUNT(*) FROM items"))
                .unwrap()
                .response;
            let sequence = engine.state.read().sequence;
            let watermark = engine.wal.lock().unwrap().len().unwrap();
            let cancellation = Arc::new(AtomicBool::new(false));
            let pending_cancel = Arc::clone(&cancellation);
            let pending_engine = Arc::clone(&engine);
            let (send, receive) = std::sync::mpsc::channel();
            let writer = std::thread::spawn(move || {
                memory::with_pool_handle(pool, |_| {
                    let result = pending_engine.execute_with_audit_cancellable(
                        request("INSERT INTO items VALUES (999, 'next')"),
                        &AuditContext::embedded(),
                        pending_cancel,
                    );
                    send.send(result).unwrap();
                });
            });
            let early = receive.recv_timeout(Duration::from_millis(150)).ok();
            let was_waiting = early.is_none();
            let untouched = engine.state.read().sequence == sequence
                && engine.wal.lock().unwrap().len().unwrap() == watermark;
            let result = if cancel_pending {
                cancellation.store(true, AtomicOrdering::Release);
                early.or_else(|| receive.recv_timeout(Duration::from_secs(2)).ok())
            } else {
                fs::write(&release, b"continue").unwrap();
                early.or_else(|| receive.recv_timeout(Duration::from_secs(10)).ok())
            };
            // Always release the paused worker before any assertion can unwind.
            fs::write(&release, b"continue").unwrap();
            writer.join().unwrap();
            assert!(engine.cancel_and_drain_checkpoint(Instant::now() + Duration::from_secs(10)));
            drop(env);
            assert!(
                reached && pressure,
                "fixture did not pause a pressured checkpoint"
            );
            assert_eq!(replay.transaction_id, first.transaction_id);
            assert!(matches!(&read.results[0], SqlResult::Rows { rows, .. }
                if rows == &vec![vec![RelationalValue::Integer(384)]]));
            assert!(
                was_waiting && untouched,
                "new write bypassed checkpoint pressure"
            );
            let result = result.expect("pending writer did not finish");
            if cancel_pending {
                assert!(
                    result
                        .err()
                        .expect("write should cancel")
                        .to_string()
                        .contains("cancel")
                );
                assert_eq!(engine.state.read().sequence, sequence);
                assert_eq!(engine.wal.lock().unwrap().len().unwrap(), watermark);
            } else {
                assert!(result.unwrap().response.committed);
            }
        });
        let reopened =
            RelationalEngine::open(temp.path(), TransactionJournal::open(temp.path()).unwrap())
                .unwrap();
        let count = reopened
            .execute(request("SELECT COUNT(*) FROM items"))
            .unwrap()
            .response;
        assert!(matches!(&count.results[0], SqlResult::Rows { rows, .. }
            if rows == &vec![vec![RelationalValue::Integer(if cancel_pending {384} else {385})]]));
    }

    #[test]
    fn pressured_checkpoint_admits_reads_replays_and_releases_the_next_writer() {
        pressured_checkpoint_writer(false);
    }

    #[test]
    fn pressured_checkpoint_writer_cancels_before_any_commit() {
        pressured_checkpoint_writer(true);
    }

    #[test]
    fn stale_worker_drains_newer_overlay_without_another_successful_write() {
        let temp = tempfile::tempdir().unwrap();
        memory::with_pool(16 * 1024 * 1024, |_| {
            let journal = TransactionJournal::open(temp.path()).unwrap();
            let engine = RelationalEngine::open(temp.path(), journal).unwrap();
            engine
                .execute(request(
                    "CREATE TABLE items (id BIGINT PRIMARY KEY, text TEXT)",
                ))
                .unwrap();
            let insert = |first, end| {
                let values = (first..end)
                    .map(|id| format!("({id},'{}')", "x".repeat(512)))
                    .collect::<Vec<_>>()
                    .join(",");
                engine
                    .execute(request(&format!("INSERT INTO items VALUES {values}")))
                    .unwrap();
            };
            insert(0, 128);
            engine.enable_background_checkpoints(Arc::new(()));
            let marker = temp.path().join("marker");
            let release = temp.path().join("release");
            let env = crate::failpoint::test_env(
                "pause:relational_checkpoint.after_segments",
                &marker,
                &release,
            );
            schedule(&engine);
            let deadline = Instant::now() + Duration::from_secs(10);
            while !marker.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            let reached = marker.exists();
            insert(128, 384);
            let sequence = engine.state.read().sequence;
            let pressure = engine.state.read().retained_bytes() >= memory::flush_threshold();
            fs::write(&release, b"continue").unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while engine
                .checkpoint_worker
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            let published = read_relational_checkpoint(&engine.checkpoint_path)
                .unwrap()
                .map(|checkpoint| checkpoint.sequence);
            let drained = engine.state.read().retained_bytes() < memory::flush_threshold();
            assert!(engine.cancel_and_drain_checkpoint(Instant::now() + Duration::from_secs(10)));
            drop(env);
            assert!(reached, "worker did not reach the publication boundary");
            assert!(pressure, "fixture did not create retained overlay pressure");
            assert_eq!(
                published,
                Some(sequence),
                "newer acknowledged writes were not checkpointed"
            );
            assert!(drained, "stale checkpoint left overlays under pressure");
        });
        let journal = TransactionJournal::open(temp.path()).unwrap();
        let engine = RelationalEngine::open(temp.path(), journal).unwrap();
        let response = engine
            .execute(request("SELECT COUNT(*) FROM items"))
            .unwrap()
            .response;
        let SqlResult::Rows { rows, .. } = &response.results[0] else {
            panic!("count did not return rows");
        };
        assert_eq!(rows[0][0], RelationalValue::Integer(384));
    }

    #[test]
    fn checkpoint_pause_drains_worker_and_resumes_publication() {
        let temp = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(temp.path()).unwrap();
        let engine = RelationalEngine::open(temp.path(), Arc::clone(&journal)).unwrap();
        engine.enable_background_checkpoints(Arc::new(()));
        let marker = temp.path().join("marker");
        let release = temp.path().join("release");
        let env = crate::failpoint::test_env(
            "pause:relational_checkpoint.after_segments",
            &marker,
            &release,
        );
        engine
            .execute(request("CREATE TABLE documents (id BIGINT PRIMARY KEY)"))
            .unwrap();
        schedule(&engine);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !marker.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let reached = marker.exists();
        let (send, receive) = std::sync::mpsc::channel();
        let paused_engine = Arc::clone(&engine);
        let pausing =
            std::thread::spawn(move || send.send(paused_engine.pause_checkpoints()).unwrap());
        let drained_before_release = receive.recv_timeout(Duration::from_millis(100)).is_ok();
        fs::write(&release, b"continue").unwrap();
        pausing.join().unwrap();
        assert!(
            reached,
            "checkpoint worker did not reach its publication boundary"
        );
        assert!(
            !drained_before_release,
            "pause returned with an active checkpoint worker"
        );
        let pause = receive
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        drop(env);
        let before = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .map(|c| c.sequence);
        engine
            .execute(request("CREATE TABLE paused (id BIGINT PRIMARY KEY)"))
            .unwrap();
        schedule(&engine);
        assert_eq!(
            read_relational_checkpoint(&engine.checkpoint_path)
                .unwrap()
                .map(|c| c.sequence),
            before
        );
        drop(pause);
        engine
            .execute(request("CREATE TABLE resumed (id BIGINT PRIMARY KEY)"))
            .unwrap();
        schedule(&engine);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if read_relational_checkpoint(&engine.checkpoint_path)
                .unwrap()
                .is_some_and(|c| c.sequence == 3)
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "checkpoint publication did not resume"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(engine.cancel_and_drain_checkpoint(Instant::now() + Duration::from_secs(10)));
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(temp.path()).unwrap();
        let reopened = RelationalEngine::open(temp.path(), journal).unwrap();
        assert_eq!(reopened.table_definitions().len(), 3);
    }
}
