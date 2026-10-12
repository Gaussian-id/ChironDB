//! Temporarily quiesce checkpoint publication while Db freezes a content root.
//! Db holds its exclusive lifecycle gate, so no new SQL commit can schedule a
//! worker before this guard restores the previous cancellation state.
use super::*;

pub(crate) struct CheckpointPause {
    engine: Arc<RelationalEngine>,
    was_cancelled: bool,
}

impl RelationalEngine {
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
