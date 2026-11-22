use super::*;

fn add(state: &mut TemporalState, time: i64) {
    state.admit_new_run().unwrap();
    let batch = TemporalBatch {
        version: 1,
        tenant: "fleet".into(),
        incarnation: None,
        samples: vec![TemporalSample::new(
            "truck",
            "temperature",
            time,
            SensorValue::Float(time as f64),
        )],
    };
    let rows = state.prepare(&batch).unwrap();
    state.apply(rows);
}

fn persist(state: &mut TemporalState, dir: &Path) -> Vec<String> {
    let config = serde_json::from_value(serde_json::json!({"name":"docs","vector_dim":2})).unwrap();
    let mut cp = CollectionCheckpoint::new(&config, 1, 0, 0, None).unwrap();
    cp.temporal_runs = state.checkpoint().unwrap();
    cp.temporal_wal_lsn = Some(0);
    write_checkpoint(dir, &cp).unwrap();
    cp.temporal_runs.unwrap()
}

#[test]
fn checkpoint_can_defer_a_merge_that_exceeds_available_memory() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("docs");
    fs::create_dir(&dir).unwrap();
    let mut state = TemporalState::empty(&dir);
    state.enabled = true;
    persist(&mut state, &dir);
    for offset in [0, 20_000] {
        let rows = BTreeMap::from([(
            Series::new("fleet", "truck", "temperature"),
            (offset..offset + 20_000)
                .map(|time| (time, SensorValue::Float(time as f64)))
                .collect(),
        )]);
        state.apply((rows, MetadataCharge::default()));
        state.flush().unwrap();
    }
    let before: Vec<_> = state.runs.iter().map(|(id, _)| id.clone()).collect();
    let ids =
        crate::relational::wal_decode::with_test_storage_pool(2 << 20, |_| state.checkpoint())
            .unwrap()
            .unwrap();
    assert_eq!(
        ids, before,
        "unadmitted merge must leave both inputs intact"
    );
    let ids = persist(&mut state, &dir);
    assert_eq!(ids.len(), 1, "maintenance resumes when memory is available");
    let reopened = TemporalState::load(&dir, Some(ids)).unwrap();
    assert_eq!(
        reopened
            .read(&Series::new("fleet", "truck", "temperature"), None)
            .unwrap()[0]
            .time,
        39_999
    );
}

#[test]
fn checkpoints_beyond_old_run_limit_preserve_history_and_reclaim_files() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("docs");
    fs::create_dir(&dir).unwrap();
    let mut state = TemporalState::empty(&dir);
    state.enabled = true;
    persist(&mut state, &dir);
    for time in 0..MAX_RUNS as i64 + 8 {
        add(&mut state, time);
        let ids = persist(&mut state, &dir);
        assert!(ids.len() < 32, "run count at {time}: {}", ids.len());
        if time % 257 == 0 {
            state = TemporalState::load(&dir, Some(ids)).unwrap();
        }
    }
    let ids = persist(&mut state, &dir);
    state = TemporalState::load(&dir, Some(ids)).unwrap();
    for time in 0..MAX_RUNS as i64 + 8 {
        let rows = state
            .read(
                &Series::new("fleet", "truck", "temperature"),
                Some((time, time + 1, 1)),
            )
            .unwrap();
        assert_eq!(
            rows,
            vec![Observation {
                time,
                value: SensorValue::Float(time as f64)
            }]
        );
    }
    state.reclaim_obsolete_runs().unwrap();
    assert_eq!(fs::read_dir(&state.dir).unwrap().count(), state.runs.len());
}

#[test]
fn full_legacy_run_set_recovers_write_capacity_without_losing_checkpoint() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("docs");
    fs::create_dir(&dir).unwrap();
    let mut state = TemporalState::empty(&dir);
    state.enabled = true;
    persist(&mut state, &dir);
    // Build the exact legacy layout without using the new checkpoint merger.
    for time in 0..MAX_RUNS as i64 {
        let mut rows = Rows::new();
        rows.entry(Series::new("fleet", "truck", "temperature"))
            .or_default()
            .insert(time, SensorValue::Float(time as f64));
        state.apply((rows, MetadataCharge::default()));
        state.flush().unwrap();
    }
    let old: Vec<_> = state.runs.iter().map(|(id, _)| id.clone()).collect();
    assert_eq!(old.len(), MAX_RUNS);
    let mut checkpoint = read_checkpoint(&dir).unwrap().unwrap();
    checkpoint.temporal_runs = Some(old.clone());
    write_checkpoint(&dir, &checkpoint).unwrap();
    add(&mut state, MAX_RUNS as i64);
    // Merge-before-checkpoint must leave every legacy referenced file readable.
    let legacy = TemporalState::load(&dir, Some(old)).unwrap();
    assert_eq!(
        legacy
            .read(&Series::new("fleet", "truck", "temperature"), None)
            .unwrap()[0]
            .time,
        MAX_RUNS as i64 - 1
    );
    let ids = persist(&mut state, &dir);
    let reopened = TemporalState::load(&dir, Some(ids)).unwrap();
    assert_eq!(
        reopened
            .read(&Series::new("fleet", "truck", "temperature"), None)
            .unwrap()[0]
            .time,
        MAX_RUNS as i64
    );
}
