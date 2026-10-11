use std::{fs, path::Path, sync::Arc};

#[cfg(feature = "fault-injection")]
use std::{
    io::Read,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
#[cfg(feature = "fault-injection")]
use chirondb_core::{GaussError, audit::AuditContext, encryption::MAGIC};
use chirondb_core::{
    RelationalValue, SqlExecutionRequest, SqlResult, SqlStatementRequest,
    encryption::{Keyring, install_process_keyring},
    relational::RelationalEngine,
    transaction_journal::TransactionJournal,
};
use serde_json::json;

fn request(sql: &str) -> SqlExecutionRequest {
    SqlExecutionRequest {
        statements: vec![SqlStatementRequest {
            sql: sql.into(),
            parameters: Vec::new(),
        }],
        idempotency_key: None,
        retry_id: None,
    }
}

fn install_keyring(root: &Path) {
    let path = root.join("keyring.json");
    fs::write(
        &path,
        json!({
            "version": 1,
            "active_key_id": "spill-test",
            "keys": [{"id": "spill-test", "key_base64": STANDARD.encode([29_u8; 32])}]
        })
        .to_string(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    install_process_keyring(Keyring::load(&path).unwrap(), true).unwrap();
}

#[test]
fn encrypted_topk_spill_keeps_order_and_cleans_up_after_reopen() {
    let root = tempfile::tempdir().unwrap();
    install_keyring(root.path());
    let data_dir = root.path().join("data");
    fs::create_dir_all(&data_dir).unwrap();
    let journal = TransactionJournal::open(&data_dir).unwrap();
    let engine = RelationalEngine::open(&data_dir, Arc::clone(&journal)).unwrap();
    engine
        .execute(request(
            "CREATE TABLE spill_test (id INTEGER PRIMARY KEY, score INTEGER, note TEXT)",
        ))
        .unwrap();
    let note = "s".repeat(64 * 1024);
    for chunk in 0..30 {
        let values = (chunk * 8..chunk * 8 + 8)
            .map(|id| {
                let score = if id % 31 == 0 {
                    "NULL".to_string()
                } else {
                    ((id * 17) % 11).to_string()
                };
                format!("({id}, {score}, '{note}')")
            })
            .collect::<Vec<_>>()
            .join(", ");
        engine
            .execute(request(&format!("INSERT INTO spill_test VALUES {values}")))
            .unwrap();
    }
    let sql =
        "SELECT id FROM spill_test ORDER BY score DESC NULLS LAST, id ASC LIMIT 13 OFFSET 160";
    let spill_parent = data_dir.join("relational/query-spill");
    #[cfg(feature = "fault-injection")]
    {
        let marker = root.path().join("spill.marker");
        let release = root.path().join("spill.release");
        // This binary has one test, so the process-wide fault injection is
        // confined to this test's worker and restored before the next query.
        unsafe {
            std::env::set_var(
                "CHIRONDB_FAILPOINT",
                "pause:relational_query_spill.after_run",
            );
            std::env::set_var("CHIRONDB_FAILPOINT_MARKER", &marker);
            std::env::set_var("CHIRONDB_FAILPOINT_RELEASE", &release);
        }
        let cancellation = Arc::new(AtomicBool::new(false));
        let worker_engine = Arc::clone(&engine);
        let worker_cancellation = Arc::clone(&cancellation);
        let worker = std::thread::spawn(move || {
            worker_engine.execute_with_audit_cancellable(
                request(sql),
                &AuditContext::embedded(),
                worker_cancellation,
            )
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        while !marker.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !marker.exists() {
            cancellation.store(true, Ordering::Release);
            fs::write(&release, b"continue").unwrap();
            let _ = worker.join();
            panic!("query never reached the spill boundary");
        }
        let directory = fs::read_dir(&spill_parent)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let file = fs::read_dir(directory)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut prefix = [0_u8; 8];
        fs::File::open(file)
            .unwrap()
            .read_exact(&mut prefix)
            .unwrap();
        assert_eq!(&prefix, MAGIC);
        cancellation.store(true, Ordering::Release);
        fs::write(&release, b"continue").unwrap();
        assert!(matches!(
            worker.join().unwrap(),
            Err(GaussError::InvalidRequest(message)) if message == "query canceled"
        ));
        unsafe {
            std::env::remove_var("CHIRONDB_FAILPOINT");
            std::env::remove_var("CHIRONDB_FAILPOINT_MARKER");
            std::env::remove_var("CHIRONDB_FAILPOINT_RELEASE");
        }
        assert_eq!(fs::read_dir(&spill_parent).unwrap().count(), 0);
    }
    let result = engine.execute(request(sql)).unwrap().response;
    let mut expected = (0_i64..240).collect::<Vec<_>>();
    expected.sort_by_key(|id| {
        let score = if id % 31 == 0 {
            None
        } else {
            Some((id * 17) % 11)
        };
        (score.is_none(), std::cmp::Reverse(score), *id)
    });
    let expected = expected[160..173]
        .iter()
        .copied()
        .map(|id| vec![RelationalValue::Integer(id)])
        .collect::<Vec<_>>();
    assert!(matches!(&result.results[0], SqlResult::Rows { rows, .. } if rows == &expected));
    assert_eq!(fs::read_dir(&spill_parent).unwrap().count(), 0);

    // Recovery removes only its own abandoned scratch namespace, then the
    // same SQL result remains stable after reopening the durable table.
    let stale = spill_parent.join(".chiron-query-spill-interrupted");
    fs::create_dir(&stale).unwrap();
    fs::write(stale.join("0.run"), b"interrupted scratch").unwrap();
    drop(engine);
    drop(journal);
    let journal = TransactionJournal::open(&data_dir).unwrap();
    let engine = RelationalEngine::open(&data_dir, journal).unwrap();
    assert!(!stale.exists());
    assert_eq!(engine.execute(request(sql)).unwrap().response, result);
    assert_eq!(fs::read_dir(&spill_parent).unwrap().count(), 0);
}
