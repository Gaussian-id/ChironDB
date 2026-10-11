use super::*;
use crate::transaction_journal::TransactionPrepare;
use std::io::Write;

#[test]
fn encoded_json_copy_preserves_finite_numeric_bits_and_integer_boundaries() {
    let values = [
        1.2345678901234567e300_f64,
        f64::MAX,
        f64::MIN_POSITIVE,
        f64::from_bits(1),
        -0.0,
        0.1,
        0.1_f32 as f64,
    ];
    for value in values {
        let original =
            serde_json::json!({"number": value, "unsigned": u64::MAX, "signed": i64::MIN});
        let copied = copy(&original).unwrap();
        assert_eq!(
            copied["number"].as_f64().unwrap().to_bits(),
            value.to_bits(),
            "value={value}"
        );
        assert_eq!(copied["unsigned"].as_u64(), Some(u64::MAX));
        assert_eq!(copied["signed"].as_i64(), Some(i64::MIN));
    }
    let mut bits = 0x2197_e452_581e_f317_u64;
    let mut samples = Vec::new();
    for _ in 0..4096 {
        bits ^= bits << 13;
        bits ^= bits >> 7;
        bits ^= bits << 17;
        let value = f64::from_bits(bits);
        if value.is_finite() {
            samples.push(value);
        }
    }
    let source = serde_json::to_value(&samples).unwrap();
    let copied = copy(&source).unwrap();
    assert_eq!(copied.as_array().unwrap().len(), samples.len());
    for (actual, expected) in copied.as_array().unwrap().iter().zip(&samples) {
        assert_eq!(actual.as_f64().unwrap().to_bits(), expected.to_bits());
    }
}

#[test]
fn borrowed_json_receiving_owner_refuses_before_serialization_and_releases_after_consumption() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[derive(Serialize)]
    struct Fields<'a> {
        floats: &'a [f32],
        body: &'a str,
        payload: &'a serde_json::Value,
    }
    struct Probe<'a> {
        fields: &'a Fields<'a>,
        calls: &'a AtomicUsize,
        used: &'a dyn Fn() -> u64,
    }
    impl Serialize for Probe<'_> {
        fn serialize<S: serde::Serializer>(
            &self,
            serializer: S,
        ) -> std::result::Result<S::Ok, S::Error> {
            assert!(
                (self.used)() > 0,
                "root must be admitted before visiting borrowed source"
            );
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.fields.serialize(serializer)
        }
    }
    let floats = [0.7181532_f32, 0.1, -0.0, f32::MAX, f32::MIN_POSITIVE];
    let body = "日本語\n".repeat(2048);
    let payload =
        serde_json::json!({"float":1.2345678901234567e300_f64,"zero":-0.0,"integer":u64::MAX});
    let fields = Fields {
        floats: &floats,
        body: &body,
        payload: &payload,
    };
    let expected = serde_json::to_value(&fields).unwrap();
    let calls = AtomicUsize::new(0);
    memory::with_storage_pool(1, |pool| {
        let used = || pool.used();
        assert!(matches!(
            json(&Probe {
                fields: &fields,
                calls: &calls,
                used: &used
            }),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(pool.used(), 0);
    });
    memory::with_storage_pool(4096, |pool| {
        let used = || pool.used();
        assert!(matches!(
            json(&Probe {
                fields: &fields,
                calls: &calls,
                used: &used
            }),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(pool.used(), 0);
    });
    memory::with_storage_pool(2 * 1024 * 1024, |pool| {
        let used = || pool.used();
        let owned = json(&Probe {
            fields: &fields,
            calls: &calls,
            used: &used,
        })
        .unwrap();
        assert_eq!(&*owned, &expected);
        assert!(pool.used() >= body.len() as u64);
        let retained = pool.used();
        owned
            .consume(|value| {
                assert_eq!(pool.used(), retained);
                assert_eq!(value, expected);
                assert_eq!(
                    value["payload"]["float"].as_f64().unwrap().to_bits(),
                    payload["float"].as_f64().unwrap().to_bits()
                );
                Ok(())
            })
            .unwrap();
        assert_eq!(pool.used(), 0);
        let error = json(&fields)
            .unwrap()
            .consume::<()>(|_| Err(invalid("consumer refused")));
        assert!(error.is_err());
        assert_eq!(pool.used(), 0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            json(&fields)
                .unwrap()
                .consume::<()>(|_| panic!("consumer panic"))
        }));
        assert!(result.is_err());
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn admitted_json_receipt_and_numeric_mutation_replay_exactly_after_journal_reopen() {
    use crate::transaction_journal::{IdempotencyAdmission, TransactionState};
    #[derive(Serialize)]
    struct Response<'a> {
        vector: &'a [f32],
        payload: &'a serde_json::Value,
    }
    let dir = tempfile::tempdir().unwrap();
    let point = crate::Point {
        id: "numeric-record".into(),
        vector: vec![0.7181532, -0.0, f32::MAX, f32::MIN_POSITIVE],
        vectors: Default::default(),
        sparse_vector: None,
        payload: serde_json::json!({"number":1.2345678901234567e300_f64,
            "unsigned":u64::MAX, "signed":i64::MIN, "negative_zero":-0.0}),
    };
    let response = Response {
        vector: &point.vector,
        payload: &point.payload,
    };
    let expected = serde_json::to_value(&response).unwrap();
    let context = AuditContext::embedded();
    let id = memory::with_storage_pool(4 * 1024 * 1024, |pool| {
        let journal = TransactionJournal::open(dir.path()).unwrap();
        let IdempotencyAdmission::Execute(claim) = journal
            .begin_idempotent("numeric-receipt", &context, "upsert", &point, || Ok(()))
            .unwrap()
        else {
            panic!("new request must execute")
        };
        let transaction = json(&response)
            .unwrap()
            .consume(|value| {
                claim.commit(
                    TransactionTarget::Collection {
                        name: "docs".into(),
                    },
                    WalEntry::Upsert {
                        point: point.clone(),
                    },
                    TransactionAudit::mutation(
                        "upsert",
                        Some("docs"),
                        &context,
                        serde_json::Value::Null,
                    ),
                    value,
                )
            })
            .unwrap();
        let id = transaction.prepare.transaction_id;
        journal.mark_projected(id, ProjectionKind::Storage).unwrap();
        journal.mark_projected(id, ProjectionKind::Audit).unwrap();
        drop(transaction);
        drop(claim);
        let IdempotencyAdmission::Replay(replay) = journal
            .begin_idempotent("numeric-receipt", &context, "upsert", &point, || Ok(()))
            .unwrap()
        else {
            panic!("committed key must replay")
        };
        assert_eq!(replay.status.transaction_id, id);
        assert_eq!(replay.response.as_ref().unwrap(), &expected);
        drop(replay);
        drop(journal);
        assert_eq!(pool.used(), 0);
        id
    });
    memory::with_storage_pool(4 * 1024 * 1024, |pool| {
        let journal = TransactionJournal::open(dir.path()).unwrap();
        let IdempotencyAdmission::Replay(replay) = journal
            .begin_idempotent("numeric-receipt", &context, "upsert", &point, || Ok(()))
            .unwrap()
        else {
            panic!("reopened key must replay")
        };
        assert_eq!(replay.status.transaction_id, id);
        assert_eq!(replay.status.state, TransactionState::Committed);
        let value = replay.response.as_ref().unwrap();
        assert_eq!(value, &expected);
        assert_eq!(
            value["payload"]["number"].as_f64().unwrap().to_bits(),
            1.2345678901234567e300_f64.to_bits()
        );
        assert_eq!(
            value["payload"]["negative_zero"]
                .as_f64()
                .unwrap()
                .to_bits(),
            (-0.0_f64).to_bits()
        );
        let transactions = journal.committed().unwrap();
        assert_eq!(
            transactions.len(),
            1,
            "replay cannot produce a second commit"
        );
        let WalEntry::Upsert { point: recovered } = &*transactions[0].prepare.mutation else {
            panic!("expected numeric point mutation")
        };
        assert_eq!(recovered.payload, point.payload);
        assert_eq!(
            recovered.payload["number"].as_f64().unwrap().to_bits(),
            1.2345678901234567e300_f64.to_bits()
        );
        assert_eq!(
            recovered
                .vector
                .iter()
                .map(|v| v.to_bits())
                .collect::<Vec<_>>(),
            point.vector.iter().map(|v| v.to_bits()).collect::<Vec<_>>()
        );
        drop(transactions);
        drop(replay);
        drop(journal);
        assert_eq!(pool.used(), 0);
    });
}

fn batch() -> RelationalBatch {
    RelationalBatch {
        sequence: 1,
        mutations: Vec::new(),
    }
}

#[test]
fn frame_admission_covers_read_and_chunked_write_peaks() {
    for len in [1, 64 * 1024 - 1, 64 * 1024, 64 * 1024 + 1, 16 * 1024 * 1024] {
        memory::with_storage_pool(128 * 1024 * 1024, |pool| {
            let mut frame = FrameAdmission::new().unwrap();
            frame.prepare(len, false).unwrap();
            let read = 3 * len as u64;
            let chunk = crate::encryption::DEFAULT_CHUNK_SIZE;
            let write = len as u64 + len.div_ceil(chunk) as u64 * 20 + 3 * len.min(chunk) as u64;
            assert!(pool.used() >= read.max(write) + 4096 + memory::LEASE_ROOT_BYTES);
            if len >= 1024 * 1024 {
                assert!(pool.used() < 4 * len as u64);
            }
            drop(frame);
            assert_eq!(pool.used(), 0);
        });
    }
}

fn write_frame(path: &Path, payload: &[u8], crc: u32) {
    let mut file = std::fs::File::create(path).unwrap();
    file.write_all(&(payload.len() as u32).to_le_bytes())
        .unwrap();
    file.write_all(&crc.to_le_bytes()).unwrap();
    file.write_all(payload).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn frame_refusal_precedes_payload_crc_and_preserves_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("000000.gdwal");
    let payload = vec![b' '; 32 * 1024];
    write_frame(&path, &payload, 7);
    let before = std::fs::read(&path).unwrap();
    memory::with_storage_pool(8192, |pool| {
        assert!(matches!(
            Wal::inspect_at(directory.path(), 0, |_| Ok(())),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    memory::with_storage_pool(16 * 1024 * 1024, |pool| {
        let error = Wal::inspect_at(directory.path(), 0, |_| Ok(())).unwrap_err();
        assert!(matches!(error, GaussError::WalCorruption { .. }));
        assert!(error.to_string().contains("crc mismatch"));
        assert_eq!(pool.used(), 0);
    });
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn expanded_dto_is_refused_and_charge_stays_through_visitor() {
    let directory = tempfile::tempdir().unwrap();
    let mut wal = Wal::open(directory.path()).unwrap();
    let entry = WalEntry::DeleteBatch {
        ids: vec![String::new(); 20_000],
    };
    wal.append(&entry).unwrap();
    wal.sync().unwrap();
    memory::with_storage_pool(1024 * 1024, |pool| {
        assert!(matches!(
            Wal::inspect_at::<()>(directory.path(), 0, |_| panic!(
                "expanded visitor must not run"
            )),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    memory::with_storage_pool(32 * 1024 * 1024, |pool| {
        Wal::inspect_at(directory.path(), 0, |record| {
            let WalEntry::DeleteBatch { ids } = &record.entry else {
                panic!("wrong entry")
            };
            assert_eq!(ids.len(), 20_000);
            assert!(pool.used() >= (ids.capacity() * size_of::<String>()) as u64);
            Err::<(), _>(invalid("visitor refused"))
        })
        .unwrap_err();
        assert_eq!(pool.used(), 0);
        Wal::inspect_at(directory.path(), 0, |_| Ok(())).unwrap();
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn cancellation_inside_inspection_releases_frame_and_typed_owners() {
    let directory = tempfile::tempdir().unwrap();
    let mut wal = Wal::open(directory.path()).unwrap();
    wal.append(&WalEntry::Delete { id: "x".into() }).unwrap();
    memory::with_storage_pool(2 * 1024 * 1024, |pool| {
        let cancel = Arc::new(AtomicBool::new(false));
        with_sql_cancellation(cancel.clone(), || {
            let error = Wal::inspect_at(directory.path(), 0, |_| {
                cancel.store(true, AtomicOrdering::Release);
                check_sql_cancelled()
            })
            .unwrap_err();
            assert!(error.to_string().contains("query canceled"));
            assert_eq!(pool.used(), 0);
            Ok(())
        })
        .unwrap();
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn json_failures_lsn_mismatch_and_legacy_shape_remain_corruption() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("000000.gdwal");
    for payload in [
        b"{broken".as_slice(),
        br#"{"lsn":8,"entry":{"Delete":{"id":"x"}}}"#,
        br#"{"Delete":{"id":"x"}}"#,
    ] {
        write_frame(&path, payload, crc32fast::hash(payload));
        memory::with_storage_pool(2 * 1024 * 1024, |pool| {
            assert!(matches!(
                Wal::inspect_at(directory.path(), 0, |_| Ok(())),
                Err(GaussError::WalCorruption { .. })
            ));
            assert_eq!(pool.used(), 0);
        });
    }
}

#[test]
fn cold_journal_proof_refusal_preserves_acknowledged_commit_and_retry() {
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let transaction = journal
        .commit(
            TransactionTarget::Relational,
            WalEntry::RelationalBatch { batch: batch() },
            TransactionAudit::mutation(
                "sql",
                None,
                &AuditContext::embedded(),
                serde_json::Value::Null,
            ),
        )
        .unwrap();
    let id = transaction.prepare.transaction_id;
    journal.mark_projected(id, ProjectionKind::Storage).unwrap();
    journal.mark_projected(id, ProjectionKind::Audit).unwrap();
    drop(journal);
    let journal = TransactionJournal::open(directory.path()).unwrap();
    memory::with_storage_pool(8192, |pool| {
        assert!(matches!(
            journal.validate_relational_projection(id, &batch()),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    memory::with_storage_pool(2 * 1024 * 1024, |pool| {
        journal
            .validate_relational_projection(id, &batch())
            .unwrap();
        assert_eq!(pool.used(), 0);
        assert!(matches!(
            journal.validate_relational_projection(
                id,
                &RelationalBatch {
                    sequence: 2,
                    mutations: Vec::new()
                }
            ),
            Err(GaussError::WalCorruption { .. })
        ));
        assert_eq!(pool.used(), 0);
    });
    assert_eq!(
        journal.status(id).state,
        crate::transaction_journal::TransactionState::Committed
    );
}

#[test]
fn nested_prepare_preserves_json_and_tagged_targets() {
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let transaction = journal
        .commit(
            TransactionTarget::Relational,
            WalEntry::RelationalBatch { batch: batch() },
            TransactionAudit::mutation(
                "sql",
                None,
                &AuditContext::embedded(),
                serde_json::json!({"tags":[null,"雪", {"a": 7}]}),
            ),
        )
        .unwrap();
    let prepare: &TransactionPrepare = &transaction.prepare;
    let entry = WalEntry::TransactionPrepare {
        prepare: prepare.clone(),
    };
    let input = serde_json::to_vec(&entry).unwrap();
    memory::with_storage_pool(2 * 1024 * 1024, |pool| {
        inspect::<WalEntry, _>(&input, |decoded| {
            assert_eq!(
                serde_json::to_value(decoded).unwrap(),
                serde_json::to_value(&entry).unwrap()
            );
            assert!(pool.used() > 0);
            Ok(())
        })
        .unwrap();
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn visitor_json_error_and_unwind_release_reservations_without_reclassifying() {
    let directory = tempfile::tempdir().unwrap();
    let mut wal = Wal::open(directory.path()).unwrap();
    wal.append(&WalEntry::Delete { id: "x".into() }).unwrap();
    memory::with_storage_pool(2 * 1024 * 1024, |pool| {
        let error = Wal::inspect_at::<()>(directory.path(), 0, |_| {
            Err(serde_json::from_str::<serde_json::Value>("{visitor")
                .unwrap_err()
                .into())
        })
        .unwrap_err();
        assert!(matches!(error, GaussError::Json(_)));
        assert_eq!(pool.used(), 0);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Wal::inspect_at::<()>(directory.path(), 0, |_| panic!("visitor panicked"))
        }));
        assert!(panic.is_err());
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn dto_destructor_observes_live_reservation_during_panic_unwind() {
    thread_local! {
        static PROBE: std::cell::RefCell<Option<Arc<memory::Pool>>> = const { std::cell::RefCell::new(None) };
        static LIVE_AT_DROP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    #[derive(Deserialize)]
    struct Probe {
        body: String,
    }
    impl Drop for Probe {
        fn drop(&mut self) {
            PROBE.with(|pool| {
                let pool = pool.borrow();
                LIVE_AT_DROP.with(|live| {
                    live.set(pool.as_ref().unwrap().used() >= self.body.capacity() as u64)
                });
            });
        }
    }
    let input = serde_json::to_vec(&serde_json::json!({"body": "x".repeat(64 * 1024)})).unwrap();
    memory::with_storage_pool(2 * 1024 * 1024, |pool| {
        PROBE.with(|p| *p.borrow_mut() = Some(pool.clone()));
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            inspect::<Probe, ()>(&input, |_| panic!("visitor panicked"))
        }));
        assert!(panic.is_err());
        assert!(
            LIVE_AT_DROP.with(std::cell::Cell::get),
            "DTO allocation outlived its reservation during unwind"
        );
        assert_eq!(pool.used(), 0);
        LIVE_AT_DROP.with(|live| live.set(false));
        inspect::<Probe, ()>(&input, |_| Err(invalid("visitor failed"))).unwrap_err();
        assert_eq!(pool.used(), 0);
        assert!(
            LIVE_AT_DROP.with(std::cell::Cell::get),
            "DTO allocation outlived its reservation on error"
        );
        PROBE.with(|p| *p.borrow_mut() = None);
    });
}
