#[test]
fn protected_sealed_point_failures_follow_authorization_and_abort_updates() {
    use std::io::{Seek, SeekFrom, Write};
    let (directory, db, key, other_key) = fixture(false);
    db.inner.read().collections["docs"]
        .write()
        .config
        .streamer_max_bytes = 1;
    let writer = db.identity_authority().unwrap().authenticate(&key).unwrap();
    let create = db
        .bind_access(&writer, "docs", "acme", Action::Create)
        .unwrap();
    let inputs = vec![point("healthy"), point(&"refund ".repeat(18_000))];
    let ids = db
        .create_points_authorized(&create, "standard", inputs, true)
        .unwrap()
        .publish(|ids| ids)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let collection = db.inner.read().collections["docs"].clone();
        let collection = collection.read();
        if collection.sealing.is_none() && !collection.searchers.is_empty() {
            break;
        }
        assert!(Instant::now() < deadline, "protected seal did not complete");
        drop(collection);
        std::thread::sleep(Duration::from_millis(10));
    }
    let read = db
        .bind_access(&writer, "docs", "acme", Action::Read)
        .unwrap();
    let search = db
        .bind_access(&writer, "docs", "acme", Action::Search)
        .unwrap();
    let update = db
        .bind_access(&writer, "docs", "acme", Action::Update)
        .unwrap();
    let physical = read.authorize(&ids[1]).unwrap().storage_id.to_string();
    let collection = db.inner.read().collections["docs"].clone();
    let (path, ordinal, frontier) = {
        let collection = collection.read();
        let searcher = &collection.searchers[0];
        let crate::searcher::SegmentStore::V4(store) = &searcher.store else {
            panic!("sealed V4 expected");
        };
        (
            searcher.dir.join(crate::seal::PAYLOAD_FILE),
            store.ordinal(&physical).unwrap(),
            collection.wal.len().unwrap(),
        )
    };
    let original = fs::read(&path).unwrap();
    let count = u64::from_le_bytes(original[8..16].try_into().unwrap()) as usize;
    let offset = 16 + 8 * ordinal;
    let start = u64::from_le_bytes(original[offset..offset + 8].try_into().unwrap()) as usize;
    let position = 16 + (count + 1) * 8 + start;
    assert_eq!(original[position], b'{');
    let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(position as u64)).unwrap();
    file.write_all(b"!").unwrap();
    let corruption = |error: GaussError| {
        assert!(matches!(error, GaussError::SegmentCorruption { .. }));
    };
    corruption(
        db.get_points_authorized(&read, &ids)
            .err()
            .expect("storage error expected"),
    );
    corruption(
        db.scroll_authorized(
            &read,
            crate::model::ScrollRequest {
                offset: None,
                limit: 2,
                filter: None,
            },
        )
        .err()
        .expect("storage error expected"),
    );
    corruption(
        db.count_authorized(&read, Some(Filter(serde_json::json!({"text":"refund"}))))
            .err()
            .expect("storage error expected"),
    );
    corruption(
        db.search_authorized(
            &search,
            serde_json::from_value(serde_json::json!({"vector":[1.0,0.0],"k":2})).unwrap(),
            None,
        )
        .err()
        .expect("storage error expected"),
    );
    corruption(
        db.text_hybrid_search_authorized(
            &search,
            crate::TextHybridSearchRequest {
                vector: vec![],
                query: "refund".into(),
                text_field: "text".into(),
                k: 2,
                filter: None,
                budget_ms: None,
            },
            None,
        )
        .err()
        .expect("storage error expected"),
    );
    corruption(
        db.update_points_authorized(
            &update,
            vec![physical_point(&point("changed"), ids[1].clone())],
            true,
        )
        .err()
        .expect("storage error expected"),
    );
    assert_eq!(collection.read().wal.len().unwrap(), frontier);
    let other = db
        .identity_authority()
        .unwrap()
        .authenticate(&other_key)
        .unwrap();
    let other_read = db
        .bind_access(&other, "docs", "acme", Action::Read)
        .unwrap();
    assert!(
        db.get_points_authorized(&other_read, &ids)
            .unwrap()
            .publish(|points| points)
            .unwrap()
            .is_empty()
    );
    file.seek(SeekFrom::Start(position as u64)).unwrap();
    file.write_all(&original[position..position + 1]).unwrap();
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(
        db.get_points_authorized(&read, &ids)
            .unwrap()
            .publish(|points| points)
            .unwrap()
            .len(),
        2
    );
    drop(file);
    drop(collection);
    drop(db);
    let reopened = Db::open(directory.path()).unwrap();
    let writer = reopened
        .identity_authority()
        .unwrap()
        .authenticate(&key)
        .unwrap();
    let read = reopened
        .bind_access(&writer, "docs", "acme", Action::Read)
        .unwrap();
    let restored = reopened
        .get_points_authorized(&read, &ids)
        .unwrap()
        .publish(|points| points)
        .unwrap();
    assert_eq!(restored.len(), 2);
    assert!(
        restored
            .iter()
            .all(|point| point.payload["text"] != "changed")
    );
}

#[cfg(feature = "fault-injection")]
fn preparation_retry_sql(text: &str, key: Option<&str>) -> crate::SqlExecutionRequest {
    crate::SqlExecutionRequest {
        statements: vec![crate::SqlStatementRequest { sql: text.into(), parameters: vec![] }],
        idempotency_key: key.map(str::to_owned),
        retry_id: Some("preparation-retry".into()),
    }
}

#[cfg(feature = "fault-injection")]
fn preparation_retry_insert(key: Option<&str>) -> crate::MultiModelInsertRequest {
    crate::MultiModelInsertRequest {
        sql: preparation_retry_sql("INSERT INTO docs VALUES ('row-1', 'before', RECORD_REF('docs', NEW_RECORD('chunk')), RECORD_REF('docs', NEW_RECORD('source'))) RETURNING chunk, source", key),
        collection: "docs".into(),
        template: "standard".into(),
        records: vec![
            crate::NewRecord { binding: "chunk".into(), point: point("before") },
            crate::NewRecord { binding: "source".into(), point: point("target") },
        ],
        relations: vec![crate::NewRelation {
            source: crate::RecordEndpoint::New("chunk".into()),
            target: crate::RecordEndpoint::New("source".into()),
            edge_type: "cites".into(),
            properties: serde_json::json!({"state":"before"}),
        }],
    }
}

#[cfg(feature = "fault-injection")]
fn preparation_retry_point(state: &str) -> crate::security::NewPoint {
    let mut value = point(state);
    if state == "after" { value.vector = vec![0.25, 0.75]; }
    value
}

#[cfg(feature = "fault-injection")]
fn assert_preparation_retry_state(
    db: &Db, identity: &crate::security::AuthenticatedIdentity, ids: &[String], state: &str,
) {
    let read = db.bind_access(identity, "docs", "acme", Action::Read).unwrap();
    let points = db.get_points_authorized(&read, ids).unwrap().publish(|points| points).unwrap();
    let rows = db.execute_sql_authorized(identity, preparation_retry_sql("SELECT title, chunk FROM docs", None), "oracle").unwrap();
    let crate::SqlResult::Rows { rows, .. } = &rows.results[0] else { panic!("rows expected") };
    let deleted = state == "deleted";
    if deleted {
        assert!(rows.is_empty());
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].id, ids[1]);
        assert_eq!(points[0].payload, point("target").payload);
    } else {
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0], crate::RelationalValue::Text(state.into()));
        assert_eq!(rows[0][1], crate::RelationalValue::RecordRef(crate::RecordRef { namespace: "docs".into(), id: ids[0].clone() }));
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].id, ids[0]);
        assert_eq!(points[0].payload, point(state).payload);
        assert_eq!(points[0].vector, preparation_retry_point(state).vector);
        assert_eq!(points[1].id, ids[1]);
        assert_eq!(points[1].payload, point("target").payload);
    }
    let graph = db.bind_access(identity, "docs", "acme", Action::GraphRead).unwrap();
    let traversal = db.traverse_authorized(&graph, crate::graph::GraphTraverseRequest {
        anchors: vec![ids[usize::from(deleted)].clone()],
        edge_types: vec!["cites".into()],
        direction: if deleted { crate::graph::GraphDirection::Incoming } else { crate::graph::GraphDirection::Outgoing },
        node_filter: None,
        edge_filter: (!deleted).then(|| Filter(serde_json::json!({"state":state}))),
        budget: crate::graph::TraversalBudget { max_depth: 1, ..Default::default() },
    }, &AtomicBool::new(false)).unwrap().publish(|traversal| traversal.nodes).unwrap();
    if deleted { assert!(traversal.is_empty()); }
    else { assert_eq!(traversal.len(), 1); assert_eq!(traversal[0].point_id, ids[1]); }
}

#[cfg(feature = "fault-injection")]
#[test]
fn protected_multimodel_insert_before_prepare_preserves_retry_and_atomic_bindings() {
    for key in [None, Some("insert-preparation-retry")] {
        let (directory, db, secret, _) = fixture(true);
        let identity = db.identity_authority().unwrap().authenticate(&secret).unwrap();
        db.execute_sql_authorized(&identity, preparation_retry_sql("CREATE TABLE docs (id TEXT PRIMARY KEY, title TEXT NOT NULL, chunk RECORD_REF('docs') NOT NULL, source RECORD_REF('docs') NOT NULL)", None), "setup").unwrap();
        let read = db.bind_access(&identity, "docs", "acme", Action::Read).unwrap();
        let generation = read.data_generation();
        let frontier = db.transaction_journal.completed_commit_frontier().unwrap();
        let collection = db.inner.read().collections["docs"].clone();
        let wal_before = collection.read().wal.len().unwrap();
        let journal = directory.path().join(crate::transaction_journal::TRANSACTION_JOURNAL_DIR).join("000000.gdwal");
        let journal_before = fs::read(&journal).unwrap();
        let request = preparation_retry_insert(key);
        let result = {
            let _fault = crate::failpoint::test_env("error:transaction.before_prepare", directory.path(), directory.path());
            db.insert_multimodel_authorized(&identity, request.clone(), "fault")
        };
        assert!(matches!(result, Err(GaussError::Io(_))), "{result:?}");
        assert_eq!(collection.read().wal.len().unwrap(), wal_before);
        assert_eq!(fs::read(&journal).unwrap(), journal_before);
        assert_eq!(db.transaction_journal.completed_commit_frontier().unwrap(), frontier);
        assert_eq!(read.data_generation(), generation);
        assert_eq!(db.count_authorized(&read, None).unwrap().publish(|count| count.count).unwrap(), 0);
        let rows = db.execute_sql_authorized(&identity, preparation_retry_sql("SELECT id FROM docs", None), "oracle").unwrap();
        assert!(matches!(rows.results.as_slice(), [crate::SqlResult::Rows { rows, .. }] if rows.is_empty()));
        let committed = db.insert_multimodel_authorized(&identity, request.clone(), "retry").unwrap();
        assert!(committed.sql.committed && !committed.graph.replayed);
        assert_eq!(committed.records.len(), 2);
        assert_eq!(committed.edge_ids.len(), 1);
        let ids = vec![committed.records["chunk"].id.clone(), committed.records["source"].id.clone()];
        assert_eq!(read.data_generation(), generation + 1);
        assert_preparation_retry_state(&db, &identity, &ids, "before");
        if key.is_some() {
            let frontier = db.transaction_journal.completed_commit_frontier().unwrap();
            let replay = db.insert_multimodel_authorized(&identity, request.clone(), "replay").unwrap();
            assert!(replay.graph.replayed);
            assert_eq!(replay.sql.transaction_id, committed.sql.transaction_id);
            assert_eq!(replay.records, committed.records);
            assert_eq!(replay.edge_ids, committed.edge_ids);
            assert_eq!(db.transaction_journal.completed_commit_frontier().unwrap(), frontier);
        }
        drop(collection); drop(db);
        let reopened = Db::open(directory.path()).unwrap();
        let identity = reopened.identity_authority().unwrap().authenticate(&secret).unwrap();
        assert_preparation_retry_state(&reopened, &identity, &ids, "before");
        if key.is_some() {
            let replay = reopened.insert_multimodel_authorized(&identity, request, "reopen-replay").unwrap();
            assert_eq!(replay.sql.transaction_id, committed.sql.transaction_id);
            assert_eq!(replay.records, committed.records);
            assert!(replay.graph.replayed);
        }
    }
}

#[cfg(feature = "fault-injection")]
#[test]
fn protected_multimodel_update_delete_before_prepare_preserves_retry_and_epoch_rules() {
    for action in [Action::Update, Action::Delete] {
        for key in [None, Some("mutation-preparation-retry")] {
            let (directory, db, secret, _) = fixture(true);
            let identity = db.identity_authority().unwrap().authenticate(&secret).unwrap();
            db.execute_sql_authorized(&identity, preparation_retry_sql("CREATE TABLE docs (id TEXT PRIMARY KEY, title TEXT NOT NULL, chunk RECORD_REF('docs') NOT NULL, source RECORD_REF('docs') NOT NULL)", None), "setup").unwrap();
            let created = db.insert_multimodel_authorized(&identity, preparation_retry_insert(None), "setup").unwrap();
            let ids = vec![created.records["chunk"].id.clone(), created.records["source"].id.clone()];
            let vector = db.bind_access(&identity, "docs", "acme", action).unwrap();
            let graph = db.bind_access(&identity, "docs", "acme", Action::GraphWrite).unwrap();
            let read = db.bind_access(&identity, "docs", "acme", Action::Read).unwrap();
            let queued = db.get_points_authorized(&read, &ids).unwrap();
            let generation = vector.data_generation();
            let revision = vector.policy_revision();
            let frontier = db.transaction_journal.completed_commit_frontier().unwrap();
            let collection = db.inner.read().collections["docs"].clone();
            let wal_before = collection.read().wal.len().unwrap();
            let journal = directory.path().join(crate::transaction_journal::TRANSACTION_JOURNAL_DIR).join("000000.gdwal");
            let journal_before = fs::read(&journal).unwrap();
            let deleted = action == Action::Delete;
            let request = MultiModelTransactionRequest {
                sql: preparation_retry_sql(if deleted { "DELETE FROM docs WHERE id='row-1'" } else { "UPDATE docs SET title='after' WHERE id='row-1'" }, key),
                collection: "docs".into(),
                points: if deleted { vec![] } else { vec![physical_point(&preparation_retry_point("after"), ids[0].clone())] },
                point_deletes: if deleted { vec![ids[0].clone()] } else { vec![] },
                relations: vec![], edge_deletes: vec![],
                edge_updates: if deleted { vec![] } else { vec![(created.edge_ids[0].clone(), crate::graph::UpdateEdgeRequest { mode: crate::graph::EdgePropertyMode::Replace, properties: serde_json::json!({"state":"after"}) })] },
            };
            let result = {
                let _fault = crate::failpoint::test_env("error:transaction.before_prepare", directory.path(), directory.path());
                db.execute_multimodel_transaction_authorized(&identity, &vector, &graph, request.clone(), "fault")
            };
            assert!(matches!(result, Err(GaussError::Io(_))), "{result:?}");
            assert_eq!(collection.read().wal.len().unwrap(), wal_before);
            assert_eq!(fs::read(&journal).unwrap(), journal_before);
            assert_eq!(db.transaction_journal.completed_commit_frontier().unwrap(), frontier);
            if deleted { assert!(queued.publish(|_| panic!("drained epoch must stay closed")).is_err()); }
            else { assert_eq!(queued.publish(|points| points[0].payload.clone()).unwrap(), point("before").payload); }
            let vector = db.bind_access(&identity, "docs", "acme", action).unwrap();
            let graph = db.bind_access(&identity, "docs", "acme", Action::GraphWrite).unwrap();
            assert_eq!(vector.data_generation(), generation);
            assert_eq!(vector.policy_revision(), revision);
            assert_preparation_retry_state(&db, &identity, &ids, "before");
            let committed = db.execute_multimodel_transaction_authorized(&identity, &vector, &graph, request.clone(), "retry").unwrap();
            assert!(committed.sql.committed && !committed.graph.replayed);
            let after = if deleted { "deleted" } else { "after" };
            assert_preparation_retry_state(&db, &identity, &ids, after);
            if key.is_some() {
                let vector = db.bind_access(&identity, "docs", "acme", action).unwrap();
                let graph = db.bind_access(&identity, "docs", "acme", Action::GraphWrite).unwrap();
                let frontier = db.transaction_journal.completed_commit_frontier().unwrap();
                let replay = db.execute_multimodel_transaction_authorized(&identity, &vector, &graph, request.clone(), "replay").unwrap();
                assert!(replay.graph.replayed);
                assert_eq!(replay.sql.transaction_id, committed.sql.transaction_id);
                assert_eq!(db.transaction_journal.completed_commit_frontier().unwrap(), frontier);
            }
            drop(collection); drop(db);
            let reopened = Db::open(directory.path()).unwrap();
            let identity = reopened.identity_authority().unwrap().authenticate(&secret).unwrap();
            assert_preparation_retry_state(&reopened, &identity, &ids, after);
            if key.is_some() {
                let vector = reopened.bind_access(&identity, "docs", "acme", action).unwrap();
                let graph = reopened.bind_access(&identity, "docs", "acme", Action::GraphWrite).unwrap();
                let replay = reopened.execute_multimodel_transaction_authorized(&identity, &vector, &graph, request, "reopen-replay").unwrap();
                assert_eq!(replay.sql.transaction_id, committed.sql.transaction_id);
                assert!(replay.graph.replayed);
            }
        }
    }
}

#[test]
fn protected_bm25_hybrid_field_domain_lifecycle_and_revocation() {
    for graph in [false, true] {
        let (directory, db, key, other_key) = fixture(graph);
        let writer = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let other = db
            .identity_authority()
            .unwrap()
            .authenticate(&other_key)
            .unwrap();
        let manage = db
            .bind_access(&writer, "docs", "acme", Action::PolicyManage)
            .unwrap();
        let mut policy = db.inner.read().collections["docs"]
            .read()
            .security
            .as_ref()
            .unwrap()
            .checkpoint()
            .policy;
        let standard = policy.templates.get_mut("standard").unwrap();
        standard.properties.insert(
            "/secret".into(),
            PropertyRule {
                classification: Classification::Internal,
                actions: BTreeSet::from([PropertyAction::Write]),
            },
        );
        // Literal punctuation in a field name must use an escaped JSON pointer.
        standard
            .properties
            .insert("/a~1b~0c".into(), standard.properties["/text"].clone());
        let mut nonquery = standard.clone();
        nonquery
            .properties
            .get_mut("/text")
            .unwrap()
            .actions
            .remove(&PropertyAction::Query);
        policy.templates.insert("nonquery".into(), nonquery);
        db.replace_collection_policy_authorized(
            &manage,
            RevisionUpdate {
                expected_revision: manage.policy_revision(),
                value: policy,
            },
        )
        .unwrap();
        let create = db
            .bind_access(&writer, "docs", "acme", Action::Create)
            .unwrap();
        let mut inputs = vec![
            point("refund refund policy"),
            point("policy"),
            point("other"),
        ];
        inputs[0].payload["secret"] = serde_json::json!("refund private");
        inputs[0].payload["a/b~c"] = serde_json::json!("punctuation");
        inputs[1].vector = vec![0.0, 1.0];
        inputs[2].vector = vec![-1.0, 0.0];
        let ids = db
            .create_points_authorized(&create, "standard", inputs, true)
            .unwrap()
            .publish(|ids| ids)
            .unwrap();
        let search = db
            .bind_access(&writer, "docs", "acme", Action::Search)
            .unwrap();
        let query = crate::TextHybridSearchRequest {
            vector: vec![],
            query: "refund policy".into(),
            text_field: "text".into(),
            k: 10,
            filter: None,
            budget_ms: None,
        };
        let run = |db: &Db, context: &AccessContext, query: crate::TextHybridSearchRequest| {
            db.text_hybrid_search_authorized(context, query, None)
                .unwrap()
                .publish(|hits| hits)
                .unwrap()
        };
        let baseline = run(&db, &search, query.clone());
        assert_eq!(
            baseline.iter().map(|hit| &hit.id).collect::<Vec<_>>(),
            vec![&ids[0], &ids[1]]
        );
        assert!(
            baseline
                .iter()
                .all(|hit| hit.payload.get("secret").is_none())
        );
        let mut hybrid = query.clone();
        hybrid.vector = vec![1.0, 0.0];
        let hybrid_baseline = run(&db, &search, hybrid.clone());
        assert_eq!(hybrid_baseline.len(), 3);
        let other_create = db
            .bind_access(&other, "docs", "acme", Action::Create)
            .unwrap();
        db.create_points_authorized(
            &other_create,
            "standard",
            vec![point(&"refund policy ".repeat(100)); 30],
            true,
        )
        .unwrap()
        .publish(|_| ())
        .unwrap();
        db.create_points_authorized(
            &create,
            "nonquery",
            vec![point(&"refund policy ".repeat(20)); 10],
            true,
        )
        .unwrap()
        .publish(|_| ())
        .unwrap();
        for (query, expected) in [
            (query.clone(), &baseline),
            (hybrid.clone(), &hybrid_baseline),
        ] {
            assert_eq!(
                serde_json::to_value(run(&db, &search, query)).unwrap(),
                serde_json::to_value(expected).unwrap()
            );
        }
        let mut filtered = query.clone();
        filtered.filter = Some(Filter(serde_json::json!({"text":"policy"})));
        let hits = run(&db, &search, filtered);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].score.to_bits(), baseline[1].score.to_bits()); // predicates never alter IDF
        for field in ["secret", "unknown", "a.b"] {
            let mut query = query.clone();
            query.text_field = field.into();
            assert!(run(&db, &search, query).is_empty());
        }
        let mut punct = query.clone();
        punct.text_field = "a/b~c".into();
        punct.query = "punctuation".into();
        assert_eq!(run(&db, &search, punct)[0].id, ids[0]);
        for filter in [
            serde_json::json!({"secret":"private"}),
            serde_json::json!({"unknown":{"ne":null}}),
        ] {
            let mut query = query.clone();
            query.filter = Some(Filter(filter));
            assert!(
                db.text_hybrid_search_authorized(&search, query, None)
                    .is_err()
            );
        }
        assert!(
            db.text_hybrid_search_authorized(&search, query.clone(), Some(&AtomicBool::new(true)))
                .is_err()
        );
        let mut expired = query.clone();
        expired.budget_ms = Some(0);
        assert!(
            db.text_hybrid_search_authorized(&search, expired, None)
                .is_err()
        );
        for (vector, field, k) in [
            (vec![1.0], "text", 10),
            (vec![f32::NAN, 0.0], "text", 10),
            (vec![], "", 10),
            (vec![], "text", usize::MAX),
        ] {
            let mut bad = query.clone();
            bad.vector = vector;
            bad.text_field = field.into();
            bad.k = k;
            assert!(
                db.text_hybrid_search_authorized(&search, bad, None)
                    .is_err()
            );
        }
        let mut zero = query.clone();
        zero.k = 0;
        assert!(run(&db, &search, zero).is_empty());
        let read = db
            .bind_access(&writer, "docs", "acme", Action::Read)
            .unwrap();
        assert!(
            db.text_hybrid_search_authorized(&read, query.clone(), None)
                .is_err()
        );
        let update = db
            .bind_access(&writer, "docs", "acme", Action::Update)
            .unwrap();
        db.update_points_authorized(
            &update,
            vec![physical_point(&point("replacement"), ids[0].clone())],
            true,
        )
        .unwrap()
        .publish(|_| ())
        .unwrap();
        assert_eq!(
            run(&db, &search, query.clone())
                .iter()
                .map(|hit| &hit.id)
                .collect::<Vec<_>>(),
            vec![&ids[1]]
        );
        let queued = db
            .text_hybrid_search_authorized(&search, query.clone(), None)
            .unwrap();
        let delete = db
            .bind_access(&writer, "docs", "acme", Action::Delete)
            .unwrap();
        db.delete_points_authorized(&delete, std::slice::from_ref(&ids[1]))
            .unwrap()
            .publish(|_| ())
            .unwrap();
        assert!(queued.publish(|_| ()).is_err());
        drop(db);
        let db = Db::open(directory.path()).unwrap();
        let writer = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let search = db
            .bind_access(&writer, "docs", "acme", Action::Search)
            .unwrap();
        assert!(run(&db, &search, query.clone()).is_empty());
        let mut replacement = query;
        replacement.query = "replacement".into();
        assert_eq!(run(&db, &search, replacement.clone())[0].id, ids[0]);
        let queued = db
            .text_hybrid_search_authorized(&search, replacement.clone(), None)
            .unwrap();
        replace_permissions(
            &db,
            &writer,
            &ids[0],
            vec![ObjectGrant {
                subject: Subject::Owner,
                actions: BTreeSet::from([Action::Search]),
                effect: Effect::Deny,
                inherit: false,
            }],
            None,
        )
        .unwrap();
        assert!(queued.publish(|_| ()).is_err());
        assert!(
            db.text_hybrid_search_authorized(&search, replacement.clone(), None)
                .is_err()
        );
        let search = db
            .bind_access(&writer, "docs", "acme", Action::Search)
            .unwrap();
        assert!(run(&db, &search, replacement).is_empty());
    }
}

#[test]
fn protected_create_output_overload_preserves_wal_and_authority_for_retry() {
    for graph in [false, true] {
        for budget in [1, 4096, 16384, 32768] {
            let (directory, db, key, _) = fixture(graph);
            let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
            let create = db.bind_access(&identity, "docs", "acme", Action::Create).unwrap();
            let collection = db.inner.read().collections["docs"].clone();
            let before = collection.read().wal.len().unwrap();
            let journal = directory.path().join(crate::transaction_journal::TRANSACTION_JOURNAL_DIR).join("000000.gdwal");
            let journal_before = fs::read(&journal).unwrap();
            crate::relational::wal_decode::with_test_storage_pool(budget, |used| {
                assert!(matches!(db.create_points_authorized(&create, "standard", vec![point(&"retry ".repeat(128))], true), Err(GaussError::ResourceExhausted(_))), "graph={graph} budget={budget}");
                assert_eq!(used(), 0);
            });
            assert_eq!(collection.read().wal.len().unwrap(), before);
            assert_eq!(fs::read(&journal).unwrap(), journal_before);
            let fresh = db.bind_access(&identity, "docs", "acme", Action::Create).unwrap();
            let ids = db.create_points_authorized(&fresh, "standard", vec![point("retry")], true).unwrap().publish(|ids| ids).unwrap();
            let read = db.bind_access(&identity, "docs", "acme", Action::Read).unwrap();
            let rows = db.get_points_authorized(&read, &ids).unwrap().publish(|points| points).unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].payload["text"], "retry");
        }
    }
}

#[test]
fn protected_create_replay_admits_ids_without_wal_mutation_and_keeps_queued_owner() {
    for graph in [false, true] {
        let (_directory, db, key, _) = fixture(graph);
        let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let create = db.bind_access(&identity, "docs", "acme", Action::Create).unwrap();
        let request = crate::security::CreatePoints {
            template: "standard".into(),
            idempotency_key: "admitted-replay".into(),
            points: vec![point("first"), point("second")],
        };
        let ids = db.create_points_idempotent_authorized(&create, request.clone()).unwrap().publish(|ids| ids).unwrap();
        let collection = db.inner.read().collections["docs"].clone();
        let before = collection.read().wal.len().unwrap();
        crate::relational::wal_decode::with_test_storage_pool(1, |used| {
            assert!(matches!(db.create_points_idempotent_authorized(&create, request.clone()), Err(GaussError::ResourceExhausted(_))));
            assert_eq!(used(), 0);
        });
        assert_eq!(collection.read().wal.len().unwrap(), before);
        crate::relational::wal_decode::with_test_storage_pool(128*1024, |used| {
            let queued = db.create_points_idempotent_authorized(&create, request.clone()).unwrap();
            let retained = used();
            assert!(retained > 0);
            assert_eq!(collection.read().wal.len().unwrap(), before);
            queued.map(|replayed| { assert_eq!(replayed, ids); assert_eq!(used(), retained); replayed }).unwrap()
                .publish(|replayed| { assert_eq!(replayed, ids); assert_eq!(used(), retained); }).unwrap();
            assert_eq!(used(), 0);
            let queued = db.create_points_idempotent_authorized(&create, request.clone()).unwrap();
            assert!(used()>0);
            crate::relational::wal_decode::with_isolated_test_storage(|| {
                replace_permissions(&db, &identity, &ids[0], vec![ObjectGrant {
                    subject: Subject::Owner,
                    actions: BTreeSet::from([Action::Read]),
                    effect: Effect::Deny,
                    inherit: false,
                }], None).unwrap();
            });
            assert!(queued.publish(|_| panic!("revoked replay IDs must not publish")).is_err());
            assert_eq!(used(), 0);
        });
        let create = db.bind_access(&identity, "docs", "acme", Action::Create).unwrap();
        let before = collection.read().wal.len().unwrap();
        assert!(db.create_points_idempotent_authorized(&create, request).is_err());
        assert_eq!(collection.read().wal.len().unwrap(), before);
    }
}

#[test]
fn protected_point_get_and_scroll_refuse_before_output_copy() {
    let (_directory, db, key, _other) = fixture(false);
    let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
    let create = db.bind_access(&identity, "docs", "acme", Action::Create).unwrap();
    let ids = db.create_points_authorized(&create, "standard", vec![point("refund")], true)
        .unwrap().publish(|ids| ids).unwrap();
    let read = db.bind_access(&identity, "docs", "acme", Action::Read).unwrap();
    crate::relational::wal_decode::with_test_storage_pool(1, |used| {
        assert!(matches!(db.get_points_authorized(&read, &ids), Err(GaussError::ResourceExhausted(_))));
        assert_eq!(used(), 0);
        let request = serde_json::from_value(serde_json::json!({"limit":1})).unwrap();
        assert!(matches!(db.scroll_authorized(&read, request), Err(GaussError::ResourceExhausted(_))));
        assert_eq!(used(), 0);
    });
    crate::relational::wal_decode::with_test_storage_pool(128*1024, |used| {
        let output = db.get_points_authorized(&read, &ids).unwrap();
        let retained = used();
        assert!(retained>0);
        output.map(|points| { assert_eq!(used(), retained); assert_eq!(points[0].id, ids[0]); points }).unwrap()
            .publish(|points| { assert_eq!(points[0].payload["text"], "refund"); assert_eq!(used(), retained); }).unwrap();
        assert_eq!(used(), 0);
        let request = serde_json::from_value(serde_json::json!({"limit":1})).unwrap();
        let output = db.scroll_authorized(&read, request).unwrap();
        assert!(used()>0);
        output.publish(|page| { assert_eq!(page.points.len(), 1); assert!(page.next_offset.is_none()); }).unwrap();
        assert_eq!(used(), 0);
        let output = db.get_points_authorized(&read, &ids).unwrap();
        crate::relational::wal_decode::with_isolated_test_storage(|| {
            replace_permissions(&db, &identity, &ids[0], vec![ObjectGrant { subject: Subject::Owner, actions: BTreeSet::from([Action::Read]), effect: Effect::Deny, inherit: false }], None).unwrap();
        });
        assert!(output.publish(|_| panic!("revoked points must not publish")).is_err());
        assert_eq!(used(), 0);
    });
}

#[test]
fn protected_filter_delete_selection_overload_precedes_wal_and_retries_cleanly() {
    let (_directory, db, key, _) = fixture(false);
    let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
    let create = db.bind_access(&identity, "docs", "acme", Action::Create).unwrap();
    let ids = db.create_points_authorized(&create, "standard", vec![point("delete"),point("keep")], true).unwrap().publish(|ids| ids).unwrap();
    let delete = db.bind_access(&identity, "docs", "acme", Action::Delete).unwrap();
    let collection = db.inner.read().collections["docs"].clone();
    let before = collection.read().wal.len().unwrap();
    crate::relational::wal_decode::with_test_storage_pool(1, |used| {
        assert!(matches!(db.delete_filter_authorized(&delete, Filter(serde_json::json!({"text":"delete"}))), Err(GaussError::ResourceExhausted(_))));
        assert_eq!(used(), 0);
    });
    assert_eq!(collection.read().wal.len().unwrap(), before);
    let read = db.bind_access(&identity, "docs", "acme", Action::Read).unwrap();
    assert_eq!(db.get_points_authorized(&read, &ids).unwrap().publish(|p|p.len()).unwrap(), 2);
    assert_eq!(db.delete_filter_authorized(&delete, Filter(serde_json::json!({"text":"delete"}))).unwrap().publish(|n|n).unwrap(), 1);
    let read = db.bind_access(&identity, "docs", "acme", Action::Read).unwrap();
    assert_eq!(db.get_points_authorized(&read, &ids).unwrap().publish(|p|p.len()).unwrap(), 1);
}

#[test]
fn protected_dense_output_refuses_before_payload_copy_and_keeps_queued_owner() {
    let (_directory, db, key, _other) = fixture(false);
    let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
    let create = db
        .bind_access(&identity, "docs", "acme", Action::Create)
        .unwrap();
    let ids = db
        .create_points_authorized(
            &create,
            "standard",
            vec![point(&"refund ".repeat(1024))],
            true,
        )
        .unwrap()
        .publish(|ids| ids)
        .unwrap();
    let search = db
        .bind_access(&identity, "docs", "acme", Action::Search)
        .unwrap();
    let request = || serde_json::from_value(serde_json::json!({"vector":[1.0,0.0],"k":1})).unwrap();
    crate::relational::wal_decode::with_test_storage_pool(1, |used| {
        let result = db.search_authorized(&search, request(), None);
        assert!(
            matches!(result, Err(GaussError::ResourceExhausted(_))),
            "protected hit must preadmit payload output"
        );
        assert_eq!(used(), 0);
    });
    crate::relational::wal_decode::with_test_storage_pool(128 * 1024, |used| {
        let output = db.search_authorized(&search, request(), None).unwrap();
        assert!(used() > 7168, "queued payload must retain its lease");
        let before = used();
        let rendered = output
            .map(|hits| {
                assert_eq!(used(), before);
                assert_eq!(hits[0].id, ids[0]);
                assert_eq!(hits[0].payload["text"], "refund ".repeat(1024));
                hits
            })
            .unwrap();
        assert_eq!(used(), before);
        let count = rendered
            .publish(|hits| {
                assert_eq!(used(), before);
                hits.len()
            })
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(used(), 0);
        let output = db.search_authorized(&search, request(), None).unwrap();
        assert!(used() > 7168);
        drop(output);
        assert_eq!(used(), 0);
        let mut slim = request();
        slim.with_payload = Some(false);
        db.search_authorized(&search, slim, None)
            .unwrap()
            .publish(|hits| {
                assert_eq!(hits[0].id, ids[0]);
                assert!(hits[0].payload.is_null());
                assert!(used() > 0);
            })
            .unwrap();
        assert_eq!(used(), 0);
        for vector in [vec![], vec![1.0, 0.0]] {
            let text = db
                .text_hybrid_search_authorized(
                    &search,
                    crate::TextHybridSearchRequest {
                        vector,
                        query: "refund".into(),
                        text_field: "text".into(),
                        k: 1,
                        filter: None,
                        budget_ms: None,
                    },
                    None,
                )
                .unwrap();
            assert!(used() > 7168);
            text.map(|hits| {
                assert!(used() > 7168);
                assert_eq!(hits[0].id, ids[0]);
                hits
            })
            .unwrap()
            .publish(|hits| {
                assert!(used() > 7168);
                assert_eq!(hits.len(), 1);
            })
            .unwrap();
            assert_eq!(used(), 0);
        }
        let output = db.search_authorized(&search, request(), None).unwrap();
        crate::relational::wal_decode::with_isolated_test_storage(|| {
            replace_permissions(
                &db,
                &identity,
                &ids[0],
                vec![ObjectGrant {
                    subject: Subject::Owner,
                    actions: BTreeSet::from([Action::Search]),
                    effect: Effect::Deny,
                    inherit: false,
                }],
                None,
            )
            .unwrap();
        });
        assert!(
            output
                .publish(|_| panic!("revoked output must not publish"))
                .is_err()
        );
        assert_eq!(used(), 0);
    });
}

#[test]
fn protected_native_update_overload_preserves_content_journals_and_retry() {
    for graph in [false, true] {
        for capacity in [1, 4096, 16384, 32768] {
            let (directory, db, key, _) = fixture(graph);
            let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
            let create = db.bind_access(&identity, "docs", "acme", Action::Create).unwrap();
            let ids = db.create_points_authorized(&create, "standard", vec![point("original")], true).unwrap().publish(|ids| ids).unwrap();
            let update = db.bind_access(&identity, "docs", "acme", Action::Update).unwrap();
            let generation = update.data_generation();
            let physical = update.authorize(&ids[0]).unwrap().storage_id;
            let collection = db.inner.read().collections["docs"].clone();
            let before = collection.read().wal.len().unwrap();
            let journal = directory.path().join(crate::transaction_journal::TRANSACTION_JOURNAL_DIR).join("000000.gdwal");
            let journal_before = fs::read(&journal).unwrap();
            crate::relational::wal_decode::with_test_storage_pool(capacity, |used| {
                assert!(matches!(db.update_points_authorized(&update, vec![physical_point(&point(&"replacement ".repeat(128)), ids[0].clone())], true), Err(GaussError::ResourceExhausted(_))), "graph={graph} capacity={capacity}");
                assert_eq!(used(), 0);
            });
            assert_eq!(collection.read().wal.len().unwrap(), before);
            assert_eq!(fs::read(&journal).unwrap(), journal_before);
            let read = db.bind_access(&identity, "docs", "acme", Action::Read).unwrap();
            assert_eq!(read.data_generation(), generation);
            assert_eq!(read.authorize(&ids[0]).unwrap().storage_id, physical);
            assert_eq!(db.get_points_authorized(&read, &ids).unwrap().publish(|points| points[0].payload["text"].clone()).unwrap(), "original");
            assert_eq!(db.update_points_authorized(&update, vec![physical_point(&point("replacement"), ids[0].clone())], true).unwrap().publish(|count|count).unwrap(), 1);
            assert_eq!(read.data_generation(), generation+1);
            assert_eq!(db.get_points_authorized(&read, &ids).unwrap().publish(|points| points[0].payload["text"].clone()).unwrap(), "replacement");
        }
    }
}

#[test]
fn protected_native_delete_overload_restores_fresh_epoch_and_retries_without_retirement() {
    for graph in [false, true] {
        for capacity in [1, 4096, 16384] {
            let (directory, db, key, _) = fixture(graph);
            let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
            let create = db.bind_access(&identity, "docs", "acme", Action::Create).unwrap();
            let ids = db.create_points_authorized(&create, "standard", vec![point("delete"), point("keep")], true).unwrap().publish(|ids| ids).unwrap();
            let delete = db.bind_access(&identity, "docs", "acme", Action::Delete).unwrap();
            let generation = delete.data_generation();
            let revision = delete.policy_revision();
            let read = db.bind_access(&identity, "docs", "acme", Action::Read).unwrap();
            let queued = db.get_points_authorized(&read, &ids).unwrap();
            let collection = db.inner.read().collections["docs"].clone();
            let before = collection.read().wal.len().unwrap();
            let journal = directory.path().join(crate::transaction_journal::TRANSACTION_JOURNAL_DIR).join("000000.gdwal");
            let journal_before = fs::read(&journal).unwrap();
            crate::relational::wal_decode::with_test_storage_pool(capacity, |used| {
                assert!(matches!(db.delete_points_authorized(&delete, &ids[..1]), Err(GaussError::ResourceExhausted(_))), "graph={graph} capacity={capacity}");
                assert_eq!(used(), 0);
            });
            assert_eq!(collection.read().wal.len().unwrap(), before);
            assert_eq!(fs::read(&journal).unwrap(), journal_before);
            assert!(queued.publish(|_| panic!("a drained epoch must not be reopened")).is_err());
            let fresh = db.bind_access(&identity, "docs", "acme", Action::Delete).unwrap();
            assert_eq!(fresh.policy_revision(), revision);
            assert_eq!(fresh.data_generation(), generation);
            let read = db.bind_access(&identity, "docs", "acme", Action::Read).unwrap();
            assert_eq!(db.get_points_authorized(&read, &ids).unwrap().publish(|points|points.len()).unwrap(), 2);
            assert_eq!(db.delete_points_authorized(&fresh, &ids[..1]).unwrap().publish(|count|count).unwrap(), 1);
            let read = db.bind_access(&identity, "docs", "acme", Action::Read).unwrap();
            let remaining = db.get_points_authorized(&read, &ids).unwrap().publish(|points|points).unwrap();
            assert_eq!(remaining.len(), 1);
            assert_eq!(remaining[0].id, ids[1]);
        }
    }
}

#[cfg(feature = "fault-injection")]
fn fault_native_mutation(
    db: &Db,
    context: &AccessContext,
    ids: &[String],
) -> crate::Result<AuthorizedOutput<usize>> {
    if context.action() == Action::Delete {
        db.delete_points_authorized(context, &ids[..1])
    } else {
        db.update_points_authorized(
            context,
            vec![physical_point(&point("replacement"), ids[0].clone())],
            true,
        )
    }
}

#[cfg(feature = "fault-injection")]
fn assert_native_content(db: &Db, key: &str, ids: &[String], deleted: bool, text: &str) {
    let identity = db.identity_authority().unwrap().authenticate(key).unwrap();
    let read = db.bind_access(&identity, "docs", "acme", Action::Read).unwrap();
    let rows = db.get_points_authorized(&read, ids).unwrap().publish(|rows| rows).unwrap();
    if deleted {
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, ids[1]);
        assert_eq!(rows[0].payload["text"], "keep");
    } else {
        assert_eq!(rows.len(), 2);
        let changed = rows.iter().find(|row| row.id == ids[0]).unwrap();
        assert_eq!(changed.payload["text"], text);
        assert_eq!(changed.vector, vec![1.0, 0.0]);
        assert_eq!(rows.iter().find(|row| row.id == ids[1]).unwrap().payload["text"], "keep");
    }
}

#[cfg(feature = "fault-injection")]
#[test]
fn protected_native_mutation_before_prepare_fault_keeps_retryable_content_and_delete_epoch() {
    for graph in [false, true] {
        for action in [Action::Update, Action::Delete] {
            let (directory, db, key, _) = fixture(graph);
            let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
            let create = db.bind_access(&identity, "docs", "acme", Action::Create).unwrap();
            let ids = db.create_points_authorized(&create, "standard", vec![point("original"), point("keep")], true).unwrap().publish(|ids| ids).unwrap();
            let context = db.bind_access(&identity, "docs", "acme", action).unwrap();
            let generation = context.data_generation();
            let revision = context.policy_revision();
            let journal = directory.path().join(crate::transaction_journal::TRANSACTION_JOURNAL_DIR).join("000000.gdwal");
            let before = fs::read(&journal).unwrap();
            let result = {
                let _env = crate::failpoint::test_env("error:transaction.before_prepare", directory.path(), directory.path());
                fault_native_mutation(&db, &context, &ids)
            };
            assert!(matches!(result, Err(GaussError::Io(_))));
            assert_eq!(fs::read(&journal).unwrap(), before);
            assert_native_content(&db, &key, &ids, false, "original");
            assert_eq!(context.publication_permit().is_ok(), action == Action::Update);
            let fresh = db.bind_access(&identity, "docs", "acme", action).unwrap();
            assert_eq!(fresh.data_generation(), generation);
            assert_eq!(fresh.policy_revision(), revision);
            assert_eq!(fault_native_mutation(&db, &fresh, &ids).unwrap().publish(|n| n).unwrap(), 1);
            assert_native_content(&db, &key, &ids, action == Action::Delete, "replacement");
        }
    }
}

#[cfg(feature = "fault-injection")]
#[test]
fn protected_native_mutation_prepare_failure_closes_until_reopen_without_partial_state() {
    for graph in [false, true] {
        for action in [Action::Update, Action::Delete] {
            for fault in ["transaction.after_prepare", "transaction.before_commit"] {
                let (directory, db, key, _) = fixture(graph);
                let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
                let create = db.bind_access(&identity, "docs", "acme", Action::Create).unwrap();
                let ids = db.create_points_authorized(&create, "standard", vec![point("original"), point("keep")], true).unwrap().publish(|ids| ids).unwrap();
                let context = db.bind_access(&identity, "docs", "acme", action).unwrap();
                let generation = context.data_generation();
                let revision = context.policy_revision();
                let result = {
                    let _env = crate::failpoint::test_env(&format!("error:{fault}"), directory.path(), directory.path());
                    fault_native_mutation(&db, &context, &ids)
                };
                assert!(matches!(result, Err(GaussError::Io(_))));
                assert!(db.bind_access(&identity, "docs", "acme", Action::Read).is_err());
                assert!(context.publication_permit().is_err());
                drop(db);
                let reopened = Db::open(directory.path()).unwrap();
                assert_native_content(&reopened, &key, &ids, false, "original");
                let identity = reopened.identity_authority().unwrap().authenticate(&key).unwrap();
                let fresh = reopened.bind_access(&identity, "docs", "acme", action).unwrap();
                assert_eq!(fresh.data_generation(), generation);
                assert_eq!(fresh.policy_revision(), revision);
                assert_eq!(fault_native_mutation(&reopened, &fresh, &ids).unwrap().publish(|n| n).unwrap(), 1);
                assert_native_content(&reopened, &key, &ids, action == Action::Delete, "replacement");
            }
        }
    }
}

#[cfg(feature = "fault-injection")]
#[test]
fn protected_native_mutation_unknown_commit_reconciles_by_owner_after_reopen() {
    for graph in [false, true] {
        for action in [Action::Update, Action::Delete] {
            let (directory, db, key, other_key) = fixture(graph);
            let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
            let create = db.bind_access(&identity, "docs", "acme", Action::Create).unwrap();
            let ids = db.create_points_authorized(&create, "standard", vec![point("original"), point("keep")], true).unwrap().publish(|ids| ids).unwrap();
            let context = db.bind_access(&identity, "docs", "acme", action).unwrap();
            let generation = context.data_generation();
            let result = {
                let _env = crate::failpoint::test_env("error:transaction.before_commit_fsync", directory.path(), directory.path());
                fault_native_mutation(&db, &context, &ids)
            };
            let transaction_id = match result {
                Err(GaussError::CommitOutcomeUnknown { transaction_id }) => transaction_id,
                _ => panic!("expected an unknown commit outcome"),
            };
            assert_eq!(db.transaction_status_authorized(&identity, &transaction_id).unwrap().state, crate::transaction_journal::TransactionState::OutcomeUnknown);
            let other = db.identity_authority().unwrap().authenticate(&other_key).unwrap();
            assert!(matches!(db.transaction_status_authorized(&other, &transaction_id), Err(GaussError::Security(SecurityError::NotFound))));
            assert!(db.bind_access(&identity, "docs", "acme", Action::Read).is_err());
            drop(db);
            let reopened = Db::open(directory.path()).unwrap();
            let identity = reopened.identity_authority().unwrap().authenticate(&key).unwrap();
            let status = reopened.transaction_status_authorized(&identity, &transaction_id).unwrap();
            assert_eq!(status.state, crate::transaction_journal::TransactionState::Committed);
            assert!(status.storage_projected && status.audit_projected);
            let other = reopened.identity_authority().unwrap().authenticate(&other_key).unwrap();
            assert!(matches!(reopened.transaction_status_authorized(&other, &transaction_id), Err(GaussError::Security(SecurityError::NotFound))));
            let read = reopened.bind_access(&identity, "docs", "acme", Action::Read).unwrap();
            assert_eq!(read.data_generation(), generation+1);
            assert_native_content(&reopened, &key, &ids, action == Action::Delete, "replacement");
        }
    }
}

#[cfg(feature = "fault-injection")]
#[test]
fn protected_native_mutation_acknowledged_commit_repairs_storage_and_audit_after_reopen() {
    for graph in [false, true] {
        for action in [Action::Update, Action::Delete] {
            for fault in ["transaction.before_storage_projection", "transaction.before_audit_projection"] {
                let (directory, db, key, _) = fixture(graph);
                let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
                let create = db.bind_access(&identity, "docs", "acme", Action::Create).unwrap();
                let ids = db.create_points_authorized(&create, "standard", vec![point("original"), point("keep")], true).unwrap().publish(|ids| ids).unwrap();
                let context = db.bind_access(&identity, "docs", "acme", action).unwrap();
                let generation = context.data_generation();
                let result = {
                    let _env = crate::failpoint::test_env(&format!("error:{fault}"), directory.path(), directory.path());
                    fault_native_mutation(&db, &context, &ids)
                };
                assert_eq!(result.unwrap().publish(|n| n).unwrap(), 1);
                assert_native_content(&db, &key, &ids, action == Action::Delete, "replacement");
                let transactions = db.transaction_journal.committed().unwrap();
                let id = transactions.iter().max_by_key(|t|t.prepare.commit_sequence).unwrap().prepare.transaction_id.to_string();
                drop(transactions);
                let before = db.transaction_status_authorized(&identity, &id).unwrap();
                assert_eq!(before.state, crate::transaction_journal::TransactionState::Committed);
                assert!(!before.storage_projected || !before.audit_projected);
                drop(db);
                let reopened = Db::open(directory.path()).unwrap();
                let identity = reopened.identity_authority().unwrap().authenticate(&key).unwrap();
                let repaired = reopened.transaction_status_authorized(&identity, &id).unwrap();
                assert_eq!(repaired.state, crate::transaction_journal::TransactionState::Committed);
                assert!(repaired.storage_projected && repaired.audit_projected);
                assert_eq!(repaired.commit_sequence, before.commit_sequence);
                let read = reopened.bind_access(&identity, "docs", "acme", Action::Read).unwrap();
                assert_eq!(read.data_generation(), generation+1);
                assert_native_content(&reopened, &key, &ids, action == Action::Delete, "replacement");
            }
        }
    }
}

#[test]
fn protected_native_point_journal_and_audit_preserve_authenticated_owner() {
    for graph in [false, true] {
        let (directory, db, key, other_key) = fixture(graph);
        let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let other = db.identity_authority().unwrap().authenticate(&other_key).unwrap();
        let create = db.bind_access(&identity, "docs", "acme", Action::Create).unwrap();
        let ids = db.create_points_authorized(&create, "standard", vec![point("original"), point("keep")], true).unwrap().publish(|ids|ids).unwrap();
        for phase in 0..3 {
            if phase == 1 {
                let update = db.bind_access(&identity, "docs", "acme", Action::Update).unwrap();
                db.update_points_authorized(&update, vec![physical_point(&point("replacement"), ids[0].clone())], true).unwrap().publish(|_|()).unwrap();
            } else if phase == 2 {
                let delete = db.bind_access(&identity, "docs", "acme", Action::Delete).unwrap();
                db.delete_points_authorized(&delete, &ids[..1]).unwrap().publish(|_|()).unwrap();
            }
            let transactions = db.transaction_journal.committed().unwrap();
            let last = transactions.iter().max_by_key(|t|t.prepare.commit_sequence).unwrap();
            assert_eq!(last.prepare.audit.principal_id, identity.principal().id);
            assert_eq!(last.prepare.audit.tenant_id.as_deref(), Some("acme"));
            assert_eq!(last.prepare.audit.transport, "protected");
            let id = last.prepare.transaction_id.to_string();
            let status = db.transaction_status_authorized(&identity, &id).unwrap();
            assert_eq!(status.state, crate::transaction_journal::TransactionState::Committed);
            assert!(status.storage_projected && status.audit_projected);
            assert!(matches!(db.transaction_status_authorized(&other, &id), Err(GaussError::Security(SecurityError::NotFound))));
            let log = fs::read_to_string(directory.path().join("audit/audit.jsonl")).unwrap();
            let events = log.lines().map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .filter(|event| event["operation_id"] == id && event["outcome"] == "success").collect::<Vec<_>>();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["principal_id"], identity.principal().id);
            assert_eq!(events[0]["tenant_id"], "acme");
            assert_eq!(events[0]["transport"], "protected");
        }
    }
}
