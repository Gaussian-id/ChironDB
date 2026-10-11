#[test]
fn protected_graph_storage_failure_is_not_hidden_result_or_committed_update() {
    use crate::graph::{
        GraphDirection, GraphTraversalQueryRequest, GraphTraversalReturn, GraphTraverseRequest,
        TraversalBudget,
    };
    use crate::{
        MultiModelInsertRequest, NewRecord, NewRelation, RecordEndpoint, SqlExecutionRequest,
        SqlStatementRequest,
    };
    use std::io::{Seek, SeekFrom, Write};
    let (directory, db, key, other_key) = fixture(true);
    let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
    let sql = |sql: &str| SqlExecutionRequest {
        statements: vec![SqlStatementRequest {
            sql: sql.into(),
            parameters: vec![],
        }],
        idempotency_key: None,
        retry_id: None,
    };
    db.execute_sql_authorized(
        &identity,
        sql("CREATE TABLE docs (id TEXT PRIMARY KEY)"),
        "test",
    )
    .unwrap();
    let inserted = db
        .insert_multimodel_authorized(
            &identity,
            MultiModelInsertRequest {
                sql: sql("INSERT INTO docs VALUES ('graph')"),
                collection: "docs".into(),
                template: "standard".into(),
                records: [
                    NewRecord {
                        binding: "root".into(),
                        point: point("root"),
                    },
                    NewRecord {
                        binding: "target".into(),
                        point: point("target"),
                    },
                ]
                .into(),
                relations: vec![NewRelation {
                    source: RecordEndpoint::New("root".into()),
                    target: RecordEndpoint::New("target".into()),
                    edge_type: "cites".into(),
                    properties: serde_json::json!({"kind":"allow"}),
                }],
            },
            "test",
        )
        .unwrap();
    let ids: BTreeMap<_, _> = inserted
        .records
        .into_iter()
        .map(|(name, record)| (name, record.id))
        .collect();
    let collection = db.inner.read().collections["docs"].clone();
    collection.write().config.streamer_max_bytes = 1;
    let create = db
        .bind_access(&identity, "docs", "acme", Action::Create)
        .unwrap();
    db.create_points_authorized(&create, "standard", vec![point("seal trigger")], true)
        .unwrap()
        .publish(|_| ())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let state = collection.read();
        if state.sealing.is_none()
            && state.graph_generation.is_some()
            && state
                .graph_mutable
                .as_ref()
                .unwrap()
                .compaction_topology()
                .count()
                == 0
        {
            break;
        }
        drop(state);
        assert!(Instant::now() < deadline, "protected graph did not seal");
        std::thread::sleep(Duration::from_millis(10));
    }
    let read = db
        .bind_access(&identity, "docs", "acme", Action::GraphRead)
        .unwrap();
    let physical = read
        .authorize(&ids["target"])
        .unwrap()
        .storage_id
        .to_string();
    let (path, ordinal, frontier) = {
        let state = collection.read();
        let searcher = state
            .searchers
            .iter()
            .find(|s| s.contains_visible(&physical, None))
            .unwrap();
        let crate::searcher::SegmentStore::V4(store) = &searcher.store else {
            panic!("V4 expected")
        };
        (
            searcher.dir.join(crate::seal::PAYLOAD_FILE),
            store.ordinal(&physical).unwrap(),
            state.wal.len().unwrap(),
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
    let traversal = GraphTraverseRequest {
        anchors: vec![ids["root"].clone()],
        edge_types: vec!["cites".into()],
        direction: GraphDirection::Outgoing,
        node_filter: Some(Filter(serde_json::json!({"text":"target"}))),
        edge_filter: Some(Filter(serde_json::json!({"kind":"allow"}))),
        budget: TraversalBudget {
            max_depth: 2,
            max_memory_bytes: 64 * 1024 * 1024,
            ..Default::default()
        },
    };
    for returns in [
        GraphTraversalReturn::Nodes,
        GraphTraversalReturn::Edges,
        GraphTraversalReturn::Paths,
    ] {
        let error = db
            .traverse_query_authorized(
                &read,
                GraphTraversalQueryRequest {
                    traversal: traversal.clone(),
                    returns,
                    limit: Some(10),
                    with_payload: true,
                },
                &AtomicBool::new(false),
            )
            .err()
            .expect("storage failure expected");
        assert!(matches!(error, GaussError::SegmentCorruption { .. }));
    }
    let update = db
        .bind_access(&identity, "docs", "acme", Action::Update)
        .unwrap();
    assert!(matches!(
        db.update_points_authorized(
            &update,
            vec![physical_point(&point("changed"), ids["target"].clone())],
            true
        )
        .err(),
        Some(GaussError::SegmentCorruption { .. })
    ));
    assert_eq!(collection.read().wal.len().unwrap(), frontier);
    let other = db
        .identity_authority()
        .unwrap()
        .authenticate(&other_key)
        .unwrap();
    let denied = db
        .bind_access(&other, "docs", "acme", Action::GraphRead)
        .unwrap();
    assert!(matches!(
        db.traverse_authorized(&denied, traversal.clone(), &AtomicBool::new(false))
            .err(),
        Some(GaussError::Security(SecurityError::NotFound))
    ));
    replace_permissions(
        &db,
        &identity,
        &ids["target"],
        vec![ObjectGrant {
            subject: Subject::Owner,
            actions: BTreeSet::from([Action::GraphRead]),
            effect: Effect::Deny,
            inherit: false,
        }],
        None,
    )
    .unwrap();
    let read = db
        .bind_access(&identity, "docs", "acme", Action::GraphRead)
        .unwrap();
    assert!(
        db.traverse_authorized(&read, traversal.clone(), &AtomicBool::new(false))
            .unwrap()
            .publish(|r| r.nodes.is_empty())
            .unwrap()
    );
    file.seek(SeekFrom::Start(position as u64)).unwrap();
    file.write_all(&original[position..position + 1]).unwrap();
    assert_eq!(fs::read(&path).unwrap(), original);
    replace_permissions(&db, &identity, &ids["target"], vec![], None).unwrap();
    let read = db
        .bind_access(&identity, "docs", "acme", Action::GraphRead)
        .unwrap();
    assert_eq!(
        db.traverse_authorized(&read, traversal.clone(), &AtomicBool::new(false))
            .unwrap()
            .publish(|r| r.nodes.len())
            .unwrap(),
        1
    );
    drop(file);
    drop(collection);
    drop(db);
    let reopened = Db::open(directory.path()).unwrap();
    let identity = reopened
        .identity_authority()
        .unwrap()
        .authenticate(&key)
        .unwrap();
    let read = reopened
        .bind_access(&identity, "docs", "acme", Action::GraphRead)
        .unwrap();
    assert_eq!(
        reopened
            .traverse_authorized(&read, traversal, &AtomicBool::new(false))
            .unwrap()
            .publish(|r| r.nodes.len())
            .unwrap(),
        1
    );
}

#[test]
fn graph_filters_respect_field_authority_and_hidden_bridges_across_seal_and_reopen() {
    use crate::graph::{GraphDirection, GraphTraverseRequest, TraversalBudget, TraversalStats};
    use crate::{
        MultiModelInsertRequest, NewRecord, NewRelation, RecordEndpoint, SqlExecutionRequest,
        SqlStatementRequest,
    };
    let (directory, db, key, _) = fixture(true);
    let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
    let manage = db
        .bind_access(&identity, "docs", "acme", Action::PolicyManage)
        .unwrap();
    let mut policy = db.inner.read().collections["docs"]
        .read()
        .security
        .as_ref()
        .unwrap()
        .checkpoint()
        .policy;
    policy
        .templates
        .get_mut("standard")
        .unwrap()
        .properties
        .insert(
            "/secret".into(),
            PropertyRule {
                classification: Classification::Internal,
                actions: BTreeSet::from([PropertyAction::Write]),
            },
        );
    db.replace_collection_policy_authorized(
        &manage,
        RevisionUpdate {
            expected_revision: manage.policy_revision(),
            value: policy,
        },
    )
    .unwrap();
    let sql = |sql: &str| SqlExecutionRequest {
        statements: vec![SqlStatementRequest {
            sql: sql.into(),
            parameters: vec![],
        }],
        idempotency_key: None,
        retry_id: None,
    };
    db.execute_sql_authorized(
        &identity,
        sql("CREATE TABLE docs (id TEXT PRIMARY KEY)"),
        "test",
    )
    .unwrap();
    let response = db
        .insert_multimodel_authorized(
            &identity,
            MultiModelInsertRequest {
                sql: sql("INSERT INTO docs VALUES ('graph')"),
                collection: "docs".into(),
                template: "standard".into(),
                records: [
                    ("root", "anchor"),
                    ("visible", "allowed"),
                    ("hidden", "allowed"),
                    ("behind", "allowed"),
                    ("other", "other"),
                    ("leaf", "allowed"),
                ]
                .into_iter()
                .map(|(binding, text)| {
                    let mut point = point(text);
                    point.payload["secret"] = serde_json::json!("classified");
                    NewRecord {
                        binding: binding.into(),
                        point,
                    }
                })
                .collect(),
                relations: [
                    ("root", "visible", "allow"),
                    ("root", "hidden", "allow"),
                    ("hidden", "behind", "allow"),
                    ("root", "other", "allow"),
                    ("visible", "root", "allow"),
                    ("visible", "leaf", "deny"),
                    ("root", "visible", "deny"),
                ]
                .into_iter()
                .map(|(source, target, kind)| NewRelation {
                    source: RecordEndpoint::New(source.into()),
                    target: RecordEndpoint::New(target.into()),
                    edge_type: "cites".into(),
                    properties: serde_json::json!({"kind":kind}),
                })
                .collect(),
            },
            "test",
        )
        .unwrap();
    let ids: BTreeMap<_, _> = response
        .records
        .into_iter()
        .map(|(name, record)| (name, record.id))
        .collect();
    replace_permissions(
        &db,
        &identity,
        &ids["hidden"],
        vec![ObjectGrant {
            subject: Subject::Owner,
            actions: BTreeSet::from([Action::GraphRead]),
            effect: Effect::Deny,
            inherit: false,
        }],
        None,
    )
    .unwrap();
    let request = GraphTraverseRequest {
        anchors: vec![ids["root"].clone()],
        edge_types: vec!["cites".into()],
        direction: GraphDirection::Outgoing,
        node_filter: Some(Filter(serde_json::json!({"text":"allowed"}))),
        edge_filter: Some(Filter(serde_json::json!({"kind":"allow"}))),
        budget: TraversalBudget {
            max_depth: 3,
            max_memory_bytes: 8 * 1024 * 1024,
            ..Default::default()
        },
    };
    let check = |db: &Db| {
        let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
        let read = db
            .bind_access(&identity, "docs", "acme", Action::GraphRead)
            .unwrap();
        let result = db
            .traverse_authorized(&read, request.clone(), &AtomicBool::new(false))
            .unwrap()
            .publish(|r| r)
            .unwrap();
        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.nodes[0].point_id, ids["visible"]);
        assert_eq!(result.nodes[0].depth, 1);
        assert_eq!(result.stats, TraversalStats::default());
        assert!(result.truncation.is_none() && result.warnings.is_empty());
        for returns in [
            crate::graph::GraphTraversalReturn::Nodes,
            crate::graph::GraphTraversalReturn::Edges,
            crate::graph::GraphTraversalReturn::Paths,
        ] {
            let query = crate::graph::GraphTraversalQueryRequest {
                traversal: request.clone(),
                returns,
                limit: Some(20),
                with_payload: true,
            };
            let response = db.traverse_query_authorized(&read, query, &AtomicBool::new(false))
                .unwrap().publish(|r| r).unwrap();
            assert_eq!(response.stats, TraversalStats::default());
            assert!(response.truncation.is_none() && response.warnings.is_empty());
            let encoded = serde_json::to_string(&response).unwrap();
            for forbidden in [&ids["hidden"], &ids["behind"], &ids["other"]] {
                assert!(!encoded.contains(forbidden));
            }
            assert!(!encoded.contains("classified") && !encoded.contains("secret"));
            match response.result {
                crate::graph::GraphTraversalRows::Nodes(rows) => {
                    assert_eq!(rows.len(), 1);
                    assert_eq!(rows[0].id, ids["visible"]);
                    assert_eq!(rows[0].payload, Some(serde_json::json!({"text":"allowed"})));
                }
                crate::graph::GraphTraversalRows::Edges(rows) => {
                    assert_eq!(rows.len(), 1);
                    assert_eq!(rows[0].source, ids["root"]);
                    assert_eq!(rows[0].target, ids["visible"]);
                    assert_eq!(rows[0].properties, Some(serde_json::json!({"kind":"allow"})));
                }
                crate::graph::GraphTraversalRows::Paths(rows) => {
                    assert_eq!(rows.len(), 1);
                    assert_eq!(rows[0].nodes.len(), 2);
                    assert_eq!(rows[0].nodes[0].id, ids["root"]);
                    assert_eq!(rows[0].nodes[1].id, ids["visible"]);
                }
            }
        }
        for field in ["secret", "unknown"] {
            let mut forbidden = request.clone();
            forbidden.node_filter = Some(Filter(serde_json::json!({field:"classified"})));
            assert!(matches!(
                db.traverse_authorized(&read, forbidden, &AtomicBool::new(false)),
                Err(GaussError::Security(SecurityError::Forbidden))
            ));
        }
        let mut all = request.clone();
        all.node_filter = None;
        all.edge_filter = None;
        let result = db
            .traverse_authorized(&read, all.clone(), &AtomicBool::new(false))
            .unwrap()
            .publish(|r| r)
            .unwrap();
        let actual: BTreeSet<_> = result.nodes.iter().map(|n| n.point_id.clone()).collect();
        assert_eq!(
            actual,
            BTreeSet::from([
                ids["visible"].clone(),
                ids["other"].clone(),
                ids["leaf"].clone()
            ])
        );
        let edges = db.traverse_query_authorized(&read, crate::graph::GraphTraversalQueryRequest {
            traversal: all.clone(), returns: crate::graph::GraphTraversalReturn::Edges,
            limit: Some(20), with_payload: true,
        }, &AtomicBool::new(false)).unwrap().publish(|r| r).unwrap();
        let crate::graph::GraphTraversalRows::Edges(edges) = edges.result else { panic!("edges") };
        assert_eq!(edges.len(), 5, "parallel edges remain distinct; hidden bridges are absent");
        assert_eq!(edges.iter().filter(|edge| edge.source == ids["root"] && edge.target == ids["visible"]).count(), 2);
        let mut incoming = request.clone();
        incoming.anchors = vec![ids["visible"].clone()];
        incoming.direction = GraphDirection::Incoming;
        incoming.node_filter = None;
        incoming.budget.max_depth = 1;
        let result = db
            .traverse_authorized(&read, incoming, &AtomicBool::new(false))
            .unwrap()
            .publish(|r| r)
            .unwrap();
        assert_eq!(result.nodes[0].point_id, ids["root"]);
        let mut unknown = request.clone();
        unknown.edge_types = vec!["missing".into()];
        assert!(
            db.traverse_authorized(&read, unknown, &AtomicBool::new(false))
                .unwrap()
                .publish(|r| r.nodes.is_empty())
                .unwrap()
        );
        let mut hidden = request.clone();
        hidden.anchors = vec![ids["hidden"].clone()];
        assert!(matches!(
            db.traverse_authorized(&read, hidden, &AtomicBool::new(false)),
            Err(GaussError::Security(SecurityError::NotFound))
        ));
        let mut tiny = request.clone();
        tiny.budget.max_edges = 1;
        assert!(matches!(
            db.traverse_authorized(&read, tiny, &AtomicBool::new(false)),
            Err(GaussError::Security(SecurityError::BudgetExceeded))
        ));
        assert!(
            db.traverse_authorized(&read, request.clone(), &AtomicBool::new(true))
                .is_err()
        );
        let mut zero = request.clone();
        zero.budget.max_depth = 0;
        zero.node_filter = Some(Filter(serde_json::json!({"text":"anchor"})));
        assert_eq!(
            db.traverse_authorized(&read, zero, &AtomicBool::new(false))
                .unwrap()
                .publish(|r| r.nodes[0].point_id.clone())
                .unwrap(),
            ids["root"]
        );
    };
    check(&db);
    let collection = db.inner.read().collections["docs"].clone();
    collection.write().config.streamer_max_bytes = 1;
    let create = db
        .bind_access(&identity, "docs", "acme", Action::Create)
        .unwrap();
    db.create_points_authorized(&create, "standard", vec![point("trigger seal")], true)
        .unwrap()
        .publish(|_| ())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let state = collection.read();
        if state.sealing.is_none()
            && state.graph_generation.is_some()
            && state
                .graph_mutable
                .as_ref()
                .unwrap()
                .compaction_topology()
                .count()
                == 0
        {
            break;
        }
        drop(state);
        assert!(Instant::now() < deadline, "protected graph did not seal");
        std::thread::sleep(Duration::from_millis(10));
    }
    check(&db);
    drop(collection);
    drop(db);
    let db = Db::open(directory.path()).unwrap();
    check(&db);
    let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
    let read = db
        .bind_access(&identity, "docs", "acme", Action::GraphRead)
        .unwrap();
    let create = db.bind_access(&identity, "docs", "acme", Action::Create).unwrap();
    let large_id = db.create_points_authorized(&create, "standard", vec![point(&"x".repeat(64 * 1024))], true)
        .unwrap().publish(|ids| ids[0].clone()).unwrap();
    let mut large = request.clone();
    large.anchors = vec![large_id.clone()];
    large.node_filter = None;
    large.edge_filter = None;
    large.budget.max_depth = 0;
    let large_query = crate::graph::GraphTraversalQueryRequest {
        traversal: large, returns: crate::graph::GraphTraversalReturn::Nodes,
        limit: Some(1), with_payload: true,
    };
    assert!(matches!(db.traverse_query_authorized(&read, large_query.clone(), &AtomicBool::new(false)),
        Err(GaussError::Security(SecurityError::BudgetExceeded))));
    let without_payload = db.traverse_query_authorized(&read, crate::graph::GraphTraversalQueryRequest {
        with_payload: false, ..large_query
    }, &AtomicBool::new(false)).unwrap().publish(|r| r).unwrap();
    let crate::graph::GraphTraversalRows::Nodes(nodes) = without_payload.result else { panic!("nodes") };
    assert_eq!(nodes[0].id, large_id, "output hydration budget refuses before cloning large payload");
    let queued = db
        .traverse_authorized(&read, request.clone(), &AtomicBool::new(false))
        .unwrap();
    let queued_edges = db.traverse_query_authorized(&read, crate::graph::GraphTraversalQueryRequest {
        traversal: request.clone(), returns: crate::graph::GraphTraversalReturn::Edges,
        limit: Some(20), with_payload: true,
    }, &AtomicBool::new(false)).unwrap();
    replace_permissions(
        &db,
        &identity,
        &ids["visible"],
        vec![ObjectGrant {
            subject: Subject::Owner,
            actions: BTreeSet::from([Action::GraphRead]),
            effect: Effect::Deny,
            inherit: false,
        }],
        None,
    )
    .unwrap();
    assert!(queued.publish(|_| ()).is_err());
    assert!(queued_edges.publish(|_| ()).is_err());
    assert!(
        db.traverse_authorized(&read, request.clone(), &AtomicBool::new(false))
            .is_err()
    );
    let read = db
        .bind_access(&identity, "docs", "acme", Action::GraphRead)
        .unwrap();
    assert!(
        db.traverse_authorized(&read, request, &AtomicBool::new(false))
            .unwrap()
            .publish(|r| r.nodes.is_empty())
            .unwrap()
    );
}
