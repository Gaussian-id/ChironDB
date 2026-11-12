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
    policy.templates.get_mut("standard").unwrap().properties.insert(
        "/edges/secret".into(), PropertyRule {
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
                    properties: serde_json::json!({"kind":kind,"secret":"edge-classified"}),
                })
                .collect(),
            },
            "test",
        )
        .unwrap();
    let edge_token = response.edge_ids[0].clone();
    let ids: BTreeMap<_, _> = response
        .records
        .into_iter()
        .map(|(name, record)| (name, record.id))
        .collect();
    let labels = db.bind_access(&identity, "docs", "acme", Action::LabelsManage).unwrap();
    let mut root = labels.authorize(&ids["root"]).unwrap();
    root.properties.get_mut("/edges/kind").unwrap().actions = BTreeSet::from([
        PropertyAction::Read, PropertyAction::Query,
    ]);
    db.replace_object_labels_authorized(&labels, &ids["root"], RevisionUpdate {
        expected_revision: labels.policy_revision(),
        value: ObjectLabels { labels:root.labels, properties:root.properties },
    }).unwrap();
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
        let vector = db.bind_access(&identity, "docs", "acme", Action::Update).unwrap();
        let graph = db.bind_access(&identity, "docs", "acme", Action::GraphWrite).unwrap();
        for (mode, properties) in [
            (crate::graph::EdgePropertyMode::Merge, serde_json::json!({"kind":"allow"})),
            (crate::graph::EdgePropertyMode::Merge, serde_json::json!({"kind":"changed"})),
            (crate::graph::EdgePropertyMode::Replace, serde_json::json!({"secret":"edge-classified"})),
        ] {
            let error = db.execute_multimodel_transaction_authorized(&identity, &vector, &graph,
                MultiModelTransactionRequest {
                    sql:sql("UPDATE docs SET id = 'denied' WHERE id = 'graph'"), collection:"docs".into(),
                    points:vec![], point_deletes:vec![], relations:vec![], edge_deletes:vec![],
                    edge_updates:vec![(edge_token.clone(), crate::graph::UpdateEdgeRequest {mode, properties})],
                }, "test").expect_err("edge field denial before SQL commit");
            assert!(matches!(error, GaussError::Security(SecurityError::Forbidden)));
        }
        let rows = db.execute_sql_authorized(&identity, sql("SELECT id FROM docs"), "test").unwrap();
        assert!(!serde_json::to_string(&rows).unwrap().contains("denied"));
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
        for field in ["secret", "unknown"] {
            let mut forbidden = request.clone();
            forbidden.edge_filter = Some(Filter(serde_json::json!({field:"edge-classified"})));
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

#[test]
fn independent_edge_policy_filters_traversal_and_atomically_rejects_writes() {
    use crate::{MultiModelInsertRequest, NewRecord, NewRelation, RecordEndpoint, SqlExecutionRequest, SqlStatementRequest};
    use crate::graph::{GraphTraverseRequest, GraphDirection, TraversalBudget, GraphTraversalQueryRequest, GraphTraversalReturn, GraphTraversalRows};
    let (directory, db, key, _) = fixture(true);
    let identity = db.identity_authority().unwrap().authenticate(&key).unwrap();
    let sql = |text: &str| SqlExecutionRequest { statements: vec![SqlStatementRequest { sql:text.into(),parameters:vec![] }], idempotency_key:None,retry_id:None };
    db.execute_sql_authorized(&identity, sql("CREATE TABLE docs (id TEXT PRIMARY KEY)"), "test").unwrap();
    let inserted = db.insert_multimodel_authorized(&identity, MultiModelInsertRequest {
        sql:sql("INSERT INTO docs VALUES ('created')"), collection:"docs".into(),template:"standard".into(),
        records: ["source", "target"].into_iter().map(|id| NewRecord { binding:id.into(),point:point(id) }).collect(),
        relations:vec![NewRelation { source:RecordEndpoint::New("source".into()),target:RecordEndpoint::New("target".into()),edge_type:"cites".into(),properties:serde_json::json!({"kind":"allow"}) }],
    }, "test").unwrap();
    let token = inserted.edge_ids[0].clone();
    let source = inserted.records["source"].id.clone();
    let target = inserted.records["target"].id.clone();
    let request = GraphTraverseRequest { anchors:vec![source],edge_types:vec!["cites".into()],direction:GraphDirection::Outgoing,node_filter:None,edge_filter:None,budget:TraversalBudget::default() };
    let bind = |action| db.bind_access(&identity,"docs","acme",action).unwrap();
    let labels = bind(Action::LabelsManage);
    let edge_id = db.edge_security_id_authorized(&labels,&token).unwrap();
    let original = labels.authorize(&edge_id).unwrap();
    assert!(!original.content.is_point());
    assert!(bind(Action::Read).authorize(&edge_id).is_err());
    let read = bind(Action::GraphRead);
    let queued = db.traverse_authorized(&read,request.clone(),&AtomicBool::new(false)).unwrap();
    // Both nodes remain readable; only the edge's object grant is denied.
    replace_permissions(&db,&identity,&edge_id,vec![ObjectGrant { subject:Subject::Owner, actions:BTreeSet::from([Action::GraphRead,Action::GraphWrite]),effect:Effect::Deny,inherit:false }],None).unwrap();
    assert!(queued.publish(|_| ()).is_err());
    assert!(bind(Action::GraphRead).authorize(&target).is_ok());
    let read = bind(Action::GraphRead);
    for returns in [GraphTraversalReturn::Nodes,GraphTraversalReturn::Edges,GraphTraversalReturn::Paths] {
        let result = db.traverse_query_authorized(&read, GraphTraversalQueryRequest { traversal:request.clone(),returns,limit:Some(10),with_payload:true },&AtomicBool::new(false)).unwrap().publish(|r|r).unwrap();
        match result.result { GraphTraversalRows::Nodes(v) => assert!(v.is_empty()), GraphTraversalRows::Edges(v) => assert!(v.is_empty()), GraphTraversalRows::Paths(v) => assert!(v.is_empty()) }
    }
    let vector = bind(Action::Update);
    let graph = bind(Action::GraphWrite);
    let change = |updates, deletes| MultiModelTransactionRequest { sql:sql("UPDATE docs SET id = 'forbidden' WHERE id = 'created'"),collection:"docs".into(),points:vec![],point_deletes:vec![],relations:vec![],edge_deletes:deletes,edge_updates:updates };
    assert!(db.execute_multimodel_transaction_authorized(&identity,&vector,&graph,change(vec![],vec![token.clone()]),"test").is_err());
    replace_permissions(&db,&identity,&edge_id,vec![],None).unwrap();
    // Own field rules are enforced independently of the fully permitted endpoints.
    for (actions, query_allowed, projected) in [
        (BTreeSet::from([PropertyAction::Read]),false,true),
        (BTreeSet::from([PropertyAction::Query]),true,false),
    ] {
        let labels = bind(Action::LabelsManage);
        let mut changed = original.clone();
        changed.properties.get_mut("/kind").unwrap().actions = actions;
        db.replace_object_labels_authorized(&labels,&edge_id,RevisionUpdate { expected_revision:labels.policy_revision(),value:ObjectLabels { labels:changed.labels,properties:changed.properties } }).unwrap();
        let read = bind(Action::GraphRead);
        let mut filtered = request.clone(); filtered.edge_filter=Some(Filter(serde_json::json!({"kind":"allow"})));
        let result = db.traverse_authorized(&read,filtered,&AtomicBool::new(false));
        if query_allowed { assert_eq!(result.unwrap().publish(|r|r.nodes.len()).unwrap(),1); } else { assert!(matches!(result,Err(GaussError::Security(SecurityError::Forbidden)))); }
        let edges = db.traverse_query_authorized(&read,GraphTraversalQueryRequest { traversal:request.clone(),returns:GraphTraversalReturn::Edges,limit:Some(10),with_payload:true },&AtomicBool::new(false)).unwrap().publish(|r|r).unwrap();
        let GraphTraversalRows::Edges(edges)=edges.result else {panic!("edges")};
        assert_eq!(edges[0].properties.as_ref().unwrap().get("kind").is_some(),projected);
        for guess in ["allow","wrong"] {
            let vector=bind(Action::Update); let graph=bind(Action::GraphWrite);
            assert!(matches!(db.execute_multimodel_transaction_authorized(&identity,&vector,&graph,change(vec![(token.clone(),crate::graph::UpdateEdgeRequest { mode:crate::graph::EdgePropertyMode::Merge,properties:serde_json::json!({"kind":guess}) })],vec![]),"test"),Err(GaussError::Security(SecurityError::Forbidden))));
        }
    }
    assert!(!serde_json::to_string(&db.execute_sql_authorized(&identity,sql("SELECT id FROM docs"),"test").unwrap()).unwrap().contains("forbidden"));
    let labels=bind(Action::LabelsManage);
    db.replace_object_labels_authorized(&labels,&edge_id,RevisionUpdate { expected_revision:labels.policy_revision(),value:ObjectLabels { labels:original.labels,properties:original.properties } }).unwrap();
    let read=bind(Action::GraphRead);
    let queued=db.traverse_authorized(&read,request.clone(),&AtomicBool::new(false)).unwrap();
    let vector=bind(Action::Update); let graph=bind(Action::GraphWrite);
    db.execute_multimodel_transaction_authorized(&identity,&vector,&graph,MultiModelTransactionRequest { sql:sql("UPDATE docs SET id = 'deleted' WHERE id = 'created'"),..change(vec![],vec![token]) },"test").unwrap();
    assert!(queued.publish(|_|()).is_err(),"edge retirement must revoke queued topology");
    drop(db);
    let db=Db::open(directory.path()).unwrap();
    let identity=db.identity_authority().unwrap().authenticate(&key).unwrap();
    let read=db.bind_access(&identity,"docs","acme",Action::GraphRead).unwrap();
    assert!(db.traverse_authorized(&read,request,&AtomicBool::new(false)).unwrap().publish(|r|r.nodes.is_empty()).unwrap());
}

#[test]
fn legacy_edges_stay_hidden_until_explicit_admin_registration_and_reopen() {
    use crate::{MultiModelInsertRequest, NewRecord, NewRelation, RecordEndpoint, SqlExecutionRequest, SqlStatementRequest};
    use crate::graph::{GraphTraverseRequest,GraphDirection,TraversalBudget};
    let (directory,db,key,limited)=fixture(true);
    let identity=db.identity_authority().unwrap().authenticate(&key).unwrap();
    let manage=db.bind_access(&identity,"docs","acme",Action::PolicyManage).unwrap();
    let mut policy=db.inner.read().collections["docs"].read().security.as_ref().unwrap().checkpoint().policy;
    policy.templates.insert("edge".into(),IngestTemplate { department:"Finance".into(),classification:Classification::Internal,properties:BTreeMap::from([("/kind".into(),PropertyRule { classification:Classification::Internal,actions:BTreeSet::from([PropertyAction::Read,PropertyAction::Query,PropertyAction::Write]) })]),representations:BTreeMap::new() });
    db.replace_collection_policy_authorized(&manage,RevisionUpdate { expected_revision:manage.policy_revision(),value:policy }).unwrap();
    let sql=|text:&str| SqlExecutionRequest { statements:vec![SqlStatementRequest { sql:text.into(),parameters:vec![] }],idempotency_key:None,retry_id:None };
    db.execute_sql_authorized(&identity,sql("CREATE TABLE docs (id TEXT PRIMARY KEY)"),"test").unwrap();
    let inserted=db.insert_multimodel_authorized(&identity,MultiModelInsertRequest {
        sql:sql("INSERT INTO docs VALUES ('old')"),collection:"docs".into(),template:"standard".into(),records:["source","target"].into_iter().map(|id| NewRecord { binding:id.into(),point:point(id) }).collect(),
        relations:vec![NewRelation { source:RecordEndpoint::New("source".into()),target:RecordEndpoint::New("target".into()),edge_type:"cites".into(),properties:serde_json::json!({"kind":"allow"}) }],
    },"test").unwrap();
    let token=inserted.edge_ids[0].clone();
    let request=GraphTraverseRequest { anchors:vec![inserted.records["source"].id.clone()],edge_types:vec!["cites".into()],direction:GraphDirection::Outgoing,node_filter:None,edge_filter:Some(Filter(serde_json::json!({"kind":"allow"}))),budget:TraversalBudget::default() };
    // Model a verified pre-edge-authority checkpoint: graph content already
    // exists, while its security catalog contains only endpoint bindings.
    db.flush_wals().unwrap();
    let root=db.inner.read().root.clone();
    let mut stored={ let collection=db.inner.read().collections["docs"].clone(); let collection=collection.read();
        crate::security::storage::StoredSecurity { wal_watermark:collection.wal.len().unwrap(),authority:collection.security.as_ref().unwrap().checkpoint() } };
    stored.authority.resources.retain(|r| !matches!(r.content,ResourceContent::GraphEdge {..}));
    drop(db);
    crate::security::storage::write(&root.join("collections/docs"),&stored).unwrap();
    let db=Db::open(directory.path()).unwrap();
    let identity=db.identity_authority().unwrap().authenticate(&key).unwrap();
    let read=db.bind_access(&identity,"docs","acme",Action::GraphRead).unwrap();
    assert!(db.traverse_authorized(&read,request.clone(),&AtomicBool::new(false)).unwrap().publish(|r|r.nodes.is_empty()).unwrap());
    let other=db.identity_authority().unwrap().authenticate(&limited).unwrap();
    let other=db.bind_access(&other,"docs","acme",Action::GraphWrite).unwrap();
    assert!(matches!(db.register_edge_authorized(&other,&token,"edge",other.policy_revision()),Err(GaussError::Security(SecurityError::Forbidden))));
    let graph=db.bind_access(&identity,"docs","acme",Action::GraphWrite).unwrap();
    let revision=db.register_edge_authorized(&graph,&token,"edge",graph.policy_revision()).unwrap().publish(|r|r).unwrap();
    let graph=db.bind_access(&identity,"docs","acme",Action::GraphWrite).unwrap();
    assert!(db.register_edge_authorized(&graph,&token,"edge",revision).is_err());
    let read=db.bind_access(&identity,"docs","acme",Action::GraphRead).unwrap();
    assert_eq!(db.traverse_authorized(&read,request.clone(),&AtomicBool::new(false)).unwrap().publish(|r|r.nodes.len()).unwrap(),1);
    drop(db);
    let db=Db::open(directory.path()).unwrap();
    let identity=db.identity_authority().unwrap().authenticate(&key).unwrap();
    let read=db.bind_access(&identity,"docs","acme",Action::GraphRead).unwrap();
    assert_eq!(db.traverse_authorized(&read,request,&AtomicBool::new(false)).unwrap().publish(|r|r.nodes.len()).unwrap(),1);
}
