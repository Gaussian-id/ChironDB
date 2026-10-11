#[allow(dead_code)]
mod common;
use chirondb::{Db, api, auth::AuthConfig, grpc, security::*, wire};
use grpc::{chiron_pb::chiron_db_client::ChironDbClient, pb};
use std::collections::{BTreeMap, BTreeSet};

#[tokio::test]
async fn protected_text_output_matches_core_over_http_grpc_and_wire() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let data = root.join("data");
    let keyfile = root.join("admin.key");
    onboarding::initialize(
        &data,
        "acme",
        "admin",
        &root.join("storage.json"),
        &keyfile,
        false,
    )
    .unwrap();
    let key = std::fs::read_to_string(&keyfile).unwrap();
    let key = key.trim().to_owned();
    let db = Db::open(&data).unwrap();
    let authority = db.identity_authority().unwrap();
    let identity = authority.authenticate(&key).unwrap();
    db.create_protected_collection_authorized(
        &identity,
        db.catalog_revision_authorized(&identity).unwrap(),
        serde_json::from_value(serde_json::json!({"name":"docs","vector_dim":2})).unwrap(),
    )
    .unwrap();
    let managed = db.management_identity(&identity).unwrap();
    let revision = db
        .collection_policy_authorized(&managed, "docs")
        .unwrap()
        .publish(|p| p.0)
        .unwrap();
    let policy = db
        .bind_access(&managed, "docs", "acme", Action::PolicyManage)
        .unwrap();
    db.replace_collection_policy_authorized(
        &policy,
        RevisionUpdate {
            expected_revision: revision,
            value: CollectionPolicy {
                department_actions: BTreeSet::new(),
                owner_actions: BTreeSet::from([Action::Read, Action::Search]),
                templates: BTreeMap::from([(
                    "standard".into(),
                    IngestTemplate {
                        department: "Security".into(),
                        classification: Classification::Internal,
                        properties: BTreeMap::from([
                            (
                                "/text".into(),
                                PropertyRule {
                                    classification: Classification::Internal,
                                    actions: BTreeSet::from([
                                        PropertyAction::Read,
                                        PropertyAction::Query,
                                        PropertyAction::Write,
                                    ]),
                                },
                            ),
                            (
                                "/secret".into(),
                                PropertyRule {
                                    classification: Classification::Restricted,
                                    actions: BTreeSet::from([PropertyAction::Write]),
                                },
                            ),
                        ]),
                        representations: BTreeMap::from([(
                            "dense".into(),
                            Representation {
                                source_fields: BTreeSet::from(["/text".into()]),
                                classification: Classification::Internal,
                            },
                        )]),
                    },
                )]),
            },
        },
    )
    .unwrap();
    let mut principal = identity.principal().clone();
    principal.grants.push(ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: BTreeSet::from(["docs".into()]),
        actions: BTreeSet::from([Action::Create, Action::Ingest, Action::Search, Action::Read]),
    });
    authority
        .put_principal(&managed, authority.revision(), principal)
        .unwrap();
    let identity = authority.authenticate(&key).unwrap();
    let create = db
        .bind_access(&identity, "docs", "acme", Action::Create)
        .unwrap();
    let text = "refund 日本語\n".repeat(1024);
    let point = serde_json::from_value(serde_json::json!({"vector":[1.0,0.0], "payload":{"text":text,"secret":"must not leave the engine"}})).unwrap();
    let ids = db
        .create_points_authorized(&create, "standard", vec![point], true)
        .unwrap()
        .publish(|ids| ids)
        .unwrap();
    let search = db
        .bind_access(&identity, "docs", "acme", Action::Search)
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = listener.local_addr().unwrap();
    let http_db = db.clone();
    let http = tokio::spawn(async move {
        axum::serve(
            listener,
            api::router_with_auth(http_db, AuthConfig::disabled()),
        )
        .await
        .unwrap()
    });
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grpc_addr = probe.local_addr().unwrap();
    drop(probe);
    let grpc_db = db.clone();
    let grpc = tokio::spawn(async move { grpc::serve(grpc_db, grpc_addr).await.unwrap() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wire_addr = listener.local_addr().unwrap();
    let wire_db = db.clone();
    let wire = tokio::spawn(async move {
        wire::serve_listener_with_auth(wire_db, AuthConfig::disabled(), listener)
            .await
            .unwrap()
    });
    let mut client = ChironDbClient::new(common::connect_grpc_channel(grpc_addr).await);
    let http_client = reqwest::Client::new();
    for vector in [vec![], vec![1.0, 0.0]] {
        let query = chirondb::TextHybridSearchRequest {
            vector: vector.clone(),
            query: "refund".into(),
            text_field: "text".into(),
            k: 1,
            filter: None,
            budget_ms: None,
        };
        let expected = db
            .text_hybrid_search_authorized(&search, query.clone(), None)
            .unwrap()
            .publish(|hits| hits)
            .unwrap();
        assert_eq!(expected[0].id, ids[0]);
        assert_eq!(expected[0].payload, serde_json::json!({"text":text}));
        for prefix in ["", "/v1"] {
            let response = http_client
                .post(format!(
                    "http://{http_addr}{prefix}/collections/docs/text_hybrid_search"
                ))
                .bearer_auth(&key)
                .json(&query)
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
            let value: serde_json::Value = response.json().await.unwrap();
            assert_eq!(value["hits"], serde_json::to_value(&expected).unwrap());
        }
        let query = pb::TextHybridSearchRequest {
            collection: "docs".into(),
            vector,
            query: "refund".into(),
            text_field: "text".into(),
            k: 1,
            filter_json: String::new(),
            budget_ms: None,
        };
        let grpc_hits = client
            .text_hybrid_search(common::grpc_auth_request(query.clone(), &key))
            .await
            .unwrap()
            .into_inner();
        let wire_reply = common::send_wire_with_key(
            &wire_addr.to_string(),
            17,
            &key,
            pb::wire_request::Operation::TextHybridSearch(query),
        )
        .await;
        assert_eq!(wire_reply.error_code, "");
        let pb::wire_response::Payload::Search(wire_hits) = wire_reply.payload.unwrap() else {
            panic!("search reply expected");
        };
        assert_eq!(grpc_hits, wire_hits);
        assert_eq!(grpc_hits.hits.len(), expected.len());
        assert_eq!(grpc_hits.hits[0].id, expected[0].id);
        assert_eq!(
            grpc_hits.hits[0].score.to_bits(),
            expected[0].score.to_bits()
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&grpc_hits.hits[0].payload_json).unwrap(),
            expected[0].payload
        );
    }
    let read = db
        .bind_access(&identity, "docs", "acme", Action::Read)
        .unwrap();
    let expected = db
        .get_points_authorized(&read, &ids)
        .unwrap()
        .publish(|points| points)
        .unwrap();
    for prefix in ["", "/v1"] {
        for (operation, body) in [
            ("points/get", serde_json::json!({"ids":ids})),
            ("scroll", serde_json::json!({"limit":1})),
        ] {
            let response = http_client
                .post(format!(
                    "http://{http_addr}{prefix}/collections/docs/{operation}"
                ))
                .bearer_auth(&key)
                .json(&body)
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
            let value: serde_json::Value = response.json().await.unwrap();
            assert_eq!(value["points"], serde_json::to_value(&expected).unwrap());
            if operation == "scroll" {
                assert!(value["next_offset"].is_null());
            }
        }
    }
    let query = pb::GetPointsRequest {
        collection: "docs".into(),
        ids: ids.clone(),
    };
    let grpc_points = client
        .get_points(common::grpc_auth_request(query.clone(), &key))
        .await
        .unwrap()
        .into_inner();
    let wire_reply = common::send_wire_with_key(
        &wire_addr.to_string(),
        18,
        &key,
        pb::wire_request::Operation::GetPoints(query),
    )
    .await;
    assert_eq!(wire_reply.error_code, "");
    let pb::wire_response::Payload::GetPoints(wire_points) = wire_reply.payload.unwrap() else {
        panic!("points reply expected");
    };
    assert_eq!(grpc_points, wire_points);
    assert_eq!(grpc_points.points.len(), expected.len());
    assert_eq!(grpc_points.points[0].id, expected[0].id);
    assert_eq!(grpc_points.points[0].vector, expected[0].vector);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&grpc_points.points[0].payload_json).unwrap(),
        expected[0].payload
    );
    let query = pb::ScrollRequest {
        collection: "docs".into(),
        offset: String::new(),
        limit: 1,
        filter_json: String::new(),
    };
    let grpc_page = client
        .scroll(common::grpc_auth_request(query.clone(), &key))
        .await
        .unwrap()
        .into_inner();
    let wire_reply = common::send_wire_with_key(
        &wire_addr.to_string(),
        19,
        &key,
        pb::wire_request::Operation::Scroll(query),
    )
    .await;
    assert_eq!(wire_reply.error_code, "");
    let pb::wire_response::Payload::Scroll(wire_page) = wire_reply.payload.unwrap() else {
        panic!("scroll reply expected");
    };
    assert_eq!(grpc_page, wire_page);
    assert_eq!(grpc_page.points, grpc_points.points);
    assert!(grpc_page.next_offset.is_empty());
    let mut legacy =
        pb::gauss_db_client::GaussDbClient::new(common::connect_grpc_channel(grpc_addr).await);
    assert_eq!(
        legacy
            .get_points(common::grpc_auth_request(
                pb::GetPointsRequest {
                    collection: "docs".into(),
                    ids: ids.clone(),
                },
                &key
            ))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        legacy
            .scroll(common::grpc_auth_request(
                pb::ScrollRequest {
                    collection: "docs".into(),
                    offset: String::new(),
                    limit: 1,
                    filter_json: String::new(),
                },
                &key
            ))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    let mut forged = common::grpc_auth_request(
        pb::GetPointsRequest {
            collection: "docs".into(),
            ids: ids.clone(),
        },
        &key,
    );
    forged
        .metadata_mut()
        .insert("x-tenant-id", "other".parse().unwrap());
    assert_eq!(
        client.get_points(forged).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        client
            .get_points(common::grpc_auth_request(
                pb::GetPointsRequest {
                    collection: "docs".into(),
                    ids: vec!["missing".into(); 1025],
                },
                &key
            ))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::ResourceExhausted
    );
    let missing = client
        .get_points(common::grpc_auth_request(
            pb::GetPointsRequest {
                collection: "docs".into(),
                ids: vec!["missing".into()],
            },
            &key,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(missing.points.is_empty());
    http.abort();
    grpc.abort();
    wire.abort();
    let _ = http.await;
    let _ = grpc.await;
    let _ = wire.await;
}
