use super::*;
use crate::{GaussError, relational::wal_decode::with_test_storage_pool};
use std::collections::HashMap;

fn fixture() -> (
    tempfile::TempDir,
    CollectionAuthority,
    Arc<IdentityAuthority>,
    AuthenticatedIdentity,
) {
    let directory = tempfile::tempdir().unwrap();
    let subject = PrincipalRecord {
        id: "reader".into(),
        tenant: "acme".into(),
        enabled: true,
        attributes: SubjectAttributes {
            department: "Finance".into(),
            clearance: Classification::Internal,
        },
        grants: vec![ScopeGrant {
            tenants: BTreeSet::from(["acme".into()]),
            collections: BTreeSet::from(["docs".into()]),
            actions: BTreeSet::from([Action::Read, Action::Search]),
        }],
        installation_actions: BTreeSet::from([Action::IdentityManage]),
        delegation: Vec::new(),
    };
    let issued = IdentityAuthority::bootstrap(directory.path(), subject).unwrap();
    let identities = IdentityAuthority::open(directory.path()).unwrap().unwrap();
    let identity = identities.authenticate(&issued.secret).unwrap();
    let incarnation = Uuid::new_v4();
    let resources = (1..=80)
        .map(|i| ResourceRecord {
            key: PointKey {
                collection: incarnation,
                tenant: if i == 80 { "foreign" } else { "acme" }.into(),
                id: format!("public-{i:03}"),
            },
            storage_id: Uuid::from_u128(i),
            labels: ResourceLabels {
                owner: "reader".into(),
                department: "Finance".into(),
                classification: Classification::Internal,
                quarantined: false,
            },
            properties: BTreeMap::from([
                (
                    "/text".into(),
                    PropertyRule {
                        classification: Classification::Internal,
                        actions: BTreeSet::from([PropertyAction::Query, PropertyAction::Read]),
                    },
                ),
                (
                    "/hidden".into(),
                    PropertyRule {
                        classification: Classification::Restricted,
                        actions: BTreeSet::from([PropertyAction::Query, PropertyAction::Read]),
                    },
                ),
            ]),
            representations: BTreeMap::from([(
                "dense".into(),
                Representation {
                    classification: Classification::Internal,
                    source_fields: BTreeSet::from(["/text".into()]),
                },
            )]),
            grants: if i % 5 == 0 {
                vec![ObjectGrant {
                    subject: Subject::Owner,
                    effect: Effect::Deny,
                    actions: BTreeSet::from([Action::Read, Action::Search]),
                    inherit: false,
                }]
            } else {
                vec![]
            },
            parent: None,
            revision: 1,
            retired: false,
            create_receipt: None,
        })
        .collect();
    let authority = CollectionAuthority::from_verified_checkpoint(SecurityCheckpoint {
        version: SECURITY_VERSION,
        collection: "docs".into(),
        incarnation,
        revision: 1,
        data_generation: 1,
        policy: CollectionPolicy {
            department_actions: BTreeSet::from([Action::Read, Action::Search]),
            owner_actions: BTreeSet::new(),
            templates: BTreeMap::new(),
        },
        resources,
    })
    .unwrap();
    (directory, authority, identities, identity)
}

#[test]
fn point_projection_copies_visible_vectors_and_preserves_payload_number_bits() {
    let (_directory, authority, _identities, identity) = fixture();
    {
        let snapshot = authority.current.read();
        let mut resources = snapshot.resources.write();
        let row = resources
            .records
            .values_mut()
            .find(|r| r.storage_id == Uuid::from_u128(1))
            .unwrap();
        for name in ["named-visible", "sparse"] {
            row.representations.insert(
                name.into(),
                Representation {
                    source_fields: BTreeSet::from(["/text".into()]),
                    classification: Classification::Internal,
                },
            );
        }
        row.representations.insert(
            "named-hidden".into(),
            Representation {
                source_fields: BTreeSet::from(["/hidden".into()]),
                classification: Classification::Restricted,
            },
        );
    }
    let context = authority.bind(&identity, "acme", Action::Read).unwrap();
    let reader = context.read_resources().unwrap();
    let record = reader.physical(Uuid::from_u128(1)).unwrap();
    let source = crate::Point {
        id: "physical-must-not-leave".into(),
        vector: vec![f32::MIN_POSITIVE, -0.0, f32::MAX],
        vectors: HashMap::from([
            ("named-visible".into(), vec![f32::MIN, -0.0]),
            ("named-hidden".into(), vec![1.0; 262144]),
        ]),
        sparse_vector: Some(crate::SparseVector {
            indices: vec![0, u32::MAX],
            values: vec![-0.0, 1.0],
        }),
        payload: serde_json::json!({"text":{"number":1.2345678901234567e300_f64,"zero":-0.0,"integer":u64::MAX},"hidden":"secret".repeat(65536)}),
    };
    with_test_storage_pool(1, |used| {
        assert!(matches!(
            record.project_point(&source),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(used(), 0);
    });
    with_test_storage_pool(16 * 1024, |used| {
        let projected = record.project_point(&source).unwrap();
        assert_eq!(projected.id, record.id());
        assert_eq!(
            projected
                .vector
                .iter()
                .map(|v| v.to_bits())
                .collect::<Vec<_>>(),
            source
                .vector
                .iter()
                .map(|v| v.to_bits())
                .collect::<Vec<_>>()
        );
        assert_ne!(projected.vector.as_ptr(), source.vector.as_ptr());
        assert_eq!(projected.vectors.len(), 1);
        assert_eq!(
            projected.vectors["named-visible"]
                .iter()
                .map(|v| v.to_bits())
                .collect::<Vec<_>>(),
            source.vectors["named-visible"]
                .iter()
                .map(|v| v.to_bits())
                .collect::<Vec<_>>()
        );
        assert_eq!(projected.sparse_vector, source.sparse_vector);
        assert_eq!(
            projected.sparse_vector.as_ref().unwrap().values[0].to_bits(),
            (-0.0_f32).to_bits()
        );
        assert_eq!(
            projected.payload["text"]["number"]
                .as_f64()
                .unwrap()
                .to_bits(),
            source.payload["text"]["number"].as_f64().unwrap().to_bits()
        );
        assert_eq!(
            projected.payload["text"]["zero"]
                .as_f64()
                .unwrap()
                .to_bits(),
            (-0.0_f64).to_bits()
        );
        assert_eq!(
            projected.payload["text"]["integer"].as_u64(),
            Some(u64::MAX)
        );
        assert!(projected.payload.get("hidden").is_none());
        assert!(
            used() > 0 && used() < 16384,
            "hidden megabyte vectors/payload are not copied"
        );
        let mut points = crate::security::output::Points::default();
        points.push(projected).unwrap();
        let output = points.finish_scroll(context.clone(), true).unwrap();
        let retained = used();
        output
            .map(|page| {
                assert_eq!(used(), retained);
                assert_eq!(page.next_offset.as_deref(), Some("public-001"));
                page
            })
            .unwrap()
            .publish(|page| {
                assert_eq!(page.points.len(), 1);
                assert_eq!(used(), retained);
            })
            .unwrap();
        assert_eq!(used(), 0);
    });
    with_test_storage_pool(16384, |used| {
        let projected = record.project_point(&source).unwrap();
        let point_bytes = used();
        let mut blocker = MetadataCharge::default();
        blocker
            .prepare(16384 - point_bytes - crate::relational::wal_decode::lease_root_bytes() - 1)
            .unwrap();
        let blocker_bytes = used() - point_bytes;
        let mut points = crate::security::output::Points::default();
        assert!(matches!(
            points.push(projected),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(
            used(),
            blocker_bytes,
            "refused receiving growth drops point leases"
        );
        drop(points);
        drop(blocker);
        assert_eq!(used(), 0);
    });
}

#[test]
fn streamed_domain_matches_reference_and_records_borrow_pinned_authority() {
    let (_directory, authority, _identities, identity) = fixture();
    let context = authority.bind(&identity, "acme", Action::Search).unwrap();
    let expected = context.authorized_domain().unwrap();
    with_test_storage_pool(1, |used| {
        let reader = context.read_resources().unwrap();
        let mut count = 0;
        let mut previous = Uuid::nil();
        reader
            .for_each_authorized(
                || Ok(()),
                |record| {
                    assert!(expected.contains(&record.storage_id()));
                    assert!(previous < record.storage_id());
                    previous = record.storage_id();
                    let pinned = &reader.resources.records[&record.record.key];
                    assert!(std::ptr::eq(record.record, pinned));
                    assert_eq!(record.id().as_ptr(), pinned.key.id.as_ptr());
                    record.query_field("/text")?;
                    assert_eq!(record.query_field("/hidden"), Err(SecurityError::NotFound));
                    assert!(record.representation_visible("dense")?);
                    assert!(!record.representation_visible("absent")?);
                    let mut buffer = [0; 36];
                    assert_eq!(
                        Uuid::parse_str(record.storage_name(&mut buffer)).unwrap(),
                        record.storage_id()
                    );
                    count += 1;
                    assert_eq!(
                        used(),
                        0,
                        "stream/record/UUID/policy scratch allocates no admitted backing"
                    );
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(count, expected.len());
        assert!(matches!(
            reader.public("public-001"),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(used(), 0);
        assert!(matches!(
            reader.physical(Uuid::from_u128(80)),
            Err(SecurityError::NotFound)
        ));
    });
    with_test_storage_pool(16 * 1024, |used| {
        let reader = context.read_resources().unwrap();
        let record = reader.public("public-001").unwrap();
        assert_eq!(used(), 0, "temporary composite key drops after lookup");
        assert!(std::ptr::eq(
            record.record,
            reader.physical(record.storage_id()).unwrap().record
        ));
        let value = serde_json::json!({"text":"visible","hidden":"secret"});
        let projected = record.project(&value).unwrap();
        assert_eq!(*projected, serde_json::json!({"text":"visible"}));
        assert!(used() > 0);
        drop(projected);
        assert_eq!(used(), 0);
    });
}

#[test]
fn pinned_read_methods_finish_while_resource_writer_waits() {
    let (_directory, authority, _identities, identity) = fixture();
    let context = authority.bind(&identity, "acme", Action::Search).unwrap();
    let reader = context.read_resources().unwrap();
    let resources = Arc::clone(&context.snapshot.resources);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        entered_tx.send(()).unwrap();
        let mut guard = resources.write();
        guard.generation += 1;
        done_tx.send(()).unwrap();
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    assert!(done_rx.try_recv().is_err());
    let record = reader.physical(Uuid::from_u128(1)).unwrap();
    record.query_field("/text").unwrap();
    assert!(record.representation_visible("dense").unwrap());
    reader.for_each_authorized(|| Ok(()), |_| Ok(())).unwrap();
    assert_eq!(
        reader.public(record.id()).unwrap().storage_id(),
        record.storage_id()
    );
    drop(reader);
    done_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    writer.join().unwrap();
}

#[test]
fn stream_aborts_on_callback_error_and_pinned_record_rechecks_closed_epoch() {
    let (_directory, authority, _identities, identity) = fixture();
    let context = authority.bind(&identity, "acme", Action::Search).unwrap();
    let reader = context.read_resources().unwrap();
    let count = std::cell::Cell::new(0);
    let result = reader.for_each_authorized(
        || Ok(()),
        |_| {
            count.set(count.get() + 1);
            if count.get() == 2 {
                Err(SecurityError::BudgetExceeded.into())
            } else {
                Ok(())
            }
        },
    );
    assert!(matches!(
        result,
        Err(GaussError::Security(SecurityError::BudgetExceeded))
    ));
    assert_eq!(count.get(), 2);
    let record = reader.physical(Uuid::from_u128(1)).unwrap();
    context.snapshot.epoch.close();
    assert_eq!(record.query_field("/text"), Err(SecurityError::Conflict));
    assert!(
        reader
            .for_each_authorized(|| Ok(()), |_| panic!("closed epoch must not visit"))
            .is_err()
    );
    assert!(
        record
            .project(&serde_json::json!({"text":"no publication"}))
            .is_err()
    );
    drop(reader);
    assert!(context.read_resources().is_err());
}
