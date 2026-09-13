use super::*;
use serde_json::json;
use tempfile::TempDir;

fn query() -> TextHybridSearchRequest {
    TextHybridSearchRequest {
        vector: vec![1.0, 0.0],
        query: "refund policy".into(),
        text_field: "text".into(),
        k: 5,
        filter: None,
        budget_ms: None,
    }
}
fn point(id: &str, text: &str, tenant: &str) -> Point {
    serde_json::from_value(
        json!({"id":id,"vector":[1.0,0.0],"payload":{"text":text,"tenant_id":tenant}}),
    )
    .unwrap()
}
type Ranking = Vec<(String, f32)>;

#[test]
fn replicated_mutations_and_background_seal_preserve_text_statistics() {
    let root = TempDir::new().unwrap();
    let db = Db::open(root.path()).unwrap();
    db.create_collection(
        serde_json::from_value(json!({
            "name":"docs", "vector_dim":2, "streamer_max_bytes":1
        }))
        .unwrap(),
    )
    .unwrap();
    db.apply_legacy_replicated_upsert(
        "docs",
        vec![
            point("a1", "refund refund", "a"),
            point("a2", "policy", "a"),
        ],
    )
    .unwrap();
    db.set_tenant_enforcement(crate::TenantEnforcement::Enforced);
    let before = signature(&db);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let coll = db.get_coll("docs").unwrap();
        let collection = coll.read();
        if collection.sealing.is_none() && !collection.searchers.is_empty() {
            break;
        }
        assert!(Instant::now() < deadline, "background seal did not finish");
        drop(collection);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(before, signature(&db));
    db.apply_legacy_replicated_payload("docs", "a1", json!({"text":"policy newword"}), true)
        .unwrap();
    db.apply_legacy_replicated_upsert("docs", vec![point("a2", "refund policy", "a")])
        .unwrap();
    db.apply_legacy_replicated_delete("docs", &["a1".into()])
        .unwrap();
    let changed = signature(&db);
    assert_eq!(changed.0.len(), 1);
    assert_eq!(changed.1.len(), 1);
    assert_eq!(changed.1[0].0, "a2");
    drop(db);
    let db = Db::open(root.path()).unwrap();
    db.set_tenant_enforcement(crate::TenantEnforcement::Enforced);
    assert_eq!(changed, signature(&db));
}

fn signature(db: &Db) -> (Ranking, Ranking) {
    let dense = db
        .text_hybrid_search_scoped("docs", query(), &TenantScope::tenant("alice", "a"))
        .unwrap();
    assert!(!dense.degraded);
    let coll = db.get_coll("docs").unwrap();
    let col = coll.read();
    let bm25 =
        col.sparse_index
            .text
            .search("text", "refund policy", Some("a"), 20, &|_| true, &|| false);
    (
        dense
            .hits
            .into_iter()
            .map(|hit| (hit.id, hit.score))
            .collect(),
        bm25.ranked
            .into_iter()
            .map(|hit| (hit.id, hit.score))
            .collect(),
    )
}

#[test]
fn lifecycle_mutations_replay_compaction_snapshot_and_cold() {
    let root = TempDir::new().unwrap();
    let cold = TempDir::new().unwrap();
    let snapshots = TempDir::new().unwrap();
    let db = Db::open_with_cold_object_store(root.path(), Some(cold.path().to_owned())).unwrap();
    db.create_collection(serde_json::from_value(json!({"name":"docs","vector_dim":2})).unwrap())
        .unwrap();
    db.upsert(
        "docs",
        vec![
            point("a1", "refund refund policy", "a"),
            point("a2", "policy delivery", "a"),
            point("b1", "refund", "b"),
        ],
    )
    .unwrap();
    db.set_tenant_enforcement(crate::TenantEnforcement::Enforced);
    let initial = signature(&db);
    db.upsert_scoped(
        "docs",
        vec![point("b2", "refund refund refund policy", "b")],
        true,
        &TenantScope::tenant("bob", "b"),
    )
    .unwrap();
    assert_eq!(initial, signature(&db));
    db.compact_collection("docs").unwrap();
    assert_eq!(initial, signature(&db));
    let a = TenantScope::tenant("alice", "a");
    db.set_payload_scoped("docs", "a1", json!({"text":"delivery"}), true, &a)
        .unwrap();
    db.upsert_scoped("docs", vec![point("a2", "refund refund", "a")], true, &a)
        .unwrap();
    db.upsert_scoped("docs", vec![point("remove", "refund", "a")], true, &a)
        .unwrap();
    assert_eq!(
        db.delete_by_filter_scoped("docs", &Filter(json!({"text":"refund"})), &a)
            .unwrap(),
        1
    );
    let changed = signature(&db);
    assert_eq!(
        changed
            .1
            .iter()
            .map(|hit| hit.0.as_str())
            .collect::<Vec<_>>(),
        ["a2"]
    );
    drop(db);
    let db = Db::open_with_cold_object_store(root.path(), Some(cold.path().to_owned())).unwrap();
    db.set_tenant_enforcement(crate::TenantEnforcement::Enforced);
    assert_eq!(changed, signature(&db));
    db.compact_collection("docs").unwrap();
    assert_eq!(changed, signature(&db));
    db.snapshot(snapshots.path().join("saved")).unwrap();
    db.delete_scoped("docs", &["a2".into()], &a).unwrap();
    assert!(signature(&db).1.is_empty());
    db.restore(snapshots.path().join("saved")).unwrap();
    db.set_tenant_enforcement(crate::TenantEnforcement::Enforced);
    assert_eq!(changed, signature(&db));
    db.tier_collection_to_cold("docs").unwrap();
    assert_eq!(changed, signature(&db));
    drop(db);
    let db = Db::open_with_cold_object_store(root.path(), Some(cold.path().to_owned())).unwrap();
    db.set_tenant_enforcement(crate::TenantEnforcement::Enforced);
    assert_eq!(changed, signature(&db));
}

#[test]
fn field_membership_tenant_filter_and_precancelled_search() {
    let root = TempDir::new().unwrap();
    let db = Db::open(root.path()).unwrap();
    db.create_collection(serde_json::from_value(json!({"name":"docs","vector_dim":2})).unwrap())
        .unwrap();
    let mut missing = point("missing", "refund", "a");
    missing.payload.as_object_mut().unwrap().remove("text");
    db.upsert(
        "docs",
        vec![
            missing,
            point("allowed", "", "a"),
            point("foreign", "refund", "b"),
        ],
    )
    .unwrap();
    db.set_tenant_enforcement(crate::TenantEnforcement::Enforced);
    let scope = TenantScope::tenant("alice", "a");
    let found = db
        .text_hybrid_search_scoped("docs", query(), &scope)
        .unwrap();
    assert_eq!(
        found
            .hits
            .iter()
            .map(|hit| hit.id.as_str())
            .collect::<Vec<_>>(),
        ["allowed"]
    );
    let mut wrong = query();
    wrong.filter = Some(Filter(json!({"tenant_id":"b"})));
    assert!(db.text_hybrid_search_scoped("docs", wrong, &scope).is_err());
    let result = db
        .text_hybrid_search_with_cancellation_scoped(
            "docs",
            query(),
            &scope,
            &AtomicBool::new(true),
        )
        .unwrap();
    assert!(result.degraded && result.hits.is_empty());
}
