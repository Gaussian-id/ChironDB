//! One exclusive WAL cut for topology, properties, lifecycle and vector visibility.

use super::*;
use crate::{
    db::{collection_dir, copy_dir_contents},
    edge_token, encryption,
    graph::{
        ConfigureEdgeTypeRequest, EdgeId, EdgePropertyMode, GraphDirection, GraphRelationScope,
        GraphTraverseRequest, RelateRequest, TraversalBudget, UpdateEdgeRequest,
    },
    tenant::TenantScope,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{env, process::Command};

#[test]
fn graph_pitr_restores_whole_state_in_both_layouts_plaintext_and_encrypted() {
    const MODE: &str = "CHIRONDB_GRAPH_PITR_MODE";
    const ROOT: &str = "CHIRONDB_GRAPH_PITR_ROOT";
    const LAYOUT: &str = "CHIRONDB_GRAPH_PITR_LAYOUT";
    const TEST: &str = "db::tests::graph_pitr::graph_pitr_restores_whole_state_in_both_layouts_plaintext_and_encrypted";
    let Some(mode) = env::var_os(MODE) else {
        for mode in ["plaintext", "encrypted"] {
            for layout in ["legacy", "generation"] {
                let temp = TempDir::new().unwrap();
                assert!(
                    Command::new(env::current_exe().unwrap())
                        .args(["--exact", TEST, "--nocapture"])
                        .env(MODE, mode)
                        .env(ROOT, temp.path())
                        .env(LAYOUT, layout)
                        .status()
                        .unwrap()
                        .success(),
                    "{mode}/{layout}"
                );
            }
        }
        return;
    };
    let root = PathBuf::from(env::var_os(ROOT).unwrap());
    if mode == "encrypted" {
        let keyring = root.join("keyring.json");
        fs::write(
            &keyring,
            json!({"version":1,"active_key_id":"pitr","keys":[
                {"id":"pitr","key_base64":STANDARD.encode([98;32])}
            ]})
            .to_string(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
        }
        encryption::install_process_keyring(encryption::Keyring::load(&keyring).unwrap(), true)
            .unwrap();
    }
    for retain_origin in [false, true] {
        exercise_pitr(
            &root.join(if retain_origin { "origin" } else { "pruned" }),
            env::var(LAYOUT).unwrap() == "generation",
            retain_origin,
        );
    }
}

fn exercise_pitr(root: &Path, generation_layout: bool, retain_origin: bool) {
    let data = root.join("db");
    if generation_layout {
        crate::storage_layout::initialize_empty(&data).unwrap();
    }
    let mut db = Db::open(&data).unwrap();
    let active = db.inner.read().root.clone();
    let wal_dir = collection_dir(&active, "docs").join("wal");
    let scope = TenantScope::tenant("pitr-writer", "acme");
    let mut config = ls_vec_config("docs");
    config.streamer_max_bytes = usize::MAX;
    db.create_collection(config).unwrap();
    db.set_graph_lifecycle_scoped("docs", true, true, &scope)
        .unwrap();
    db.upsert(
        "docs",
        vec![graph_point("a", 1.0, "acme"), graph_point("b", 2.0, "acme")],
    )
    .unwrap();
    db.configure_edge_type_scoped(
        "docs",
        ConfigureEdgeTypeRequest {
            name: "links".into(),
            weight_property: None,
        },
        true,
        &scope,
    )
    .unwrap();
    let token = db
        .relate_scoped(
            "docs",
            RelateRequest {
                source_point_id: "a".into(),
                target_point_id: "b".into(),
                edge_type: "links".into(),
                properties: json!({"revision":1}),
                scope: GraphRelationScope::Local,
                idempotency_key: Some("original".into()),
            },
            true,
            &scope,
        )
        .unwrap()
        .edge_id;
    let id = edge_token::decode(db.graph_database_id(), &token).unwrap();
    let before_checkpoint = cut(&db, &wal_dir, id);
    thread::sleep(Duration::from_millis(3));
    db.update_edge_scoped(
        "docs",
        &token,
        UpdateEdgeRequest {
            mode: EdgePropertyMode::Merge,
            properties: json!({"revision":2}),
        },
        true,
        &scope,
    )
    .unwrap();
    db.upsert("docs", vec![graph_point("a", 3.0, "acme")])
        .unwrap();
    let checkpoint_cut = cut(&db, &wal_dir, id);
    let seal = prepare_forced_graph_vector_seal(&db, &active, "docs");
    assert_eq!(seal.end_lsn, checkpoint_cut.0);
    // A post-cut tail now lands in the rotated successor segment. The sealed
    // prefix can therefore retire while its checked archive preserves origin.
    if retain_origin {
        db.upsert("docs", vec![graph_point("trigger", 5.0, "acme")])
            .unwrap();
    }
    run_segment_seal(&seal).unwrap();
    drop(seal);
    assert_eq!(Wal::retained_base_lsn(&wal_dir).unwrap(), checkpoint_cut.0);
    if !retain_origin {
        // Model an operator retention policy that deliberately discards the
        // origin archive; historical PITR must then continue to fail closed.
        for entry in fs::read_dir(wal_dir.join("archive")).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                fs::remove_dir_all(path).unwrap();
            }
        }
    }
    if !retain_origin {
        db.upsert("docs", vec![graph_point("trigger", 5.0, "acme")])
            .unwrap();
    }
    db.update_edge_scoped(
        "docs",
        &token,
        UpdateEdgeRequest {
            mode: EdgePropertyMode::Merge,
            properties: json!({"revision":3}),
        },
        true,
        &scope,
    )
    .unwrap();
    db.upsert("docs", vec![graph_point("a", 4.0, "acme")])
        .unwrap();
    let tail_cut = cut(&db, &wal_dir, id);
    thread::sleep(Duration::from_millis(3));
    db.delete_with_edges_scoped("docs", &["b".into()], &scope)
        .unwrap();
    db.upsert("docs", vec![graph_point("b", 9.0, "acme")])
        .unwrap();
    let replaced_cut = cut(&db, &wal_dir, id);
    assert_ne!(tail_cut.2["nids"][1], replaced_cut.2["nids"][1]);
    db.set_graph_lifecycle_scoped("docs", false, true, &scope)
        .unwrap();
    let disabled_cut = cut(&db, &wal_dir, id);
    db.set_graph_lifecycle_scoped("docs", true, true, &scope)
        .unwrap();
    db.upsert("docs", vec![graph_point("a", 10.0, "acme")])
        .unwrap();
    let source = root.join("snapshot");
    db.snapshot(&source).unwrap();
    let source_dir = collection_dir(&source, "docs");
    let source_manifest = checkpoint::read_segments_manifest(&source_dir)
        .unwrap()
        .unwrap();
    let source_marker = snapshot::read_snapshot_marker(&source).unwrap().unwrap();
    let source_wal = Wal::load(&source_dir.join("wal")).unwrap();
    let database_id = db.graph_database_id();

    for (label, target, by_time) in [
        ("checkpoint", &checkpoint_cut, false),
        ("tail-lsn", &tail_cut, false),
        ("tail-time", &tail_cut, true),
        ("replacement", &replaced_cut, false),
        ("disabled", &disabled_cut, false),
    ] {
        let epoch = db.graph_allocator_epoch();
        restore_cut(&db, &source, target, by_time).unwrap();
        assert_eq!(state(&db, id), target.2, "{label}");
        assert_eq!(db.graph_database_id(), database_id);
        assert!(db.graph_allocator_epoch() > epoch);
        let active = db.inner.read().root.clone();
        let marker = snapshot::read_snapshot_marker(&active).unwrap().unwrap();
        assert_eq!(marker.collections[0].wal_lsn, target.0, "{label}");
        assert_eq!(
            checkpoint::read_segments_manifest(&collection_dir(&active, "docs"))
                .unwrap()
                .unwrap(),
            source_manifest
        );
        drop(db);
        db = Db::open(&data).unwrap();
        assert_eq!(state(&db, id), target.2, "reopen {label}");
    }
    for by_time in [false, true] {
        let before = state(&db, id);
        let result = restore_cut(&db, &source, &before_checkpoint, by_time);
        if retain_origin {
            result.unwrap();
            assert_eq!(state(&db, id), before_checkpoint.2);
            let active = db.inner.read().root.clone();
            let manifest = checkpoint::read_segments_manifest(&collection_dir(&active, "docs"))
                .unwrap()
                .unwrap();
            assert!(manifest.graph.is_none());
            assert!(manifest.segments.is_empty());
            assert_eq!(manifest.generation, source_manifest.generation);
            drop(db);
            db = Db::open(&data).unwrap();
            assert_eq!(state(&db, id), before_checkpoint.2);
            // Subsequent publication must not collide with unselected future peers.
            let active = db.inner.read().root.clone();
            let seal = prepare_forced_graph_vector_seal(&db, &active, "docs");
            run_segment_seal(&seal).unwrap();
            drop(seal);
            assert!(
                checkpoint::read_segments_manifest(&collection_dir(&active, "docs"))
                    .unwrap()
                    .unwrap()
                    .generation
                    > source_manifest.generation
            );
            assert_eq!(state(&db, id), before_checkpoint.2);
        } else {
            let error = result.unwrap_err().to_string();
            assert!(error.contains("graph PITR unavailable"), "{error}");
            assert_eq!(state(&db, id), before);
        }
    }
    // No interior frame, out-of-range cut or unknowable timestamp may install.
    for (target, by_time) in [
        (tail_cut.0 - 1, false),
        (source_marker.collections[0].wal_lsn + 1, false),
    ] {
        let before = state(&db, id);
        let current_root = db.inner.read().root.clone();
        let epoch = db.graph_allocator_epoch();
        assert!(restore_cut(&db, &source, &(target, target, json!(null)), by_time).is_err());
        assert_eq!(state(&db, id), before);
        assert_eq!(db.inner.read().root, current_root);
        // Failed attempts may burn an allocator epoch; it must never rewind.
        assert!(db.graph_allocator_epoch() >= epoch);
        assert_eq!(db.graph_database_id(), database_id);
    }
    if retain_origin {
        restore_cut(&db, &source, &(0, 0, json!(null)), false).unwrap();
        assert_eq!(db.count("docs", None).unwrap().count, 0);
        assert!(
            db.get_coll("docs")
                .unwrap()
                .read()
                .graph_lifecycle
                .epoch()
                .is_none()
        );
        drop(db);
        db = Db::open(&data).unwrap();
        assert_eq!(db.count("docs", None).unwrap().count, 0);
    } else {
        let before = state(&db, id);
        let error = restore_cut(&db, &source, &(0, 0, json!(null)), true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("timestamp cannot identify"), "{error}");
        assert_eq!(state(&db, id), before);
    }
    assert_eq!(
        checkpoint::read_segments_manifest(&source_dir)
            .unwrap()
            .unwrap(),
        source_manifest
    );
    assert_eq!(
        snapshot::read_snapshot_marker(&source).unwrap().unwrap(),
        source_marker
    );
    assert_eq!(
        serde_json::to_value(Wal::load(&source_dir.join("wal")).unwrap()).unwrap(),
        serde_json::to_value(source_wal).unwrap()
    );

    // A graph checkpoint cannot substitute for a gap in its replay suffix.
    let bad = root.join("missing-history");
    copy_dir_contents(&source, &bad).unwrap();
    let mut wal = Wal::open(&collection_dir(&bad, "docs").join("wal")).unwrap();
    wal.drop_prefix(wal.len().unwrap()).unwrap();
    drop(wal);
    let error = match Db::open(&bad) {
        Ok(_) => panic!("accepted missing suffix"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("retained WAL does not cover"),
        "{error}"
    );
    let before = state(&db, id);
    assert!(db.restore(&bad).is_err());
    assert_eq!(state(&db, id), before);
}

fn restore_cut(
    db: &Db,
    source: &Path,
    target: &(u64, u64, serde_json::Value),
    by_time: bool,
) -> crate::Result<()> {
    let targets = HashMap::from([("docs".into(), if by_time { target.1 } else { target.0 })]);
    if by_time {
        db.restore_to_wal_targets(source, &HashMap::new(), &targets)
    } else {
        db.restore_to_wal_targets(source, &targets, &HashMap::new())
    }
}

fn cut(db: &Db, wal: &Path, id: EdgeId) -> (u64, u64, serde_json::Value) {
    (
        db.get_coll("docs").unwrap().read().wal.len().unwrap(),
        Wal::load(wal).unwrap().last().unwrap().unix_ms,
        state(db, id),
    )
}

pub(super) fn state(db: &Db, id: EdgeId) -> serde_json::Value {
    let ids = ["a".into(), "b".into(), "trigger".into()];
    let points = db.get_points("docs", &ids).unwrap();
    let coll = db.get_coll("docs").unwrap();
    let collection = coll.read();
    let enabled = collection.graph_lifecycle.is_enabled();
    let epoch = collection.graph_lifecycle.epoch().map(|epoch| epoch.raw());
    let nids: Vec<_> = ids
        .iter()
        .map(|id| {
            collection
                .graph_resolver
                .as_ref()
                .and_then(|r| r.live_nid(id))
                .map(|nid| nid.raw())
        })
        .collect();
    let properties = collection
        .graph_mutable
        .as_ref()
        .and_then(|g| g.edge_properties(id).unwrap().map(|p| p.into_owned()));
    drop(collection);
    let mut nodes = Vec::new();
    if enabled {
        for (anchor, direction) in [
            ("a", GraphDirection::Outgoing),
            ("b", GraphDirection::Incoming),
        ] {
            let result = db
                .traverse_scoped(
                    "docs",
                    GraphTraverseRequest {
                        anchors: vec![anchor.into()],
                        edge_types: Vec::new(),
                        direction,
                        node_filter: None,
                        edge_filter: None,
                        budget: TraversalBudget {
                            max_depth: 1,
                            ..TraversalBudget::default()
                        },
                    },
                    &TenantScope::tenant("pitr-reader", "acme"),
                )
                .unwrap();
            assert!(result.truncation.is_none());
            nodes.push(json!(result.nodes));
        }
    }
    json!({"points":points,"enabled":enabled,"epoch":epoch,"nids":nids,"properties":properties,"nodes":nodes})
}

#[test]
fn wal_only_graph_pitr_reopens_pending_session_before_its_commit() {
    let temp = TempDir::new().unwrap();
    let data = temp.path().join("db");
    let db = Db::open(&data).unwrap();
    let scope = TenantScope::tenant("pitr-deferred", "acme");
    let mut config = ls_vec_config("docs");
    config.streamer_max_bytes = usize::MAX;
    db.create_collection(config).unwrap();
    db.set_graph_lifecycle_scoped("docs", true, true, &scope)
        .unwrap();
    db.upsert("docs", vec![graph_point("a", 1.0, "acme")])
        .unwrap();
    db.configure_edge_type_scoped(
        "docs",
        ConfigureEdgeTypeRequest {
            name: "links".into(),
            weight_property: None,
        },
        true,
        &scope,
    )
    .unwrap();
    let session = db
        .open_deferred_graph_session_scoped("docs", true, &scope)
        .unwrap();
    let request = RelateRequest {
        source_point_id: "a".into(),
        target_point_id: "b".into(),
        edge_type: "links".into(),
        properties: json!({"pending":true}),
        scope: GraphRelationScope::Local,
        idempotency_key: Some("pitr-pending".into()),
    };
    let pending = db
        .relate_deferred_scoped("docs", &session.session_id, request.clone(), true, &scope)
        .unwrap();
    let target = db.get_coll("docs").unwrap().read().wal.len().unwrap();
    db.upsert_deferred_scoped(
        "docs",
        &session.session_id,
        vec![graph_point("b", 2.0, "acme")],
        true,
        &scope,
    )
    .unwrap();
    db.commit_deferred_graph_session_scoped("docs", &session.session_id, true, &scope)
        .unwrap();
    let source = temp.path().join("snapshot");
    db.snapshot(&source).unwrap();
    assert!(
        checkpoint::read_segments_manifest(&collection_dir(&source, "docs"))
            .unwrap()
            .is_none()
    );
    db.restore_to_wal_lsns(&source, &HashMap::from([("docs".into(), target)]))
        .unwrap();
    assert!(db.get_points("docs", &["b".into()]).unwrap().is_empty());
    drop(db);
    let db = Db::open(&data).unwrap();
    {
        let coll = db.get_coll("docs").unwrap();
        let collection = coll.read();
        let graph = collection.graph_mutable.as_ref().unwrap();
        assert!(graph.deferred_session_is_open(session.session_id.as_str()));
        assert_eq!(graph.pending_edge_count(), 1);
        assert_eq!(graph.idempotency_len(), 1);
    }
    let retried = db
        .relate_deferred_scoped("docs", &session.session_id, request, true, &scope)
        .unwrap();
    assert_eq!(retried.edge_id, pending.edge_id);
    db.upsert_deferred_scoped(
        "docs",
        &session.session_id,
        vec![graph_point("b", 3.0, "acme")],
        true,
        &scope,
    )
    .unwrap();
    db.commit_deferred_graph_session_scoped("docs", &session.session_id, true, &scope)
        .unwrap();
    let id = edge_token::decode(db.graph_database_id(), &pending.edge_id).unwrap();
    assert_eq!(state(&db, id)["properties"], json!({"pending":true}));
    assert_eq!(
        db.get_points("docs", &["b".into()]).unwrap()[0].vector,
        vec![3.0, 0.0]
    );
}
