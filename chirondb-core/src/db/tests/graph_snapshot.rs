//! Whole-state graph snapshot/restore through both production install layouts.

use super::*;
use crate::{
    edge_token, encryption,
    graph::{
        EdgeMutation, EdgePropertyMode, GraphDirection, GraphNamespace, GraphRelationScope,
        GraphTraverseRequest, RelateMutation, RelateRequest, TraversalBudget, TypeId,
        UpdateEdgeRequest,
    },
    graph_generation::{ArtifactFamily, GraphGeneration, artifact_path},
    tenant::TenantScope,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{env, num::NonZeroU64, process::Command};

#[test]
fn graph_snapshots_bind_generations_and_restore_both_layouts_plaintext_and_encrypted() {
    const MODE: &str = "CHIRONDB_GRAPH_SNAPSHOT_MODE";
    const ROOT: &str = "CHIRONDB_GRAPH_SNAPSHOT_ROOT";
    const LAYOUT: &str = "CHIRONDB_GRAPH_SNAPSHOT_LAYOUT";
    const TEST: &str = "db::tests::graph_snapshot::graph_snapshots_bind_generations_and_restore_both_layouts_plaintext_and_encrypted";
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
            json!({"version":1,"active_key_id":"snapshot","keys":[
                {"id":"snapshot","key_base64":STANDARD.encode([97;32])}
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
    let data = root.join("db");
    if env::var(LAYOUT).unwrap() == "generation" {
        crate::storage_layout::initialize_empty(&data).unwrap();
    }
    let db = Db::open(&data).unwrap();
    let active = db.inner.read().root.clone();
    let scope = TenantScope::tenant("snapshot-writer", "acme");
    super::partitioned_delta::bootstrap(&db, &active, &scope);
    db.create_collection(ls_vec_config("vectors")).unwrap();
    db.upsert("vectors", vec![ls_vec_point("vector-only", 1.0, "live")])
        .unwrap();
    let ids: Vec<_> = db
        .graph_identity
        .allocate_edge_ids(NonZeroU64::new(4096).unwrap())
        .unwrap()
        .edge_ids()
        .collect();
    let nids = {
        let coll = db.get_coll("docs").unwrap();
        let state = coll.read();
        let resolver = state.graph_resolver.as_ref().unwrap();
        [
            resolver.live_nid("a").unwrap(),
            resolver.live_nid("b").unwrap(),
        ]
    };
    db.commit_graph_batch_scoped(
        "docs",
        GraphBatch {
            edge_mutations: ids
                .iter()
                .map(|&edge_id| {
                    EdgeMutation::Relate(RelateMutation {
                        edge_id,
                        source: nids[0],
                        target: nids[1],
                        type_id: TypeId::from_raw(1),
                        namespace: GraphNamespace::Tenant("acme".into()),
                        properties: json!({"revision":1}),
                    })
                })
                .collect(),
            ..GraphBatch::default()
        },
        true,
        &scope,
    )
    .unwrap();
    let session = db
        .open_deferred_graph_session_scoped("docs", true, &scope)
        .unwrap();
    let pending = db
        .relate_deferred_scoped(
            "docs",
            &session.session_id,
            RelateRequest {
                source_point_id: "a".into(),
                target_point_id: "future".into(),
                edge_type: "links".into(),
                properties: json!({"pending":true}),
                scope: GraphRelationScope::Local,
                idempotency_key: Some("pending-snapshot".into()),
            },
            true,
            &scope,
        )
        .unwrap();
    db.upsert("docs", vec![graph_point("trigger", 3.0, "acme")])
        .unwrap();
    let seal = prepare_forced_graph_vector_seal(&db, &active, "docs");
    run_segment_seal(&seal).unwrap();
    drop(seal);
    let last = *ids.last().unwrap();
    let token = edge_token::encode(db.graph_database_id(), last).unwrap();
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
    db.unrelate_scoped(
        "docs",
        &edge_token::encode(db.graph_database_id(), ids[0]).unwrap(),
        true,
        &scope,
    )
    .unwrap();
    db.upsert("docs", vec![graph_point("trigger", 4.0, "acme")])
        .unwrap();

    let source = root.join("snapshot");
    let database_id = db.graph_database_id();
    db.snapshot(&source).unwrap();
    assert!(!source.join(GRAPH_IDENTITY_FILE).exists());
    let marker = snapshot::read_snapshot_marker(&source).unwrap().unwrap();
    assert_eq!(marker.version, 2);
    let marked = &marker.collections[0];
    assert_eq!(marked.collection, "docs");
    assert!(marked.graph.as_ref().unwrap().manifest_sha256.is_some());
    assert!(marker.collections[1].graph.is_none());
    let snap_dir = crate::db::collection_dir(&source, "docs");
    let pinned = GraphGeneration::open(&snap_dir).unwrap().unwrap();
    let graph = pinned.manifest.graph.as_ref().unwrap();
    assert_eq!(graph.version, 3);
    assert_eq!(graph.topology_deltas.len(), 2);
    assert!(marked.wal_lsn > graph.graph_batch_watermark);
    assert_eq!(
        pinned.edge_properties(last).unwrap().unwrap()["revision"],
        1
    );
    for run in &pinned.deltas {
        assert_eq!(
            fs::read(&run.path).unwrap().starts_with(encryption::MAGIC),
            mode == "encrypted"
        );
    }

    // A fork has the exact data cut but a different installation/token domain.
    let fork_root = root.join("fork");
    crate::db::copy_dir_contents(&source, &fork_root).unwrap();
    let fork = Db::open(&fork_root).unwrap();
    assert_ne!(fork.graph_database_id(), database_id);
    assert_state(&fork, last, 2, 4.0);
    assert!(fork.unrelate_scoped("docs", &token, true, &scope).is_err());
    fork.upsert("docs", vec![graph_point("trigger", 6.0, "acme")])
        .unwrap();
    drop(fork);
    let fork = Db::open(&fork_root).unwrap();
    assert_state(&fork, last, 2, 6.0);
    drop(fork);

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
    db.upsert("docs", vec![graph_point("trigger", 9.0, "acme")])
        .unwrap();
    let before_root = db.inner.read().root.clone();
    // Bad binding, duplicate membership, missing graph peers and a shortened
    // WAL must all fail before either restore install path changes the target.
    for case in [
        "digest",
        "epoch",
        "duplicate",
        "missing-delta",
        "missing-directory",
        "short-wal",
    ] {
        let bad = root.join(case);
        crate::db::copy_dir_contents(&source, &bad).unwrap();
        let mut changed = marker.clone();
        let bad_dir = crate::db::collection_dir(&bad, "docs");
        match case {
            "digest" => {
                changed.collections[0]
                    .graph
                    .as_mut()
                    .unwrap()
                    .manifest_sha256
                    .as_mut()
                    .unwrap()[0] ^= 1
            }
            "epoch" => {
                changed.collections[0].graph.as_mut().unwrap().epoch =
                    crate::graph::GraphEpoch::from_raw(3).unwrap()
            }
            "duplicate" => changed.collections[1] = changed.collections[0].clone(),
            "missing-delta" => fs::remove_file(
                artifact_path(
                    &bad_dir,
                    ArtifactFamily::Topology,
                    &graph.topology_deltas[1].id,
                )
                .unwrap(),
            )
            .unwrap(),
            "missing-directory" => {
                let checkpoint::FragmentDirectoryManifest::Present { base, .. } =
                    &graph.fragment_directory
                else {
                    panic!("expected bound directory")
                };
                fs::remove_file(
                    artifact_path(&bad_dir, ArtifactFamily::Fragments, &base.id).unwrap(),
                )
                .unwrap();
            }
            "short-wal" => {
                Wal::truncate_to_lsn(&bad_dir.join("wal"), graph.graph_batch_watermark).unwrap()
            }
            _ => unreachable!(),
        }
        snapshot::write_snapshot_marker(&bad, &changed).unwrap();
        assert!(Db::open(&bad).is_err(), "invalid first activation: {case}");
        assert!(!bad.join(GRAPH_IDENTITY_FILE).exists());
        assert!(db.restore(&bad).is_err(), "{case}");
        assert_eq!(db.inner.read().root, before_root);
        assert_eq!(db.graph_database_id(), database_id);
        assert_state(&db, last, 3, 9.0);
    }
    let epoch_before = db.graph_allocator_epoch();
    db.restore(&source).unwrap();
    assert_eq!(db.graph_database_id(), database_id);
    assert!(db.graph_allocator_epoch() > epoch_before);
    assert_state(&db, last, 2, 4.0);
    // The source checkpoint and pending session remain reusable, not consumed.
    assert_eq!(
        pinned.edge_properties(last).unwrap().unwrap()["revision"],
        1
    );
    db.upsert_deferred_scoped(
        "docs",
        &session.session_id,
        vec![graph_point("future", 5.0, "acme")],
        true,
        &scope,
    )
    .unwrap();
    db.commit_deferred_graph_session_scoped("docs", &session.session_id, true, &scope)
        .unwrap();
    db.update_edge_scoped(
        "docs",
        &pending.edge_id,
        UpdateEdgeRequest {
            mode: EdgePropertyMode::Merge,
            properties: json!({"restored":true}),
        },
        true,
        &scope,
    )
    .unwrap();

    // A disabled live tail may still select an older enabled manifest; bind
    // both independently, and recover the disable from the snapshot WAL.
    db.set_graph_lifecycle_scoped("docs", false, true, &scope)
        .unwrap();
    let disabled = root.join("disabled-snapshot");
    db.snapshot(&disabled).unwrap();
    let disabled_marker = snapshot::read_snapshot_marker(&disabled).unwrap().unwrap();
    let binding = disabled_marker.collections[0].graph.as_ref().unwrap();
    assert!(!binding.enabled);
    assert_eq!(binding.epoch.raw(), 2);
    db.set_graph_lifecycle_scoped("docs", true, true, &scope)
        .unwrap();
    db.restore(&disabled).unwrap();
    assert!(
        !db.get_coll("docs")
            .unwrap()
            .read()
            .graph_lifecycle
            .is_enabled()
    );
    drop(db);
    let reopened = Db::open(&data).unwrap();
    assert_eq!(reopened.graph_database_id(), database_id);
    assert!(
        !reopened
            .get_coll("docs")
            .unwrap()
            .read()
            .graph_lifecycle
            .is_enabled()
    );
    reopened.restore(&source).unwrap();
    assert_state(&reopened, last, 2, 4.0);

    // Copying a live pinned source with a missing peer must not publish a
    // successful snapshot, even though its in-memory pin still works.
    let current = reopened.inner.read().root.clone();
    let live_dir = crate::db::collection_dir(&current, "docs");
    let peer = artifact_path(
        &live_dir,
        ArtifactFamily::Topology,
        &graph.topology_deltas[0].id,
    )
    .unwrap();
    let saved = peer.with_extension("held-for-test");
    fs::rename(&peer, &saved).unwrap();
    let rejected = root.join("rejected-snapshot");
    let result = reopened.snapshot(&rejected);
    fs::rename(&saved, &peer).unwrap();
    assert!(result.is_err());
    assert!(!rejected.join(snapshot::SNAPSHOT_FILE).exists());
    assert_state(&reopened, last, 2, 4.0);
}

fn assert_state(db: &Db, last: crate::graph::EdgeId, revision: u64, vector: f32) {
    let scope = TenantScope::tenant("snapshot-reader", "acme");
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
                &scope,
            )
            .unwrap();
        assert!(result.truncation.is_none());
        assert_eq!(result.stats.visible_edges_examined, 4095);
        assert_eq!(result.nodes.len(), 1);
    }
    let coll = db.get_coll("docs").unwrap();
    assert_eq!(
        coll.read()
            .graph_mutable
            .as_ref()
            .unwrap()
            .edge_properties(last)
            .unwrap()
            .unwrap()["revision"],
        revision
    );
    assert_eq!(
        db.get_points("docs", &["trigger".into()]).unwrap()[0].vector,
        vec![vector, 0.0]
    );
    assert_eq!(db.count("vectors", None).unwrap().count, 1);
}

#[test]
fn legacy_graph_snapshot_retains_wal_authority_without_a_v2_binding() {
    let temp = TempDir::new().unwrap();
    let db = Db::open(temp.path().join("db")).unwrap();
    let scope = TenantScope::tenant("legacy-snapshot", "acme");
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
        crate::graph::ConfigureEdgeTypeRequest {
            name: "links".into(),
            weight_property: None,
        },
        true,
        &scope,
    )
    .unwrap();
    let edge = db
        .relate_scoped(
            "docs",
            RelateRequest {
                source_point_id: "a".into(),
                target_point_id: "b".into(),
                edge_type: "links".into(),
                properties: json!({}),
                scope: GraphRelationScope::Local,
                idempotency_key: None,
            },
            true,
            &scope,
        )
        .unwrap();
    let source = temp.path().join("legacy-snapshot");
    db.snapshot(&source).unwrap();
    let mut marker = snapshot::read_snapshot_marker(&source).unwrap().unwrap();
    assert_eq!(marker.version, 2);
    assert!(
        marker.collections[0]
            .graph
            .as_ref()
            .unwrap()
            .manifest_sha256
            .is_none()
    );
    // Reproduce the pre-D2a marker bytes; graph data remains in the old WAL.
    marker.version = 1;
    marker.collections[0].graph = None;
    snapshot::write_snapshot_marker(&source, &marker).unwrap();
    db.unrelate_scoped("docs", &edge.edge_id, true, &scope)
        .unwrap();
    db.restore(&source).unwrap();
    let id = edge_token::decode(db.graph_database_id(), &edge.edge_id).unwrap();
    assert!(
        db.get_coll("docs")
            .unwrap()
            .read()
            .graph_mutable
            .as_ref()
            .unwrap()
            .edge(id)
            .is_some()
    );
    db.unrelate_scoped("docs", &edge.edge_id, true, &scope)
        .unwrap();
}
