use super::*;

use base64::{Engine, engine::general_purpose::STANDARD};
use std::{env, fs, process::Command};

use crate::{
    graph::{ConfigureEdgeTypeRequest, GraphNamespace, GraphRelationScope, RelateRequest},
    tenant::TenantScope,
};

const MODE: &str = "CHIRONDB_GRAPH_COMPACTION_TEST_MODE";
const ROOT: &str = "CHIRONDB_GRAPH_COMPACTION_TEST_ROOT";
const TEST: &str =
    "db::tests::graph_compaction::graph_compaction_plan_freezes_degree_bfs_and_external_merge";

#[test]
fn graph_compaction_plan_freezes_degree_bfs_and_external_merge() {
    let Some(mode) = env::var_os(MODE) else {
        for mode in ["plaintext", "encrypted"] {
            let root = TempDir::new().unwrap();
            assert!(
                Command::new(env::current_exe().unwrap())
                    .args(["--exact", TEST, "--nocapture"])
                    .env(MODE, mode)
                    .env(ROOT, root.path())
                    .status()
                    .unwrap()
                    .success(),
                "{mode} graph compaction child failed"
            );
        }
        return;
    };
    let root = PathBuf::from(env::var_os(ROOT).unwrap());
    if mode == "encrypted" {
        let keyring = root.join("keyring.json");
        fs::write(
            &keyring,
            serde_json::json!({
                "version": 1,
                "active_key_id": "graph-compaction",
                "keys": [{
                    "id": "graph-compaction",
                    "key_base64": STANDARD.encode([83_u8; 32])
                }]
            })
            .to_string(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
        }
        crate::encryption::install_process_keyring(
            crate::encryption::Keyring::load(&keyring).unwrap(),
            true,
        )
        .unwrap();
    }

    {
        let db = Db::open(&root).unwrap();
        let scope = TenantScope::tenant("graph-compaction", "acme");
        let mut config = ls_vec_config("docs");
        config.streamer_max_bytes = usize::MAX;
        db.create_collection(config).unwrap();
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        db.upsert(
            "docs",
            ["hub", "a", "b", "c", "d", "retired"]
                .into_iter()
                .enumerate()
                .map(|(index, id)| graph_point(id, index as f32, "acme"))
                .collect(),
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
        let relate = |source: &str, target: &str| {
            db.relate_scoped(
                "docs",
                RelateRequest {
                    source_point_id: source.into(),
                    target_point_id: target.into(),
                    edge_type: "links".into(),
                    properties: serde_json::json!({"source":source,"target":target}),
                    scope: GraphRelationScope::Local,
                    idempotency_key: None,
                },
                true,
                &scope,
            )
            .unwrap()
            .edge_id
        };
        let retained = relate("hub", "a");
        relate("hub", "a"); // Multi-edge identity must survive the merge.
        let removed = relate("hub", "b");
        relate("hub", "c");
        relate("hub", "d");
        relate("c", "d");
        relate("hub", "retired");
        let seal = prepare_forced_graph_vector_seal(&db, &root, "docs");
        run_segment_seal(&seal).unwrap();

        // These mutations remain outside the selected generation. Capturing
        // under one collection read lock must include the new topology and
        // current visibility without mixing a later state into either pass.
        relate("a", "d");
        db.unrelate_scoped("docs", &removed, true, &scope).unwrap();
        assert_eq!(
            db.delete_with_edges_scoped("docs", &["retired".into()], &scope)
                .unwrap(),
            1
        );

        let mut plan = db.prepare_graph_compaction_plan("docs").unwrap().unwrap();
        assert_plan(&mut plan, mode == "encrypted");
        drop(plan);

        let response = db.compact_collection("docs").unwrap();
        assert_eq!(response.points, 5);
        assert_eq!(
            db.get_points("docs", &["hub".into(), "d".into()])
                .unwrap()
                .len(),
            2
        );
        let retained_id = crate::edge_token::decode(db.graph_database_id(), &retained).unwrap();
        let removed_id = crate::edge_token::decode(db.graph_database_id(), &removed).unwrap();
        {
            let coll = db.get_coll("docs").unwrap();
            let collection = coll.read();
            let mutable = collection.graph_mutable.as_ref().unwrap();
            assert!(mutable.contains_edge_id(retained_id).unwrap());
            assert!(!mutable.contains_edge_id(removed_id).unwrap());
            assert_eq!(
                mutable
                    .edge_properties(retained_id)
                    .unwrap()
                    .unwrap()
                    .as_object()
                    .unwrap()["source"],
                "hub"
            );
        }
        let manifest = crate::checkpoint::read_segments_manifest(&root.join("collections/docs"))
            .unwrap()
            .unwrap();
        assert_eq!(
            manifest.segments.as_slice(),
            std::slice::from_ref(&response.segment_id)
        );
        let graph = manifest.graph.as_ref().unwrap();
        assert_eq!(graph.base_segments, manifest.segments);
        assert!(graph.topology_deltas.is_empty());
        assert!(graph.edge_ledger.runs.is_empty());
        assert!(graph.edge_properties.runs.is_empty());
        assert!(matches!(
            graph.fragment_directory,
            crate::checkpoint::FragmentDirectoryManifest::Present {
                ref overlays,
                ..
            } if overlays.is_empty()
        ));
        let stats = db.graph_maintenance_stats("docs").unwrap().unwrap();
        assert_eq!(stats.physical_edge_records, 6);
        assert_eq!(stats.reclaimable_edge_records, 0);
        assert_eq!(stats.p95_fragments_per_node, 1);
        assert_eq!(stats.max_fragments_per_node, 1);

        let mut compacted = db.prepare_graph_compaction_plan("docs").unwrap().unwrap();
        assert_compacted_plan(&mut compacted, mode == "encrypted");
    }

    let db = Db::open(&root).unwrap();
    let manifest = crate::checkpoint::read_segments_manifest(&root.join("collections/docs"))
        .unwrap()
        .unwrap();
    assert_eq!(manifest.segments.len(), 1);
    let mut reopened = db.prepare_graph_compaction_plan("docs").unwrap().unwrap();
    assert_compacted_plan(&mut reopened, mode == "encrypted");
}

fn assert_compacted_plan(
    plan: &mut crate::graph_generation::compaction::GraphCompactionPlan,
    encrypted: bool,
) {
    assert_eq!(plan.resolver.live_len(), 5);
    assert_eq!(plan.source_edge_records, 6);
    assert_eq!(plan.live_edge_records, 6);
    assert_eq!(plan.dropped_edge_records, 0);
    assert_eq!(plan.nodes.len(), 5);
    assert_eq!(plan.scratch_is_encrypted().unwrap(), encrypted);
    let mut edges = 0;
    plan.visit_edges(|_, _| {
        edges += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(edges, 6);
}

fn assert_plan(
    plan: &mut crate::graph_generation::compaction::GraphCompactionPlan,
    encrypted: bool,
) {
    assert_eq!(plan.graph_epoch.raw(), 1);
    assert!(plan.graph_batch_watermark > 0);
    assert_eq!(
        plan.source_generation.manifest.generation,
        plan.overlay.generation()
    );
    assert_eq!(plan.resolver.live_len(), plan.nodes.len());
    assert!(plan.mutable.is_some());
    assert_eq!(plan.source_edge_records, 8);
    assert_eq!(plan.live_edge_records, 6);
    assert_eq!(plan.dropped_edge_records, 2);
    assert_eq!(plan.namespaces(), &[GraphNamespace::Tenant("acme".into())]);
    assert!(plan.incident_sort.buffer_capacity_bytes <= 1024 * 1024);
    assert!(plan.edge_sort.buffer_capacity_bytes <= 1024 * 1024);
    assert_eq!(plan.scratch_is_encrypted().unwrap(), encrypted);

    let order = plan
        .nodes
        .iter()
        .map(|node| node.point_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(order, ["hub", "d", "a", "c", "b"]);
    for node in &plan.nodes {
        assert_eq!(plan.location_map.lookup(node.nid), Some(node.ordinal));
    }

    let point_by_nid = plan
        .nodes
        .iter()
        .map(|node| (node.nid, node.point_id.clone()))
        .collect::<HashMap<_, _>>();
    let location_map = plan.location_map.clone();
    let mut edges = Vec::new();
    plan.visit_edges(|namespace, edge| {
        assert_eq!(namespace, &GraphNamespace::Tenant("acme".into()));
        assert_eq!(
            location_map.lookup(edge.source_nid),
            Some(edge.source_ordinal)
        );
        assert_eq!(
            location_map.lookup(edge.target_nid),
            Some(edge.target_ordinal)
        );
        edges.push((
            point_by_nid[&edge.source_nid].clone(),
            point_by_nid[&edge.target_nid].clone(),
        ));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        edges,
        [
            ("hub".into(), "d".into()),
            ("hub".into(), "a".into()),
            ("hub".into(), "a".into()),
            ("hub".into(), "c".into()),
            ("a".into(), "d".into()),
            ("c".into(), "d".into()),
        ]
    );
}

#[cfg(feature = "fault-injection")]
#[test]
fn graph_compaction_keeps_post_cut_wal_and_topology_tail() {
    const CHILD: &str = "CHIRONDB_GRAPH_COMPACTION_TAIL_CHILD";
    const TEST: &str =
        "db::tests::graph_compaction::graph_compaction_keeps_post_cut_wal_and_topology_tail";
    let Some(root) = env::var_os(CHILD) else {
        let root = TempDir::new().unwrap();
        assert!(
            Command::new(env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env(CHILD, root.path())
                .status()
                .unwrap()
                .success(),
            "graph compaction tail child failed"
        );
        return;
    };
    let root = PathBuf::from(root);
    let db = Db::open(&root).unwrap();
    let scope = TenantScope::tenant("graph-compaction", "acme");
    let mut config = ls_vec_config("docs");
    config.streamer_max_bytes = usize::MAX;
    db.create_collection(config).unwrap();
    db.set_graph_lifecycle_scoped("docs", true, true, &scope)
        .unwrap();
    db.upsert(
        "docs",
        ["a", "b", "c"]
            .into_iter()
            .enumerate()
            .map(|(index, id)| graph_point(id, index as f32, "acme"))
            .collect(),
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
    let relate = |db: &Db, source: &str, target: &str| {
        db.relate_scoped(
            "docs",
            RelateRequest {
                source_point_id: source.into(),
                target_point_id: target.into(),
                edge_type: "links".into(),
                properties: serde_json::json!({"source":source,"target":target}),
                scope: GraphRelationScope::Local,
                idempotency_key: None,
            },
            true,
            &scope,
        )
        .unwrap()
    };
    relate(&db, "a", "b");
    let seal = prepare_forced_graph_vector_seal(&db, &root, "docs");
    run_segment_seal(&seal).unwrap();
    drop(seal);

    let marker = root.join("compaction-paused");
    let release = root.join("compaction-release");
    let _failpoint_guard =
        crate::failpoint::test_env("pause:graph_compaction.after_stage", &marker, &release);
    let compact_db = db.clone();
    let compact = std::thread::spawn(move || compact_db.compact_collection("docs"));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !marker.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "compaction did not reach its frozen-cut pause"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    relate(&db, "b", "c");
    fs::write(&release, b"release").unwrap();
    compact.join().unwrap().unwrap();
    let live = db.prepare_graph_compaction_plan("docs").unwrap().unwrap();
    assert_eq!(live.source_edge_records, 2);
    assert_eq!(live.live_edge_records, 2);
    drop(live);
    drop(db);
    let db = Db::open(&root).unwrap();
    let mut reopened = db.prepare_graph_compaction_plan("docs").unwrap().unwrap();
    assert_eq!(reopened.source_edge_records, 2);
    assert_eq!(reopened.live_edge_records, 2);
    let mut edges = 0;
    reopened
        .visit_edges(|_, _| {
            edges += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(edges, 2);
}

#[test]
fn graph_compaction_reclaims_dropped_epoch_and_retains_point_handles() {
    let root = TempDir::new().unwrap();
    {
        let db = Db::open(root.path()).unwrap();
        let scope = TenantScope::tenant("graph-compaction", "acme");
        let mut config = ls_vec_config("docs");
        config.streamer_max_bytes = usize::MAX;
        db.create_collection(config).unwrap();
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        db.upsert(
            "docs",
            vec![graph_point("a", 0.0, "acme"), graph_point("b", 1.0, "acme")],
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
        db.relate_scoped(
            "docs",
            RelateRequest {
                source_point_id: "a".into(),
                target_point_id: "b".into(),
                edge_type: "links".into(),
                properties: serde_json::json!({}),
                scope: GraphRelationScope::Local,
                idempotency_key: None,
            },
            true,
            &scope,
        )
        .unwrap();
        let seal = prepare_forced_graph_vector_seal(&db, root.path(), "docs");
        run_segment_seal(&seal).unwrap();
        drop(seal);
        db.set_graph_lifecycle_scoped("docs", false, true, &scope)
            .unwrap();

        let response = db.compact_collection("docs").unwrap();
        assert_eq!(response.points, 2);
        let mut plan = db.prepare_graph_compaction_plan("docs").unwrap().unwrap();
        assert_eq!(plan.graph_epoch.raw(), 2);
        assert_eq!(plan.nodes.len(), 2);
        assert_eq!(plan.source_edge_records, 0);
        assert_eq!(plan.live_edge_records, 0);
        assert!(plan.mutable.is_none());
        assert_eq!(
            db.get_points("docs", &["a".into(), "b".into()])
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            plan.nodes
                .iter()
                .map(|node| node.point_id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        plan.visit_edges(|_, _| panic!("dropped epoch topology survived"))
            .unwrap();
    }
    let db = Db::open(root.path()).unwrap();
    let plan = db.prepare_graph_compaction_plan("docs").unwrap().unwrap();
    assert_eq!(plan.graph_epoch.raw(), 2);
    assert_eq!(plan.nodes.len(), 2);
    assert_eq!(plan.source_edge_records, 0);
    let collection = db.get_coll("docs").unwrap();
    assert!(!collection.read().graph_lifecycle.is_enabled());
}
