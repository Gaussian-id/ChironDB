//! A real production seal, including a single WAL batch wider than a delta row.

use super::*;
use crate::{
    edge_token, encryption,
    graph::{
        ConfigureEdgeTypeRequest, EdgeMutation, EdgePropertyMode, GRAPH_ALLOCATOR_MAX_EPOCH,
        GraphDirection, GraphNamespace, GraphTraverseRequest, MAX_GRAPH_EDGES_PER_BATCH, Nid,
        RelateMutation, TraversalBudget, TypeId, UpdateEdgeRequest,
    },
    graph_generation::GraphGeneration,
    tenant::TenantScope,
    wal::GraphHandleAssignment,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{env, num::NonZeroU64, process::Command};

const MODE: &str = "CHIRONDB_PARTITIONED_DELTA_TEST_MODE";
const ROOT: &str = "CHIRONDB_PARTITIONED_DELTA_TEST_ROOT";
const STAGE: &str = "CHIRONDB_PARTITIONED_DELTA_TEST_STAGE";
const TEST: &str =
    "db::tests::partitioned_delta::production_split_batch_seal_plaintext_and_encrypted";

#[test]
fn production_split_batch_seal_plaintext_and_encrypted() {
    let Some(mode) = env::var_os(MODE) else {
        let cases: &[&str] = if cfg!(feature = "fault-injection") {
            &["normal", "before_manifest", "after_install"]
        } else {
            &["normal"]
        };
        for mode in ["plaintext", "encrypted"] {
            for case in cases {
                let temp = TempDir::new().unwrap();
                // Bootstrap in a separate process so failpoint configuration
                // is immutable, and affects only the second, split seal.
                for stage in ["bootstrap", *case] {
                    let mut command = Command::new(env::current_exe().unwrap());
                    command
                        .args(["--exact", TEST, "--nocapture"])
                        .env(MODE, mode)
                        .env(ROOT, temp.path())
                        .env(STAGE, stage)
                        .env_remove("CHIRONDB_FAILPOINT");
                    if !matches!(stage, "bootstrap" | "normal") {
                        command.env(
                            "CHIRONDB_FAILPOINT",
                            format!("error:graph_generation.{stage}"),
                        );
                    }
                    assert!(command.status().unwrap().success(), "{mode}/{stage}");
                }
            }
        }
        return;
    };
    let root = PathBuf::from(env::var_os(ROOT).unwrap());
    if mode == "encrypted" {
        let keyring = root.join("keyring.json");
        if !keyring.exists() {
            fs::write(
                &keyring,
                json!({"version":1,"active_key_id":"split","keys":[
                    {"id":"split","key_base64":STANDARD.encode([95;32])}
                ]})
                .to_string(),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        encryption::install_process_keyring(encryption::Keyring::load(&keyring).unwrap(), true)
            .unwrap();
    }
    let data = root.join("db");
    let dir = crate::db::collection_dir(&data, "docs");
    let stage = env::var(STAGE).unwrap();
    let scope = TenantScope::tenant("split-writer", "acme");
    let db = Db::open(&data).unwrap();
    if stage == "bootstrap" {
        bootstrap(&db, &data, &scope);
        return;
    }
    let old = GraphGeneration::open(&dir).unwrap().unwrap();
    let old_manifest_bytes = fs::read(dir.join(checkpoint::SEGMENTS_MANIFEST_FILE)).unwrap();
    let first_cut = old.manifest.graph.as_ref().unwrap().graph_batch_watermark;
    assert_eq!(old.manifest.graph.as_ref().unwrap().version, 2);
    let edge_ids: Vec<_> = db
        .graph_identity
        .allocate_edge_ids(NonZeroU64::new(MAX_GRAPH_EDGES_PER_BATCH as u64).unwrap())
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
    // High-epoch imported identities require the widest canonical varints.
    // All 4096 edges are legal in ONE GraphBatch, but exceed one row's bytes.
    db.commit_graph_batch_scoped(
        "docs",
        GraphBatch {
            edge_mutations: edge_ids
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
    db.upsert("docs", vec![graph_point("trigger", 3.0, "acme")])
        .unwrap();
    let seal = prepare_forced_graph_vector_seal(&db, &data, "docs");
    let second_cut = seal.end_lsn;
    let last = *edge_ids.last().unwrap();
    db.update_edge_scoped(
        "docs",
        &edge_token::encode(db.graph_database_id(), last).unwrap(),
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
        &edge_token::encode(db.graph_database_id(), edge_ids[0]).unwrap(),
        true,
        &scope,
    )
    .unwrap();
    let result = run_segment_seal(&seal);
    if stage != "normal" {
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("injected failpoint")
        );
        if stage == "before_manifest" {
            assert!(!crate::db::seal_generation_is_published(&seal));
            assert_eq!(
                fs::read(dir.join(checkpoint::SEGMENTS_MANIFEST_FILE)).unwrap(),
                old_manifest_bytes
            );
            crate::db::cleanup_unpublished_seal(&seal);
            crate::db::restore_failed_seal(seal.coll, seal.frozen);
            drop(seal.data_dir_lock);
        } else {
            assert!(crate::db::seal_generation_is_published(&seal));
            assert_eq!(seal.coll.read().wal_watermark, second_cut);
            assert_eq!(
                checkpoint::read_segments_manifest(&dir)
                    .unwrap()
                    .unwrap()
                    .graph
                    .unwrap()
                    .version,
                3
            );
            drop(seal);
        }
        drop(db);
        let reopened = Db::open(&data).unwrap();
        assert_live(&reopened, last);
        return;
    }
    result.unwrap();
    drop(seal);
    assert_live(&db, last);
    let pinned = GraphGeneration::open(&dir).unwrap().unwrap();
    let graph = pinned.manifest.graph.as_ref().unwrap();
    assert_eq!(graph.version, 3);
    assert_eq!(graph.topology_deltas.len(), 2);
    assert_eq!(graph.edge_ledger.runs.len(), 1);
    assert_eq!(graph.edge_properties.runs.len(), 1);
    assert_eq!(
        pinned
            .deltas
            .iter()
            .map(|run| run.reader.edge_count())
            .sum::<u64>(),
        4096
    );
    assert!(
        graph
            .topology_deltas
            .windows(2)
            .all(|pair| pair[0].id < pair[1].id)
    );
    for descriptor in &graph.topology_deltas {
        assert_eq!(
            (descriptor.first_lsn, descriptor.last_lsn),
            (first_cut, second_cut - 1)
        );
    }
    for run in &pinned.deltas {
        assert_eq!(
            fs::read(&run.path).unwrap().starts_with(encryption::MAGIC),
            mode == "encrypted"
        );
    }
    assert_eq!(
        pinned.edge_properties(last).unwrap().unwrap()["revision"],
        1
    );
    assert!(old.deltas.is_empty(), "old generation pin is immutable");
    // Both an explicit missing binding and an absent-directory fallback must
    // reject a partial cohort; recovery authority still names all identities.
    let mut partial = (*pinned.manifest).clone();
    partial.graph.as_mut().unwrap().topology_deltas.pop();
    assert!(GraphGeneration::load_candidate(&dir, partial.clone()).is_err());
    partial.graph.as_mut().unwrap().fragment_catalog = None;
    partial.graph.as_mut().unwrap().fragment_directory =
        checkpoint::FragmentDirectoryManifest::Absent;
    assert!(GraphGeneration::load_candidate(&dir, partial).is_err());

    // A property-only subsequent cut must retain v3 and stable source IDs,
    // without replaying topology or ledger keys already acknowledged.
    db.upsert("docs", vec![graph_point("trigger", 4.0, "acme")])
        .unwrap();
    let next = prepare_forced_graph_vector_seal(&db, &data, "docs");
    run_segment_seal(&next).unwrap();
    drop(next);
    let next_manifest = checkpoint::read_segments_manifest(&dir).unwrap().unwrap();
    let next_graph = next_manifest.graph.as_ref().unwrap();
    assert_eq!(next_graph.version, 3);
    assert_eq!(next_graph.topology_deltas, graph.topology_deltas);
    assert_eq!(next_graph.edge_ledger, graph.edge_ledger);
    assert_eq!(next_graph.edge_properties.runs.len(), 2);
    let bindings = &next_graph.fragment_catalog.as_ref().unwrap().bindings;
    for binding in &graph.fragment_catalog.as_ref().unwrap().bindings {
        assert!(bindings.contains(binding));
    }
    assert_eq!(
        pinned.edge_properties(last).unwrap().unwrap()["revision"],
        1
    );
    drop(db);
    let reopened = Db::open(&data).unwrap();
    assert_live(&reopened, last);
    let coll = reopened.get_coll("docs").unwrap();
    assert_eq!(
        coll.read()
            .graph_mutable
            .as_ref()
            .unwrap()
            .unsealed_topology_rows(),
        0
    );
    assert_eq!(
        coll.read()
            .graph_mutable
            .as_ref()
            .unwrap()
            .unsealed_ledger_keys(),
        0
    );
    assert_eq!(
        coll.read()
            .graph_mutable
            .as_ref()
            .unwrap()
            .unsealed_property_documents(),
        0
    );
    // Manifest versions cannot regress through disabled/re-enabled epochs.
    for enabled in [false, true] {
        reopened
            .set_graph_lifecycle_scoped("docs", enabled, true, &scope)
            .unwrap();
        reopened
            .upsert("docs", vec![graph_point("trigger", 5.0, "acme")])
            .unwrap();
        let seal = prepare_forced_graph_vector_seal(&reopened, &data, "docs");
        run_segment_seal(&seal).unwrap();
        assert_eq!(
            checkpoint::read_segments_manifest(&dir)
                .unwrap()
                .unwrap()
                .graph
                .unwrap()
                .version,
            3
        );
        assert!(GraphGeneration::open(&dir).unwrap().is_some());
    }
}

pub(super) fn bootstrap(db: &Db, data: &Path, scope: &TenantScope) {
    let mut config = ls_vec_config("docs");
    config.streamer_max_bytes = usize::MAX;
    db.create_collection(config).unwrap();
    db.set_graph_lifecycle_scoped("docs", true, true, scope)
        .unwrap();
    let points = [
        graph_point("a", 1.0, "acme"),
        graph_point("b", 2.0, "acme"),
        graph_point("other", 0.0, "globex"),
    ];
    db.commit_graph_batch_scoped(
        "docs",
        GraphBatch {
            point_mutations: points
                .iter()
                .cloned()
                .map(|point| GraphPointMutation::Upsert { point })
                .collect(),
            handle_assignments: points
                .iter()
                .enumerate()
                .map(|(index, point)| GraphHandleAssignment {
                    point_id: point.id.clone(),
                    nid: Nid::from_parts(GRAPH_ALLOCATOR_MAX_EPOCH, index as u64 + 1).unwrap(),
                })
                .collect(),
            ..GraphBatch::default()
        },
        true,
        scope,
    )
    .unwrap();
    db.configure_edge_type_scoped(
        "docs",
        ConfigureEdgeTypeRequest {
            name: "links".into(),
            weight_property: None,
        },
        true,
        scope,
    )
    .unwrap();
    let seal = prepare_forced_graph_vector_seal(db, data, "docs");
    run_segment_seal(&seal).unwrap();
}

fn assert_live(db: &Db, last: crate::graph::EdgeId) {
    for (anchor, direction, tenant, expected) in [
        ("a", GraphDirection::Outgoing, "acme", 4095),
        ("b", GraphDirection::Incoming, "acme", 4095),
        ("other", GraphDirection::Outgoing, "globex", 0),
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
                &TenantScope::tenant("split-reader", tenant),
            )
            .unwrap();
        assert_eq!(result.stats.visible_edges_examined, expected);
        // Public traversal returns reached nodes, excluding depth-zero anchors.
        if expected == 0 {
            assert!(result.nodes.is_empty());
        } else {
            assert_eq!(result.nodes.len(), 1);
            assert_eq!(
                result.nodes[0].point_id,
                if anchor == "a" { "b" } else { "a" }
            );
            assert_eq!(result.nodes[0].depth, 1);
        }
        assert!(result.truncation.is_none());
    }
    let coll = db.get_coll("docs").unwrap();
    let state = coll.read();
    assert_eq!(
        state
            .graph_mutable
            .as_ref()
            .unwrap()
            .edge_properties(last)
            .unwrap()
            .unwrap()["revision"],
        2
    );
}
