//! Local archive-backed graph restore, including graph first enabled after snapshot.

use super::*;
use crate::{
    db::collection_dir,
    edge_token, encryption,
    graph::{
        ConfigureEdgeTypeRequest, EdgePropertyMode, GraphRelationScope, RelateRequest,
        UpdateEdgeRequest,
    },
    tenant::TenantScope,
    wal_archive::{mirror_wal_archive, mirror_wal_archive_to_object_store},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{env, process::Command};

#[test]
fn graph_archives_extend_exact_snapshot_history_in_both_layouts_and_encryption_modes() {
    const MODE: &str = "CHIRONDB_GRAPH_ARCHIVE_MODE";
    const ROOT: &str = "CHIRONDB_GRAPH_ARCHIVE_ROOT";
    const LAYOUT: &str = "CHIRONDB_GRAPH_ARCHIVE_LAYOUT";
    const TEST: &str = "db::tests::graph_archive::graph_archives_extend_exact_snapshot_history_in_both_layouts_and_encryption_modes";
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
            json!({"version":1,"active_key_id":"archive","keys":[
                {"id":"archive","key_base64":STANDARD.encode([99;32])}
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
        rejects_plaintext_archive_without_offset_reencoding(&root);
    }
    for graph_at_snapshot in [true, false] {
        exercise(
            &root.join(if graph_at_snapshot { "graph" } else { "vector" }),
            env::var(LAYOUT).unwrap() == "generation",
            graph_at_snapshot,
        );
    }
}

#[test]
fn graph_seal_captures_cut_before_retirement_in_both_layouts_and_encryption_modes() {
    const MODE: &str = "CHIRONDB_GRAPH_SEAL_ARCHIVE_MODE";
    const ROOT: &str = "CHIRONDB_GRAPH_SEAL_ARCHIVE_ROOT";
    const LAYOUT: &str = "CHIRONDB_GRAPH_SEAL_ARCHIVE_LAYOUT";
    const TEST: &str = "db::tests::graph_archive::graph_seal_captures_cut_before_retirement_in_both_layouts_and_encryption_modes";
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
            json!({"version":1,"active_key_id":"seal-archive","keys":[
                {"id":"seal-archive","key_base64":STANDARD.encode([101;32])}
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
    let generation_layout = env::var(LAYOUT).unwrap() == "generation";
    exercise_graph_seal_archive_pipeline(&root.join("success"), generation_layout);
    exercise_graph_seal_mirror_failure(&root.join("mirror-failure"), generation_layout);
}

fn exercise_graph_seal_archive_pipeline(root: &Path, generation_layout: bool) {
    let data = root.join("db");
    if generation_layout {
        crate::storage_layout::initialize_empty(&data).unwrap();
    }
    let db = Db::open(&data).unwrap();
    let scope = TenantScope::tenant("seal-archive-writer", "acme");
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
    let token = relate(&db, &scope);
    let edge_id = edge_token::decode(db.graph_database_id(), &token).unwrap();
    let source = root.join("snapshot");
    db.snapshot(&source).unwrap();

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
    db.upsert("docs", vec![graph_point("a", 4.0, "acme")])
        .unwrap();
    let expected_at_cut = super::graph_pitr::state(&db, edge_id);
    let external = root.join("external");
    let objects = root.join("objects");
    db.set_wal_external_archive_dir(Some(external.clone()));
    db.set_wal_object_store_dir(Some(objects.clone()));
    db.set_wal_archive_retain_last(Some(0));
    #[cfg(unix)]
    let command_marker = {
        let marker = root.join("archive-command-ran");
        db.set_wal_archive_command(Some(format!(
            "printf '%s' \"$CHIRONDB_WAL_ARCHIVE_COLLECTION\" > \"{}\"",
            marker.display()
        )));
        marker
    };

    let active = db.inner.read().root.clone();
    let seal = prepare_forced_graph_vector_seal(&db, &active, "docs");
    let cut = seal.end_lsn;
    let later_external = root.join("must-not-use-after-cut");
    db.set_wal_external_archive_dir(Some(later_external.clone()));
    db.set_wal_object_store_dir(None);
    db.set_wal_archive_retain_last(None);
    #[cfg(unix)]
    db.set_wal_archive_command(None);
    assert_eq!(db.get_coll("docs").unwrap().read().wal.len().unwrap(), cut);
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
    let tip = db.get_coll("docs").unwrap().read().wal.len().unwrap();
    assert!(tip > cut);
    assert_ne!(super::graph_pitr::state(&db, edge_id), expected_at_cut);

    run_segment_seal(&seal).unwrap();
    assert_eq!(
        Wal::retained_base_lsn(&collection_dir(&active, "docs").join("wal")).unwrap(),
        cut
    );
    assert_eq!(
        fs::read_dir(collection_dir(&active, "docs").join("wal/archive"))
            .unwrap()
            .count(),
        0,
        "retention runs only after configured mirrors and prefix retirement"
    );
    #[cfg(unix)]
    assert_eq!(fs::read_to_string(command_marker).unwrap(), "docs");
    assert!(!later_external.exists());
    drop(seal);

    db.restore_to_wal_targets_with_archive_sources(
        &source,
        &HashMap::from([("docs".into(), cut)]),
        &HashMap::new(),
        Some(&external),
        None,
    )
    .unwrap();
    assert_eq!(super::graph_pitr::state(&db, edge_id), expected_at_cut);
    assert_eq!(db.get_coll("docs").unwrap().read().wal.len().unwrap(), cut);

    db.restore_to_wal_targets_with_archive_sources(
        &source,
        &HashMap::from([("docs".into(), cut)]),
        &HashMap::new(),
        None,
        Some(&ColdObjectStoreConfig::LocalDir(objects)),
    )
    .unwrap();
    assert_eq!(super::graph_pitr::state(&db, edge_id), expected_at_cut);
    drop(db);
    let reopened = Db::open(&data).unwrap();
    assert_eq!(
        super::graph_pitr::state(&reopened, edge_id),
        expected_at_cut
    );
}

fn exercise_graph_seal_mirror_failure(root: &Path, generation_layout: bool) {
    let data = root.join("db");
    if generation_layout {
        crate::storage_layout::initialize_empty(&data).unwrap();
    }
    let db = Db::open(&data).unwrap();
    let scope = TenantScope::tenant("seal-archive-writer", "acme");
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
    relate(&db, &scope);
    let invalid_external = root.join("not-a-directory");
    fs::create_dir_all(root).unwrap();
    fs::write(&invalid_external, b"file").unwrap();
    db.set_wal_external_archive_dir(Some(invalid_external));
    let active = db.inner.read().root.clone();
    let seal = prepare_forced_graph_vector_seal(&db, &active, "docs");
    let cut = seal.end_lsn;
    db.upsert("docs", vec![graph_point("tail", 3.0, "acme")])
        .unwrap();
    let tip = db.get_coll("docs").unwrap().read().wal.len().unwrap();

    assert!(run_segment_seal(&seal).is_err());
    assert!(!super::super::seal_generation_is_published(&seal));
    let wal_dir = collection_dir(&active, "docs").join("wal");
    assert_eq!(Wal::retained_base_lsn(&wal_dir).unwrap(), 0);
    assert_eq!(db.get_coll("docs").unwrap().read().wal.len().unwrap(), tip);
    let local_archives = fs::read_dir(wal_dir.join("archive"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    assert_eq!(local_archives.len(), 1);
    assert_eq!(
        Wal::scan_from(&local_archives[0], 0, |_| Ok(()))
            .unwrap()
            .end_lsn,
        cut
    );

    super::super::cleanup_unpublished_seal(&seal);
    restore_failed_seal(Arc::clone(&seal.coll), Arc::clone(&seal.frozen));
    drop(seal);
    let external = root.join("retry-external");
    db.set_wal_external_archive_dir(Some(external.clone()));
    let retry = prepare_forced_graph_vector_seal(&db, &active, "docs");
    assert_eq!(retry.end_lsn, tip);
    run_segment_seal(&retry).unwrap();
    assert_eq!(Wal::retained_base_lsn(&wal_dir).unwrap(), tip);
    assert!(external.join("collections/docs").is_dir());
}

#[test]
fn graph_seal_local_archive_failure_is_retryable_without_prefix_loss() {
    let temp = TempDir::new().unwrap();
    let db = Db::open(temp.path()).unwrap();
    let scope = TenantScope::tenant("seal-archive-writer", "acme");
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
    relate(&db, &scope);
    let seal = prepare_forced_graph_vector_seal(&db, temp.path(), "docs");
    let cut = seal.end_lsn;
    let wal_dir = collection_dir(temp.path(), "docs").join("wal");
    let archive_root = wal_dir.join("archive");
    fs::write(&archive_root, b"blocks directory creation").unwrap();

    assert!(run_segment_seal(&seal).is_err());
    assert!(!super::super::seal_generation_is_published(&seal));
    assert_eq!(Wal::retained_base_lsn(&wal_dir).unwrap(), 0);
    super::super::cleanup_unpublished_seal(&seal);
    restore_failed_seal(Arc::clone(&seal.coll), Arc::clone(&seal.frozen));
    drop(seal);
    fs::remove_file(&archive_root).unwrap();

    let retry = prepare_forced_graph_vector_seal(&db, temp.path(), "docs");
    assert_eq!(retry.end_lsn, cut);
    run_segment_seal(&retry).unwrap();
    assert_eq!(Wal::retained_base_lsn(&wal_dir).unwrap(), cut);
}

#[cfg(unix)]
#[test]
fn graph_seal_archive_command_failure_keeps_local_archive_and_live_prefix() {
    let temp = TempDir::new().unwrap();
    let db = Db::open(temp.path()).unwrap();
    let scope = TenantScope::tenant("seal-archive-writer", "acme");
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
    relate(&db, &scope);
    db.set_wal_archive_retain_last(Some(0));
    db.set_wal_archive_command(Some("echo graph archive failed >&2; exit 7".into()));
    let seal = prepare_forced_graph_vector_seal(&db, temp.path(), "docs");
    let cut = seal.end_lsn;
    let wal_dir = collection_dir(temp.path(), "docs").join("wal");

    let error = run_segment_seal(&seal).unwrap_err();
    assert!(error.to_string().contains("status 7"), "{error}");
    assert!(!super::super::seal_generation_is_published(&seal));
    assert_eq!(Wal::retained_base_lsn(&wal_dir).unwrap(), 0);
    assert_eq!(
        fs::read_dir(wal_dir.join("archive"))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().is_dir())
            .count(),
        1,
        "retention must not prune the recovery archive after command failure"
    );
    let archive = fs::read_dir(wal_dir.join("archive"))
        .unwrap()
        .find_map(|entry| {
            let path = entry.ok()?.path();
            path.is_dir().then_some(path)
        })
        .unwrap();
    assert_eq!(
        Wal::scan_from(&archive, 0, |_| Ok(())).unwrap().end_lsn,
        cut
    );
}

fn exercise(root: &Path, generation_layout: bool, graph_at_snapshot: bool) {
    let data = root.join("db");
    if generation_layout {
        crate::storage_layout::initialize_empty(&data).unwrap();
    }
    let mut db = Db::open(&data).unwrap();
    let scope = TenantScope::tenant("archive-writer", "acme");
    let mut config = ls_vec_config("docs");
    config.streamer_max_bytes = usize::MAX;
    db.create_collection(config).unwrap();
    if graph_at_snapshot {
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
    }
    db.upsert(
        "docs",
        vec![graph_point("a", 1.0, "acme"), graph_point("b", 2.0, "acme")],
    )
    .unwrap();
    let mut token = None;
    if graph_at_snapshot {
        token = Some(relate(&db, &scope));
    }
    let active = db.inner.read().root.clone();
    let seal = prepare_forced_graph_vector_seal(&db, &active, "docs");
    run_segment_seal(&seal).unwrap();
    drop(seal);
    let wal_dir = collection_dir(&active, "docs").join("wal");
    assert!(Wal::retained_base_lsn(&wal_dir).unwrap() > 0);
    // This snapshot tail overlaps the later archive; replay must not duplicate it.
    db.upsert("docs", vec![graph_point("trigger", 3.0, "acme")])
        .unwrap();
    let source = root.join("snapshot");
    db.snapshot(&source).unwrap();
    let marker = snapshot::read_snapshot_marker(&source).unwrap().unwrap();
    let source_wal =
        serde_json::to_value(Wal::load(&collection_dir(&source, "docs").join("wal")).unwrap())
            .unwrap();
    assert_eq!(marker.collections[0].graph.is_some(), graph_at_snapshot);
    if !graph_at_snapshot {
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        wait_for_graph_backfill(&db, "docs");
        token = Some(relate(&db, &scope));
    }
    let token = token.unwrap();
    let id = edge_token::decode(db.graph_database_id(), &token).unwrap();
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
    db.upsert("docs", vec![graph_point("a", 4.0, "acme")])
        .unwrap();
    let target_lsn = db.get_coll("docs").unwrap().read().wal.len().unwrap();
    let target_time = Wal::load(&wal_dir).unwrap().last().unwrap().unix_ms;
    let target_state = super::graph_pitr::state(&db, id);
    assert!(target_lsn > marker.collections[0].wal_lsn);
    thread::sleep(Duration::from_millis(3));
    db.delete_with_edges_scoped("docs", &["b".into()], &scope)
        .unwrap();
    db.upsert("docs", vec![graph_point("b", 9.0, "acme")])
        .unwrap();
    db.set_graph_lifecycle_scoped("docs", false, true, &scope)
        .unwrap();
    let tip_state = super::graph_pitr::state(&db, id);
    let original_records = Wal::load(&wal_dir).unwrap();
    let tip_lsn = db.get_coll("docs").unwrap().read().wal.len().unwrap();
    let archive = db
        .get_coll("docs")
        .unwrap()
        .read()
        .wal
        .archive_current(&root.join("captured"))
        .unwrap()
        .unwrap();
    assert_eq!(
        db.get_coll("docs").unwrap().read().wal.len().unwrap(),
        tip_lsn
    );
    let external = root.join("external");
    let objects = ColdObjectStoreConfig::LocalDir(root.join("objects"));
    mirror_wal_archive(&external, "docs", &archive).unwrap();
    mirror_wal_archive_to_object_store(&objects, "docs", &archive).unwrap();
    let database_id = db.graph_database_id();
    for case in ["lsn", "time", "both-tip"] {
        let lsns = if case == "lsn" {
            HashMap::from([("docs".into(), target_lsn)])
        } else {
            HashMap::new()
        };
        let times = if case == "time" {
            HashMap::from([("docs".into(), target_time)])
        } else {
            HashMap::new()
        };
        db.restore_to_wal_targets_with_archive_sources(
            &source,
            &lsns,
            &times,
            (case != "time").then_some(external.as_path()),
            (case != "lsn").then_some(&objects),
        )
        .unwrap();
        let expected = if case == "both-tip" {
            &tip_state
        } else {
            &target_state
        };
        assert_eq!(&super::graph_pitr::state(&db, id), expected, "{case}");
        let end = if case == "both-tip" {
            tip_lsn
        } else {
            target_lsn
        };
        let active = db.inner.read().root.clone();
        let actual_records = Wal::load(&collection_dir(&active, "docs").join("wal")).unwrap();
        let expected_records: Vec<_> = original_records
            .iter()
            .filter(|record| record.lsn < end)
            .collect();
        assert_eq!(
            serde_json::to_value(actual_records).unwrap(),
            serde_json::to_value(expected_records).unwrap(),
            "original LSN/time {case}"
        );
        assert_eq!(
            snapshot::read_snapshot_marker(&active)
                .unwrap()
                .unwrap()
                .collections[0]
                .wal_lsn,
            end
        );
        assert_eq!(db.graph_database_id(), database_id);
        drop(db);
        db = Db::open(&data).unwrap();
        assert_eq!(
            &super::graph_pitr::state(&db, id),
            expected,
            "reopen {case}"
        );
    }
    let absent = root.join("absent-archives");
    fs::create_dir_all(&absent).unwrap();
    let before = super::graph_pitr::state(&db, id);
    let old_root = db.inner.read().root.clone();
    assert!(
        db.restore_to_wal_targets_with_archive_dir(
            &source,
            &HashMap::from([("docs".into(), target_lsn)]),
            &HashMap::new(),
            Some(&absent)
        )
        .is_err()
    );
    assert_eq!(super::graph_pitr::state(&db, id), before);
    assert_eq!(db.inner.read().root, old_root);
    assert_eq!(
        snapshot::read_snapshot_marker(&source).unwrap().unwrap(),
        marker
    );
    assert_eq!(
        serde_json::to_value(Wal::load(&collection_dir(&source, "docs").join("wal")).unwrap())
            .unwrap(),
        source_wal
    );
}

fn relate(db: &Db, scope: &TenantScope) -> crate::graph::EdgeToken {
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
    db.relate_scoped(
        "docs",
        RelateRequest {
            source_point_id: "a".into(),
            target_point_id: "b".into(),
            edge_type: "links".into(),
            properties: json!({"revision":1}),
            scope: GraphRelationScope::Local,
            idempotency_key: Some("archived-edge".into()),
        },
        true,
        scope,
    )
    .unwrap()
    .edge_id
}

fn rejects_plaintext_archive_without_offset_reencoding(root: &Path) {
    let archive = root.join("legacy-plaintext");
    fs::create_dir_all(&archive).unwrap();
    let payload = serde_json::to_vec(&crate::wal::WalRecord {
        lsn: 0,
        unix_ms: 100,
        entry: WalEntry::Delete {
            id: "plain-only".into(),
        },
    })
    .unwrap();
    let mut frame = Vec::new();
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
    frame.extend_from_slice(&payload);
    fs::write(archive.join("000000.gdwal"), frame).unwrap();
    let mut target = Wal::open(&root.join("encrypted-target")).unwrap();
    let error = target.replay_archive(&archive, |_| Ok(())).unwrap_err();
    assert!(error.to_string().contains("plaintext"), "{error}");
    assert_eq!(target.len().unwrap(), 0);
}
