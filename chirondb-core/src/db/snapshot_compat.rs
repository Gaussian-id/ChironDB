//! Explicit conversion of unordered legacy snapshot checksums. The source is
//! never opened as a Db or changed; only a verified, separately staged copy is
//! published. Ordinary snapshot readers never waive a checksum mismatch.

use super::*;
use std::collections::BTreeMap;

#[derive(Debug, Serialize)]
pub struct SnapshotConversionReceipt {
    pub source_version: u32,
    pub snapshot_version: u32,
    pub verified_collections: usize,
    pub verified_commit_frontier: u64,
}

fn invalid(message: &str) -> GaussError {
    GaussError::InvalidRequest(format!("snapshot conversion: {message}"))
}

fn config_digest(config: &CollectionConfig) -> Result<[u8; 32]> {
    Ok(Sha256::digest(&*crate::snapshot::canonical_config_bytes(config)?).into())
}

/// Convert a v1/v2 native snapshot into a new v3 snapshot, verifying its full
/// configuration and schema epochs against the retained committed journal.
///
/// The complete original journal is required: lost HashMap iteration order
/// cannot safely be recovered from the legacy CRC. Never infer trust from the
/// catalog alone or modify the source marker to make ordinary import succeed.
pub fn convert_legacy_snapshot(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
) -> Result<SnapshotConversionReceipt> {
    let source = fs::canonicalize(source)?;
    if !source.is_dir() {
        return Err(invalid("source must be a snapshot directory"));
    }
    let _source_lock = DataDirLock::acquire(&source)?;
    if source.join(GRAPH_IDENTITY_FILE).try_exists()?
        || source
            .join(crate::storage_layout::CURRENT_FILE)
            .try_exists()?
        || source
            .join(restore_journal::RESTORE_JOURNAL_FILE)
            .try_exists()?
        || source.join("security").try_exists()?
    {
        return Err(invalid(
            "source must be an unactivated flat native snapshot",
        ));
    }
    let marker =
        read_snapshot_marker(&source)?.ok_or_else(|| invalid("source has no snapshot marker"))?;
    if marker.version >= 3 {
        return Err(invalid("source already uses canonical checksums"));
    }
    if !source
        .join(crate::transaction_journal::TRANSACTION_FORMAT_MARKER)
        .try_exists()?
    {
        return Err(invalid("complete retained transaction journal is required"));
    }
    reject_storage_path_overlap(
        "snapshot conversion destination",
        destination.as_ref(),
        &source,
    )?;
    let destination_lock = DataDirLock::acquire(destination.as_ref())?;
    let destination = destination_lock.root();
    match fs::symlink_metadata(destination) {
        Ok(_) => return Err(invalid("destination already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = destination
        .parent()
        .ok_or_else(|| invalid("destination must have a parent"))?;
    let staging = tempfile::Builder::new()
        .prefix(".chirondb-snapshot-convert-")
        .tempdir_in(parent)?;
    copy_dir_contents(&source, staging.path())?;

    let catalog = read_catalog(staging.path())?;
    if catalog.installation.is_some() || !catalog.protected.is_empty() {
        return Err(invalid(
            "protected backups require the protected restore workflow",
        ));
    }
    let journal = TransactionJournal::open(staging.path())?;
    let frontier = journal
        .completed_commit_frontier()?
        .ok_or_else(|| invalid("journal has unfinished or uncertain projections"))?;
    let configs = verified_configs(&journal)?;
    let loaded = load_db_root_with_journal(staging.path(), None, Some(&journal))?;
    if configs.len() != loaded.collections.len() {
        return Err(invalid(
            "journal does not cover the complete snapshot catalog",
        ));
    }
    let mut converted = marker.clone();
    converted.version = 3;
    for marked in &mut converted.collections {
        let collection = loaded
            .collections
            .get(&marked.collection)
            .ok_or_else(|| invalid("marker references a missing collection"))?
            .read();
        let expected = configs
            .get(&marked.collection)
            .ok_or_else(|| invalid("collection has no retained journal creation"))?;
        if expected.0 != collection.schema_epoch || expected.1 != config_digest(&collection.config)?
        {
            return Err(invalid(
                "configuration or schema epoch disagrees with journal",
            ));
        }
        marked.config_crc = crate::snapshot::config_crc(&collection.config, 3)?;
        // v1 snapshots could carry graph WAL without the later v2 binding.
        // Bind the validated replayed graph when publishing the v3 copy.
        if marker.version == 1 {
            marked.graph = collection.snapshot_graph()?;
        }
    }
    // Counts, names, schema epochs, segment IDs, WAL cuts and existing v2
    // graph bindings retain their ordinary strict validation.
    validate_snapshot_marker(Some(&converted), &loaded.collections)?;
    let receipt = SnapshotConversionReceipt {
        source_version: marker.version,
        snapshot_version: converted.version,
        verified_collections: converted.collections.len(),
        verified_commit_frontier: frontier,
    };
    write_snapshot_marker(staging.path(), &converted)?;
    let writer = audit::AuditWriter::open_with_journal(staging.path(), Arc::clone(&journal))?;
    writer.record(audit::AuditEvent {
        category: "admin",
        operation: "convert_legacy_snapshot",
        outcome: "success",
        collection: None,
        context: &audit::AuditContext::embedded(),
        error_code: None,
        details: serde_json::to_value(&receipt)?,
        durable: true,
    })?;
    drop(writer);
    drop(loaded);
    drop(journal);
    sync_tree(staging.path())?;
    durable_rename(staging.path(), destination)?;
    Ok(receipt)
}

type VerifiedConfigs = BTreeMap<String, (u64, [u8; 32])>;

fn verified_configs(
    journal: &TransactionJournal,
) -> Result<crate::relational::wal_decode::Owned<VerifiedConfigs>> {
    let mut configs = VerifiedConfigs::new();
    let mut memory = crate::relational::wal_decode::MetadataCharge::default();
    let mut bytes = 0_u64;
    journal.for_each_committed(|transaction| {
        let prepare = &transaction.prepare;
        match (&prepare.target, prepare.mutation.as_ref()) {
            (TransactionTarget::Catalog, WalEntry::CreateCollection { config }) => {
                validate_config(config)?;
                bytes = bytes
                    .checked_add(config.name.len() as u64 + 256)
                    .ok_or_else(|| invalid("journal catalog is too large"))?;
                memory.prepare(bytes)?;
                if configs
                    .insert(config.name.clone(), (1, config_digest(config)?))
                    .is_some()
                {
                    return Err(invalid("journal repeats a live collection creation"));
                }
            }
            (TransactionTarget::Catalog, WalEntry::DropCollection { name }) => {
                if configs.remove(name).is_none() {
                    return Err(invalid("journal collection history is incomplete"));
                }
            }
            (
                TransactionTarget::Collection { name },
                WalEntry::Schema {
                    schema_epoch,
                    config,
                    previous_config,
                },
            ) => {
                let previous = configs
                    .get_mut(name)
                    .ok_or_else(|| invalid("journal schema history has no creation"))?;
                if config.name != *name
                    || previous.0.checked_add(1) != Some(*schema_epoch)
                    || previous_config
                        .as_ref()
                        .map(config_digest)
                        .transpose()?
                        .is_some_and(|digest| digest != previous.1)
                {
                    return Err(invalid("journal schema history is inconsistent"));
                }
                validate_config(config)?;
                *previous = (*schema_epoch, config_digest(config)?);
            }
            (
                _,
                WalEntry::CreateCollection { .. }
                | WalEntry::DropCollection { .. }
                | WalEntry::Schema { .. },
            ) => {
                return Err(invalid("journal schema mutation has the wrong target"));
            }
            _ => {}
        }
        Ok(())
    })?;
    Ok(crate::relational::wal_decode::Owned::from_parts(
        configs,
        memory.into_reservation(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant::TenantScope;
    use serde_json::json;

    fn config() -> CollectionConfig {
        serde_json::from_value(json!({
            "name":"docs", "vector_dim":2, "metric":"cosine",
            "payload_schema":{"category":"optional_string", "active":"optional_bool"},
            "named_vector_dims":{"title":2,"body":3}
        }))
        .unwrap()
    }

    fn legacy_snapshot(root: &Path, version: u32) -> PathBuf {
        let data = root.join("data");
        if version == 2 {
            crate::storage_layout::initialize_empty(&data).unwrap();
        }
        let db = Db::open(&data).unwrap();
        // Cover a retired incarnation as well as a changed, compacted schema.
        db.create_collection(config()).unwrap();
        db.delete_collection("docs").unwrap();
        let mut config = db.create_collection(config()).unwrap();
        config
            .payload_schema
            .insert("source".into(), PayloadType::OptionalString);
        db.update_payload_schema("docs", config.payload_schema)
            .unwrap();
        db.upsert(
            "docs",
            vec![
                serde_json::from_value(json!({
                    "id":"keep", "vector":[1,0], "vectors":{"title":[1,0],"body":[0,1,0]},
                    "payload":{"category":"docs","active":true,"source":"legacy"}
                }))
                .unwrap(),
            ],
        )
        .unwrap();
        let scope = TenantScope::tenant("converter-test", "acme");
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        db.compact_collection("docs").unwrap();
        let source = root.join("snapshot");
        db.snapshot(&source).unwrap();
        let mut marker = read_snapshot_marker(&source).unwrap().unwrap();
        marker.version = version;
        if version == 1 {
            marker.collections[0].graph = None;
        }
        // Simulate the unrecoverable legacy map order. Normal readers must
        // refuse, but conversion may replace it only after independent proof.
        marker.collections[0].config_crc = 0;
        write_snapshot_marker(&source, &marker).unwrap();
        source
    }

    fn hashes(root: &Path) -> BTreeMap<PathBuf, [u8; 32]> {
        fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, [u8; 32]>) {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    visit(root, &entry.path(), result);
                } else {
                    result.insert(
                        entry.path().strip_prefix(root).unwrap().to_path_buf(),
                        Sha256::digest(fs::read(entry.path()).unwrap()).into(),
                    );
                }
            }
        }
        let mut result = BTreeMap::new();
        visit(root, root, &mut result);
        result
    }

    #[test]
    fn converts_legacy_schema_history_and_graph_without_changing_source() {
        for version in [1, 2] {
            let temp = tempfile::tempdir().unwrap();
            let source = legacy_snapshot(temp.path(), version);
            let before = hashes(&source);
            let destination = temp.path().join("converted");
            let receipt = convert_legacy_snapshot(&source, &destination).unwrap();
            assert_eq!(receipt.source_version, version);
            assert_eq!(receipt.snapshot_version, 3);
            assert_eq!(receipt.verified_collections, 1);
            assert!(receipt.verified_commit_frontier > 0);
            assert_eq!(before, hashes(&source));
            let marker = read_snapshot_marker(&destination).unwrap().unwrap();
            assert_eq!(marker.version, 3);
            assert!(marker.collections[0].graph.is_some());
            assert!(
                fs::read_to_string(destination.join("audit/audit.jsonl"))
                    .unwrap()
                    .contains("convert_legacy_snapshot")
            );
            // Exercise both restore installation layouts, then restart.
            let target = temp.path().join("target");
            if version == 2 {
                crate::storage_layout::initialize_empty(&target).unwrap();
            }
            let db = Db::open(&target).unwrap();
            let error = db.restore(&source).unwrap_err();
            assert!(error.to_string().contains("config checksum"), "{error}");
            db.restore(&destination).unwrap();
            drop(db);
            let reopened = Db::open(&target).unwrap();
            assert_eq!(
                reopened.get_points("docs", &["keep".into()]).unwrap().len(),
                1
            );
            assert_eq!(reopened.list_collections()[0].payload_schema.len(), 3);
            assert_eq!(reopened.list_collections()[0].named_vector_dims.len(), 2);
            assert!(
                reopened
                    .get_coll("docs")
                    .unwrap()
                    .read()
                    .snapshot_graph()
                    .unwrap()
                    .is_some()
            );
            reopened.snapshot(temp.path().join("resnapshot")).unwrap();
            assert_eq!(before, hashes(&source));
        }
    }

    #[test]
    fn conversion_refuses_unverifiable_or_corrupt_copies_without_publishing() {
        let temp = tempfile::tempdir().unwrap();
        let source = legacy_snapshot(temp.path(), 2);
        for case in [
            "missing_journal",
            "missing_creation",
            "catalog",
            "epoch",
            "points",
            "graph",
            "wal",
            "marker_crc",
            "already_v3",
            "activated",
            "generation_pointer",
            "restore_control",
            "identity_control",
        ] {
            let bad = temp.path().join(case);
            fs::create_dir(&bad).unwrap();
            copy_dir_contents(&source, &bad).unwrap();
            let mut marker = read_snapshot_marker(&bad).unwrap().unwrap();
            match case {
                "missing_journal" => fs::remove_dir_all(bad.join("transactions")).unwrap(),
                "missing_creation" => {
                    fs::remove_dir_all(bad.join("transactions")).unwrap();
                    drop(TransactionJournal::open(&bad).unwrap());
                }
                "catalog" => {
                    let mut catalog = read_catalog(&bad).unwrap();
                    catalog.collections[0]
                        .named_vector_dims
                        .insert("title".into(), 7);
                    let payload = serde_json::to_vec(&catalog).unwrap();
                    let framed = crate::security::storage::encode_metadata(
                        TRANSACTION_CATALOG_MAGIC,
                        &payload,
                    );
                    crate::encryption::atomic_write_persistent(
                        &bad.join(CATALOG_FILE),
                        crate::encryption::FileType::Metadata,
                        &framed,
                    )
                    .unwrap();
                }
                "epoch" => marker.collections[0].schema_epoch += 1,
                "points" => marker.collections[0].points += 1,
                "graph" => {
                    marker.collections[0]
                        .graph
                        .as_mut()
                        .unwrap()
                        .manifest_sha256 = Some([9; 32])
                }
                "wal" => marker.collections[0].wal_lsn += 1,
                "marker_crc" => {
                    let path = crate::snapshot::snapshot_marker_path(&bad);
                    let mut bytes = fs::read(&path).unwrap();
                    *bytes.last_mut().unwrap() ^= 1;
                    fs::write(path, bytes).unwrap();
                }
                "already_v3" => marker.version = 3,
                "activated" => fs::write(bad.join(GRAPH_IDENTITY_FILE), b"activated").unwrap(),
                "generation_pointer" => fs::write(
                    bad.join(crate::storage_layout::CURRENT_FILE),
                    b"generation-1",
                )
                .unwrap(),
                "restore_control" => {
                    fs::write(bad.join(restore_journal::RESTORE_JOURNAL_FILE), b"pending").unwrap()
                }
                "identity_control" => fs::create_dir(bad.join("security")).unwrap(),
                _ => unreachable!(),
            }
            if !matches!(case, "marker_crc") {
                write_snapshot_marker(&bad, &marker).unwrap();
            }
            let before = hashes(&bad);
            let destination = temp.path().join(format!("output-{case}"));
            assert!(
                convert_legacy_snapshot(&bad, &destination).is_err(),
                "{case}"
            );
            assert!(!destination.exists(), "{case}");
            assert_eq!(hashes(&bad), before, "{case}");
        }
        let destination = temp.path().join("existing");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("keep"), b"unchanged").unwrap();
        assert!(convert_legacy_snapshot(&source, &destination).is_err());
        assert_eq!(fs::read(destination.join("keep")).unwrap(), b"unchanged");
        assert!(convert_legacy_snapshot(&source, source.join("nested")).is_err());
        assert!(!source.join("nested").exists());
        let _lock = DataDirLock::acquire(&source).unwrap();
        assert!(convert_legacy_snapshot(&source, temp.path().join("locked")).is_err());
    }
}
