use std::{
    borrow::Cow,
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use parking_lot::RwLock;

use super::{Collection, freeze_streamer_for_seal, remove_seal_candidate, restore_failed_seal};
use crate::{GaussError, Result, model::Point};

type PriorGraphSource = (usize, PathBuf, Arc<crate::seal::V4Store>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LsvecCompactionScope {
    SizeTiered,
    #[cfg(feature = "benchmark-internals")]
    Full,
}

/// Stable input for an off-lock LS-VEC generation build. The active streamer
/// is frozen at `end_lsn`; immutable stores are retained by `Arc`. Only IDs
/// and snapshot locations are copied, so the build does not duplicate the
/// vector corpus on heap.
pub(super) struct MergeSnapshotInput {
    pub(super) frozen: Option<Arc<crate::streamer::Streamer>>,
    stores: Vec<Option<Arc<crate::seal::V4Store>>>,
    pub(super) entries: Vec<(String, crate::searcher::SegLoc)>,
}

impl crate::seal::VectorInput for MergeSnapshotInput {
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn point(&self, ordinal: usize) -> Result<Cow<'_, Point>> {
        let (id, location) = self.entries.get(ordinal).ok_or_else(|| {
            GaussError::InvalidRequest(format!("merge snapshot ordinal {ordinal} is out of bounds"))
        })?;
        match location {
            crate::searcher::SegLoc::Sealing => self
                .frozen
                .as_ref()
                .and_then(|frozen| frozen.points.get(id))
                .map(Cow::Borrowed)
                .ok_or_else(|| GaussError::PointNotFound(id.clone())),
            crate::searcher::SegLoc::Searcher(index) => self
                .stores
                .get(*index as usize)
                .and_then(Option::as_ref)
                .and_then(|store| store.get(id).map(Cow::Owned))
                .ok_or_else(|| GaussError::PointNotFound(id.clone())),
            crate::searcher::SegLoc::Streamer => Err(GaussError::InvalidRequest(format!(
                "merge snapshot retained mutable streamer location for {id}"
            ))),
        }
    }
}

pub(super) struct StagedLsvecCompaction {
    pub(super) input: MergeSnapshotInput,
    pub(super) segment_id: String,
    pub(super) final_dir: PathBuf,
    pub(super) store: Arc<crate::seal::V4Store>,
    pub(super) index: crate::searcher::SegmentIndex,
    pub(super) named_index: HashMap<String, crate::searcher::SegmentIndex>,
    pub(super) marker_points: usize,
    pub(super) end_lsn: u64,
    pub(super) generation: u64,
    pub(super) build_workspace: PathBuf,
    /// `Some` means a bounded partial merge: only these immutable segments
    /// plus the frozen mutable prefix are replaced. `None` is the legacy
    /// full-generation migration path.
    pub(super) selected_segment_ids: Option<std::collections::HashSet<String>>,
}

pub(super) struct StagedGraphCompaction {
    pub(super) input: MergeSnapshotInput,
    pub(super) plan: crate::graph_generation::compaction::GraphCompactionPlan,
    pub(super) segment_id: String,
    pub(super) final_dir: PathBuf,
    pub(super) store: Arc<crate::seal::V4Store>,
    pub(super) index: crate::searcher::SegmentIndex,
    pub(super) named_index: HashMap<String, crate::searcher::SegmentIndex>,
    pub(super) marker_points: usize,
    pub(super) end_lsn: u64,
    pub(super) generation: u64,
    pub(super) build_workspace: PathBuf,
    pub(super) expected: crate::checkpoint::SegmentsManifest,
    pub(super) prepared_graph: crate::graph_generation::GraphGeneration,
    pub(super) enabled: bool,
}

/// Freeze one complete vector+graph cut, emit a degree-BFS ordered segment,
/// and preflight the replacement generation off the collection lock.
pub(super) fn stage_graph_compaction(
    coll: &Arc<RwLock<Collection>>,
    collection_dir: &Path,
    collection_name: &str,
) -> Result<Option<StagedGraphCompaction>> {
    let prepared = {
        let mut collection = coll.write();
        let Some(source_generation) = collection.graph_generation.as_ref().map(Arc::clone) else {
            return Ok(None);
        };
        if collection.sealing.is_some() || collection.generation_build_in_flight {
            return Ok(None);
        }
        let stores = collection
            .searchers
            .iter()
            .map(|searcher| match &searcher.store {
                crate::searcher::SegmentStore::V4(store) => Some(Arc::clone(store)),
                crate::searcher::SegmentStore::Heap(_) => None,
            })
            .collect::<Vec<_>>();
        if stores.iter().any(Option::is_none) {
            return Err(GaussError::InvalidRequest(
                "graph compaction requires checked current-format vector segments".into(),
            ));
        }
        collection.wal.sync()?;
        collection.overlays.publish_pending()?;
        let end_lsn = collection.wal.len()?;
        let expected = crate::checkpoint::read_segments_manifest(collection_dir)?
            .ok_or_else(|| GaussError::InvalidRequest("graph compaction has no manifest".into()))?;
        if expected != *source_generation.manifest {
            return Err(GaussError::InvalidRequest(
                "graph compaction source generation is stale".into(),
            ));
        }
        let generation = expected.generation.checked_add(1).ok_or_else(|| {
            GaussError::InvalidRequest("segment manifest generation overflow".into())
        })?;
        let resolver = collection
            .graph_resolver
            .clone()
            .ok_or_else(|| GaussError::InvalidRequest("graph generation has no resolver".into()))?;
        let enabled = collection.graph_lifecycle.is_enabled();
        let plan = crate::graph_generation::compaction::GraphCompactionPlan::prepare(
            source_generation,
            resolver,
            collection.overlays.current(),
            collection.graph_mutable.clone(),
            enabled,
        )?;
        if end_lsn < plan.graph_batch_watermark {
            return Err(GaussError::InvalidRequest(
                "graph compaction WAL cut regressed below the installed watermark".into(),
            ));
        }
        let mut entries = plan
            .nodes
            .iter()
            .map(|node| {
                let location = collection
                    .id_index
                    .get(&node.point_id)
                    .copied()
                    .ok_or_else(|| {
                        GaussError::InvalidRequest(format!(
                            "graph resolver point '{}' has no vector location",
                            node.point_id
                        ))
                    })?;
                Ok((node.point_id.clone(), location))
            })
            .collect::<Result<Vec<_>>>()?;
        if entries.len() != collection.live_points() {
            return Err(GaussError::InvalidRequest(
                "graph resolver and live vector set disagree during compaction".into(),
            ));
        }
        let cut_overlay = collection.overlays.stage_replacement_generation(
            generation,
            crate::ordinal::SegmentOrdinalSet::new(),
            roaring::RoaringTreemap::new(),
        )?;
        let frozen = if collection.streamer.points.is_empty() {
            None
        } else {
            Some(freeze_streamer_for_seal(&mut collection, end_lsn))
        };
        for (_, location) in &mut entries {
            if *location == crate::searcher::SegLoc::Streamer {
                *location = crate::searcher::SegLoc::Sealing;
            }
        }
        collection.generation_build_in_flight = true;
        Some((
            MergeSnapshotInput {
                frozen,
                stores,
                entries,
            },
            collection.config.clone(),
            plan,
            end_lsn,
            generation,
            expected,
            cut_overlay.version(),
            enabled,
        ))
    };
    let Some((input, config, mut plan, end_lsn, generation, expected, overlay_version, enabled)) =
        prepared
    else {
        return Ok(None);
    };

    let segment_id = format!("sg-v6-graph-merge-{end_lsn:020}-{generation:020}");
    let searchers_dir = collection_dir.join("searchers");
    let final_dir = searchers_dir.join(&segment_id);
    let workspace = crate::build_progress::workspace(&searchers_dir, &segment_id);
    let candidate_dir = crate::build_progress::BuildProgress::candidate_dir(&workspace);
    let build = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<_> {
        fs::create_dir_all(&searchers_dir)?;
        if crate::checkpoint::read_segments_manifest(collection_dir)?
            .is_some_and(|manifest| manifest.segments.contains(&segment_id))
        {
            return Err(GaussError::InvalidRequest(format!(
                "refusing to replace installed graph segment generation {segment_id}"
            )));
        }
        remove_seal_candidate(&final_dir)?;
        let index_kind = if input.entries.is_empty() {
            crate::seal::SealIndexKind::Hnsw
        } else {
            crate::seal::SealIndexKind::Algorithm2
        };
        let marker = crate::seal::build_segment_resumable(
            &input,
            &workspace,
            &segment_id,
            crate::seal::SealConfig {
                vector_dim: config.vector_dim,
                metric: config.metric,
                hnsw_m: config.hnsw_m,
                hnsw_ef_construction: config.hnsw_ef_construction,
                index_kind,
                base_lsn: 0,
                end_lsn,
            },
        )?
        .marker;
        let graph_artifacts = if enabled {
            plan.emit_segment_graph(&candidate_dir)?
        } else {
            crate::graph_generation::compaction::CompactedGraphArtifacts::empty()
        };
        crate::fs_util::durable_rename(&candidate_dir, &final_dir)?;
        let manifest = plan.write_replacement_manifest(
            collection_dir,
            collection_name,
            &segment_id,
            generation,
            end_lsn,
            overlay_version,
            enabled,
            &graph_artifacts,
        )?;
        let mut prepared_graph = crate::graph_generation::GraphGeneration::prepare_publication(
            collection_dir,
            manifest,
        )?;
        prepared_graph.recovered.take();
        crate::failpoint::check("graph_compaction.after_stage")?;
        let store = Arc::new(if enabled {
            crate::seal::V4Store::open_graph_base(&final_dir)?
        } else {
            crate::seal::V4Store::open(&final_dir)?
        });
        let index = match index_kind {
            crate::seal::SealIndexKind::Hnsw => crate::searcher::SegmentIndex::LegacyH2qg(
                Box::new(crate::h2qg::read_index_paged(&final_dir)?),
            ),
            crate::seal::SealIndexKind::Algorithm2 => crate::searcher::SegmentIndex::Ivf(Box::new(
                crate::index::ivf_segment::IvfSegmentIndex::open(
                    &final_dir,
                    Arc::clone(&store),
                    config.metric,
                )?,
            )),
        };
        let named_index = match index_kind {
            crate::seal::SealIndexKind::Algorithm2 => {
                crate::searcher::load_named_algorithm2_indexes(&final_dir, config.metric)?
            }
            crate::seal::SealIndexKind::Hnsw => HashMap::new(),
        };
        Ok((marker, store, index, named_index, prepared_graph))
    }));

    match build {
        Ok(Ok((marker, store, index, named_index, prepared_graph))) => {
            Ok(Some(StagedGraphCompaction {
                input,
                plan,
                segment_id,
                final_dir,
                store,
                index,
                named_index,
                marker_points: marker.points,
                end_lsn,
                generation,
                build_workspace: workspace,
                expected,
                prepared_graph,
                enabled,
            }))
        }
        Ok(Err(error)) => {
            abort_graph_compaction(coll, collection_dir, &input, &final_dir);
            Err(error)
        }
        Err(_) => {
            abort_graph_compaction(coll, collection_dir, &input, &final_dir);
            Err(GaussError::InvalidRequest(
                "graph generation build panicked before publication".into(),
            ))
        }
    }
}

fn abort_graph_compaction(
    coll: &Arc<RwLock<Collection>>,
    collection_dir: &Path,
    input: &MergeSnapshotInput,
    final_dir: &Path,
) {
    let frozen = input.frozen.as_ref().map(Arc::clone);
    let installed = crate::checkpoint::read_segments_manifest(collection_dir)
        .ok()
        .flatten()
        .is_some_and(|manifest| {
            final_dir.file_name().is_some_and(|id| {
                manifest
                    .segments
                    .iter()
                    .any(|item| item == &id.to_string_lossy())
            })
        });
    if !installed {
        let _ = remove_seal_candidate(final_dir);
    }
    let mut collection = coll.write();
    collection.generation_build_in_flight = false;
    drop(collection);
    if let Some(frozen) = frozen {
        restore_failed_seal(Arc::clone(coll), frozen);
    }
}

/// Freeze a repeatable LS-VEC snapshot, build its immutable generation off
/// the collection lock, and reopen every checksummed artifact before it can
/// become a manifest candidate. Returns `None` for no-op/empty collections
/// and legacy heap segments, which retain the compatibility compactor.
pub(super) fn stage_lsvec_compaction(
    coll: &Arc<RwLock<Collection>>,
    collection_dir: &Path,
    scope: LsvecCompactionScope,
) -> Result<Option<StagedLsvecCompaction>> {
    let prepared = {
        let mut collection = coll.write();
        let is_lsvec = collection
            .config
            .index_kind
            .as_deref()
            .is_none_or(|kind| kind.eq_ignore_ascii_case("lsvec"));
        let stores = collection
            .searchers
            .iter()
            .map(|searcher| match &searcher.store {
                crate::searcher::SegmentStore::V4(store) => Some(Arc::clone(store)),
                crate::searcher::SegmentStore::Heap(_) => None,
            })
            .collect::<Vec<_>>();
        let all_v4 = stores.iter().all(Option::is_some);
        let exact_vectors_current = collection.searchers.iter().all(|searcher| {
            matches!(
                &searcher.store,
                crate::searcher::SegmentStore::V4(store)
                    if store.segment_format_version() >= 6
                        && (searcher.named_index.is_empty()
                            || store.segment_format_version() >= 8)
            )
        });
        if !is_lsvec
            || collection.live_points() == 0
            || collection.sealing.is_some()
            || collection.generation_build_in_flight
        {
            None
        } else if all_v4 {
            let mut live_per_segment = vec![0usize; collection.searchers.len()];
            for location in collection.id_index.values() {
                if let crate::searcher::SegLoc::Searcher(index) = location
                    && let Some(live) = live_per_segment.get_mut(*index as usize)
                {
                    *live = live.saturating_add(1);
                }
            }
            let full_generation = match scope {
                LsvecCompactionScope::SizeTiered => false,
                #[cfg(feature = "benchmark-internals")]
                LsvecCompactionScope::Full => true,
            };
            let selected_positions = if exact_vectors_current && !full_generation {
                crate::compaction::select_size_tier(
                    &collection
                        .searchers
                        .iter()
                        .enumerate()
                        .map(|(position, searcher)| crate::compaction::SegmentTierStats {
                            position,
                            physical_points: searcher.store.len(),
                            live_points: live_per_segment[position],
                        })
                        .collect::<Vec<_>>(),
                )
            } else {
                (0..collection.searchers.len()).collect()
            };
            let partial = exact_vectors_current && !full_generation;
            if partial && selected_positions.is_empty() && collection.streamer.points.is_empty() {
                return Ok(None);
            }
            collection.wal.sync()?;
            let end_lsn = collection.wal.len()?;
            let generation = crate::checkpoint::read_segments_manifest(collection_dir)?
                .map_or(0, |manifest| manifest.generation)
                .checked_add(1)
                .ok_or_else(|| {
                    GaussError::InvalidRequest("segment manifest generation overflow".into())
                })?;
            let frozen = if collection.streamer.points.is_empty() {
                None
            } else {
                Some(freeze_streamer_for_seal(&mut collection, end_lsn))
            };
            collection.generation_build_in_flight = true;
            let selected_positions = selected_positions
                .into_iter()
                .collect::<std::collections::HashSet<_>>();
            let mut entries = collection
                .id_index
                .iter()
                .filter(|(_, location)| match location {
                    crate::searcher::SegLoc::Sealing => frozen.is_some(),
                    crate::searcher::SegLoc::Searcher(index) => {
                        !partial || selected_positions.contains(&(*index as usize))
                    }
                    crate::searcher::SegLoc::Streamer => false,
                })
                .map(|(id, location)| (id.clone(), *location))
                .collect::<Vec<_>>();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let selected_segment_ids = partial.then(|| {
                selected_positions
                    .iter()
                    .map(|position| collection.searchers[*position].id.clone())
                    .collect()
            });
            let mut prior_positions = selected_positions.iter().copied().collect::<Vec<_>>();
            prior_positions.sort_unstable();
            let prior_sources = prior_positions
                .into_iter()
                .filter_map(|position| {
                    Some((
                        position,
                        collection.searchers.get(position)?.dir.clone(),
                        stores.get(position)?.as_ref().map(Arc::clone)?,
                    ))
                })
                .collect::<Vec<_>>();
            Some((
                MergeSnapshotInput {
                    frozen,
                    stores,
                    entries,
                },
                collection.config.clone(),
                end_lsn,
                generation,
                selected_segment_ids,
                prior_sources,
            ))
        } else {
            None
        }
    };

    let Some((input, config, end_lsn, generation, selected_segment_ids, prior_sources)) = prepared
    else {
        return Ok(None);
    };
    let prior_graph = match collect_prior_graph(&prior_sources, &input.entries) {
        Ok(seed) if !seed.is_empty() => Some(seed),
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(
                %error,
                "discarding prior-generation Vamana seed and rebuilding from vectors"
            );
            None
        }
    };
    let segment_id = format!("sg-v6-merge-{end_lsn:020}-{generation:020}");
    let searchers_dir = collection_dir.join("searchers");
    let final_dir = searchers_dir.join(&segment_id);
    let workspace = crate::build_progress::workspace(&searchers_dir, &segment_id);
    let candidate_dir = crate::build_progress::BuildProgress::candidate_dir(&workspace);
    let build = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<_> {
        fs::create_dir_all(&searchers_dir)?;
        let installed = crate::checkpoint::read_segments_manifest(collection_dir)?
            .is_some_and(|manifest| manifest.segments.contains(&segment_id));
        if installed {
            return Err(GaussError::InvalidRequest(format!(
                "refusing to replace installed segment generation {segment_id}"
            )));
        }
        remove_seal_candidate(&final_dir)?;
        let seal_config = crate::seal::SealConfig {
            vector_dim: config.vector_dim,
            metric: config.metric,
            hnsw_m: config.hnsw_m,
            hnsw_ef_construction: config.hnsw_ef_construction,
            index_kind: crate::seal::SealIndexKind::Algorithm2,
            base_lsn: 0,
            end_lsn,
        };
        let marker = if let Some(prior_graph) = prior_graph.as_ref() {
            crate::seal::build_segment_resumable_with_prior_graph(
                &input,
                &workspace,
                &segment_id,
                seal_config,
                prior_graph,
            )?
        } else {
            crate::seal::build_segment_resumable(&input, &workspace, &segment_id, seal_config)?
        }
        .marker;
        #[cfg(feature = "fault-injection")]
        crate::fs_util::fault_injection::crash_hook(
            crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_SEGMENT_TREE_SYNC,
        )?;
        crate::fs_util::durable_rename(&candidate_dir, &final_dir)?;
        crate::failpoint::check("compaction.after_segment_sync")?;
        #[cfg(feature = "fault-injection")]
        crate::fs_util::fault_injection::crash_hook(
            crate::fs_util::fault_injection::HOOK_COMPACT_AFTER_SEGMENT_PUBLISH,
        )?;

        let store = Arc::new(crate::seal::V4Store::open(&final_dir)?);
        let index = crate::searcher::SegmentIndex::Ivf(Box::new(
            crate::index::ivf_segment::IvfSegmentIndex::open(
                &final_dir,
                Arc::clone(&store),
                config.metric,
            )?,
        ));
        let named_index =
            crate::searcher::load_named_algorithm2_indexes(&final_dir, config.metric)?;
        Ok((marker, store, index, named_index))
    }));

    match build {
        Ok(Ok((marker, store, index, named_index))) => Ok(Some(StagedLsvecCompaction {
            input,
            segment_id,
            final_dir,
            store,
            index,
            named_index,
            marker_points: marker.points,
            end_lsn,
            generation,
            build_workspace: workspace,
            selected_segment_ids,
        })),
        Ok(Err(error)) => {
            let frozen = input.frozen.as_ref().map(Arc::clone);
            drop(input);
            let installed = crate::checkpoint::read_segments_manifest(collection_dir)
                .ok()
                .flatten()
                .is_some_and(|manifest| manifest.segments.contains(&segment_id));
            if !installed {
                let _ = remove_seal_candidate(&final_dir);
            }
            let mut collection = coll.write();
            collection.generation_build_in_flight = false;
            drop(collection);
            if let Some(frozen) = frozen {
                restore_failed_seal(Arc::clone(coll), frozen);
            }
            Err(error)
        }
        Err(_) => {
            let frozen = input.frozen.as_ref().map(Arc::clone);
            drop(input);
            let installed = crate::checkpoint::read_segments_manifest(collection_dir)
                .ok()
                .flatten()
                .is_some_and(|manifest| manifest.segments.contains(&segment_id));
            if !installed {
                let _ = remove_seal_candidate(&final_dir);
            }
            let mut collection = coll.write();
            collection.generation_build_in_flight = false;
            drop(collection);
            if let Some(frozen) = frozen {
                restore_failed_seal(Arc::clone(coll), frozen);
            }
            Err(GaussError::InvalidRequest(
                "LS-VEC generation build panicked before publication".to_string(),
            ))
        }
    }
}

fn collect_prior_graph(
    sources: &[PriorGraphSource],
    entries: &[(String, crate::searcher::SegLoc)],
) -> Result<crate::index::vamana::StableGraphSeed> {
    let mut live_locations = HashMap::with_capacity(entries.len());
    for (ordinal, (id, location)) in entries.iter().enumerate() {
        let ordinal = u32::try_from(ordinal).map_err(|_| {
            GaussError::InvalidRequest("prior Vamana seed exceeds u32 ordinals".to_string())
        })?;
        live_locations.insert(id.as_str(), (*location, ordinal));
    }
    let mut seed = crate::index::vamana::StableGraphSeed::new(entries.len());
    for (position, dir, store) in sources {
        let ivf = crate::index::ivf::IvfArtifact::open(&dir.join(crate::index::ivf::IVF_FILE))?;
        let vamana = crate::index::vamana::VamanaArtifact::open(
            &dir.join(crate::index::vamana::VAMANA_SEGMENT_FILE),
            &ivf,
        )?;
        if vamana.len() != store.len() {
            return Err(GaussError::InvalidRequest(format!(
                "prior Vamana/store count mismatch in {}",
                dir.display()
            )));
        }
        let ordinal_to_key = vamana.ordinal_to_key(&ivf)?;
        let expected = crate::searcher::SegLoc::Searcher(*position as u32);
        for ordinal in 0..store.len() {
            let Some(id) = store.id(ordinal) else {
                return Err(GaussError::InvalidRequest(format!(
                    "prior Vamana ordinal {ordinal} has no stable ID"
                )));
            };
            let Some(&(location, new_ordinal)) = live_locations.get(id) else {
                continue;
            };
            if location != expected {
                continue;
            }
            let inherited = vamana
                .ordinal_neighbors(&ivf, &ordinal_to_key, ordinal)?
                .into_iter()
                .filter_map(|neighbor| store.id(neighbor as usize))
                .filter_map(|neighbor| live_locations.get(neighbor).copied())
                .filter_map(|(location, ordinal)| (location == expected).then_some(ordinal))
                .collect::<Vec<_>>();
            seed.insert(new_ordinal as usize, inherited)?;
        }
    }
    Ok(seed)
}
