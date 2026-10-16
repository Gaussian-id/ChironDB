//! Route candidate hydration through the pinned visibility authority.
use super::*;
use crate::search::CandidatePoint;

pub(super) fn vector<'a>(
    collection: &'a Collection,
    state: Option<&crate::overlay::OverlayReadState>,
    id: &str,
    name: Option<&str>,
) -> Result<Option<crate::index::VectorRead<'a>>> {
    match collection.id_index.get(id) {
        Some(crate::searcher::SegLoc::Streamer) => collection
            .streamer
            .points
            .get(id)
            .map(|point| CandidatePoint::Borrowed(point).vector_read(name))
            .transpose()
            .map(Option::flatten),
        Some(crate::searcher::SegLoc::Sealing) => collection
            .sealing
            .as_ref()
            .and_then(|streamer| streamer.points.get(id))
            .map(|point| CandidatePoint::Borrowed(point).vector_read(name))
            .transpose()
            .map(Option::flatten),
        Some(crate::searcher::SegLoc::Searcher(index)) => {
            match collection.searchers.get(*index as usize) {
                Some(searcher) => searcher.vector_visible(
                    id,
                    state.and_then(|state| state.point_tombstones(*index as usize)),
                    name,
                ),
                None => Ok(None),
            }
        }
        None => Ok(None),
    }
}

/// Match the existing exact-prefilter iterator's fallback/segment/ordinal order
/// while deferring every payload/vector read until the scoring visitor asks.
pub(super) fn visit_payload_candidates<'a>(
    collection: &'a Collection,
    state: &'a crate::overlay::OverlayReadState,
    candidates: &crate::payload_index::PayloadCandidateSet,
    resolver: &'a dyn crate::search::PointResolver,
    visit: &mut dyn FnMut(&str, crate::search::CandidateRead<'a>) -> Result<bool>,
) -> Result<()> {
    for id in &candidates.fallback {
        if collection.contains_in_read_state(state, id)
            && !visit(id, crate::search::CandidateRead::Resolver(resolver))?
        {
            return Ok(());
        }
    }
    for (segment_id, ordinals) in candidates.sealed.iter() {
        let Some((index, searcher)) = collection
            .searchers
            .iter()
            .enumerate()
            .find(|(_, searcher)| searcher.id == segment_id)
        else {
            continue;
        };
        let tombstones = state.point_tombstones(index);
        for ordinal in ordinals.iter() {
            let crate::searcher::SegmentStore::V4(store) = &searcher.store else {
                continue;
            };
            let id = store
                .id(ordinal as usize)
                .ok_or_else(|| GaussError::InvalidRequest("point ordinal out of range".into()))?;
            if searcher.contains_visible(id, tombstones)
                && !visit(id, crate::search::CandidateRead::Store(store))?
            {
                return Ok(());
            }
        }
    }
    Ok(())
}

pub(super) fn resolve<'a>(
    collection: &'a Collection,
    state: Option<&crate::overlay::OverlayReadState>,
    id: &str,
) -> Result<Option<CandidatePoint<'a>>> {
    Ok(match collection.id_index.get(id) {
        Some(crate::searcher::SegLoc::Streamer) => collection
            .streamer
            .points
            .get(id)
            .map(CandidatePoint::Borrowed),
        Some(crate::searcher::SegLoc::Sealing) => collection
            .sealing
            .as_ref()
            .and_then(|streamer| streamer.points.get(id))
            .map(CandidatePoint::Borrowed),
        Some(crate::searcher::SegLoc::Searcher(index)) => {
            let index = *index as usize;
            match collection.searchers.get(index) {
                Some(searcher) => match state {
                    Some(state) => {
                        searcher.get_visible_admitted(id, state.point_tombstones(index))?
                    }
                    None => searcher.get_live_admitted(id)?,
                },
                None => None,
            }
        }
        None => None,
    })
}
