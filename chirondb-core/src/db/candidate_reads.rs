//! Route candidate hydration through the pinned visibility authority.
use super::*;
use crate::search::CandidatePoint;

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
