//! Segment-scoped ordinal sets used by sealed visibility and filtering.
//!
//! Mutable streamers and legacy stores remain string-keyed. Current sealed
//! stores have a stable ordinal domain, so internal candidate exchange uses
//! one Roaring bitmap per segment and materializes point IDs only when a
//! result crosses back into an ID-oriented compatibility boundary.

use std::{collections::HashMap, sync::Arc};

use roaring::RoaringBitmap;

/// A collection-wide set of sealed point locations.
///
/// Ordinals are meaningful only inside their owning segment, hence the outer
/// segment key. Empty bitmaps are not retained.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SegmentOrdinalSet {
    segments: HashMap<String, Arc<RoaringBitmap>>,
}

impl SegmentOrdinalSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_bitmap(&mut self, segment: impl Into<String>, bitmap: RoaringBitmap) {
        let segment = segment.into();
        if bitmap.is_empty() {
            self.segments.remove(&segment);
        } else {
            self.segments.insert(segment, Arc::new(bitmap));
        }
    }

    pub fn insert(&mut self, segment: impl Into<String>, ordinal: u32) -> bool {
        Arc::make_mut(
            self.segments
                .entry(segment.into())
                .or_insert_with(|| Arc::new(RoaringBitmap::new())),
        )
        .insert(ordinal)
    }

    pub fn contains(&self, segment: &str, ordinal: u32) -> bool {
        self.segments
            .get(segment)
            .is_some_and(|bitmap| bitmap.contains(ordinal))
    }

    pub fn bitmap(&self, segment: &str) -> Option<&RoaringBitmap> {
        self.segments.get(segment).map(Arc::as_ref)
    }

    /// Clone a segment bitmap handle without copying its ordinal payload.
    ///
    /// Query read states use this to resolve the collection-wide string key
    /// once per installed segment and then carry a direct bitmap handle
    /// through candidate loops.
    pub(crate) fn bitmap_arc(&self, segment: &str) -> Option<Arc<RoaringBitmap>> {
        self.segments.get(segment).cloned()
    }

    pub fn bitmap_mut(&mut self, segment: &str) -> Option<&mut RoaringBitmap> {
        self.segments.get_mut(segment).map(Arc::make_mut)
    }

    pub fn remove_segment(&mut self, segment: &str) -> Option<RoaringBitmap> {
        self.segments.remove(segment).map(Arc::unwrap_or_clone)
    }

    pub fn retain_segments(&mut self, mut keep: impl FnMut(&str) -> bool) {
        self.segments.retain(|segment, _| keep(segment));
    }

    pub fn len(&self) -> u64 {
        self.segments.values().map(|bitmap| bitmap.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &RoaringBitmap)> {
        self.segments
            .iter()
            .map(|(segment, bitmap)| (segment.as_str(), bitmap.as_ref()))
    }

    pub fn union_with(&mut self, other: &Self) {
        for (segment, other_bitmap) in &other.segments {
            match self.segments.entry(segment.clone()) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    *Arc::make_mut(entry.get_mut()) |= other_bitmap.as_ref();
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(Arc::clone(other_bitmap));
                }
            }
        }
    }

    pub fn intersect_with(&mut self, other: &Self) {
        self.segments.retain(|segment, bitmap| {
            let Some(other_bitmap) = other.segments.get(segment) else {
                return false;
            };
            *Arc::make_mut(bitmap) &= other_bitmap.as_ref();
            !bitmap.is_empty()
        });
    }

    pub fn subtract(&mut self, other: &Self) {
        self.segments.retain(|segment, bitmap| {
            if let Some(other_bitmap) = other.segments.get(segment) {
                *Arc::make_mut(bitmap) -= other_bitmap.as_ref();
            }
            !bitmap.is_empty()
        });
    }
}

impl crate::index::OrdinalFilterPredicate for SegmentOrdinalSet {
    fn matches_ordinal(&self, segment: &str, ordinal: u32) -> bool {
        self.contains(segment, ordinal)
    }
}

#[cfg(test)]
mod tests {
    use roaring::RoaringBitmap;

    use super::SegmentOrdinalSet;

    fn bitmap(values: impl IntoIterator<Item = u32>) -> RoaringBitmap {
        values.into_iter().collect()
    }

    #[test]
    fn set_algebra_is_segment_scoped() {
        let mut left = SegmentOrdinalSet::new();
        left.insert_bitmap("a", bitmap([1, 2, 4]));
        left.insert_bitmap("b", bitmap([8]));

        let mut right = SegmentOrdinalSet::new();
        right.insert_bitmap("a", bitmap([2, 3, 4]));
        right.insert_bitmap("c", bitmap([9]));

        let mut intersection = left.clone();
        intersection.intersect_with(&right);
        assert_eq!(intersection.len(), 2);
        assert!(intersection.contains("a", 2));
        assert!(intersection.contains("a", 4));
        assert!(!intersection.contains("b", 8));

        left.union_with(&right);
        assert_eq!(left.len(), 6);
        assert!(left.contains("c", 9));

        left.subtract(&right);
        assert_eq!(left.len(), 2);
        assert!(left.contains("a", 1));
        assert!(left.contains("b", 8));
    }
}
