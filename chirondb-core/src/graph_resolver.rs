#![cfg_attr(
    not(test),
    allow(dead_code, reason = "activated by the following GraphBatch slice")
)]

use std::collections::{HashMap, HashSet};

use crate::{GaussError, Result, graph::Nid};

/// Collection-local live point-incarnation authority.
///
/// The installation allocator makes every Nid globally unique. This resolver
/// maintains the one-to-one relationship between a collection's public point
/// ID and its current live incarnation. Retired Nids remain recorded and can
/// never become live again.
#[derive(Clone, Debug, Default)]
pub(crate) struct PointIncarnationResolver {
    live_by_point: HashMap<String, Nid>,
    live_by_nid: HashMap<Nid, String>,
    retired: HashSet<Nid>,
}

impl PointIncarnationResolver {
    pub(crate) fn live_bindings(&self) -> impl Iterator<Item = (&str, Nid)> {
        self.live_by_point
            .iter()
            .map(|(id, nid)| (id.as_str(), *nid))
    }

    pub(crate) fn retired_nids(&self) -> impl Iterator<Item = Nid> + '_ {
        self.retired.iter().copied()
    }

    pub(crate) fn from_checkpoint(live: Vec<(String, Nid)>, retired: Vec<Nid>) -> Result<Self> {
        let mut resolver = Self::default();
        for nid in retired {
            if Nid::from_parts(nid.epoch(), nid.counter()) != Some(nid)
                || !resolver.retired.insert(nid)
            {
                return Err(invalid("invalid or duplicate retired checkpoint Nid"));
            }
        }
        for (id, nid) in live {
            if id.is_empty()
                || id.len() > 1024
                || Nid::from_parts(nid.epoch(), nid.counter()) != Some(nid)
                || resolver.live_by_point.contains_key(&id)
            {
                return Err(invalid("invalid or duplicate live checkpoint binding"));
            }
            resolver.bind_live(id, nid)?;
        }
        Ok(resolver)
    }

    pub(crate) fn live_nid(&self, point_id: &str) -> Option<Nid> {
        self.live_by_point.get(point_id).copied()
    }

    pub(crate) fn live_point_id(&self, nid: Nid) -> Option<&str> {
        self.live_by_nid.get(&nid).map(String::as_str)
    }

    pub(crate) fn is_retired(&self, nid: Nid) -> bool {
        self.retired.contains(&nid)
    }

    pub(crate) fn live_len(&self) -> usize {
        self.live_by_point.len()
    }

    pub(crate) fn retired_len(&self) -> usize {
        self.retired.len()
    }

    /// Install or idempotently replay one live assignment. A point ID cannot
    /// silently change Nid while live, and a Nid cannot move to another point
    /// or return after retirement.
    pub(crate) fn bind_live(&mut self, point_id: String, nid: Nid) -> Result<()> {
        if !nid.is_assigned() {
            return Err(invalid("Nid=0 cannot identify a live graph node"));
        }
        if self.retired.contains(&nid) {
            return Err(invalid("a retired Nid cannot become live again"));
        }
        if let Some(existing) = self.live_by_point.get(&point_id) {
            return if *existing == nid {
                Ok(())
            } else {
                Err(invalid("a live point ID cannot change Nid"))
            };
        }
        if self.live_by_nid.contains_key(&nid) {
            return Err(invalid("a live Nid cannot identify two point IDs"));
        }

        self.live_by_nid.insert(nid, point_id.clone());
        self.live_by_point.insert(point_id, nid);
        Ok(())
    }

    /// Retire the current incarnation. Repeating a delete is a no-op. The
    /// retired watermark is retained so replay/corruption can never rebind it.
    pub(crate) fn retire(&mut self, point_id: &str) -> Option<Nid> {
        let nid = self.live_by_point.remove(point_id)?;
        self.live_by_nid.remove(&nid);
        self.retired.insert(nid);
        Some(nid)
    }
}

fn invalid(message: &str) -> GaussError {
    GaussError::InvalidRequest(format!("invalid graph incarnation assignment: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(counter: u64) -> Nid {
        Nid::from_parts(7, counter).unwrap()
    }

    #[test]
    fn existing_upsert_preserves_nid_and_reinsert_gets_fresh_incarnation() {
        let mut resolver = PointIncarnationResolver::default();
        resolver.bind_live("point-a".to_string(), nid(1)).unwrap();

        assert_eq!(resolver.live_nid("point-a"), Some(nid(1)));
        resolver.bind_live("point-a".to_string(), nid(1)).unwrap();
        assert_eq!(resolver.live_len(), 1);

        assert_eq!(resolver.retire("point-a"), Some(nid(1)));
        assert_eq!(resolver.retire("point-a"), None);
        assert_eq!(resolver.live_nid("point-a"), None);
        assert!(resolver.is_retired(nid(1)));

        resolver.bind_live("point-a".to_string(), nid(2)).unwrap();
        assert_eq!(resolver.live_nid("point-a"), Some(nid(2)));
        assert_eq!(resolver.live_point_id(nid(2)), Some("point-a"));
        assert_eq!(resolver.retired_len(), 1);
    }

    #[test]
    fn conflicts_and_retired_reuse_fail_closed() {
        let mut resolver = PointIncarnationResolver::default();
        resolver.bind_live("point-a".to_string(), nid(1)).unwrap();
        assert!(resolver.bind_live("point-a".to_string(), nid(2)).is_err());
        assert!(resolver.bind_live("point-b".to_string(), nid(1)).is_err());
        assert!(
            resolver
                .bind_live("point-zero".to_string(), Nid::UNASSIGNED)
                .is_err()
        );

        resolver.retire("point-a");
        assert!(resolver.bind_live("point-b".to_string(), nid(1)).is_err());
    }
}
