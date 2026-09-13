use crate::{
    Result,
    graph::{GraphEpoch, GraphError, GraphErrorCode},
};

/// Collection-global graph lifecycle reconstructed from `GraphEpochAdvance`
/// WAL records. Every real transition advances the epoch; idempotent API
/// retries do not manufacture a new epoch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct GraphLifecycleState {
    epoch: Option<GraphEpoch>,
    enabled: bool,
}

impl GraphLifecycleState {
    pub(crate) fn from_checkpoint(epoch: GraphEpoch, enabled: bool) -> Result<Self> {
        if GraphEpoch::from_raw(epoch.raw()).is_none() {
            return Err(GraphError::new(
                GraphErrorCode::EpochMismatch,
                "checkpoint graph epoch is zero",
            )
            .into());
        }
        // Replay starts enabled at epoch 1 and every real transition toggles
        // state and increments exactly once. Checkpoints must obey that history.
        if enabled != (epoch.raw() % 2 == 1) {
            return Err(GraphError::new(
                GraphErrorCode::EpochMismatch,
                "checkpoint lifecycle disagrees with graph epoch",
            )
            .into());
        }
        Ok(Self {
            epoch: Some(epoch),
            enabled,
        })
    }

    pub(crate) fn epoch(self) -> Option<GraphEpoch> {
        self.epoch
    }

    pub(crate) fn is_enabled(self) -> bool {
        self.enabled
    }

    pub(crate) fn next_epoch(self) -> Result<GraphEpoch> {
        match self.epoch {
            Some(epoch) => epoch.next().ok_or_else(|| {
                GraphError::new(
                    GraphErrorCode::EpochMismatch,
                    "graph epoch space is exhausted",
                )
                .into()
            }),
            None => Ok(GraphEpoch::INITIAL),
        }
    }

    pub(crate) fn apply_advance(&mut self, epoch: GraphEpoch, enabled: bool) -> Result<()> {
        let expected = self.next_epoch()?;
        if epoch != expected {
            return Err(GraphError::new(
                GraphErrorCode::EpochMismatch,
                format!(
                    "graph epoch transition expected {}, got {}",
                    expected.raw(),
                    epoch.raw()
                ),
            )
            .into());
        }
        if self.enabled == enabled {
            return Err(GraphError::new(
                GraphErrorCode::EpochMismatch,
                if enabled {
                    "graph enable requires a previously disabled collection"
                } else {
                    "graph drop requires a previously enabled collection"
                },
            )
            .into());
        }
        self.epoch = Some(epoch);
        self.enabled = enabled;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_lifecycle_matches_replay_transitions() {
        for raw in 1..=8 {
            let epoch = GraphEpoch::from_raw(raw).unwrap();
            let enabled = raw % 2 == 1;
            let state = GraphLifecycleState::from_checkpoint(epoch, enabled).unwrap();
            assert_eq!(state.epoch(), Some(epoch));
            assert_eq!(state.is_enabled(), enabled);
            assert!(GraphLifecycleState::from_checkpoint(epoch, !enabled).is_err());
            let mut advanced = state;
            advanced
                .apply_advance(state.next_epoch().unwrap(), !enabled)
                .unwrap();
        }
    }

    #[test]
    fn enable_drop_and_reenable_advance_without_reusing_epoch() {
        let mut state = GraphLifecycleState::default();
        assert_eq!(state.next_epoch().unwrap(), GraphEpoch::INITIAL);
        state.apply_advance(GraphEpoch::INITIAL, true).unwrap();
        assert!(state.is_enabled());

        let dropped = GraphEpoch::from_raw(2).unwrap();
        state.apply_advance(dropped, false).unwrap();
        assert!(!state.is_enabled());

        let reenabled = GraphEpoch::from_raw(3).unwrap();
        state.apply_advance(reenabled, true).unwrap();
        assert_eq!(state.epoch(), Some(reenabled));
    }

    #[test]
    fn invalid_transition_keeps_prior_state() {
        let mut state = GraphLifecycleState::default();
        state.apply_advance(GraphEpoch::INITIAL, true).unwrap();
        let before = state;
        assert!(
            state
                .apply_advance(GraphEpoch::from_raw(3).unwrap(), false)
                .is_err()
        );
        assert_eq!(state, before);
        assert!(
            state
                .apply_advance(GraphEpoch::from_raw(2).unwrap(), true)
                .is_err()
        );
        assert_eq!(state, before);
    }
}
