//! Immutable EdgeId-only authority. Union scans retain one bounded cursor per
//! selected run, not a collection-wide membership bitmap or endpoint records.

use std::{cmp::Reverse, collections::BinaryHeap, sync::Arc};

use crate::{
    GaussError, Result, graph::EdgeId, graph_edgeid::OpenedEdgeLedgerRun, graph_group::EdgeIdCursor,
};

#[derive(Clone, Default)]
pub(crate) struct SealedLedger {
    readers: Arc<[Arc<OpenedEdgeLedgerRun>]>,
    unique_keys: u64,
}

impl std::fmt::Debug for SealedLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedLedger")
            .field("runs", &self.readers.len())
            .field("unique_keys", &self.unique_keys)
            .finish()
    }
}

impl SealedLedger {
    pub(super) fn new(readers: Vec<Arc<OpenedEdgeLedgerRun>>) -> Result<Self> {
        let mut ledger = Self {
            readers: readers.into(),
            unique_keys: 0,
        };
        ledger.unique_keys = ledger.keys()?.try_fold(0_u64, |count, id| {
            id?;
            count
                .checked_add(1)
                .ok_or_else(|| GaussError::InvalidRequest("graph ledger key count overflow".into()))
        })?;
        Ok(ledger)
    }

    pub(crate) fn len(&self) -> u64 {
        self.unique_keys
    }

    pub(super) fn readers(&self) -> &[Arc<OpenedEdgeLedgerRun>] {
        &self.readers
    }

    pub(crate) fn contains(&self, id: EdgeId) -> Result<bool> {
        for reader in self.readers.iter().rev() {
            if reader.contains(id)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn keys(&self) -> Result<LedgerKeys<'_>> {
        Ok(LedgerKeys {
            cursors: self
                .readers
                .iter()
                .map(|reader| reader.keys())
                .collect::<Result<Vec<_>>>()?,
            heap: BinaryHeap::new(),
            previous: None,
            initialized: false,
            failed: false,
        })
    }
}

pub(crate) struct LedgerKeys<'a> {
    cursors: Vec<EdgeIdCursor<'a>>,
    heap: BinaryHeap<Reverse<(EdgeId, usize)>>,
    previous: Option<EdgeId>,
    initialized: bool,
    failed: bool,
}

impl LedgerKeys<'_> {
    fn read_next(&mut self) -> Result<Option<EdgeId>> {
        if !self.initialized {
            for (index, cursor) in self.cursors.iter_mut().enumerate() {
                if let Some(id) = cursor.next() {
                    self.heap.push(Reverse((id?, index)));
                }
            }
            self.initialized = true;
        }
        while let Some(Reverse((id, index))) = self.heap.pop() {
            if let Some(next) = self.cursors[index].next() {
                self.heap.push(Reverse((next?, index)));
            }
            if self.previous != Some(id) {
                self.previous = Some(id);
                return Ok(Some(id));
            }
        }
        Ok(None)
    }
}

impl Iterator for LedgerKeys<'_> {
    type Item = Result<EdgeId>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        match self.read_next() {
            Ok(id) => id.map(Ok),
            Err(error) => {
                self.failed = true;
                self.heap.clear();
                self.cursors.clear();
                Some(Err(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        graph::GraphEpoch,
        graph_edgeid::{self, EdgeLedgerRun, EdgeLedgerRunKind, EdgeLedgerRunMetadata},
    };
    use std::{collections::BTreeSet, fs, path::Path};

    fn edge(id: u64) -> EdgeId {
        EdgeId::from_parts(3, id).unwrap()
    }

    fn reader(dir: &Path, index: usize, keys: Vec<EdgeId>) -> Arc<OpenedEdgeLedgerRun> {
        let path = dir.join(format!("run-{index}.gdx"));
        let run = EdgeLedgerRun::build(
            EdgeLedgerRunMetadata {
                graph_epoch: GraphEpoch::INITIAL,
                first_lsn: index as u64,
                last_lsn: index as u64,
                kind: if index == 0 {
                    EdgeLedgerRunKind::Base
                } else {
                    EdgeLedgerRunKind::Delta
                },
            },
            keys,
        )
        .unwrap();
        graph_edgeid::write(&path, &run).unwrap();
        Arc::new(graph_edgeid::open(&path).unwrap())
    }

    #[test]
    fn streaming_union_deduplicates_across_chunks_plaintext_and_encrypted() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use std::{env, process::Command};
        const MODE: &str = "CHIRONDB_LEDGER_UNION_TEST_MODE";
        const ROOT: &str = "CHIRONDB_LEDGER_UNION_TEST_ROOT";
        const TEST: &str = "graph_generation::ledger::tests::streaming_union_deduplicates_across_chunks_plaintext_and_encrypted";
        let Some(mode) = env::var_os(MODE) else {
            for mode in ["plaintext", "encrypted"] {
                let temp = tempfile::tempdir().unwrap();
                assert!(
                    Command::new(env::current_exe().unwrap())
                        .args(["--exact", TEST, "--nocapture"])
                        .env(MODE, mode)
                        .env(ROOT, temp.path())
                        .status()
                        .unwrap()
                        .success()
                );
            }
            return;
        };
        let root = std::path::PathBuf::from(env::var_os(ROOT).unwrap());
        if mode == "encrypted" {
            let path = root.join("keyring.json");
            fs::write(&path, serde_json::json!({"version":1,"active_key_id":"ledger-union","keys":[{"id":"ledger-union","key_base64":STANDARD.encode([96;32])}]}).to_string()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            crate::encryption::install_process_keyring(
                crate::encryption::Keyring::load(&path).unwrap(),
                true,
            )
            .unwrap();
        }
        let runs = [
            (1..=20_000).map(edge).collect::<Vec<_>>(),
            (10_000..=30_000).step_by(2).map(edge).collect(),
            vec![],
            vec![edge(1), edge(10_000), EdgeId::from_parts(4, 1).unwrap()],
        ];
        let expected = runs.iter().flatten().copied().collect::<BTreeSet<_>>();
        let ledger = SealedLedger::new(
            runs.into_iter()
                .enumerate()
                .map(|(index, keys)| reader(&root, index, keys))
                .collect(),
        )
        .unwrap();
        assert_eq!(ledger.len(), expected.len() as u64);
        assert_eq!(
            ledger.keys().unwrap().collect::<Result<Vec<_>>>().unwrap(),
            expected.into_iter().collect::<Vec<_>>()
        );
        assert_eq!(
            ledger
                .keys()
                .unwrap()
                .take(3)
                .collect::<Result<Vec<_>>>()
                .unwrap(),
            vec![edge(1), edge(2), edge(3)]
        );
        for id in [
            edge(1),
            edge(8192),
            edge(20_000),
            edge(30_000),
            EdgeId::from_parts(4, 1).unwrap(),
        ] {
            assert!(ledger.contains(id).unwrap());
        }
        for id in [
            EdgeId::from_raw(0),
            edge(20_001),
            edge(30_001),
            EdgeId::from_parts(4, 2).unwrap(),
        ] {
            assert!(!ledger.contains(id).unwrap());
        }
        let pinned = ledger.clone();
        assert!(Arc::ptr_eq(&ledger.readers, &pinned.readers));
        drop(ledger);
        assert!(pinned.contains(edge(30_000)).unwrap());
        let empty = SealedLedger::new(vec![reader(&root, 5, vec![])]).unwrap();
        assert_eq!(empty.len(), 0);
        assert!(empty.keys().unwrap().next().is_none());
        assert!(!empty.contains(edge(1)).unwrap());
    }

    #[test]
    fn union_read_failure_is_reported_once_and_never_becomes_exhaustion() {
        let temp = tempfile::tempdir().unwrap();
        let _reader = reader(temp.path(), 0, (1..=8192).map(edge).collect());
        // Deliberately oversized cursor over a valid immutable section: the
        // second range fails without truncating/mutating a mapped file.
        let artifact = crate::graph_artifact::open(
            &temp.path().join("run-0.gdx"),
            crate::graph_artifact::ArtifactSpec {
                magic: graph_edgeid::EDGEID_MAGIC,
                allowed_flags: 3,
                required_sections: &[1, 2],
                optional_sections: &[],
                max_file_len: u64::MAX,
            },
        )
        .unwrap();
        let cursor = EdgeIdCursor::new(
            &artifact,
            2,
            &crate::graph_group::GroupFrame {
                elem_count: 8193,
                payload_offset: 0,
                payload_len: 8193 * 8,
            },
            0..8193,
        )
        .unwrap();
        let mut keys = LedgerKeys {
            cursors: vec![cursor],
            heap: BinaryHeap::new(),
            previous: None,
            initialized: false,
            failed: false,
        };
        for id in 1..8192 {
            assert_eq!(keys.next().unwrap().unwrap(), edge(id));
        }
        assert!(keys.next().unwrap().is_err());
        assert!(keys.next().is_none());
        assert!(keys.next().is_none());
        assert!(keys.cursors.is_empty());
        assert!(keys.heap.is_empty());
    }
}
