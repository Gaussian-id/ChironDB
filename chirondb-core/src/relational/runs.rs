//! Ordered, newest-run-wins merge. At most one decoded head per immutable run
//! is retained; EOF validation must succeed before publishing a checkpoint.

use super::*;

pub(super) struct RunMerge {
    cursors: Vec<segment::SegmentCursor>,
    heads: Vec<Option<SegmentRecord>>,
    finished: bool,
    offsets: Vec<usize>,
}

impl RunMerge {
    pub(super) fn open(
        directory: &Path,
        kind: SegmentKind,
        references: &[RelationalSegmentReference],
    ) -> Result<Self> {
        if references.len() > RELATIONAL_MAX_RUNS_PER_TABLE {
            return Err(invalid("relational run count exceeds the manifest bound"));
        }
        let mut cursors = Vec::with_capacity(references.len());
        let mut heads = Vec::with_capacity(references.len());
        let mut offsets = Vec::with_capacity(references.len());
        let mut previous_sequence = 0;
        for reference in references {
            if reference.kind != kind || reference.sequence <= previous_sequence {
                return Err(relational_checkpoint_corruption(
                    Path::new(&reference.file_name),
                    "segment runs must have one kind and strictly increasing sequences",
                ));
            }
            previous_sequence = reference.sequence;
            let path = checkpoint_segment_path(directory, reference)?;
            let mut cursor = segment::SegmentCursor::open(&path)?;
            validate_segment_reference(reference, cursor.metadata())?;
            offsets.push(cursor.next_offset());
            heads.push(cursor.next().transpose()?);
            cursors.push(cursor);
        }
        Ok(Self {
            cursors,
            heads,
            finished: false,
            offsets,
        })
    }
}

impl RunMerge {
    pub(super) fn readers(&self) -> Vec<segment::SegmentReader> {
        self.cursors.iter().map(|cursor| cursor.reader()).collect()
    }

    pub(super) fn next_positioned(&mut self) -> Option<Result<(SegmentRecord, usize, usize)>> {
        if self.finished {
            return None;
        }
        let newest = self
            .heads
            .iter()
            .enumerate()
            .filter_map(|(index, head)| head.as_ref().map(|record| (index, &record.key)))
            .min_by(|(left_index, left_key), (right_index, right_key)| {
                left_key
                    .cmp(right_key)
                    .then_with(|| right_index.cmp(left_index))
            })
            .map(|(index, _)| index);
        let Some(newest) = newest else {
            self.finished = true;
            return None;
        };
        let record = self.heads[newest].take().expect("selected head");
        let offset = self.offsets[newest];
        for (index, (head, cursor)) in self.heads.iter_mut().zip(&mut self.cursors).enumerate() {
            if index == newest || head.as_ref().is_some_and(|other| other.key == record.key) {
                // Drop an obsolete value before allocating its successor.
                *head = None;
                self.offsets[index] = cursor.next_offset();
                match cursor.next().transpose() {
                    Ok(next) => *head = next,
                    Err(error) => {
                        self.finished = true;
                        return Some(Err(error));
                    }
                }
            }
        }
        Some(Ok((record, newest, offset)))
    }
}

impl Iterator for RunMerge {
    type Item = Result<SegmentRecord>;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_positioned()
            .map(|result| result.map(|(record, _, _)| record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn publish(
        directory: &Path,
        sequence: u64,
        records: &[SegmentRecord],
    ) -> RelationalSegmentReference {
        let name = format!("run-{sequence}.rseg");
        let metadata =
            write_segment(&directory.join(&name), SegmentKind::Row, sequence, records).unwrap();
        segment_reference(name, &metadata)
    }

    #[test]
    fn merge_matches_independent_map_with_one_resident_head_per_run() {
        let directory = tempdir().unwrap();
        let mut expected = BTreeMap::new();
        let mut references = Vec::new();
        for sequence in 1..=4 {
            let records = (0_u32..4000)
                .filter(|id| !(id + sequence as u32).is_multiple_of(3))
                .map(|id| SegmentRecord {
                    key: (id.to_be_bytes().to_vec()).into(),
                    value: (format!("sequence-{sequence}-id-{id}").into_bytes()).into(),
                })
                .collect::<Vec<_>>();
            expected.extend(
                records
                    .iter()
                    .map(|record| (record.key.to_vec(), record.value.to_vec())),
            );
            references.push(publish(directory.path(), sequence, &records));
        }
        let mut merge = RunMerge::open(directory.path(), SegmentKind::Row, &references).unwrap();
        for (key, value) in expected {
            let live = merge.heads.iter().flatten().collect::<Vec<_>>();
            assert!(live.len() <= 4);
            assert!(
                live.iter()
                    .map(|head| head.key.len() + head.value.len())
                    .sum::<usize>()
                    < 128
            );
            let actual = merge.next().unwrap().unwrap();
            assert_eq!(actual.key, key);
            assert_eq!(actual.value, value);
        }
        assert!(merge.next().is_none());
        assert!(merge.heads.iter().all(Option::is_none));
        assert!(merge.next().is_none());
    }

    #[test]
    fn merge_refuses_manifest_mismatch_order_and_corrupt_superseded_tail() {
        let directory = tempdir().unwrap();
        let records = (0_u32..300)
            .map(|id| SegmentRecord {
                key: (id.to_be_bytes().to_vec()).into(),
                value: (vec![42; 128]).into(),
            })
            .collect::<Vec<_>>();
        let old = publish(directory.path(), 1, &records);
        let new = publish(directory.path(), 2, &records);
        assert!(
            RunMerge::open(
                directory.path(),
                SegmentKind::Row,
                &[new.clone(), old.clone()]
            )
            .is_err()
        );
        let mut invalid = old.clone();
        invalid.record_count += 1;
        assert!(RunMerge::open(directory.path(), SegmentKind::Row, &[invalid]).is_err());
        assert!(
            RunMerge::open(
                directory.path(),
                SegmentKind::Index,
                std::slice::from_ref(&old)
            )
            .is_err()
        );
        let path = directory.path().join(&old.file_name);
        let mut encoded = fs::read(&path).unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        fs::write(path, encoded).unwrap();
        let mut merge = RunMerge::open(
            directory.path(),
            SegmentKind::Row,
            &[old.clone(), new.clone()],
        )
        .unwrap();
        assert!(merge.by_ref().collect::<Result<Vec<_>>>().is_err());
        assert!(merge.next().is_none());
        // Even unchanged output cannot mask damage in a superseded run.
        assert!(
            checkpoint::RunWriter {
                directory: directory.path(),
                sequence: 3,
                table_id: 1
            }
            .publish(
                SegmentKind::Row,
                &[],
                vec![old, new],
                checkpoint::RunMode::Delta { reclaim_before: 0 }
            )
            .is_err()
        );
        assert!(
            !directory
                .path()
                .join("row-00000000000000000003-00000000000000000001.rseg")
                .exists()
        );
    }

    #[test]
    fn checkpoint_streams_only_changed_records_and_publishes_empty_compaction() {
        let directory = tempdir().unwrap();
        let records = (0_u32..1000)
            .map(|id| SegmentRecord {
                key: (id.to_be_bytes().to_vec()).into(),
                value: (vec![42; 32]).into(),
            })
            .collect::<Vec<_>>();
        let first = checkpoint::RunWriter {
            directory: directory.path(),
            sequence: 1,
            table_id: 1,
        }
        .publish(
            SegmentKind::Row,
            &records,
            vec![],
            checkpoint::RunMode::Replace,
        )
        .unwrap();
        let unchanged = checkpoint::RunWriter {
            directory: directory.path(),
            sequence: 2,
            table_id: 1,
        }
        .publish(
            SegmentKind::Row,
            &[],
            first.clone(),
            checkpoint::RunMode::Delta { reclaim_before: 0 },
        )
        .unwrap();
        assert_eq!(unchanged[0].file_name, first[0].file_name);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        let mut changed = records;
        changed[512].value = b"changed".to_vec().into();
        changed.push(SegmentRecord {
            key: (1000_u32.to_be_bytes().to_vec()).into(),
            value: (b"new".to_vec()).into(),
        });
        let second = checkpoint::RunWriter {
            directory: directory.path(),
            sequence: 3,
            table_id: 1,
        }
        .publish(
            SegmentKind::Row,
            &[changed[512].clone(), changed[1000].clone()],
            unchanged,
            checkpoint::RunMode::Delta { reclaim_before: 0 },
        )
        .unwrap();
        assert_eq!(second.len(), 2);
        assert_eq!(second[1].record_count, 2);
        assert_eq!(
            RunMerge::open(directory.path(), SegmentKind::Row, &second)
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap(),
            changed
        );
        let empty = checkpoint::RunWriter {
            directory: directory.path(),
            sequence: 4,
            table_id: 1,
        }
        .publish(SegmentKind::Row, &[], second, checkpoint::RunMode::Replace)
        .unwrap();
        assert_eq!(empty.len(), 1);
        assert_eq!(empty[0].record_count, 0);
        assert!(
            RunMerge::open(directory.path(), SegmentKind::Row, &empty)
                .unwrap()
                .next()
                .is_none()
        );
    }
}
