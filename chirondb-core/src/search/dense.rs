//! Dense scoring retains a bounded batch and only the winning IDs/scores.
use super::*;
use rayon::prelude::*;

pub(crate) fn dense_hits(
    resolver: &dyn PointResolver,
    ranked: Rankings,
    with_payload: bool,
    should_stop: &dyn Fn() -> bool,
) -> Result<(
    Vec<SearchHit>,
    crate::security::output::OutputAdmission,
    bool,
)> {
    let mut hits = crate::security::output::Hits::default();
    let mut degraded = false;
    for row in ranked.iter() {
        if should_stop() {
            degraded = true;
            break;
        }
        if with_payload {
            if let Some(point) = resolver.resolve_candidate(&row.id)? {
                hits.push(
                    &row.id,
                    row.score,
                    crate::relational::wal_decode::borrowed_json(&point.payload)?,
                )?;
            }
        } else {
            hits.push(
                &row.id,
                row.score,
                crate::relational::wal_decode::borrowed_json(&serde_json::Value::Null)?,
            )?;
        }
        // A payload read/copy may itself cross the soft deadline. Retain the
        // completed hit, mark degradation, and begin no further reads.
        if should_stop() {
            degraded = true;
            break;
        }
    }
    // Keep payload, ID and container leases through the native DTO handoff.
    let (hits, admission) = hits.into_parts();
    Ok((hits, admission, degraded))
}

/// Only scalar equality/IN on plain top-level keys is an exact membership proof.
/// Paths can collide with literal dotted keys, and compound ranges on arrays
/// can admit a point whose separate elements satisfy different bounds.
pub(crate) fn indexed_filter_is_exact(filter: Option<&Filter>) -> bool {
    filter.is_some_and(|filter| {
        filter.0.as_object().is_some_and(|conditions| {
            !conditions.is_empty()
                && conditions.iter().all(|(field, expected)| {
                    !field.is_empty()
                        && field
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                        && expected.as_object().is_none_or(|operators| {
                            operators.len() == 1
                                && (operators.contains_key("eq") || operators.contains_key("in"))
                        })
                })
        }) && filter.indexed_predicates().is_some_and(|predicates| {
            predicates.iter().all(|predicate| {
                matches!(predicate,
                crate::filter::IndexedFilterPredicate::Equality(term)
                if term.values.iter().all(|value| !value.is_array() && !value.is_object()))
            })
        })
    })
}

enum DenseInput<'a> {
    Point(CandidatePoint<'a>),
    Vector {
        id: String,
        vector: Option<crate::index::VectorRead<'a>>,
        _memory: crate::relational::wal_decode::MetadataCharge,
    },
}
impl DenseInput<'_> {
    fn id(&self) -> &str {
        match self {
            Self::Point(point) => &point.id,
            Self::Vector { id, .. } => id,
        }
    }
    fn matches(&self, filter: Option<&Filter>) -> bool {
        match self {
            Self::Point(point) => filter.is_none_or(|filter| filter.matches(&point.payload)),
            Self::Vector { .. } => true,
        }
    }
    fn vector(&self, name: Option<&str>) -> Option<&[f32]> {
        match self {
            Self::Point(point) => point_vector(point, name),
            Self::Vector { vector, .. } => vector.as_deref(),
        }
    }
}

// Reuse the existing parallel crossover as the maximum hydrated batch size.
const BATCH_SIZE: usize = 128;

#[cfg(test)]
mod tests;

pub(crate) struct DenseSearchParams<'a> {
    pub(crate) query: &'a [f32],
    pub(crate) vector_name: Option<&'a str>,
    pub(crate) metric: crate::DistanceMetric,
    pub(crate) k: usize,
    pub(crate) filter: Option<&'a Filter>,
    pub(crate) excluded: &'a HashSet<String>,
    pub(crate) eligible: &'a dyn Fn(&str) -> bool,
    pub(crate) should_stop: &'a dyn Fn() -> bool,
    pub(crate) parallel: bool,
    pub(crate) payload_free: bool,
}

pub(crate) struct DenseRanker<'a, 'p> {
    params: DenseSearchParams<'p>,
    pending: AdmittedVec<DenseInput<'a>>,
    ranked: RankedHeap,
    pub(crate) searched: usize,
    scored: usize,
    pub(crate) degraded: bool,
    visited: usize,
}

impl<'a, 'p> DenseRanker<'a, 'p> {
    pub(crate) fn new(params: DenseSearchParams<'p>) -> Self {
        Self {
            ranked: RankedHeap::new(params.k),
            params,
            pending: AdmittedVec::default(),
            searched: 0,
            scored: 0,
            degraded: false,
            visited: 0,
        }
    }

    pub(crate) fn visit(&mut self, id: &str, source: CandidateRead<'a>) -> Result<bool> {
        self.visited += 1;
        if self.params.excluded.contains(id) {
            return Ok(true);
        }
        if (self.params.should_stop)() {
            self.degraded = true;
            return Ok(false);
        }
        if !(self.params.eligible)(id) {
            return Ok(true);
        }
        let input = if self.params.payload_free
            && let CandidateRead::Point(point) = source
        {
            // Live candidates already have a stable borrowed ID/vector.
            DenseInput::Point(CandidatePoint::Borrowed(point))
        } else if self.params.payload_free {
            let mut memory = crate::relational::wal_decode::MetadataCharge::default();
            memory.prepare(id.len() as u64 + 128)?;
            let mut copied = String::new();
            copied.try_reserve_exact(id.len()).map_err(|_| {
                GaussError::ResourceExhausted("dense candidate ID memory is full".into())
            })?;
            copied.push_str(id);
            DenseInput::Vector {
                id: copied,
                vector: source.vector(id, self.params.vector_name)?,
                _memory: memory,
            }
        } else if let Some(point) = source.resolve(id)? {
            DenseInput::Point(point)
        } else {
            return Ok(true);
        };
        if self.params.parallel {
            self.pending.push(input)?;
            if self.pending.len() == BATCH_SIZE {
                self.flush(true)?;
            }
        } else {
            self.score_serial(&input)?;
        }
        Ok(true)
    }

    pub(crate) fn force_serial(&mut self) {
        self.params.parallel = false;
    }

    fn score_serial(&mut self, input: &DenseInput<'_>) -> Result<()> {
        if (self.params.should_stop)() {
            self.degraded = true;
            return Ok(());
        }
        if !input.matches(self.params.filter.filter(|_| !self.params.payload_free)) {
            return Ok(());
        }
        // Preserve the existing serial/parallel named-vector counters.
        self.searched += 1;
        if let Some(vector) = input.vector(self.params.vector_name) {
            self.ranked.copy_push(
                input.id(),
                self.params.metric.score(self.params.query, vector)?,
            )?;
            self.scored += 1;
        }
        Ok(())
    }

    fn flush(&mut self, parallel: bool) -> Result<()> {
        let mut pending = std::mem::take(&mut self.pending);
        if parallel {
            let query = self.params.query;
            let metric = self.params.metric;
            let vector_name = self.params.vector_name;
            let filter = self.params.filter.filter(|_| !self.params.payload_free);
            let k = self.params.k;
            let partials: Result<AdmittedVec<(Rankings, usize)>> = crate::search_pool::SEARCH_POOL
                .install(|| {
                    pending
                        .par_chunks(
                            BATCH_SIZE
                                .div_ceil(crate::search_pool::SEARCH_POOL.current_num_threads()),
                        )
                        .map(|chunk| -> Result<(Rankings, usize)> {
                            let mut heap = RankedHeap::new(k);
                            let mut searched = 0;
                            for point in chunk {
                                if !point.matches(filter) {
                                    continue;
                                }
                                if let Some(vector) = point.vector(vector_name) {
                                    heap.copy_push(point.id(), metric.score(query, vector)?)?;
                                    searched += 1;
                                }
                            }
                            Ok((heap.finish(), searched))
                        })
                        .try_fold(AdmittedVec::default, |mut rows, partial| {
                            rows.push(partial?)?;
                            Ok(rows)
                        })
                        .try_reduce(AdmittedVec::default, |mut left, right| {
                            for partial in right {
                                left.push(partial)?;
                            }
                            Ok(left)
                        })
                });
            for (rows, searched) in partials? {
                self.searched += searched;
                self.scored += searched;
                for row in rows.iter() {
                    self.ranked.copy_push(&row.id, row.score)?;
                }
            }
        } else {
            for point in pending.values.drain(..) {
                self.score_serial(&point)?;
                if self.degraded {
                    break;
                }
            }
        }
        pending.values.clear();
        self.pending = pending;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<(Rankings, usize, usize, bool)> {
        if !self.pending.is_empty() {
            self.flush(self.params.parallel && self.visited >= BATCH_SIZE)?;
        }
        Ok((
            self.ranked.finish(),
            self.searched,
            self.scored,
            self.degraded,
        ))
    }
}
