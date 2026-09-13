//! Feature-gated structural counters for one dense-search request.
//!
//! Timed release builds leave `search-metrics` disabled. The recording macro
//! then expands to nothing, including the expression used to calculate the
//! increment. Diagnostic builds use a request-local atomic collector so Rayon
//! cell scoring can contribute without mixing concurrent requests.

use serde::Serialize;

/// Observable work performed by LS-VEC for one request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SearchMetrics {
    pub estimator_calls: u64,
    pub graph_hops: u64,
    pub graph_traversals: u64,
    pub cells_touched: u64,
    pub entries_touched: u64,
    pub posting_scan_calls: u64,
    pub posting_records_scanned: u64,
    pub posting_scan_estimator_calls: u64,
    pub valid_record_admissions: u64,
    pub invalid_record_admissions: u64,
    pub filter_rejections: u64,
    pub exact_reranks: u64,
    pub heap_pushes: u64,
    pub heap_pops: u64,
    pub returned_count: u64,
    pub underfilled_count: u64,
    pub degraded_count: u64,
    pub cancelled_count: u64,
}

impl SearchMetrics {
    pub fn total_distance_work(&self) -> u64 {
        self.estimator_calls + self.exact_reranks
    }

    pub fn accumulate(&mut self, other: Self) {
        self.estimator_calls += other.estimator_calls;
        self.graph_hops += other.graph_hops;
        self.graph_traversals += other.graph_traversals;
        self.cells_touched += other.cells_touched;
        self.entries_touched += other.entries_touched;
        self.posting_scan_calls += other.posting_scan_calls;
        self.posting_records_scanned += other.posting_records_scanned;
        self.posting_scan_estimator_calls += other.posting_scan_estimator_calls;
        self.valid_record_admissions += other.valid_record_admissions;
        self.invalid_record_admissions += other.invalid_record_admissions;
        self.filter_rejections += other.filter_rejections;
        self.exact_reranks += other.exact_reranks;
        self.heap_pushes += other.heap_pushes;
        self.heap_pops += other.heap_pops;
        self.returned_count += other.returned_count;
        self.underfilled_count += other.underfilled_count;
        self.degraded_count += other.degraded_count;
        self.cancelled_count += other.cancelled_count;
    }
}

#[cfg(feature = "search-metrics")]
#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum Counter {
    EstimatorCalls,
    GraphHops,
    GraphTraversals,
    CellsTouched,
    EntriesTouched,
    PostingScanCalls,
    PostingRecordsScanned,
    PostingScanEstimatorCalls,
    ValidRecordAdmissions,
    InvalidRecordAdmissions,
    FilterRejections,
    ExactReranks,
    HeapPushes,
    HeapPops,
    ReturnedCount,
    UnderfilledCount,
    DegradedCount,
    CancelledCount,
}

#[cfg(feature = "search-metrics")]
mod imp {
    use super::{Counter, SearchMetrics};
    use std::{
        cell::RefCell,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };

    const COUNTERS: usize = 18;

    pub(crate) struct Collector {
        values: [AtomicU64; COUNTERS],
    }

    impl Collector {
        fn new() -> Self {
            Self {
                values: std::array::from_fn(|_| AtomicU64::new(0)),
            }
        }

        fn add(&self, counter: Counter, amount: u64) {
            self.values[counter as usize].fetch_add(amount, Ordering::Relaxed);
        }

        fn get(&self, counter: Counter) -> u64 {
            self.values[counter as usize].load(Ordering::Relaxed)
        }

        fn snapshot(&self) -> SearchMetrics {
            SearchMetrics {
                estimator_calls: self.get(Counter::EstimatorCalls),
                graph_hops: self.get(Counter::GraphHops),
                graph_traversals: self.get(Counter::GraphTraversals),
                cells_touched: self.get(Counter::CellsTouched),
                entries_touched: self.get(Counter::EntriesTouched),
                posting_scan_calls: self.get(Counter::PostingScanCalls),
                posting_records_scanned: self.get(Counter::PostingRecordsScanned),
                posting_scan_estimator_calls: self.get(Counter::PostingScanEstimatorCalls),
                valid_record_admissions: self.get(Counter::ValidRecordAdmissions),
                invalid_record_admissions: self.get(Counter::InvalidRecordAdmissions),
                filter_rejections: self.get(Counter::FilterRejections),
                exact_reranks: self.get(Counter::ExactReranks),
                heap_pushes: self.get(Counter::HeapPushes),
                heap_pops: self.get(Counter::HeapPops),
                returned_count: self.get(Counter::ReturnedCount),
                underfilled_count: self.get(Counter::UnderfilledCount),
                degraded_count: self.get(Counter::DegradedCount),
                cancelled_count: self.get(Counter::CancelledCount),
            }
        }
    }

    thread_local! {
        static CURRENT: RefCell<Option<Arc<Collector>>> = const { RefCell::new(None) };
    }

    pub(crate) struct Attachment(Option<Arc<Collector>>);

    impl Drop for Attachment {
        fn drop(&mut self) {
            CURRENT.with(|current| current.replace(self.0.take()));
        }
    }

    pub fn reset() {
        CURRENT.with(|current| current.replace(Some(Arc::new(Collector::new()))));
    }

    pub fn snapshot() -> SearchMetrics {
        CURRENT.with(|current| {
            current
                .borrow()
                .as_ref()
                .map_or_else(SearchMetrics::default, |collector| collector.snapshot())
        })
    }

    pub(crate) fn record(counter: Counter, amount: u64) {
        CURRENT.with(|current| {
            if let Some(collector) = current.borrow().as_ref() {
                collector.add(counter, amount);
            }
        });
    }

    pub(crate) fn current() -> Option<Arc<Collector>> {
        CURRENT.with(|current| current.borrow().clone())
    }

    pub(crate) fn attach(collector: Option<Arc<Collector>>) -> Attachment {
        let previous = CURRENT.with(|current| current.replace(collector));
        Attachment(previous)
    }
}

#[cfg(not(feature = "search-metrics"))]
mod imp {
    use super::SearchMetrics;

    #[inline(always)]
    pub fn reset() {}

    #[inline(always)]
    pub fn snapshot() -> SearchMetrics {
        SearchMetrics::default()
    }
}

pub use imp::{reset, snapshot};

#[cfg(feature = "search-metrics")]
pub(crate) use imp::{attach, current, record};

#[cfg(feature = "search-metrics")]
macro_rules! record_search_metric {
    ($counter:ident, $amount:expr) => {
        $crate::index::search_metrics::record(
            $crate::index::search_metrics::Counter::$counter,
            $amount as u64,
        )
    };
}

#[cfg(not(feature = "search-metrics"))]
macro_rules! record_search_metric {
    ($counter:ident, $amount:expr) => {};
}

pub(crate) use record_search_metric;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_distance_work_sums_estimator_and_exact() {
        let mut metrics = SearchMetrics {
            estimator_calls: 7,
            exact_reranks: 5,
            posting_scan_estimator_calls: 3,
            ..SearchMetrics::default()
        };
        assert_eq!(metrics.total_distance_work(), 12);
        metrics.accumulate(SearchMetrics {
            estimator_calls: 2,
            posting_scan_estimator_calls: 1,
            ..SearchMetrics::default()
        });
        assert_eq!(metrics.estimator_calls, 9);
        assert_eq!(metrics.posting_scan_estimator_calls, 4);
    }

    #[test]
    fn recording_is_safe_in_both_build_modes() {
        reset();
        record_search_metric!(GraphHops, 3);
        record_search_metric!(GraphHops, 4);
        if cfg!(feature = "search-metrics") {
            assert_eq!(snapshot().graph_hops, 7);
        } else {
            assert_eq!(snapshot().graph_hops, 0);
        }
    }

    #[cfg(feature = "search-metrics")]
    #[test]
    fn collector_can_be_attached_to_worker_threads() {
        reset();
        let collector = current();
        std::thread::spawn(move || {
            let _attachment = attach(collector);
            record_search_metric!(EstimatorCalls, 11);
        })
        .join()
        .unwrap();
        assert_eq!(snapshot().estimator_calls, 11);
    }
}
