//! W3 — dedicated rayon thread pools for the search hot path.
//!
//! Separate from the global rayon pool (sized in `chirondb-server/src/main.rs`,
//! PD-3) which compaction and batch-upsert use. Splitting the two prevents
//! background index maintenance work from contending with live query
//! parallelism for rayon worker slots — the structural fix flagged (but not
//! shipped) in the 2026-06-21 session handoff's W3 section. Multi-search
//! branch dispatch has a second pool because a branch can hold a collection
//! read guard while its search fans out internally. Scheduling both layers on
//! one writer-preferring pool can deadlock when the WAL flusher queues a write
//! between those two layers.
//!
//! Sizing mirrors the global pool's existing policy exactly (half the
//! worker-thread count, floor 2, overridable via `CHIRONDB_WORKER_THREADS`
//! (`GAUSSDB_WORKER_THREADS` remains a deprecated fallback)
//! rather than introducing a new knob.

use std::sync::LazyLock;

fn configured_workers() -> usize {
    std::env::var("CHIRONDB_WORKER_THREADS")
        .or_else(|_| std::env::var("GAUSSDB_WORKER_THREADS"))
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|workers| *workers >= 1)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|value| value.get())
                .unwrap_or(1)
        })
}

/// Dedicated pool for search-path `par_iter` calls: HNSW beam neighbor
/// scoring (`h2qg.rs`) and post-search candidate rescore / multi-search
/// branch fan-out (`db.rs`).
pub static SEARCH_POOL: LazyLock<rayon::ThreadPool> = LazyLock::new(|| {
    let threads = (configured_workers() / 2).max(2);
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(|i| format!("chirondb-search-{i}"))
        .build()
        .expect("failed to build dedicated search rayon pool")
});

/// Dispatches independent multi-search branches. Branch-internal scoring
/// remains on `SEARCH_POOL`, so a queued collection writer cannot strand all
/// scoring workers behind branch jobs waiting for a new read guard.
pub static MULTI_SEARCH_POOL: LazyLock<rayon::ThreadPool> = LazyLock::new(|| {
    let threads = (configured_workers() / 2).max(2);
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(|i| format!("chirondb-multi-search-{i}"))
        .build()
        .expect("failed to build dedicated multi-search rayon pool")
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_and_inner_search_work_run_on_distinct_pools() {
        let (branch_name, inner_name) = MULTI_SEARCH_POOL.install(|| {
            let branch_name = std::thread::current()
                .name()
                .expect("multi-search worker has a name")
                .to_string();
            let inner_name = SEARCH_POOL.install(|| {
                std::thread::current()
                    .name()
                    .expect("search worker has a name")
                    .to_string()
            });
            (branch_name, inner_name)
        });
        assert!(branch_name.starts_with("chirondb-multi-search-"));
        assert!(inner_name.starts_with("chirondb-search-"));
    }
}
