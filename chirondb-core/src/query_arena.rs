//! Thread-local bumpalo arena for per-query scratch buffers.
//!
//! SPEC Section VI.D / M4-001: candidate heaps and intermediate Vecs are
//! allocated in a per-thread arena. The arena is reset (cursor-rewound) on
//! each call instead of dropped — capacity persists, so subsequent queries on
//! the same worker thread reuse the same memory pages without going through
//! the system allocator.
//!
//! `Bump::with_capacity(64 KiB)` matches the typical working-set size of a
//! single ANN query at k=10 with ef_search=64 across a few hundred candidates.
//! Larger queries grow the arena; the high-water mark is preserved across
//! resets (`reset()` does not shrink).
//!
//! ## Usage
//!
//! ```ignore
//! use chirondb_core::query_arena::with_query_arena;
//!
//! let result = with_query_arena(|arena| {
//!     let mut scratch: bumpalo::collections::Vec<u32> =
//!         bumpalo::collections::Vec::with_capacity_in(256, arena);
//!     scratch.push(1);
//!     scratch.push(2);
//!     scratch.iter().sum::<u32>()
//! });
//! ```

use std::cell::RefCell;

use bumpalo::Bump;

const INITIAL_CAPACITY: usize = 64 * 1024;

thread_local! {
    static QUERY_ARENA: RefCell<Bump> = RefCell::new(Bump::with_capacity(INITIAL_CAPACITY));
}

/// Run `f` with exclusive access to the calling thread's query arena.
/// The arena is reset (cursor rewound to zero) on entry; capacity is preserved.
/// Returns whatever `f` returns. The arena reference must not escape `f`.
pub fn with_query_arena<R>(f: impl FnOnce(&Bump) -> R) -> R {
    QUERY_ARENA.with(|cell| {
        let mut arena = cell.borrow_mut();
        arena.reset();
        f(&arena)
    })
}

/// Bytes currently allocated in the calling thread's query arena.
/// Intended for tests and diagnostics — not a hot-path API.
pub fn allocated_bytes() -> usize {
    QUERY_ARENA.with(|cell| cell.borrow().allocated_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bumpalo::collections::Vec as BumpVec;

    #[test]
    fn arena_resets_between_calls() {
        // First call: allocate 1 KiB.
        with_query_arena(|arena| {
            let mut v: BumpVec<u8> = BumpVec::with_capacity_in(1024, arena);
            v.resize(1024, 0u8);
            assert_eq!(v.len(), 1024);
        });
        let after_first = allocated_bytes();

        // Second call: arena reset on entry. Allocate same 1 KiB — should not
        // grow past the first call's high-water mark.
        with_query_arena(|arena| {
            let mut v: BumpVec<u8> = BumpVec::with_capacity_in(1024, arena);
            v.resize(1024, 0u8);
            assert_eq!(v.len(), 1024);
        });
        let after_second = allocated_bytes();

        assert_eq!(
            after_first, after_second,
            "arena capacity must not grow when workload is unchanged \
             (got {after_first} then {after_second})"
        );
    }

    #[test]
    fn arena_grows_for_larger_workload_and_reuses_chunk_for_small_followup() {
        with_query_arena(|arena| {
            let mut v: BumpVec<u64> = BumpVec::with_capacity_in(128, arena);
            v.resize(128, 0u64);
        });
        let small = allocated_bytes();

        with_query_arena(|arena| {
            let mut v: BumpVec<u64> = BumpVec::with_capacity_in(32_768, arena);
            v.resize(32_768, 0u64);
        });
        let big = allocated_bytes();

        assert!(
            big > small,
            "arena must grow to accommodate larger workload: {big} <= {small}"
        );

        // Subsequent small workload reuses the now-larger chunk(s). bumpalo's
        // `reset` keeps at least the largest chunk, so a small follow-up must
        // fit in already-allocated capacity (no allocator call).
        let baseline = allocated_bytes();
        with_query_arena(|arena| {
            let mut v: BumpVec<u64> = BumpVec::with_capacity_in(128, arena);
            v.resize(128, 0u64);
        });
        let after_small_again = allocated_bytes();
        assert!(
            after_small_again >= 128 * std::mem::size_of::<u64>(),
            "arena chunk after reset must fit the small follow-up workload"
        );
        assert!(
            after_small_again <= baseline,
            "small follow-up must not grow the arena past its high-water mark \
             ({after_small_again} > {baseline})"
        );
    }

    #[test]
    fn arena_is_thread_local() {
        // Two threads each allocate into their own arena — neither sees the
        // other's allocations.
        let h1 = std::thread::spawn(|| {
            with_query_arena(|arena| {
                let mut v: BumpVec<u8> = BumpVec::with_capacity_in(4096, arena);
                v.resize(4096, 0xAA);
                v.len()
            })
        });
        let h2 = std::thread::spawn(|| {
            with_query_arena(|arena| {
                let mut v: BumpVec<u8> = BumpVec::with_capacity_in(8192, arena);
                v.resize(8192, 0x55);
                v.len()
            })
        });
        assert_eq!(h1.join().unwrap(), 4096);
        assert_eq!(h2.join().unwrap(), 8192);
    }
}
