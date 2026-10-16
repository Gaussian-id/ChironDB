//! Untimed allocation diagnostic for a pinned dense-search fixture.
//! Usage: dense_workspace DATA_DIR REQUESTS_JSON REPORT_JSON
//! REQUESTS_JSON: {"collection":"docs", "requests":[SearchRequest, ...]}.
//! Use production chironbench builds for latency/QPS, never this allocator.
use chirondb_core::{Db, SearchRequest};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct Meter;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static REQUESTED: AtomicUsize = AtomicUsize::new(0);

fn allocation(bytes: usize) {
    if ACTIVE.load(Ordering::Relaxed) {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        REQUESTED.fetch_add(bytes, Ordering::Relaxed);
    }
}

fn acquired(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    if ACTIVE.load(Ordering::Relaxed) {
        PEAK.fetch_max(live, Ordering::Relaxed);
    }
}

// Every successful allocation/deallocation is forwarded to System unchanged.
// Counters cover Rust heap allocations across the complete process, including
// Rayon workers; mmap pages and foreign allocators require separate RSS/I/O data.
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            allocation(layout.size());
            acquired(layout.size());
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            allocation(layout.size());
            acquired(layout.size());
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, bytes: usize) -> *mut u8 {
        let pointer = unsafe { System.realloc(pointer, layout, bytes) };
        if !pointer.is_null() {
            allocation(bytes);
            if bytes >= layout.size() {
                acquired(bytes - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - bytes, Ordering::Relaxed);
            }
        }
        pointer
    }
}

#[global_allocator]
static ALLOCATOR: Meter = Meter;

#[derive(Deserialize)]
struct Fixture {
    collection: String,
    requests: Vec<SearchRequest>,
}

fn hash(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes).iter() {
        write!(&mut output, "{byte:02x}").expect("String formatting cannot fail");
    }
    output
}

fn main() -> anyhow::Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    anyhow::ensure!(
        arguments.len() == 3,
        "expected DATA_DIR REQUESTS_JSON REPORT_JSON"
    );
    let bytes = std::fs::read(&arguments[1])?;
    let fixture_sha256 = hash(&bytes);
    let fixture: Fixture = serde_json::from_slice(&bytes)?;
    drop(bytes);
    let db = Db::open(&arguments[0])?;
    // Complete untimed warmup, including lazy pools/caches, before measuring.
    for request in &fixture.requests {
        db.search(&fixture.collection, request.clone())?;
    }
    let mut rows = Vec::new();
    for request in &fixture.requests {
        let request = request.clone();
        let before = LIVE.load(Ordering::Relaxed);
        PEAK.store(before, Ordering::Relaxed);
        ALLOCATIONS.store(0, Ordering::Relaxed);
        REQUESTED.store(0, Ordering::Relaxed);
        ACTIVE.store(true, Ordering::Relaxed);
        let response = db.search(&fixture.collection, request);
        ACTIVE.store(false, Ordering::Relaxed);
        let peak = PEAK.load(Ordering::Relaxed);
        let retained = LIVE.load(Ordering::Relaxed);
        let allocations = ALLOCATIONS.load(Ordering::Relaxed);
        let requested = REQUESTED.load(Ordering::Relaxed);
        let response = response?;
        let ranking = response
            .hits
            .iter()
            .map(|hit| (&hit.id, hit.score.to_bits()))
            .collect::<Vec<_>>();
        rows.push(serde_json::json!({
            "peak_query_heap_delta_bytes": peak.saturating_sub(before),
            "retained_response_heap_delta_bytes": retained.saturating_sub(before),
            "allocation_events": allocations,
            "requested_allocation_bytes": requested,
            "hits": response.hits.len(), "searched": response.searched,
            "degraded": response.degraded,
            "ranking_sha256": hash(&serde_json::to_vec(&ranking)?),
        }));
    }
    std::fs::write(
        &arguments[2],
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "chirondb-dense-workspace-diagnostic-v2",
            "timing_evidence": false, "fixture_sha256": fixture_sha256,
            "scope": "process Rust System heap; exclude mmap and foreign allocations",
            "allocation_scope": "successful alloc/alloc_zeroed/realloc calls; requested bytes include full new realloc size",
            "collection": fixture.collection, "queries": rows,
        }))?,
    )?;
    Ok(())
}
