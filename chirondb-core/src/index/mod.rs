//! Pluggable index backend trait. P4 of the 6-pillar UVP roadmap
//! (`AGENTS.md` § Mission & Posture). This module locks down the contract
//! that every dense index backend implements so HNSW, RaBitQ (PC-1),
//! Vamana (PC-2), and ScaNN can be swapped behind the same query API.
//!
//! The HNSW/IVF/Flat dispatcher in [`crate::h2qg::H2qgIndex`] is the
//! reference impl. New backends land as additional `impl IndexBackend`
//! sites in sibling modules under `crate::index::*`.

pub mod diskann;
pub mod ivf;
pub mod ivf_segment;
pub mod rabitq;
pub mod rabitq_estimator;
pub mod search_metrics;
pub mod vamana;

use crate::Result;
use crate::model::Point;

/// Inline result predicate consulted during dense search. Graph backends may
/// retain payload-rejected live rows as navigation bridges, but only rows for
/// which [`Self::matches`] returns `true` may occupy result capacity.
///
/// The trait is implemented for any `Fn(&str) -> bool + Send + Sync`, so
/// callers can pass a closure that closes over a `HashSet<String>` of
/// prefilter candidates (built from `payload_index`) or over the
/// `points: &HashMap<String, Point>` map for the full `Filter::matches`
/// check. The closure is the only thing the HNSW engine holds; payload
/// data stays in the caller's collection state.
pub trait FilterPredicate: Send + Sync {
    fn matches(&self, id: &str) -> bool;

    /// Whether an indexed row may be used as a graph-navigation bridge.
    /// Payload-rejected live rows remain navigable; segment wrappers override
    /// this to reject tombstoned or otherwise invalid rows before they consume
    /// frontier capacity.
    fn navigable(&self, _id: &str) -> bool {
        true
    }
}

/// P0 — sealed-tier filter predicate over a stable segment ordinal.
///
/// This lives alongside [`FilterPredicate`]. Mutable streamers and legacy
/// segments keep the string contract permanently; current sealed indexes use
/// this predicate to avoid hashing and materializing IDs in their hot loops.
pub trait OrdinalFilterPredicate: Send + Sync {
    fn matches_ordinal(&self, segment: &str, ordinal: u32) -> bool;

    /// Whether a rejected ordinal may still be used as a graph-navigation
    /// bridge. Payload predicates keep the default `true`; visibility wrappers
    /// override this for deleted or otherwise invalid records.
    fn navigable_ordinal(&self, _segment: &str, _ordinal: u32) -> bool {
        true
    }
}

impl<F> FilterPredicate for F
where
    F: Fn(&str) -> bool + Send + Sync,
{
    fn matches(&self, id: &str) -> bool {
        self(id)
    }
}

/// P2F convenience impl: the canonical prefilter candidate set built from
/// `payload_index::payload_filter_candidates`. Direct cast at the call site
/// (`payload_candidates.as_ref().map(|set| set as &dyn FilterPredicate)`)
/// avoids the closure allocation when the set is already in hand.
impl FilterPredicate for std::collections::HashSet<String> {
    fn matches(&self, id: &str) -> bool {
        self.contains(id)
    }
}

/// Discriminator for the live backend behind a trait object. Pattern-match
/// on this when a call site needs to branch on backend identity (e.g. choosing
/// a write filename, gating a feature). Most code paths should not need it —
/// prefer the trait methods.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndexKind {
    Hnsw,
    HnswSq8,
    Flat,
    Ivf,
    /// P4 / PC-1 — binary cascade backend (sign-bit + L2 rerank). See
    /// [`rabitq::RabitqBackend`].
    Rabitq,
    /// P4 / PC-2 — single-layer DiskANN-style graph with robust angular
    /// pruning. See [`vamana::VamanaBackend`].
    Vamana,
}

/// W1 — bits per packed sign-code word.
const SIGN_WORD_BITS: usize = 64;

/// W1 — number of `u64` words needed to pack `dim` sign bits.
pub(crate) fn sign_word_count(dim: usize) -> usize {
    dim.div_ceil(SIGN_WORD_BITS)
}

/// W1 — sign-bit binary code shared by the flat RaBitQ backend
/// ([`rabitq::RabitqBackend`]) and the in-beam HNSW cascade
/// ([`crate::h2qg`]). Packs the sign bit of each dimension into `word_count`
/// `u64` words, little-endian within word. Bit positions beyond `vec.len()`
/// stay zero. Tie-break: `0.0` → 1, `-0.0` → 0 (matches `is_sign_positive`).
pub(crate) fn encode_sign_bits(vec: &[f32], word_count: usize) -> Vec<u64> {
    let mut words = vec![0_u64; word_count];
    for (i, &v) in vec.iter().enumerate() {
        if v.is_sign_positive() {
            words[i / SIGN_WORD_BITS] |= 1_u64 << (i % SIGN_WORD_BITS);
        }
    }
    words
}

/// W1 Phase 3 — fixed seed for the deterministic pseudo-random rotation
/// applied before sign-bit encoding. The same seed is used everywhere
/// (query side and stored-vector side) so the two rotations always match;
/// nothing about it needs to be persisted.
const ROTATION_SEED: u64 = 0x5241_4249_5451_5141;

/// W1 Phase 3 — next power of two `>= n` (the Hadamard transform below
/// requires a power-of-two length).
pub(crate) fn next_pow2(n: usize) -> usize {
    n.next_power_of_two().max(1)
}

/// W1 Phase 3 — deterministic pseudo-random `+-1.0` sign mask, one entry
/// per padded dimension. Same `padded_dim` always yields the same mask.
fn rotation_sign_mask(padded_dim: usize) -> Vec<f32> {
    let mut state = ROTATION_SEED;
    let mut mask = Vec::with_capacity(padded_dim);
    for _ in 0..padded_dim {
        state = crate::h2qg::splitmix64(state);
        mask.push(if state & 1 == 0 { 1.0 } else { -1.0 });
    }
    mask
}

/// W1 Phase 3 — in-place Fast Walsh-Hadamard Transform. `buf.len()` must be
/// a power of two (callers go through [`rotate_for_cascade`], which pads).
/// Unnormalized: output magnitude scales by `sqrt(len)`.
fn fht_inplace(buf: &mut [f32]) {
    let n = buf.len();
    let mut len = 1;
    while len < n {
        let mut i = 0;
        while i < n {
            for j in i..i + len {
                let a = buf[j];
                let b = buf[j + len];
                buf[j] = a + b;
                buf[j + len] = a - b;
            }
            i += len * 2;
        }
        len *= 2;
    }
}

/// W1 Phase 3 — RaBitQ-style structured random rotation: a deterministic
/// sign-flip diagonal followed by a Fast Hadamard Transform, normalized by
/// `1/sqrt(padded_dim)`. This is the standard fast substitute for a dense
/// random-orthogonal matmul (`O(d log d)` instead of `O(d^2)`) and is exactly
/// orthogonal (sign-flip and Hadamard/`sqrt(n)` are each orthogonal, so the
/// composition is too) — `||rotate(v)|| == ||v||` exactly, up to the zero
/// padding. Applying the same rotation to both the query and every stored
/// vector before sign-bit encoding decorrelates dimensions, which is what
/// the 1-bit estimator's accuracy bound assumes; this is the fix the
/// previous session's symmetric-Hamming cascade was missing (see
/// `h2qg.rs`'s `asym_proxy` doc and the 2026-06-21 handoff).
pub(crate) fn rotate_for_cascade(vector: &[f32]) -> Vec<f32> {
    let padded_dim = next_pow2(vector.len());
    let mask = rotation_sign_mask(padded_dim);
    let mut buf = vec![0.0_f32; padded_dim];
    buf[..vector.len()].copy_from_slice(vector);
    for (b, m) in buf.iter_mut().zip(&mask) {
        *b *= m;
    }
    fht_inplace(&mut buf);
    let scale = 1.0 / (padded_dim as f32).sqrt();
    for b in buf.iter_mut() {
        *b *= scale;
    }
    buf
}

/// Build-time parameters. Replaces the positional
/// `(vector_dim, hnsw_m, hnsw_ef_construction, use_sq8)` quadruple that the
/// HNSW backend exposes today.
#[derive(Clone, Debug, Default)]
pub struct IndexParams {
    pub vector_dim: usize,
    pub hnsw_m: Option<u32>,
    pub hnsw_ef_construction: Option<u32>,
    pub use_sq8: bool,
    pub metric: crate::DistanceMetric,
}

/// One dense ANN index backend.
///
/// Implementors must be `Send + Sync` so the per-collection `RwLock<Collection>`
/// in [`crate::db`] can hand the backend out for concurrent reads. `Debug` is
/// required so `Collection` itself can derive `Debug`.
///
/// Defaults on `default_ef_search` and `ef_search_for_recall_target` delegate
/// to the HNSW-tuned step curves in [`crate::h2qg`]; new backends override
/// when their operating point differs.
pub trait IndexBackend: Send + Sync + std::fmt::Debug {
    /// Top-`k` retrieval. `ef_search = None` falls back to
    /// [`Self::default_ef_search`].
    fn candidate_ids_with_ef(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
    ) -> Vec<String>;

    /// P2F — filter-aware variant of [`Self::candidate_ids_with_ef`].
    /// `filter = None` is equivalent to the un-filtered call.
    ///
    /// Implementations consult the predicate during traversal rather than
    /// relying only on post-filtering. LS-VEC separates navigation admission
    /// from result admission; legacy graph backends may still prune rejected
    /// rows during expansion.
    ///
    /// The default implementation ignores the filter and delegates to
    /// the un-filtered method. Backends that participate in dense
    /// filtered search (HNSW, Vamana) override it; the override is
    /// what unlocks the Filtered50K benchmark case.
    fn candidate_ids_with_ef_filter(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
        filter: Option<&dyn FilterPredicate>,
    ) -> Vec<String> {
        // Default: filter ignored. The prefilter-exact path in
        // `db::search_excluding` and the post-filter rescore at the
        // call site both still apply, so callers that take the default
        // path get correct (but un-pruned) results.
        let _ = filter;
        self.candidate_ids_with_ef(query, k, ef_search)
    }

    /// Candidate selection with the effective collection/query recall target.
    ///
    /// Most backends express recall only through `ef_search`, so the default
    /// delegates to [`Self::candidate_ids_with_ef_filter`]. LS-VEC sealed
    /// segments additionally derive their exact-rerank inflation from this
    /// target, keeping that policy engine-owned rather than exposing `ρ`.
    fn candidate_ids_with_recall_target(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
        recall_target: f32,
        filter: Option<&dyn FilterPredicate>,
    ) -> Vec<String> {
        let _ = recall_target;
        self.candidate_ids_with_ef_filter(query, k, ef_search, filter)
    }

    /// P0 sealed-tier counterpart to
    /// [`Self::candidate_ids_with_recall_target`]. The default preserves
    /// legacy and mutable behavior by ignoring the ordinal predicate.
    fn candidate_ids_with_recall_target_ordinal_filter(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
        recall_target: f32,
        filter: Option<&dyn FilterPredicate>,
        ordinal_filter: Option<&dyn OrdinalFilterPredicate>,
    ) -> Vec<String> {
        let _ = ordinal_filter;
        self.candidate_ids_with_recall_target(query, k, ef_search, recall_target, filter)
    }

    /// Cancellation-aware variant used by budgeted coordinators.
    ///
    /// Backends with long-running candidate selection override this method and
    /// poll `cancelled` inside their traversal. The default keeps compatibility
    /// for small/legacy backends while still avoiding work when cancellation
    /// was already requested before dispatch.
    fn candidate_ids_with_recall_target_cancellable(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
        recall_target: f32,
        filter: Option<&dyn FilterPredicate>,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Vec<String> {
        if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            Vec::new()
        } else {
            self.candidate_ids_with_recall_target(query, k, ef_search, recall_target, filter)
        }
    }

    /// Cancellation-aware ordinal-filter dispatch. Sealed indexes with a
    /// stable ordinal domain override this; all other backends retain the
    /// string fallback through the default implementation.
    #[allow(clippy::too_many_arguments)]
    fn candidate_ids_with_recall_target_ordinal_filter_cancellable(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
        recall_target: f32,
        filter: Option<&dyn FilterPredicate>,
        ordinal_filter: Option<&dyn OrdinalFilterPredicate>,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Vec<String> {
        let _ = ordinal_filter;
        self.candidate_ids_with_recall_target_cancellable(
            query,
            k,
            ef_search,
            recall_target,
            filter,
            cancelled,
        )
    }

    /// Engine default `ef_search` when neither the request nor the collection
    /// config supplies one. PE-1 baseline: `k.max(100)`.
    fn default_ef_search(&self, k: usize) -> usize {
        crate::h2qg::default_ef_search(k, self.indexed_points(), self.vector_dim())
    }

    /// Pick `ef_search` from a recall target. PA-1/PE-1b step curve.
    fn ef_search_for_recall_target(&self, k: usize, recall_target: f32) -> usize {
        crate::h2qg::ef_search_for_recall_target(
            k,
            recall_target,
            self.indexed_points(),
            self.vector_dim(),
        )
    }

    /// Steady-state Phase 3a inline insert into the live graph. Backends that
    /// don't support incremental insert may treat this as a no-op (the next
    /// compact rebuilds them from sealed segments).
    fn insert_point(&mut self, point: &Point, vector_dim: usize) -> Result<()>;

    /// Backend discriminator. See [`IndexKind`].
    fn kind(&self) -> IndexKind;

    /// Total points indexed and reachable from query.
    fn indexed_points(&self) -> usize;

    /// Configured vector dimensionality. A4 — feeds `dim_scale` in the
    /// default `ef_search` floors above; also useful for dimension-mismatch
    /// diagnostics at call sites that don't already have `IndexParams` handy.
    fn vector_dim(&self) -> usize;

    /// Whether `id` is present in the index.
    fn contains(&self, id: &str) -> bool;

    /// Backend-internal partitioning count (HNSW node count, IVF cell count).
    /// Used for observability and the `optimize` metrics surface.
    fn cells(&self) -> usize;

    /// Whether vector storage is paged via mmap rather than fully in RAM.
    fn is_paged(&self) -> bool;

    fn is_hnsw(&self) -> bool {
        matches!(self.kind(), IndexKind::Hnsw | IndexKind::HnswSq8)
    }

    fn is_flat_fallback(&self) -> bool {
        matches!(self.kind(), IndexKind::Flat)
    }

    fn uses_sq8(&self) -> bool {
        matches!(self.kind(), IndexKind::HnswSq8)
    }
}

/// Default factory: build a fresh backend from the current HNSW reference impl.
/// New backends register a parallel `build_*` factory in their own module; the
/// dispatch from `CollectionConfig.index_kind` → factory ships with PC-1.
pub fn build(points: &[Point], params: &IndexParams) -> Box<dyn IndexBackend> {
    use crate::h2qg::H2qgIndex;
    let built = if params.use_sq8 {
        H2qgIndex::build_sq8_with_params(
            points,
            params.vector_dim,
            params.hnsw_m,
            params.hnsw_ef_construction,
            params.metric,
        )
    } else {
        H2qgIndex::build_with_params(
            points,
            params.vector_dim,
            params.hnsw_m,
            params.hnsw_ef_construction,
            params.metric,
        )
    };
    Box::new(built)
}

/// P4 / PC-2 — Vamana / DiskANN single-layer graph backend factory. Returns a
/// trait-object `IndexBackend` so call sites stay backend-agnostic. The actual
/// algorithm (medoid seeding, robust-prune, beam search) lives in
/// [`vamana::VamanaBackend`]; this is the single entry point `Collection`
/// uses when `CollectionConfig.index_kind = Some("vamana")`.
///
/// The factory deliberately mirrors the shape of the HNSW [`build`] above so
/// the dispatcher in `db.rs` can be written as a uniform
/// `match CollectionConfig.index_kind` ladder instead of reaching into each
/// backend module. New PC-* backends register a `build_*` here and one `match`
/// arm in `db.rs` — nothing else.
pub fn build_vamana(points: &[Point], params: &IndexParams) -> Box<dyn IndexBackend> {
    vamana::build(points, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Point;

    fn p(id: &str, v: Vec<f32>) -> Point {
        Point {
            id: id.into(),
            vector: v,
            vectors: Default::default(),
            sparse_vector: None,
            payload: serde_json::Value::Null,
        }
    }

    #[test]
    fn h2qg_impls_index_backend_send_sync() {
        fn assert_traits<T: IndexBackend + ?Sized>() {}
        assert_traits::<crate::h2qg::H2qgIndex>();
        assert_traits::<dyn IndexBackend>();
    }

    #[test]
    fn build_returns_trait_object_with_correct_kind() {
        let points = vec![
            p("a", vec![1.0, 0.0, 0.0, 0.0]),
            p("b", vec![0.0, 1.0, 0.0, 0.0]),
            p("c", vec![0.0, 0.0, 1.0, 0.0]),
        ];
        let params = IndexParams {
            vector_dim: 4,
            ..Default::default()
        };
        let idx: Box<dyn IndexBackend> = build(&points, &params);
        assert_eq!(idx.indexed_points(), 3);
        // Below HNSW_THRESHOLD → flat backend.
        assert_eq!(idx.kind(), IndexKind::Flat);
        assert!(idx.is_flat_fallback());
        assert!(!idx.is_hnsw());
        let hits = idx.candidate_ids_with_ef(&[1.0, 0.0, 0.0, 0.0], 2, None);
        assert!(!hits.is_empty());
    }

    #[test]
    fn trait_default_ef_curve_monotonic() {
        let points = vec![p("a", vec![1.0, 0.0])];
        let idx = build(
            &points,
            &IndexParams {
                vector_dim: 2,
                ..Default::default()
            },
        );
        let high = idx.ef_search_for_recall_target(10, 0.99);
        let mid = idx.ef_search_for_recall_target(10, 0.95);
        let low = idx.ef_search_for_recall_target(10, 0.80);
        assert!(high >= mid && mid >= low, "{high} {mid} {low}");
    }
}
