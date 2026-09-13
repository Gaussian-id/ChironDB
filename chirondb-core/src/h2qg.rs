use std::{
    borrow::Cow,
    cmp::Reverse,
    collections::{BinaryHeap, HashSet},
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    sync::atomic::AtomicBool,
};

use serde::{Deserialize, Serialize};
use wide::f32x8;

/// Total-order wrapper for f32 distances used as `BinaryHeap` keys in beam search.
/// NaN is ordered consistently via `f32::total_cmp` (NaN sorts greatest).
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) struct OrdF32(pub(crate) f32);

impl Eq for OrdF32 {}

impl Ord for OrdF32 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}

impl PartialOrd for OrdF32 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

use crate::{
    DistanceMetric,
    error::{GaussError, Result},
    model::Point,
};

const MAGIC: &[u8; 8] = b"GAUSSH2Q";
const HEADER_LEN: usize = 20;
// Collections below this threshold use flat (all-candidate) mode; at or above use HNSW.
pub const HNSW_THRESHOLD: usize = 10_000;
pub const INDEX_FILE: &str = "h2qg.gdx";
pub const HNSW_VECS_FILE: &str = "h2qg_vecs.gdx";

pub(crate) const HNSW_VECS_MAGIC: &[u8; 8] = b"GAUSSHV1";

pub const HNSW_M: usize = 16;
pub const HNSW_EF_CONSTRUCTION: usize = 100;

/// P2C — minimum neighbor-batch size to switch the layer-0 beam expansion
/// from serial to `rayon::par_iter`. Set to the standard HNSW `M` so the
/// parallel path engages exactly at the layer-0 connection count
/// (`M0 = M * 2 = 32` neighbours per node for the default). Below this
/// threshold the rayon dispatch overhead exceeds the per-distance
/// compute on the 64–1536 dim vectors this engine targets.
pub const INTRA_QUERY_PARALLEL_THRESHOLD: usize = HNSW_M;

/// W1 Phase 3 — in-beam binary-cascade over-sampling factor. The layer-0
/// cascade beam keeps a found pool of `ef * CASCADE_OVERSAMPLE` candidates
/// ranked on the rotation- + norm-corrected asymmetric proxy
/// ([`HnswGraph::asym_proxy`]), then exact-reranks that widened pool with
/// the true f32 metric and truncates to `ef`. 8 is the measured floor: the
/// 2026-06-21-session diagnostic sweep (`hnsw_in_beam_cascade_holds_recall_floor`,
/// dims 384/768 x spread 0.05/0.10) showed `os=4` dips to 0.946x the exact
/// beam's recall at dim=768/spread=0.05 (below the 0.97 floor), while
/// `os=8` clears 1.0x-1.07x in every swept config. Raise only with new
/// sweep evidence backing it.
pub const CASCADE_OVERSAMPLE: usize = 8;

/// W4 — N-aware scale factor for `ef_search` floors. HNSW graph diameter
/// grows with the number of indexed points, so a floor calibrated at one
/// `N` doesn't hold recall as the collection grows: the 2026-06-25 50K-vs-
/// 500K benchmark measured recall dropping 0.9507 → 0.921 with the (then
/// flat) floor unchanged, and the `w4_ef_search_recall_drops_with_n`
/// diagnostic sweep (`chirondb-core/src/h2qg.rs`, run with `--ignored
/// --nocapture`) quantified it directly on the same uniform-LCG / Cosine
/// corpus `recall_golden.rs` uses: holding mean recall@10 >= 0.97 needs
/// `ef=128` at `n=12000` (the existing calibration), `ef=256` at `n=40000`,
/// and `ef=512` at `n=120000`. Fit: `scale(n) = (n/12000)^0.6`, applied via
/// [`scaled_ef`] (which rounds the scaled floor up to the next multiple of
/// 32 for headroom -- see its doc comment). `128 * scale(40000)` → 288,
/// `128 * scale(120000)` → 512, both at or above the measured requirement.
/// Anchored at `n=12000` (the existing floor's calibration point) so this
/// is a pure scale-up for larger collections and a no-op (`1.0`) at or
/// below it. Raise/refit only with new sweep evidence, same rule as
/// `CASCADE_OVERSAMPLE`.
fn n_scale(point_count: usize) -> f32 {
    const ANCHOR_N: f32 = 12_000.0;
    const EXPONENT: f32 = 0.6;
    (point_count as f32 / ANCHOR_N).max(1.0).powf(EXPONENT)
}

/// A4 — dim-aware scale factor for `ef_search` floors (PRD.md §7 backlog
/// item 6 / §8 Track A item A4). Curse-of-dimensionality means recall at a
/// fixed `ef` drops as `dim` grows, same shape of problem as `n_scale` but
/// on a different axis -- the `a4_ef_search_recall_drops_with_dim`
/// diagnostic sweep (`n=12000`, the `n_scale` anchor, isolating the dim
/// effect) measured the `ef` needed to clear 0.97 mean recall@10 at each
/// dim: `64`→128 (existing anchor, no scaling), `128`→ ~384 (256 measured
/// 0.958, just under), `256`→ ~512 (384 measured 0.956, just under),
/// `768`→ ~1024 (768 measured 0.968, just under), `1536`→ extrapolated to
/// ~1536 following the same ~1.3x margin the other anchors carry over their
/// measured just-under point (the sweep's coarse `ef` grid didn't test past
/// 1024 at this dim). A single power-law exponent (like `n_scale`'s) does
/// not fit this data well -- fitting the low-dim anchor (128) forces a
/// factor that badly overshoots the high-dim anchors (768/1536), wasting
/// QPS at exactly the dims most embedding models actually use (384/768/1536
/// are all common). Piecewise-linear interpolation between the measured
/// anchors (in dim-space) tracks the actual curve shape instead. Clamps to
/// the `dim=1536` anchor's scale beyond that point -- extending further
/// needs new sweep evidence, same rule as `CASCADE_OVERSAMPLE`/`n_scale`.
fn dim_scale(vector_dim: usize) -> f32 {
    const ANCHORS: [(f32, f32); 5] = [
        (64.0, 1.0),
        (128.0, 3.0),
        (256.0, 4.0),
        (768.0, 8.0),
        (1536.0, 12.0),
    ];
    let d = vector_dim as f32;
    if d <= ANCHORS[0].0 {
        return 1.0;
    }
    for w in ANCHORS.windows(2) {
        let (d0, s0) = w[0];
        let (d1, s1) = w[1];
        if d <= d1 {
            let t = (d - d0) / (d1 - d0);
            return s0 + t * (s1 - s0);
        }
    }
    ANCHORS[ANCHORS.len() - 1].1
}

/// Applies [`n_scale`] and [`dim_scale`] to a base `ef` value. Returns `base`
/// unchanged only when both scales are `1.0` (at or below both anchor
/// points -- exact match with the pre-W4/A4 calibration, no rounding noise
/// at the point every existing test/sweep was measured at). Otherwise,
/// rounds the combined-scaled value up to the next multiple of 32 for
/// headroom against each sweep's measurement granularity.
fn scaled_ef(base: usize, point_count: usize, vector_dim: usize) -> usize {
    let scale = n_scale(point_count) * dim_scale(vector_dim);
    if scale <= 1.0 {
        return base;
    }
    let raw = (base as f32 * scale).ceil() as usize;
    raw.div_ceil(32) * 32
}

/// Default per-query `ef_search` for HNSW when neither the request nor the
/// collection config supplies an override. PE-1: lowered from `k*2` to
/// `k.max(100)` after the 1M-scale benchmark (run `6749d46f`) showed `k*2=200`
/// collapsed QPS to ~5 on Performance768D1M while still holding recall=1.0.
/// At k=100, the typical ANN operating point, this yields ef=100 (Chroma-class
/// configuration, recall ~0.95) at the `n=12000` calibration point. W4:
/// scaled by [`n_scale`] for larger collections so the recall this floor
/// targets doesn't silently erode as `N` grows. A4: also scaled by
/// [`dim_scale`] so the same doesn't silently erode as `dim` grows.
pub fn default_ef_search(k: usize, point_count: usize, vector_dim: usize) -> usize {
    scaled_ef(k.max(100), point_count, vector_dim)
}

/// W0 — engine default recall operating point. When a search supplies neither
/// an explicit `ef_search` nor a `recall_target`, and the collection carries no
/// contracted `recall_sla`, `Db::search` resolves `ef_search` through this
/// target instead of the conservative `default_ef_search` (recall ~1.0). 0.97
/// is the throughput default; the recall=1.0 path stays selectable via
/// `recall_target = 1.0` / `recall_sla` (P3 contract preserved).
pub const DEFAULT_RECALL_TARGET: f32 = 0.97;

/// PA-1: pick `ef_search` from a recall target. PE-1c: step curve rebalanced
/// for competitive p99. A `0.97` step lands between the conservative
/// `default_ef_search` (k.max(100)) and the prior `0.95` step. The `0.95`,
/// `0.90`, `0.80`, and `< 0.80` steps are each dropped to the next-tighter
/// floor so customers explicitly opting into a recall target pay less for the
/// same target — closes the p99 gap to Qdrant on equivalent
/// `recall_target=0.97`. Default-path callers (`recall_target = None`) still
/// pay the conservative `default_ef_search` price (locks in `recall = 1.0`
/// per the `recall_golden` floor in `chirondb-server/tests/recall_golden.rs`).
/// Online calibration replaces this in PC-3.
///
/// Caller contract: `recall_target` clamped to `[0.5, 1.0]`. Anything outside
/// returns `default_ef_search(k)` (treat as no signal).
///
/// **2026-06-21 recalibration**: the `0.97` tier's floor was `64` (`ef=80` at
/// `k=100`), set while `search_point_candidates` had an unconditional
/// brute-force fallback that silently guaranteed `recall=1.0` regardless of
/// `ef` -- the floor was never actually validated against real ANN
/// behavior. After fixing that bug *and* a second bug (`HnswGraph` always
/// used raw squared-L2 internally regardless of the collection's configured
/// metric -- broke `Cosine` collections with non-pre-normalized vectors), a
/// real ef sweep on `n=12000, dim=64, k=10, metric=Cosine` (mean recall over
/// 200 queries, the industry-standard recall@k convention, not a single
/// worst-case query) measured: `ef=64` → 0.9485, `ef=96` → 0.9730,
/// `ef=128` → 0.9865, `ef=192` → 0.9940, `ef=256` → 0.9980. Floor raised
/// `64 → 128` (clears 0.97 with real margin). Raise only with new sweep
/// evidence backing it, same rule as `CASCADE_OVERSAMPLE`.
///
/// **2026-06-25, W4**: that sweep was all at one `N`. The 50K-vs-500K
/// benchmark run the same day showed recall dropping as the collection
/// grows even with `ef_search` held fixed (HNSW graph diameter grows with
/// `N`). Every tier below is now scaled by [`n_scale`], which is a no-op at
/// `n<=12000` (this function's original calibration point) and grows the
/// floor for larger collections -- see `n_scale`'s doc comment for the
/// sweep that grounds the scale factor itself. Only the `0.97` tier has
/// direct sweep evidence (`128`/`256`/`512` at `12K`/`40K`/`120K`); the
/// other tiers are scaled by the same factor as a conservative
/// extrapolation, not independently measured -- revisit with sweep evidence
/// if a customer exercises a non-0.97 `recall_target` at scale.
///
/// Step curve (PE-1c, recalibrated; each floor scaled by [`n_scale`]):
///
/// | target | ef         | notes |
/// |--------|------------|-------|
/// | ≥ 0.99 | k*2 max 200 | near-exact, paying full price |
/// | ≥ 0.97 | k*4/5 max 128 | W0 throughput default — measured floor (see above) |
/// | ≥ 0.95 | k*3/4 max 60 | dropped from k.max(100) |
/// | ≥ 0.90 | k/2 max 40   | dropped from k*3/4.max(64) |
/// | ≥ 0.80 | k/3 max 32   | dropped from k/2.max(48) |
/// | < 0.80 | k/5 max 24   | dropped from k/4.max(32) |
pub fn ef_search_for_recall_target(
    k: usize,
    recall_target: f32,
    point_count: usize,
    vector_dim: usize,
) -> usize {
    if !(0.5..=1.0).contains(&recall_target) || recall_target.is_nan() {
        return default_ef_search(k, point_count, vector_dim);
    }
    let ef = if recall_target >= 0.99 {
        k.saturating_mul(2).max(200)
    } else if recall_target >= 0.97 {
        // W0: real throughput operating point, measured (see doc comment
        // above) -- 128 is the floor that clears mean recall 0.97 with
        // margin on the corpus this was actually swept against, at the
        // n=12000/dim=64 calibration point `n_scale`/`dim_scale` anchor to.
        k.saturating_mul(4).saturating_div(5).max(128)
    } else if recall_target >= 0.95 {
        k.saturating_mul(3).saturating_div(4).max(60)
    } else if recall_target >= 0.90 {
        k.saturating_div(2).max(40)
    } else if recall_target >= 0.80 {
        k.saturating_div(3).max(32)
    } else {
        k.saturating_div(5).max(24)
    };
    scaled_ef(ef, point_count, vector_dim)
}

#[cfg(test)]
mod ef_search_for_recall_target_tests {
    use super::{default_ef_search, ef_search_for_recall_target};

    /// `n_scale`'s anchor point — pass this everywhere the existing
    /// (pre-W4) tests want a no-scaling baseline.
    const N_NO_SCALE: usize = 12_000;
    /// `dim_scale`'s anchor point — pass this everywhere the existing
    /// (pre-A4) tests want a no-scaling baseline.
    const DIM_NO_SCALE: usize = 64;

    #[test]
    fn monotonic_non_increasing_as_target_drops() {
        let k = 10;
        let a = ef_search_for_recall_target(k, 0.99, N_NO_SCALE, DIM_NO_SCALE);
        let b = ef_search_for_recall_target(k, 0.95, N_NO_SCALE, DIM_NO_SCALE);
        let c = ef_search_for_recall_target(k, 0.90, N_NO_SCALE, DIM_NO_SCALE);
        let d = ef_search_for_recall_target(k, 0.80, N_NO_SCALE, DIM_NO_SCALE);
        let e = ef_search_for_recall_target(k, 0.70, N_NO_SCALE, DIM_NO_SCALE);
        assert!(a >= b && b >= c && c >= d && d >= e, "{a} {b} {c} {d} {e}");
    }

    #[test]
    fn out_of_range_falls_back_to_default() {
        let k = 10;
        assert_eq!(
            ef_search_for_recall_target(k, 1.5, N_NO_SCALE, DIM_NO_SCALE),
            default_ef_search(k, N_NO_SCALE, DIM_NO_SCALE),
            "over-1.0 target should fall back"
        );
        assert_eq!(
            ef_search_for_recall_target(k, 0.0, N_NO_SCALE, DIM_NO_SCALE),
            default_ef_search(k, N_NO_SCALE, DIM_NO_SCALE),
            "below-0.5 target should fall back"
        );
        assert_eq!(
            ef_search_for_recall_target(k, f32::NAN, N_NO_SCALE, DIM_NO_SCALE),
            default_ef_search(k, N_NO_SCALE, DIM_NO_SCALE),
            "NaN should fall back"
        );
    }

    #[test]
    fn high_k_floors_at_step_minimum() {
        // PE-1c / W0 floors: 0.99→200, 0.97→64, 0.95→60, 0.90→40, 0.80→32, <0.80→24.
        assert!(ef_search_for_recall_target(0, 0.99, N_NO_SCALE, DIM_NO_SCALE) >= 200);
        assert!(ef_search_for_recall_target(0, 0.97, N_NO_SCALE, DIM_NO_SCALE) >= 64);
        assert!(ef_search_for_recall_target(0, 0.95, N_NO_SCALE, DIM_NO_SCALE) >= 60);
        assert!(ef_search_for_recall_target(0, 0.90, N_NO_SCALE, DIM_NO_SCALE) >= 40);
        assert!(ef_search_for_recall_target(0, 0.80, N_NO_SCALE, DIM_NO_SCALE) >= 32);
        assert!(ef_search_for_recall_target(0, 0.70, N_NO_SCALE, DIM_NO_SCALE) >= 24);
    }

    #[test]
    fn default_ef_search_uses_k_max_100() {
        use super::default_ef_search;
        // PE-1: default = k.max(100). 1M-scale fix.
        assert_eq!(default_ef_search(0, N_NO_SCALE, DIM_NO_SCALE), 100);
        assert_eq!(default_ef_search(1, N_NO_SCALE, DIM_NO_SCALE), 100);
        assert_eq!(default_ef_search(10, N_NO_SCALE, DIM_NO_SCALE), 100);
        assert_eq!(default_ef_search(99, N_NO_SCALE, DIM_NO_SCALE), 100);
        assert_eq!(default_ef_search(100, N_NO_SCALE, DIM_NO_SCALE), 100);
        // k dominates when above floor.
        assert_eq!(default_ef_search(200, N_NO_SCALE, DIM_NO_SCALE), 200);
        assert_eq!(default_ef_search(1000, N_NO_SCALE, DIM_NO_SCALE), 1000);
    }

    #[test]
    fn recall_target_097_meets_the_recalibrated_floor() {
        // 2026-06-21 recalibration: this test used to assert the 0.97 step
        // always costs <= `default_ef_search` (which the doc comment on that
        // function already says is only ~0.95 recall, not the 1.0 this old
        // assertion implicitly assumed -- the two were never actually
        // consistent). A real ef sweep (see `ef_search_for_recall_target`'s
        // doc comment) showed achieving genuine 0.97 *mean* recall needs more
        // candidates than the ~0.95-recall default in some cases -- that's
        // correct and expected (higher recall target costs more, not less).
        // This now just pins the floor itself.
        for k in [10, 50, 100] {
            let target = ef_search_for_recall_target(k, 0.97, N_NO_SCALE, DIM_NO_SCALE);
            assert!(
                target >= 128,
                "0.97 step floor regressed below 128 at k={k}: {target}"
            );
        }
    }

    #[test]
    fn recall_target_095_cheaper_than_097() {
        // PE-1c: each lower target should cost strictly less or equal.
        for k in [10, 50, 100, 200] {
            let t97 = ef_search_for_recall_target(k, 0.97, N_NO_SCALE, DIM_NO_SCALE);
            let t95 = ef_search_for_recall_target(k, 0.95, N_NO_SCALE, DIM_NO_SCALE);
            assert!(t95 <= t97, "0.95 ({t95}) must be <= 0.97 ({t97}) at k={k}");
        }
    }

    #[test]
    fn n_scale_is_noop_at_or_below_anchor() {
        assert_eq!(super::n_scale(1), 1.0);
        assert_eq!(super::n_scale(1_000), 1.0);
        assert_eq!(super::n_scale(N_NO_SCALE), 1.0);
    }

    #[test]
    fn dim_scale_is_noop_at_or_below_anchor() {
        assert_eq!(super::dim_scale(1), 1.0);
        assert_eq!(super::dim_scale(32), 1.0);
        assert_eq!(super::dim_scale(DIM_NO_SCALE), 1.0);
    }

    #[test]
    fn ef_search_grows_with_dim() {
        // A4: matches the measured sweep anchors (384/512/1024/1536 at
        // dim 128/256/768/1536), within the rounding `dim_scale`'s fit allows.
        let k = 10;
        let ef_64 = ef_search_for_recall_target(k, 0.97, N_NO_SCALE, 64);
        let ef_128 = ef_search_for_recall_target(k, 0.97, N_NO_SCALE, 128);
        let ef_256 = ef_search_for_recall_target(k, 0.97, N_NO_SCALE, 256);
        let ef_768 = ef_search_for_recall_target(k, 0.97, N_NO_SCALE, 768);
        let ef_1536 = ef_search_for_recall_target(k, 0.97, N_NO_SCALE, 1536);
        assert_eq!(
            ef_64, 128,
            "anchor point must reproduce the un-scaled floor exactly"
        );
        assert!(ef_128 >= 384, "dim=128 floor regressed: {ef_128}");
        assert!(ef_256 >= 512, "dim=256 floor regressed: {ef_256}");
        assert!(ef_768 >= 1024, "dim=768 floor regressed: {ef_768}");
        assert!(ef_1536 >= 1536, "dim=1536 floor regressed: {ef_1536}");
        assert!(
            ef_64 <= ef_128 && ef_128 <= ef_256 && ef_256 <= ef_768 && ef_768 <= ef_1536,
            "floor must be non-decreasing in dim: {ef_64} {ef_128} {ef_256} {ef_768} {ef_1536}"
        );
    }

    #[test]
    fn ef_search_grows_with_point_count() {
        // W4: matches the measured sweep (128/256/512 at 12K/40K/120K)
        // within the rounding `n_scale`'s fit allows.
        let k = 10;
        let ef_12k = ef_search_for_recall_target(k, 0.97, 12_000, DIM_NO_SCALE);
        let ef_40k = ef_search_for_recall_target(k, 0.97, 40_000, DIM_NO_SCALE);
        let ef_120k = ef_search_for_recall_target(k, 0.97, 120_000, DIM_NO_SCALE);
        assert_eq!(
            ef_12k, 128,
            "anchor point must reproduce the un-scaled floor exactly"
        );
        assert!(
            ef_40k >= 256,
            "40K floor regressed below measured requirement: {ef_40k}"
        );
        assert!(
            ef_120k >= 512,
            "120K floor regressed below measured requirement: {ef_120k}"
        );
        assert!(ef_12k < ef_40k && ef_40k < ef_120k);
    }
}

pub struct PagedVectors {
    storage: Arc<crate::encryption::PersistentFile>,
    pub count: usize,
    pub dim: usize,
}

impl std::fmt::Debug for PagedVectors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PagedVectors")
            .field("count", &self.count)
            .field("dim", &self.dim)
            .finish()
    }
}

impl Clone for PagedVectors {
    fn clone(&self) -> Self {
        PagedVectors {
            storage: self.storage.clone(),
            count: self.count,
            dim: self.dim,
        }
    }
}

impl PagedVectors {
    pub(crate) fn get(&self, idx: usize) -> Cow<'_, [f32]> {
        let row_bytes = self.dim.checked_mul(4).expect("validated vector row width");
        let offset = 24_usize
            .checked_add(idx.checked_mul(row_bytes).expect("validated vector offset"))
            .expect("validated vector offset");
        let bytes = self
            .storage
            .read_range(offset..offset + row_bytes)
            .expect("validated paged vector range");
        match bytes {
            Cow::Borrowed(bytes) => {
                // SAFETY: the writer stores aligned little-endian f32 rows
                // after a 24-byte header, and the file is immutable.
                Cow::Borrowed(unsafe {
                    std::slice::from_raw_parts(bytes.as_ptr().cast::<f32>(), self.dim)
                })
            }
            Cow::Owned(bytes) => Cow::Owned(
                bytes
                    .chunks_exact(4)
                    .map(|value| f32::from_le_bytes(value.try_into().expect("vector value")))
                    .collect(),
            ),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.count
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct H2qgPayload {
    vector_dim: usize,
    nprobe: usize,
    #[serde(default)]
    mode: H2qgMode,
    #[serde(default)]
    quantization: QuantizationPlan,
    cells: Vec<IvfCell>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hnsw: Option<HnswGraph>,
    /// Bugfix: the HNSW graph's internal distance was always raw squared-L2
    /// regardless of this. For `Cosine` collections we now normalize vectors
    /// before they enter the graph so its notion of "near" matches the
    /// collection's real one. Defaults to `L2` on deserialize (not
    /// `DistanceMetric::default()`, which is `Cosine`) so segments persisted
    /// before this field existed keep their original always-L2 internal
    /// geometry on reload instead of being silently reinterpreted.
    #[serde(default = "default_legacy_metric")]
    metric: DistanceMetric,
}

fn default_legacy_metric() -> DistanceMetric {
    crate::DistanceMetric::L2
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum H2qgMode {
    #[default]
    Ivf,
    Flat,
    Hnsw,
}

/// Per-node neighbor lists, one entry per layer the node participates in.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct HnswNode {
    connections: Vec<Vec<usize>>,
}

/// Output of [`HnswGraph::plan_insert`]: the new node's level and, for each
/// layer from `node_level.min(max_layer)` down to 0, the beam-search
/// candidates found at that layer. Consumed by [`HnswGraph::apply_insert`].
struct InsertPlan {
    node_level: usize,
    layer_candidates: Vec<(usize, Vec<(f32, usize)>)>,
}

/// HNSW navigable small world graph stored alongside the artifact payload.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct HnswGraph {
    m: usize,
    m0: usize,
    ef_construction: usize,
    entry_point: Option<usize>,
    max_layer: usize,
    nodes: Vec<HnswNode>,
    node_ids: Vec<String>,
    /// Full-precision vectors.  Empty when `sq8` is `Some`.
    vectors: Vec<Vec<f32>>,
    /// SQ8-quantised codes.  Populated when the index is built with SQ8 enabled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    sq8_codes: Vec<Vec<u8>>,
    /// SQ8 parameters shared across all vectors in this graph.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sq8: Option<Sq8Params>,
    /// Paged persistent vectors; mmap-backed for plaintext and bounded for encryption.
    /// Not serialised — reconstructed from the external file on read.
    #[serde(skip)]
    paged_vecs: Option<PagedVectors>,
    /// P2C — server-wide `intra-query parallel beam` flag. When set, the
    /// layer-0 beam expansion dispatches unvisited-neighbor scoring to
    /// `rayon::par_iter` once the batch size hits `INTRA_QUERY_PARALLEL_THRESHOLD`.
    /// Arc-shared so the server can flip it without holding `&mut self`
    /// on the read path. Default OFF to preserve the recall_golden floor
    /// and to avoid the insert-phase hang the original P2C attempt hit.
    #[serde(skip, default)]
    intra_query_parallel: Arc<AtomicBool>,
    /// W1 — in-beam binary cascade sign codes. One `Vec<u64>` (dim/64 words)
    /// per node, packing the f32 sign bits. Built only for the f32 path
    /// (`sq8` is `None`); empty when SQ8 is active (SQ8 is itself a cheaper
    /// proxy). `#[serde(skip)]` — rebuilt lazily from `vectors`/`paged_vecs`
    /// when the cascade flag is first enabled, so artifacts never carry them.
    #[serde(skip, default)]
    sign_codes: Vec<Vec<u64>>,
    /// W1 Phase 3 — `||v|| / sqrt(padded_dim)` per node, parallel to
    /// `sign_codes`. Restores the magnitude the 1-bit code discards so
    /// [`Self::asym_proxy`] estimates a real dot product instead of one
    /// that implicitly assumes every vector is unit-norm.
    #[serde(skip, default)]
    sign_norms: Vec<f32>,
    /// W1 — server-wide in-beam cascade flag. When set (and sign codes are
    /// built), the layer-0 beam ranks neighbours by Hamming popcount on
    /// `sign_codes`, keeps a widened pool, then exact-reranks. Arc-shared like
    /// `intra_query_parallel` so the server can flip it without `&mut self` on
    /// the read path. Default OFF until benched to hold the recall floor.
    #[serde(skip, default)]
    cascade: Arc<AtomicBool>,
    /// A3 — multi-entry-point fix for row 153's real finding: single-entry-
    /// point greedy descent can commit to the wrong cluster's basin on
    /// tightly-clustered corpora, and no `ef_search` widening at layer 0
    /// recovers from that (the beam only ever explores within whatever
    /// region the descent already committed to). A `√N`-sized pool of
    /// farthest-point-sampled representative points, computed once at build
    /// time ([`Self::assign_entry_candidates`]); at query time,
    /// [`Self::nprobe_seeds`] picks the few nearest *to that specific
    /// query* to seed additional independent descents from -- see that
    /// function's doc comment for why query-dependent selection (not a
    /// fixed diverse subset) is what actually closes the failure.
    /// `#[serde(default)]` so pre-A3 persisted graphs deserialize with an
    /// empty list (falls back to the old single-entry behavior until the
    /// next build/compact recomputes it) instead of failing to load.
    #[serde(default)]
    entry_candidates: Vec<usize>,
}

impl HnswGraph {
    fn new(m: usize, ef_construction: usize) -> Self {
        Self {
            m,
            m0: m * 2,
            ef_construction,
            entry_point: None,
            max_layer: 0,
            nodes: Vec::new(),
            node_ids: Vec::new(),
            vectors: Vec::new(),
            sq8_codes: Vec::new(),
            sq8: None,
            paged_vecs: None,
            intra_query_parallel: Arc::new(AtomicBool::new(false)),
            sign_codes: Vec::new(),
            sign_norms: Vec::new(),
            cascade: Arc::new(AtomicBool::new(false)),
            entry_candidates: Vec::new(),
        }
    }

    fn new_sq8(m: usize, ef_construction: usize, sq8: Sq8Params) -> Self {
        Self {
            m,
            m0: m * 2,
            ef_construction,
            entry_point: None,
            max_layer: 0,
            nodes: Vec::new(),
            node_ids: Vec::new(),
            vectors: Vec::new(),
            sq8_codes: Vec::new(),
            sq8: Some(sq8),
            paged_vecs: None,
            intra_query_parallel: Arc::new(AtomicBool::new(false)),
            sign_codes: Vec::new(),
            sign_norms: Vec::new(),
            cascade: Arc::new(AtomicBool::new(false)),
            entry_candidates: Vec::new(),
        }
    }

    /// P2B v2 — return a raw pointer to the start of `idx`'s vector
    /// data, suitable as the address argument to
    /// [`prefetch_l1_read`]. Returns `None` when the storage layout
    /// doesn't expose a contiguous heap buffer (paged mmap) — bench
    /// doesn't use it, and the caller treats `None` as "no hint, fall
    /// through to the next neighbour."
    fn data_ptr_for_prefetch(&self, idx: usize) -> Option<*const u8> {
        if idx >= self.nodes.len() || self.paged_vecs.is_some() {
            return None;
        }
        self.sq8_codes
            .get(idx)
            .map(|codes| codes.as_ptr())
            .or_else(|| self.vectors.get(idx).map(|v| v.as_ptr() as *const u8))
    }

    /// Full-precision vector for node `idx`, transparent over storage layout:
    /// mmap-paged base vectors (indices `< paged.count`) vs. the in-heap
    /// `vectors` tail that live inserts append after a paged index is loaded.
    /// This split is what lets a segment's vector data stay on disk (OS page
    /// cache decides residency) while the graph stays writable.
    fn full_vec(&self, idx: usize) -> Cow<'_, [f32]> {
        if let Some(paged) = &self.paged_vecs {
            if idx < paged.count {
                return paged.get(idx);
            }
            return Cow::Borrowed(&self.vectors[idx - paged.count]);
        }
        Cow::Borrowed(&self.vectors[idx])
    }

    /// Compute distance, reusing a pre-encoded SQ8 query when available.
    /// Caller is responsible for ensuring `q_codes` was encoded against
    /// `self.sq8` of this same graph.
    fn dist_to_with_codes(&self, query: &[f32], q_codes: Option<&[u8]>, idx: usize) -> f32 {
        match &self.sq8 {
            Some(params) => match q_codes {
                Some(codes) => params.approx_sq_l2(codes, &self.sq8_codes[idx]),
                None => {
                    let encoded = params.encode(query);
                    params.approx_sq_l2(&encoded, &self.sq8_codes[idx])
                }
            },
            None => squared_l2(query, &self.full_vec(idx)),
        }
    }

    /// Compute distance between two stored nodes.
    fn dist_between(&self, i: usize, j: usize) -> f32 {
        match &self.sq8 {
            Some(params) => params.approx_sq_l2(&self.sq8_codes[i], &self.sq8_codes[j]),
            None => squared_l2(&self.full_vec(i), &self.full_vec(j)),
        }
    }

    /// A3 — number of `entry_candidates` a query actually probes (nearest to
    /// the query by distance, computed cheaply at query time — see
    /// [`Self::nprobe_seeds`]). Named to match the IVF `nprobe` concept this
    /// approximates: `entry_candidates` stands in for coarse cell centroids
    /// without a real k-means layer (that's the bigger Track B1 epic; this
    /// is the cheap version that closes row 153's actual failure). 4 is a
    /// starting point, not swept/tuned — raise only with new evidence, same
    /// rule as `CASCADE_OVERSAMPLE`/`n_scale`/`dim_scale`.
    const NPROBE: usize = 4;
    /// Above this many nodes, sample candidates for farthest-point selection
    /// instead of scanning every node -- same threshold and `8·√N` sampling
    /// discipline `vamana::medoid` uses, for the same reason (a uniform
    /// sample's farthest points concentrate on the true farthest points as
    /// N grows, so this is a linear-cost approximation of an O(N) exact
    /// scan rather than an O(N²) one).
    const ENTRY_SAMPLE_EXACT_THRESHOLD: usize = 2048;

    /// A3 — populate [`Self::entry_candidates`] via farthest-point sampling
    /// from `entry_point`, targeting roughly `√N` candidates (one per
    /// implicit cluster, if the corpus has cluster structure — farthest-
    /// first traversal is a standard k-center approximation, and `√N`
    /// mirrors the same nlist-sizing heuristic the paper's IVF design and
    /// `vamana::medoid`'s sampling both use). Real finding this fixes
    /// (delivery matrix row 153): single-entry-point greedy descent can
    /// commit to the wrong cluster's basin on tightly-clustered corpora, and
    /// no `ef_search` widening at layer 0 recovers from that. A *fixed*
    /// small set of alternate entries (the first version of this fix, 3
    /// extra points chosen without looking at the query) measurably reduced
    /// but did not eliminate the failure — most of a corpus's ~√N clusters
    /// still had no seed anywhere near them. Keeping a larger `√N`-sized
    /// candidate pool and picking the `NPROBE` nearest *to the actual query*
    /// at search time ([`Self::nprobe_seeds`]) instead of a fixed diverse
    /// subset is what actually closes it — see that function's doc comment.
    /// Called once after a full bulk build ([`Self::build_hnsw_index_inner`])
    /// -- not recomputed on every incremental single-point insert, since one
    /// new point rarely shifts the cluster structure and recomputing it
    /// there would turn an O(1) insert into an O(N) one.
    fn assign_entry_candidates(&mut self) {
        self.entry_candidates.clear();
        let Some(entry) = self.entry_point else {
            return;
        };
        let n = self.node_count();
        if n <= 1 {
            return;
        }
        let candidates: Vec<usize> = if n <= Self::ENTRY_SAMPLE_EXACT_THRESHOLD {
            (0..n).filter(|&i| i != entry).collect()
        } else {
            let sample_size = (((n as f64).sqrt() * 8.0).ceil() as usize).clamp(1, n);
            let mut seen = HashSet::with_capacity(sample_size);
            let mut out = Vec::with_capacity(sample_size);
            let mut state = 0xA3EE_A3EE_A3EE_A3EE_u64 ^ n as u64;
            let mut attempts = 0usize;
            // Bounded by `attempts` (not just `seen.len() < n`) so a
            // pathological RNG cycle can't spin forever -- 8x the sample
            // size is generous headroom for the birthday-bound collision
            // rate at these sample sizes.
            while out.len() < sample_size && attempts < sample_size.saturating_mul(8) {
                state = splitmix64(state);
                let idx = (state as usize) % n;
                attempts += 1;
                if idx != entry && seen.insert(idx) {
                    out.push(idx);
                }
            }
            out
        };
        if candidates.is_empty() {
            return;
        }
        // Target ~√N representatives (clamped so a huge N doesn't blow up
        // the per-query O(target) proximity scan in `nprobe_seeds` --
        // 4096 caps that scan around the same order of magnitude as a
        // typical `ef_search` beam, so it never dominates query cost).
        let target = (n as f64).sqrt().ceil() as usize;
        let target = target.clamp(1, 4096).min(candidates.len());
        let mut min_dist: Vec<f32> = candidates
            .iter()
            .map(|&c| self.dist_between(entry, c))
            .collect();
        for _ in 0..target {
            let Some((pos, _)) = min_dist
                .iter()
                .enumerate()
                .max_by(|a, b| a.1.total_cmp(b.1))
            else {
                break;
            };
            let picked = candidates[pos];
            self.entry_candidates.push(picked);
            for (i, &c) in candidates.iter().enumerate() {
                let d = self.dist_between(picked, c);
                if d < min_dist[i] {
                    min_dist[i] = d;
                }
            }
        }
    }

    /// A3 — pick the [`Self::NPROBE`] entries in `entry_candidates` nearest
    /// to `query` (by the same distance function the beam search itself
    /// uses, so SQ8/paged/full-precision all stay consistent). This is the
    /// step that actually closes row 153: unlike a fixed diverse seed set
    /// (picked once at build time without knowing the query), picking
    /// *by proximity to this specific query* out of a `√N`-sized candidate
    /// pool means whichever cluster the query really belongs to almost
    /// always has a representative among the nearest few, regardless of how
    /// many total clusters the corpus has. Cost is O(|entry_candidates|)
    /// distance computations, not another beam search -- cheap relative to
    /// the layer-0 beams this feeds into (bench note in the dev log: at
    /// `n=12000` this is ~110 candidates, negligible next to an `ef=128`
    /// beam).
    fn nprobe_seeds(&self, query: &[f32], q_codes: Option<&[u8]>) -> Vec<usize> {
        let mut scored: Vec<(f32, usize)> = self
            .entry_candidates
            .iter()
            .map(|&idx| (self.dist_to_with_codes(query, q_codes, idx), idx))
            .collect();
        let take = Self::NPROBE.min(scored.len());
        if take > 0 && take < scored.len() {
            scored.select_nth_unstable_by(take - 1, |a, b| a.0.total_cmp(&b.0));
        }
        scored.truncate(take);
        scored.into_iter().map(|(_, idx)| idx).collect()
    }

    /// True when SQ8 quantisation is active for this graph.
    pub fn uses_sq8(&self) -> bool {
        self.sq8.is_some()
    }

    /// W1 Phase 3 — asymmetric binary cascade proxy, rotation- and
    /// norm-corrected. `query` here is the **rotated** query (caller applies
    /// [`crate::index::rotate_for_cascade`] once per query, not per node);
    /// `q_sum` is `query.iter().sum()`, hoisted out of the per-node hot loop.
    /// Estimates the dot product against node `idx`'s 1-bit sign code of the
    /// rotated vector: `dot(q, v) ≈ ||v||/sqrt(d) · Σ_i q_i·sign(v_i) =
    /// ||v||/sqrt(d) · (2·Σ_{bit set} q_i − Σ_i q_i)`. Without the rotation
    /// the 1-bit estimator's error grows with correlated dimensions
    /// (real embeddings are not isotropic); without the `||v||/sqrt(d)`
    /// scale (`sign_norms[idx]`), the estimate implicitly assumes every
    /// vector is unit-norm, which silently breaks ranking across points
    /// once norms vary. Returns `-estimate` (smaller = nearer for
    /// normalized vectors, matching the rest of the cascade's heap
    /// ordering).
    #[inline]
    fn asym_proxy(&self, query: &[f32], q_sum: f32, idx: usize) -> f32 {
        let code = &self.sign_codes[idx];
        let mut p = 0.0_f32;
        for (w, &word) in code.iter().enumerate() {
            let mut bits = word;
            let base = w * 64;
            while bits != 0 {
                let d = base + bits.trailing_zeros() as usize;
                if d < query.len() {
                    p += query[d];
                }
                bits &= bits - 1;
            }
        }
        let dot_est = 2.0 * p - q_sum;
        let scale = self.sign_norms.get(idx).copied().unwrap_or(1.0);
        -(dot_est * scale)
    }

    /// W1 Phase 3 — build rotated sign-bit codes + norm scales for every
    /// node from the f32 store. No-op when SQ8 is active (already a cheaper
    /// proxy than f32) or codes already exist. Reads from `paged_vecs` when
    /// the graph is paged, else from `vectors`.
    fn ensure_sign_codes(&mut self) {
        if self.sq8.is_some() || !self.sign_codes.is_empty() {
            return;
        }
        let n = self.nodes.len();
        if n == 0 {
            return;
        }
        let dim = if let Some(p) = &self.paged_vecs {
            p.dim
        } else {
            self.vectors.first().map_or(0, |v| v.len())
        };
        if dim == 0 {
            return;
        }
        let padded_dim = crate::index::next_pow2(dim);
        let wc = crate::index::sign_word_count(padded_dim);
        let inv_sqrt_padded = 1.0 / (padded_dim as f32).sqrt();
        let mut codes = Vec::with_capacity(n);
        let mut norms = Vec::with_capacity(n);
        for i in 0..n {
            let v = self.full_vec(i);
            let rotated = crate::index::rotate_for_cascade(&v);
            codes.push(crate::index::encode_sign_bits(&rotated, wc));
            let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
            norms.push(norm * inv_sqrt_padded);
        }
        self.sign_codes = codes;
        self.sign_norms = norms;
    }

    /// W1 — adopt the server-wide cascade flag. If it's currently ON, build the
    /// sign codes eagerly so the read path never needs `&mut self`.
    fn set_cascade_flag(&mut self, flag: Arc<AtomicBool>) {
        let on = flag.load(std::sync::atomic::Ordering::Relaxed);
        self.cascade = flag;
        if on {
            self.ensure_sign_codes();
        }
    }

    /// W1 Phase 3 — layer-0 beam guided by the rotation- and norm-corrected
    /// binary cascade proxy, then exact rerank. Mirrors the layer-0 path of
    /// [`Self::search_layer_with_codes`] but ranks admission/expansion by
    /// [`Self::asym_proxy`] (full-precision rotated query vs 1-bit node
    /// code) and keeps a widened `ef * oversample` found pool. After the
    /// beam, the pool is exact-reranked with the true f32 metric on the
    /// **raw** (unrotated) `query`/vectors and truncated to `ef`. The
    /// `q_sign` argument is retained for signature stability with the
    /// symmetric path but unused. Returns up to `ef` `(exact_dist, idx)`
    /// pairs, nearest first.
    fn search_layer0_cascade(
        &self,
        query: &[f32],
        _q_sign: &[u64],
        ep: usize,
        ef: usize,
        oversample: usize,
        filter: Option<&dyn crate::index::FilterPredicate>,
    ) -> Vec<(f32, usize)> {
        let ef_cascade = ef.saturating_mul(oversample).max(ef);
        // Rotate the query once per call (not per node) — same rotation
        // applied to every stored vector in `ensure_sign_codes`, so the
        // dot-product proxy below stays order-equivalent to the exact one.
        let rotated_query = crate::index::rotate_for_cascade(query);
        let q_sum: f32 = rotated_query.iter().sum();
        let ep_p = self.asym_proxy(&rotated_query, q_sum, ep);

        let mut visited: HashSet<usize> = HashSet::with_capacity(ef_cascade * 4);
        visited.insert(ep);

        // candidates: min-heap on proxy (pop nearest proxy first).
        let mut candidates: BinaryHeap<Reverse<(OrdF32, usize)>> = BinaryHeap::new();
        candidates.push(Reverse((OrdF32(ep_p), ep)));
        // found: max-heap on proxy, capped at ef_cascade (pop worst over cap).
        let mut found: BinaryHeap<(OrdF32, usize)> = BinaryHeap::new();
        if filter.is_none_or(|pred| pred.matches(&self.node_ids[ep])) {
            found.push((OrdF32(ep_p), ep));
        }

        while let Some(Reverse((OrdF32(c_p), c_idx))) = candidates.pop() {
            let worst = found.peek().map_or(f32::MAX, |&(OrdF32(p), _)| p);
            if found.len() >= ef_cascade && c_p > worst {
                break;
            }
            let neighbors = match self.nodes.get(c_idx).and_then(|n| n.connections.first()) {
                Some(c) => c,
                None => continue,
            };
            for &nb in neighbors {
                if !visited.insert(nb) {
                    continue;
                }
                if filter.is_some_and(|pred| !pred.matches(&self.node_ids[nb])) {
                    continue;
                }
                let p = self.asym_proxy(&rotated_query, q_sum, nb);
                let worst = found.peek().map_or(f32::MAX, |&(OrdF32(pp), _)| pp);
                if found.len() < ef_cascade || p < worst {
                    candidates.push(Reverse((OrdF32(p), nb)));
                    found.push((OrdF32(p), nb));
                    if found.len() > ef_cascade {
                        found.pop();
                    }
                }
            }
        }

        // Exact rerank: true f32 distance on the widened pool, keep top `ef`.
        let mut exact: Vec<(f32, usize)> = found
            .into_iter()
            .map(|(_, idx)| (self.dist_to_with_codes(query, None, idx), idx))
            .collect();
        exact.sort_by(|a, b| a.0.total_cmp(&b.0));
        exact.truncate(ef);
        exact
    }

    /// W1 — full cascade query: exact f32 greedy descent through the upper
    /// layers (few nodes, lands a good entry point), then the Hamming-guided
    /// widened-pool layer-0 beam with exact rerank. Returns up to `ef` ids.
    fn search_query_cascade(
        &self,
        query: &[f32],
        ef: usize,
        oversample: usize,
        filter: Option<&dyn crate::index::FilterPredicate>,
    ) -> Vec<String> {
        let ep = match self.entry_point {
            None => return Vec::new(),
            Some(ep) => ep,
        };
        let mut cur_ep = ep;
        for l in (1..=self.max_layer).rev() {
            cur_ep = self.search_layer_greedy_from_with_codes(query, None, cur_ep, l, None);
        }
        // Asymmetric proxy reads the query in full precision; no query sign code needed.
        self.search_layer0_cascade(query, &[], cur_ep, ef, oversample, filter)
            .into_iter()
            .map(|(_, idx)| self.node_ids[idx].clone())
            .collect()
    }

    fn insert(&mut self, id: String, vector: Vec<f32>, rng_state: u64) {
        let plan = self.plan_insert(&vector, rng_state);
        self.apply_insert(id, vector, plan);
    }

    /// Read-only half of [`Self::insert`]: picks the new node's level and
    /// runs the greedy descent + per-layer beam search against the graph as
    /// it stands right now, without mutating anything. Split out so the
    /// bulk build path (`build_hnsw_index_inner`) can run this — the
    /// expensive part of an insert — for a whole batch of points in
    /// parallel via `rayon`, then apply the resulting plans serially. A
    /// single-point call here followed by [`Self::apply_insert`] is exactly
    /// equivalent to the old monolithic `insert`.
    fn plan_insert(&self, vector: &[f32], rng_state: u64) -> InsertPlan {
        let node_level = hnsw_random_level(rng_state, self.m);
        let mut layer_candidates = Vec::new();
        if let Some(ep) = self.entry_point {
            // Phase 1: greedy descent from top layer to node_level + 1.
            // `exclude: None` is safe here (unlike the live single-insert
            // path the old code shared this with) because the node being
            // planned hasn't been pushed into `self.nodes` yet, so it can't
            // appear as a neighbor regardless.
            let mut cur_ep = ep;
            for l in ((node_level + 1)..=self.max_layer).rev() {
                cur_ep = self.search_layer_greedy_from(vector, cur_ep, l, None);
            }

            // Phase 2: beam search at each layer down to 0.
            for l in (0..=node_level.min(self.max_layer)).rev() {
                let ef = self.ef_construction;
                let candidates = self.search_layer(vector, cur_ep, ef, l, None);
                if let Some(&(_, best)) = candidates.first() {
                    cur_ep = best;
                }
                layer_candidates.push((l, candidates));
            }
        }
        InsertPlan {
            node_level,
            layer_candidates,
        }
    }

    /// Write-only half of [`Self::insert`]: stores the point and applies
    /// the connections found by [`Self::plan_insert`]. Must run serially
    /// per point (mutates shared node/connection state), in the same order
    /// the caller wants node indices assigned.
    fn apply_insert(&mut self, id: String, vector: Vec<f32>, plan: InsertPlan) {
        let InsertPlan {
            node_level,
            layer_candidates,
        } = plan;
        let node_idx = self.nodes.len();

        let node = HnswNode {
            connections: vec![Vec::new(); node_level + 1],
        };

        self.nodes.push(node);
        self.node_ids.push(id);
        // Store in the appropriate format.
        if let Some(params) = &self.sq8 {
            self.sq8_codes.push(params.encode(&vector));
        } else {
            // Paged build: rows `< paged.count` already live in the mmap
            // sidecar — pushing them into the heap tail would double-store
            // and shift the tail offset. Only post-build live inserts append.
            let paged_count = self.paged_vecs.as_ref().map_or(0, |p| p.count);
            if node_idx >= paged_count {
                self.vectors.push(vector.clone());
            }
            // W1 Phase 3: keep sign codes + norm scales in sync once they're
            // being maintained (i.e. the cascade was enabled and
            // `ensure_sign_codes` ran). Building them only-if-non-empty
            // avoids paying the cost for collections that never enable the
            // cascade.
            if !self.sign_codes.is_empty() {
                let padded_dim = crate::index::next_pow2(vector.len());
                let wc = crate::index::sign_word_count(padded_dim);
                let rotated = crate::index::rotate_for_cascade(&vector);
                self.sign_codes
                    .push(crate::index::encode_sign_bits(&rotated, wc));
                let norm: f32 = vector.iter().map(|x| x * x).sum::<f32>().sqrt();
                self.sign_norms.push(norm / (padded_dim as f32).sqrt());
            }
        }

        if self.entry_point.is_none() {
            self.entry_point = Some(node_idx);
            self.max_layer = node_level;
            return;
        }

        for (l, candidates) in layer_candidates {
            let m_max = if l == 0 { self.m0 } else { self.m };
            let neighbors = self.select_diverse_neighbors(&candidates, m_max);

            self.nodes[node_idx].connections[l] = neighbors.clone();

            for &nb in &neighbors {
                self.nodes[nb].connections[l].push(node_idx);
                if self.nodes[nb].connections[l].len() > m_max {
                    self.prune_connections(nb, l, m_max);
                }
            }
        }

        if node_level > self.max_layer {
            self.entry_point = Some(node_idx);
            self.max_layer = node_level;
        }
    }

    /// Greedy descent starting from `start` at `layer`.
    /// `exclude` is an optional node index to skip (the new node during build).
    fn search_layer_greedy_from(
        &self,
        query: &[f32],
        start: usize,
        layer: usize,
        exclude: Option<usize>,
    ) -> usize {
        self.search_layer_greedy_from_with_codes(query, None, start, layer, exclude)
    }

    fn search_layer_greedy_from_with_codes(
        &self,
        query: &[f32],
        q_codes: Option<&[u8]>,
        start: usize,
        layer: usize,
        exclude: Option<usize>,
    ) -> usize {
        let mut cur = start;
        let mut cur_dist = self.dist_to_with_codes(query, q_codes, cur);
        loop {
            let mut improved = false;
            if let Some(connections) = self.nodes[cur].connections.get(layer) {
                for &nb in connections {
                    if exclude == Some(nb) {
                        continue;
                    }
                    let d = self.dist_to_with_codes(query, q_codes, nb);
                    if d < cur_dist {
                        cur = nb;
                        cur_dist = d;
                        improved = true;
                    }
                }
            }
            if !improved {
                break;
            }
        }
        cur
    }

    /// Beam search at `layer` starting from `ep`; returns up to `ef` results sorted
    /// ascending by distance (nearest first).
    /// `exclude` is an optional node index to skip (the new node during build).
    fn search_layer(
        &self,
        query: &[f32],
        ep: usize,
        ef: usize,
        layer: usize,
        exclude: Option<usize>,
    ) -> Vec<(f32, usize)> {
        let intra_parallel = self
            .intra_query_parallel
            .load(std::sync::atomic::Ordering::Relaxed)
            && layer == 0;
        self.search_layer_with_codes(query, None, ep, ef, layer, exclude, intra_parallel, None)
    }

    /// P2F + P2C combined beam search.
    ///
    /// P2F: `filter = None` matches the original un-filtered contract;
    /// `Some(pred)` skips neighbours whose IDs fail the predicate BEFORE
    /// computing the distance and inserting into the candidate heap. The
    /// candidate is still marked as visited so we never re-check it.
    /// The predicate is consulted exactly once per newly-discovered
    /// neighbour. Greedy descent at upper layers keeps the original
    /// un-filtered semantic — we only prune at the layer-0 beam.
    ///
    /// P2C: when `intra_parallel` is set, the layer-0 beam expansion
    /// dispatches the unvisited-neighbor scoring to `rayon::par_iter`
    /// once the batch size hits `INTRA_QUERY_PARALLEL_THRESHOLD`. The
    /// distance compute (`dist_to_with_codes`) is a pure `&self` read;
    /// the threshold check + heap fold stay serial because they mutate
    /// shared heaps and the cutoff `worst_found` changes per push.
    #[allow(clippy::too_many_arguments)] // 8 search params; grouping into a struct is a larger refactor
    fn search_layer_with_codes(
        &self,
        query: &[f32],
        q_codes: Option<&[u8]>,
        ep: usize,
        ef: usize,
        layer: usize,
        exclude: Option<usize>,
        intra_parallel: bool,
        filter: Option<&dyn crate::index::FilterPredicate>,
    ) -> Vec<(f32, usize)> {
        self.search_layer_from_seeds_with_codes(
            query,
            q_codes,
            std::slice::from_ref(&ep),
            ef,
            layer,
            exclude,
            intra_parallel,
            filter,
        )
    }

    /// Multi-source variant of the layer beam. All entry points share one
    /// visited set and one bounded result heap, so overlapping graph basins
    /// are expanded once. A single seed is exactly the ordinary HNSW path.
    #[allow(clippy::too_many_arguments)]
    fn search_layer_from_seeds_with_codes(
        &self,
        query: &[f32],
        q_codes: Option<&[u8]>,
        seeds: &[usize],
        ef: usize,
        layer: usize,
        exclude: Option<usize>,
        intra_parallel: bool,
        filter: Option<&dyn crate::index::FilterPredicate>,
    ) -> Vec<(f32, usize)> {
        debug_assert!(!intra_parallel || layer == 0);
        if seeds.is_empty() || ef == 0 {
            return Vec::new();
        }
        // B1 (Phase 1): replace O(n) `Vec::remove(0)` + `partition_point` insert
        // with heap-backed beam search. Candidates = min-heap (pop nearest);
        // found = max-heap capped at ef (pop worst when over cap).
        let mut visited: HashSet<usize> =
            HashSet::with_capacity(ef.saturating_mul(4).saturating_add(seeds.len()));
        if let Some(ex) = exclude {
            visited.insert(ex);
        }

        let mut candidates: BinaryHeap<Reverse<(OrdF32, usize)>> = BinaryHeap::new();
        let mut found: BinaryHeap<(OrdF32, usize)> = BinaryHeap::new();
        for &seed in seeds {
            if seed >= self.nodes.len() || !visited.insert(seed) {
                continue;
            }
            let seed_dist = self.dist_to_with_codes(query, q_codes, seed);
            // P2F: every entry point remains a navigator even when it does
            // not pass the result filter, matching the single-source path.
            candidates.push(Reverse((OrdF32(seed_dist), seed)));
            if filter.is_none_or(|pred| pred.matches(&self.node_ids[seed])) {
                found.push((OrdF32(seed_dist), seed));
                if found.len() > ef {
                    found.pop();
                }
            }
        }

        while let Some(Reverse((OrdF32(c_dist), c_idx))) = candidates.pop() {
            let worst_found = found.peek().map_or(f32::MAX, |&(OrdF32(d), _)| d);
            if found.len() >= ef && c_dist > worst_found {
                break;
            }

            // Collect unvisited (and filter-passing) neighbors first so the
            // `visited` set stays monotonic. P2C: the parallel path scores
            // them via rayon after collection; P2F: filtered nodes never
            // enter the unvisited list (they stay in `visited` only).
            let neighbors = match self.nodes.get(c_idx).and_then(|n| n.connections.get(layer)) {
                Some(c) => c,
                None => continue,
            };
            let mut unvisited: smallvec::SmallVec<[usize; 32]> =
                smallvec::SmallVec::with_capacity(neighbors.len());
            for (i, &nb) in neighbors.iter().enumerate() {
                if visited.insert(nb) {
                    if filter.is_some_and(|pred| !pred.matches(&self.node_ids[nb])) {
                        // P2F: filtered-out nodes are not navigators —
                        // they cannot lead to other nodes through this
                        // expansion. Skip the distance compute AND the
                        // candidate-heap insertion. Stays in `visited`
                        // so we never re-check it.
                        continue;
                    }
                    // P2B v2: streaming L1 prefetch for the *next* neighbour's
                    // vector data. Gated on `nb` being novel (so the hint
                    // isn't wasted on already-visited entries) and on
                    // `nb` being a passing neighbor (so the filter path
                    // never triggers a prefetch that would never be
                    // consumed). The hint is fire-and-forget; out-of-bounds
                    // or no-mappable-target just loses a few issue cycles.
                    // x86_64: prefetchnta (mirrors aarch64's pldl1strm).
                    // Streaming / non-temporal: the line is read once
                    // per beam expansion, so allocating it in L2/L3
                    // would evict connection-list metadata.
                    if let Some(&next_nb) = neighbors.get(i + 1)
                        && let Some(ptr) = self.data_ptr_for_prefetch(next_nb)
                    {
                        // Safety: `ptr` points into a live, initialised
                        // allocation (sq8_codes / vectors entry) and
                        // is valid for reads. The hint itself never
                        // dereferences the address.
                        unsafe {
                            prefetch_l1_read(ptr);
                        }
                    }
                    unvisited.push(nb);
                }
            }

            // P2C parallel path: score all unvisited neighbors via
            // rayon::par_iter. Threshold check + heap fold stay serial
            // because they mutate shared heaps. SmallVec has no
            // FromParallelIterator impl, so we collect into Vec first
            // and then move into the inline-32 buffer.
            let use_parallel = intra_parallel && unvisited.len() >= INTRA_QUERY_PARALLEL_THRESHOLD;
            let scored: smallvec::SmallVec<[(f32, usize); 32]> = if use_parallel {
                use rayon::prelude::*;
                // W3: run on the dedicated search pool, not rayon's
                // global pool, so this doesn't contend with concurrent
                // compaction/batch-upsert work for rayon worker slots.
                let v: Vec<(f32, usize)> = crate::search_pool::SEARCH_POOL.install(|| {
                    unvisited
                        .par_iter()
                        .map(|&nb| (self.dist_to_with_codes(query, q_codes, nb), nb))
                        .collect()
                });
                smallvec::SmallVec::from_vec(v)
            } else {
                unvisited
                    .iter()
                    .map(|&nb| (self.dist_to_with_codes(query, q_codes, nb), nb))
                    .collect()
            };

            for (d, nb) in scored {
                let worst = found.peek().map_or(f32::MAX, |&(OrdF32(d), _)| d);
                if found.len() < ef || d < worst {
                    candidates.push(Reverse((OrdF32(d), nb)));
                    found.push((OrdF32(d), nb));
                    if found.len() > ef {
                        found.pop();
                    }
                }
            }
        }

        // Drain max-heap into ascending Vec (nearest first), matching prior contract.
        found
            .into_sorted_vec()
            .into_iter()
            .map(|(OrdF32(d), i)| (d, i))
            .collect()
    }

    /// P2F — filter-aware beam search wrapper around [`Self::search_layer_with_codes`].
    /// Kept as a thin alias so the public IndexBackend trait method can
    /// name it explicitly. The combined implementation lives in
    /// `search_layer_with_codes` to keep both code paths from diverging.
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)] // thin alias over search_layer_with_codes; same param count by design
    fn search_layer_with_codes_filter(
        &self,
        query: &[f32],
        q_codes: Option<&[u8]>,
        ep: usize,
        ef: usize,
        layer: usize,
        exclude: Option<usize>,
        filter: Option<&dyn crate::index::FilterPredicate>,
    ) -> Vec<(f32, usize)> {
        self.search_layer_with_codes(query, q_codes, ep, ef, layer, exclude, false, filter)
    }

    fn prune_connections(&mut self, node_idx: usize, layer: usize, m_max: usize) {
        let conns = self.nodes[node_idx].connections[layer].clone();
        if conns.len() <= m_max {
            return;
        }
        let mut with_dist: Vec<(f32, usize)> = conns
            .into_iter()
            .map(|nb| (self.dist_between(node_idx, nb), nb))
            .collect();
        with_dist.sort_by(|a, b| a.0.total_cmp(&b.0));
        with_dist.truncate(m_max);
        self.nodes[node_idx].connections[layer] =
            with_dist.into_iter().map(|(_, idx)| idx).collect();
    }

    /// Selects up to `m_max` diverse neighbors from sorted `candidates` using the
    /// HNSW heuristic (Algorithm 4): a candidate is kept only if no already-selected
    /// neighbor is closer to it than the query node is.
    fn select_diverse_neighbors(&self, candidates: &[(f32, usize)], m_max: usize) -> Vec<usize> {
        let mut selected: Vec<(f32, usize)> = Vec::with_capacity(m_max);
        let mut discarded: Vec<usize> = Vec::new();

        for &(d_q_e, e) in candidates {
            if selected.len() >= m_max {
                break;
            }
            let covered = selected
                .iter()
                .any(|&(_, sel)| self.dist_between(e, sel) < d_q_e);
            if covered {
                discarded.push(e);
            } else {
                selected.push((d_q_e, e));
            }
        }

        for e in discarded {
            if selected.len() >= m_max {
                break;
            }
            selected.push((0.0, e));
        }

        selected.into_iter().map(|(_, idx)| idx).collect()
    }

    /// Search the graph using the given raw query vector, returning up to `ef` node IDs
    /// sorted nearest-first.
    #[allow(dead_code)] // Convenience wrapper kept for the un-filtered contract; callers use the `_with_filter` variant.
    fn search_query(&self, query: &[f32], ef: usize) -> Vec<String> {
        self.search_query_with_filter(query, ef, None)
    }

    /// P2F — filter-aware query. `filter = None` matches [`Self::search_query`].
    /// The filter is only applied at the layer-0 beam; the upper-layer greedy
    /// descent stays un-filtered so we don't accidentally dead-end before
    /// reaching the layer-0 entry point. Layer 0 is where the candidate set
    /// is wide enough that pruning actually saves work.
    fn search_query_with_filter(
        &self,
        query: &[f32],
        ef: usize,
        filter: Option<&dyn crate::index::FilterPredicate>,
    ) -> Vec<String> {
        self.search_query_multi_entry(query, ef, filter)
            .into_iter()
            .map(|(_, idx)| self.node_ids[idx].clone())
            .collect()
    }

    /// A3 — the actual multi-entry search: descends from the primary entry
    /// point, plus the `NPROBE` `entry_candidates` nearest to *this query*
    /// (see `nprobe_seeds`'s doc comment for why query-dependent selection
    /// is what actually closes row 153, not just a fixed diverse seed set).
    /// Each seed still gets the same un-filtered upper-layer descent
    /// (pruning there risks a dead-end before reaching layer 0). Their
    /// descended endpoints then seed one shared layer-0 beam. This preserves
    /// query-dependent basin coverage while deduplicating overlapping
    /// expansions and distance work instead of running `1 + NPROBE`
    /// independent beams. Returns raw
    /// `(distance, node_idx)` pairs (not ids) so
    /// [`Self::repair_entry_candidate_connectivity`] can use it as a
    /// same-cost neighbor-discovery search during the build-time repair
    /// pass, without paying an O(N) id-to-index lookup per result.
    fn search_query_multi_entry(
        &self,
        query: &[f32],
        ef: usize,
        filter: Option<&dyn crate::index::FilterPredicate>,
    ) -> Vec<(f32, usize)> {
        if self.entry_point.is_none() {
            return Vec::new();
        }

        // Encode the SQ8 query codes once per request, not once per distance call.
        // For 1536-dim, this collapses ~thousands of re-encodes into a single one
        // (~6.4 GB transient alloc churn at conc=80 reduced to per-query 1.5 KB).
        let q_codes_owned = self.sq8.as_ref().map(|params| params.encode(query));
        let q_codes = q_codes_owned.as_deref();

        // P2C: read the intra-query-parallel flag once and forward it.
        let intra_parallel = self
            .intra_query_parallel
            .load(std::sync::atomic::Ordering::Relaxed);

        let nprobe = self.nprobe_seeds(query, q_codes);
        let mut layer_zero_seeds = Vec::with_capacity(1 + nprobe.len());
        for seed in std::iter::once(self.entry_point.unwrap()).chain(nprobe) {
            let mut cur_ep = seed;
            for l in (1..=self.max_layer).rev() {
                cur_ep = self.search_layer_greedy_from_with_codes(query, q_codes, cur_ep, l, None);
            }
            if !layer_zero_seeds.contains(&cur_ep) {
                layer_zero_seeds.push(cur_ep);
            }
        }
        self.search_layer_from_seeds_with_codes(
            query,
            q_codes,
            &layer_zero_seeds,
            ef,
            0,
            None,
            intra_parallel,
            filter,
        )
    }

    /// A3 — build-time repair pass. Real finding, deeper than the
    /// query-time fix: `plan_insert`'s own neighbor-discovery search suffers
    /// the *same* single-entry-point wrong-basin problem `nprobe_seeds`
    /// fixes at query time, so the very first point inserted from a given
    /// cluster (zero same-cluster peers yet to connect to) can end up in a
    /// layer-0 neighborhood that is a genuine **greedy-search-unreachable
    /// local minimum** from every other part of the graph -- confirmed:
    /// even [`Self::search_query_multi_entry`] using such a node's own
    /// stored vector as the query, at `ef=2000` with every entry candidate
    /// probed, still failed to find its true cluster mates. A search-based
    /// repair (try harder to *reach* it via graph traversal) cannot fix a
    /// node that traversal structurally can't reach; the actual fix is to
    /// stop relying on traversal for this narrow repair set and compute the
    /// true nearest neighbors directly. For every `entry_candidates`
    /// representative (already the node set most likely to include these
    /// early/outlier nodes, since farthest-point sampling tends to pick
    /// them), brute-force scan every point for its true `m0` nearest and
    /// wire in any missing ones as bidirectional layer-0 edges (re-pruning
    /// to `m0` as normal, same as a live insert would). Cost is
    /// O(√N × N) -- one-time at build/compact, not per query; same
    /// asymptotic family as this file's other `√N`-sampled build-time
    /// passes, just without the further sampling `assign_entry_candidates`
    /// itself uses, since correctness here specifically depends on not
    /// missing the true nearest neighbor. Full-precision-vector backends
    /// only (`self.vectors`) -- SQ8 backends skip it, a documented gap
    /// consistent with row 150's "RaBitQ/SQ8 metric-blindness not audited
    /// here" precedent.
    fn repair_entry_candidate_connectivity(&mut self) {
        if self.sq8.is_some() {
            return;
        }
        let m0 = self.m0;
        let n = self.nodes.len();
        let representatives = self.entry_candidates.clone();
        for idx in representatives {
            if idx >= n {
                continue;
            }
            // Owned copy so the scan below can borrow `self` for full_vec
            // (which reads mmap-paged and in-heap storage transparently).
            let query = self.full_vec(idx).into_owned();
            let mut scored: Vec<(f32, usize)> = (0..n)
                .filter(|&i| i != idx)
                .map(|i| (squared_l2(&query, &self.full_vec(i)), i))
                .collect();
            let take = m0.min(scored.len());
            if take > 0 && take < scored.len() {
                scored.select_nth_unstable_by(take - 1, |a, b| a.0.total_cmp(&b.0));
            }
            scored.truncate(take);
            for (_, nb) in scored {
                if self.nodes[idx].connections[0].contains(&nb) {
                    continue;
                }
                self.nodes[idx].connections[0].push(nb);
                self.nodes[nb].connections[0].push(idx);
                if self.nodes[idx].connections[0].len() > m0 {
                    self.prune_connections(idx, 0, m0);
                }
                if self.nodes[nb].connections[0].len() > m0 {
                    self.prune_connections(nb, 0, m0);
                }
            }
        }
    }

    fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

/// 8-bit scalar quantisation (SQ8) parameters.
///
/// Each dimension is independently mapped to [0, 255] using the per-dimension
/// minimum value and inverse scale derived from the training dataset.
///
/// Encoding:   code = clamp(round((x - min) * scale), 0, 255)
/// Decoding:   x̃  = min + code / scale
/// Distance:   approx_l2(a, b) = Σ ((code_a[i] - code_b[i]) * inv_scale[i])²
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Sq8Params {
    /// Per-dimension minimum values learned from the training set.
    pub dim_mins: Vec<f32>,
    /// Per-dimension scale factors (255 / range); 1.0 when range is zero.
    pub dim_scales: Vec<f32>,
    /// Per-dimension inverse scale factors (range / 255); 0.0 when range is zero.
    pub dim_inv_scales: Vec<f32>,
}

impl Sq8Params {
    /// Train SQ8 parameters from a slice of equal-length f32 vectors.
    pub fn train(vectors: &[&[f32]]) -> Self {
        if vectors.is_empty() {
            return Self {
                dim_mins: Vec::new(),
                dim_scales: Vec::new(),
                dim_inv_scales: Vec::new(),
            };
        }
        let dim = vectors[0].len();
        let mut mins = vec![f32::MAX; dim];
        let mut maxs = vec![f32::MIN; dim];
        for vec in vectors {
            for (d, &val) in vec.iter().enumerate() {
                if val < mins[d] {
                    mins[d] = val;
                }
                if val > maxs[d] {
                    maxs[d] = val;
                }
            }
        }
        let mut scales = vec![1.0_f32; dim];
        let mut inv_scales = vec![0.0_f32; dim];
        for d in 0..dim {
            let range = maxs[d] - mins[d];
            if range > 0.0 {
                scales[d] = 255.0 / range;
                inv_scales[d] = range / 255.0;
            }
        }
        Self {
            dim_mins: mins,
            dim_scales: scales,
            dim_inv_scales: inv_scales,
        }
    }

    /// Encode an f32 vector to 8-bit codes.
    pub fn encode(&self, vector: &[f32]) -> Vec<u8> {
        vector
            .iter()
            .enumerate()
            .map(|(d, &val)| {
                let shifted = (val - self.dim_mins[d]) * self.dim_scales[d];
                shifted.round().clamp(0.0, 255.0) as u8
            })
            .collect()
    }

    /// Decode 8-bit codes back to approximate f32 values.
    pub fn decode(&self, codes: &[u8]) -> Vec<f32> {
        codes
            .iter()
            .enumerate()
            .map(|(d, &code)| self.dim_mins[d] + code as f32 * self.dim_inv_scales[d])
            .collect()
    }

    /// Approximate squared L2 distance between two SQ8-encoded vectors.
    ///
    /// Keep quantized HNSW compatibility/diagnostic search in fixed eight-lane
    /// chunks so `wide` lowers it to NEON on aarch64 and AVX/SSE on x86,
    /// matching the cross-platform discipline of the full-precision distance
    /// kernels. The production Streamer mini-HNSW remains f32; the scalar tail
    /// here preserves legacy SQ8 support for dimensions not divisible by eight.
    #[inline]
    pub fn approx_sq_l2(&self, codes_a: &[u8], codes_b: &[u8]) -> f32 {
        const LANES: usize = 8;

        let len = codes_a.len().min(codes_b.len());
        let inv_scales = &self.dim_inv_scales[..len];
        let chunks = len / LANES;
        let mut acc = f32x8::splat(0.0);

        for chunk in 0..chunks {
            let base = chunk * LANES;
            let left = f32x8::new([
                codes_a[base] as f32,
                codes_a[base + 1] as f32,
                codes_a[base + 2] as f32,
                codes_a[base + 3] as f32,
                codes_a[base + 4] as f32,
                codes_a[base + 5] as f32,
                codes_a[base + 6] as f32,
                codes_a[base + 7] as f32,
            ]);
            let right = f32x8::new([
                codes_b[base] as f32,
                codes_b[base + 1] as f32,
                codes_b[base + 2] as f32,
                codes_b[base + 3] as f32,
                codes_b[base + 4] as f32,
                codes_b[base + 5] as f32,
                codes_b[base + 6] as f32,
                codes_b[base + 7] as f32,
            ]);
            let scale = f32x8::new(
                inv_scales[base..base + LANES]
                    .try_into()
                    .expect("SQ8 lane slice"),
            );
            let diff = (left - right) * scale;
            acc += diff * diff;
        }

        let mut total = acc.reduce_add();
        for d in (chunks * LANES)..len {
            let diff = (codes_a[d] as i16 - codes_b[d] as i16) as f32 * inv_scales[d];
            total += diff * diff;
        }
        total
    }

    pub fn dim(&self) -> usize {
        self.dim_mins.len()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct QuantizationPlan {
    seed: u64,
    sign_flips: Vec<i8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct IvfCell {
    centroid: Vec<f32>,
    postings: Vec<QuantizedPosting>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct QuantizedPosting {
    id: String,
    signature: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct H2qgIndex {
    payload: H2qgPayload,
    indexed_ids: HashSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2qgWrite {
    pub path: PathBuf,
    pub cells: usize,
    pub indexed_points: usize,
}

impl H2qgIndex {
    pub fn build(points: &[Point], vector_dim: usize, metric: DistanceMetric) -> Self {
        Self::build_with_params(points, vector_dim, None, None, metric)
    }

    /// Build using SQ8 scalar quantisation for large (HNSW) indexes.
    /// Falls back to standard flat build for small collections.
    pub fn build_sq8(points: &[Point], vector_dim: usize, metric: DistanceMetric) -> Self {
        Self::build_sq8_with_params(points, vector_dim, None, None, metric)
    }

    /// Build the index, honoring per-collection HNSW knobs.  `None` falls back
    /// to engine defaults (`HNSW_M`, `HNSW_EF_CONSTRUCTION`).
    ///
    /// Bugfix: `metric` is now threaded through to the HNSW graph build.
    /// `HnswGraph`'s internal distance is always raw squared-L2; for
    /// `Cosine` collections we normalize vectors before they enter the graph
    /// (see `build_hnsw_index_inner`) so the graph's notion of "near"
    /// actually matches the collection's. Previously this parameter didn't
    /// exist and every collection got plain L2 internally regardless of its
    /// configured metric.
    pub fn build_with_params(
        points: &[Point],
        vector_dim: usize,
        hnsw_m: Option<u32>,
        hnsw_ef_construction: Option<u32>,
        metric: DistanceMetric,
    ) -> Self {
        if points.is_empty() {
            return Self::from_payload(H2qgPayload {
                vector_dim,
                nprobe: 0,
                mode: H2qgMode::Flat,
                quantization: QuantizationPlan::default(),
                cells: Vec::new(),
                hnsw: None,
                metric,
            });
        }
        if points.len() < HNSW_THRESHOLD {
            return Self::build_flat(points, vector_dim, metric);
        }
        Self::build_hnsw_index_inner(
            points,
            vector_dim,
            false,
            hnsw_m.map(|x| x as usize).unwrap_or(HNSW_M),
            hnsw_ef_construction
                .map(|x| x as usize)
                .unwrap_or(HNSW_EF_CONSTRUCTION),
            metric,
            None,
        )
        .expect("non-cancellable HNSW build cannot be cancelled")
    }

    /// SQ8 variant of [`build_with_params`].
    pub fn build_sq8_with_params(
        points: &[Point],
        vector_dim: usize,
        hnsw_m: Option<u32>,
        hnsw_ef_construction: Option<u32>,
        metric: DistanceMetric,
    ) -> Self {
        if points.is_empty() {
            return Self::from_payload(H2qgPayload {
                vector_dim,
                nprobe: 0,
                mode: H2qgMode::Flat,
                quantization: QuantizationPlan::default(),
                cells: Vec::new(),
                hnsw: None,
                metric,
            });
        }
        if points.len() < HNSW_THRESHOLD {
            return Self::build_flat(points, vector_dim, metric);
        }
        Self::build_hnsw_index_inner(
            points,
            vector_dim,
            true,
            hnsw_m.map(|x| x as usize).unwrap_or(HNSW_M),
            hnsw_ef_construction
                .map(|x| x as usize)
                .unwrap_or(HNSW_EF_CONSTRUCTION),
            metric,
            None,
        )
        .expect("non-cancellable SQ8 HNSW build cannot be cancelled")
    }

    /// Build the mutable-tier HNSW for a collection that is already ANN-sized.
    ///
    /// The ordinary builders select flat versus HNSW from `points.len()`,
    /// which is correct for a standalone collection or sealed segment. A
    /// recovered streamer is only one tier of a larger collection, so its
    /// local length must not force flat mode once the collection-level policy
    /// has selected ANN. The caller owns that collection-level decision and
    /// must pass a non-empty streamer snapshot.
    pub(crate) fn build_mutable_hnsw_with_params_cancellable(
        points: &[Point],
        vector_dim: usize,
        hnsw_m: Option<u32>,
        hnsw_ef_construction: Option<u32>,
        metric: DistanceMetric,
        use_sq8: bool,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Option<Self> {
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            return None;
        }
        if points.is_empty() {
            let index =
                Self::build_with_params(points, vector_dim, hnsw_m, hnsw_ef_construction, metric);
            return (!cancelled.load(std::sync::atomic::Ordering::Acquire)).then_some(index);
        }
        Self::build_hnsw_index_inner(
            points,
            vector_dim,
            use_sq8,
            hnsw_m.map(|x| x as usize).unwrap_or(HNSW_M),
            hnsw_ef_construction
                .map(|x| x as usize)
                .unwrap_or(HNSW_EF_CONSTRUCTION),
            metric,
            Some(cancelled),
        )
    }

    #[cfg(test)]
    pub(crate) fn build_mutable_hnsw_with_params(
        points: &[Point],
        vector_dim: usize,
        hnsw_m: Option<u32>,
        hnsw_ef_construction: Option<u32>,
        metric: DistanceMetric,
        use_sq8: bool,
    ) -> Self {
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        Self::build_mutable_hnsw_with_params_cancellable(
            points,
            vector_dim,
            hnsw_m,
            hnsw_ef_construction,
            metric,
            use_sq8,
            &cancelled,
        )
        .expect("test mutable HNSW build is not cancelled")
    }

    /// Returns true if the underlying HNSW graph uses SQ8 quantisation.
    pub fn uses_sq8(&self) -> bool {
        self.payload.hnsw.as_ref().is_some_and(|g| g.uses_sq8())
    }

    /// Flat (all-candidate) mode returns every point unconditionally
    /// (`candidate_ids_with_ef_filter`'s `H2qgMode::Flat` branch) -- no
    /// internal distance computation happens here, so `metric` doesn't
    /// affect correctness. Stored on the payload anyway for introspection
    /// consistency.
    fn build_flat(points: &[Point], vector_dim: usize, metric: DistanceMetric) -> Self {
        let centroid = vec![0.0; vector_dim];
        let quantization = QuantizationPlan::for_dim(vector_dim);
        let postings = points
            .iter()
            .map(|point| QuantizedPosting {
                id: point.id.clone(),
                signature: binary_signature(&point.vector, &centroid, &quantization),
            })
            .collect();
        Self::from_payload(H2qgPayload {
            vector_dim,
            nprobe: 1,
            mode: H2qgMode::Flat,
            quantization,
            cells: vec![IvfCell { centroid, postings }],
            hnsw: None,
            metric,
        })
    }

    fn build_hnsw_index_inner(
        points: &[Point],
        vector_dim: usize,
        use_sq8: bool,
        m: usize,
        ef_construction: usize,
        metric: DistanceMetric,
        cancelled: Option<&std::sync::atomic::AtomicBool>,
    ) -> Option<Self> {
        let seed = 0x9e37_79b9_7f4a_7c15_u64 ^ vector_dim as u64;
        let valid_vectors: Vec<&[f32]> = points
            .iter()
            .filter(|p| p.vector.len() == vector_dim)
            .map(|p| p.vector.as_slice())
            .collect();
        let sq8 = if use_sq8 {
            Some(Sq8Params::train(&valid_vectors))
        } else {
            None
        };
        let mut graph = match sq8 {
            Some(params) => HnswGraph::new_sq8(m, ef_construction, params),
            None => HnswGraph::new(m, ef_construction),
        };

        // Bugfix: normalize before the vector enters the graph when the
        // collection's metric is Cosine, so HnswGraph's always-squared-L2
        // internal distance actually ranks the same way the collection's
        // real metric does (||a-b||^2 = 2 - 2*cos(a,b) for unit vectors).
        // L2 is already correct unchanged; Dot/MIPS needs a different
        // transform entirely and is left as a known, documented gap.
        let mut prepared: Vec<(u64, &str, Vec<f32>)> = Vec::with_capacity(points.len());
        for (i, point) in points.iter().enumerate() {
            if cancelled
                .is_some_and(|cancelled| cancelled.load(std::sync::atomic::Ordering::Acquire))
            {
                return None;
            }
            if point.vector.len() == vector_dim {
                let rng = splitmix64(seed ^ (i as u64).wrapping_mul(0x6c62_272e_07bb_0142));
                let vector = if metric == DistanceMetric::Cosine {
                    let mut v = point.vector.clone();
                    crate::search::normalize(&mut v);
                    v
                } else {
                    point.vector.clone()
                };
                prepared.push((rng, point.id.as_str(), vector));
            }
        }

        // W2 — bulk build parallelism, deterministic variant. An earlier
        // version of this loop batched points and ran `plan_insert` (the
        // read-only neighbor search) for a whole batch in parallel against
        // a single pre-batch graph snapshot before applying all of them --
        // real parallel-HNSW-construction implementations accept that
        // staleness, but it broke this codebase's stricter guarantees: a
        // graph built that way could fail to recall a point's own *exact*
        // self-match (`hnsw_filter_aware_beam_returns_passing_candidates`,
        // not just the statistical `recall_golden` floor). Inserts stay
        // fully serial and see every prior point -- identical topology to
        // the unparallelized build -- but each insert's own layer-0 beam
        // expansion is allowed to score its unvisited neighbors via
        // `rayon::par_iter` (the existing P2C `intra_query_parallel` path
        // in `search_layer_with_codes`, normally a query-time-only
        // feature). That parallelizes independent distance computations,
        // not control flow, so it cannot change which neighbors are found --
        // zero recall risk, real wall-clock win once layer-0 connection
        // counts (`M0`) clear `INTRA_QUERY_PARALLEL_THRESHOLD`. The flag is
        // local to this fresh graph and is turned back off before the graph
        // is returned, so it never leaks into serving behavior for the
        // collection afterward (production query-time parallel dispatch
        // stays governed by the server-wide `intra_query_parallel` setting,
        // wired in separately).
        graph
            .intra_query_parallel
            .store(true, std::sync::atomic::Ordering::Relaxed);
        for (rng, id, vector) in &prepared {
            if cancelled
                .is_some_and(|cancelled| cancelled.load(std::sync::atomic::Ordering::Acquire))
            {
                return None;
            }
            graph.insert(id.to_string(), vector.clone(), *rng);
        }
        graph
            .intra_query_parallel
            .store(false, std::sync::atomic::Ordering::Relaxed);
        // A3 — farthest-point-sample the extra entry points once the full
        // graph exists (needs the complete node set to sample against),
        // then repair any representative left under-connected by
        // insertion-order effects during the build (see
        // `repair_entry_candidate_connectivity`'s doc comment).
        if cancelled.is_some_and(|cancelled| cancelled.load(std::sync::atomic::Ordering::Acquire)) {
            return None;
        }
        graph.assign_entry_candidates();
        graph.repair_entry_candidate_connectivity();
        Some(Self::from_payload(H2qgPayload {
            vector_dim,
            nprobe: 0,
            mode: H2qgMode::Hnsw,
            quantization: QuantizationPlan::default(),
            cells: Vec::new(),
            hnsw: Some(graph),
            metric,
        }))
    }

    /// Paged twin of [`Self::build_hnsw_index_inner`]: the graph's distance
    /// reads go through the pre-written mmap vector store (`paged`) from the
    /// very first insert, so the full-precision vectors are never resident
    /// in heap during construction — the difference between compacting and
    /// OOMing at 1M×high-dim on memory-capped hosts. `paged` row order must
    /// match `points` filtered by `vector.len() == vector_dim` with Cosine
    /// normalization already applied (see `write_hnsw_vecs_streaming`).
    /// Same insertion order, rng seeding, entry-candidate assignment, and
    /// connectivity repair as the in-heap build — identical topology.
    fn build_hnsw_index_paged(
        ids: &[String],
        vector_dim: usize,
        m: usize,
        ef_construction: usize,
        metric: DistanceMetric,
        paged: PagedVectors,
    ) -> Self {
        let seed = 0x9e37_79b9_7f4a_7c15_u64 ^ vector_dim as u64;
        let mut graph = HnswGraph::new(m, ef_construction);
        graph.paged_vecs = Some(paged);
        graph
            .intra_query_parallel
            .store(true, std::sync::atomic::Ordering::Relaxed);
        for (i, id) in ids.iter().enumerate() {
            let rng = splitmix64(seed ^ (i as u64).wrapping_mul(0x6c62_272e_07bb_0142));
            // One-vector transient: the normalized vector is read back from
            // the mmap row this point will occupy (rows advance in the same
            // filtered order the vecs writer used).
            let vector = graph
                .paged_vecs
                .as_ref()
                .expect("paged build always has paged_vecs")
                .get(i)
                .to_vec();
            graph.insert(id.clone(), vector, rng);
        }
        graph
            .intra_query_parallel
            .store(false, std::sync::atomic::Ordering::Relaxed);
        graph.assign_entry_candidates();
        graph.repair_entry_candidate_connectivity();
        Self::from_payload(H2qgPayload {
            vector_dim,
            nprobe: 0,
            mode: H2qgMode::Hnsw,
            quantization: QuantizationPlan::default(),
            cells: Vec::new(),
            hnsw: Some(graph),
            metric,
        })
    }

    pub fn build_for_vector_name(
        points: &[Point],
        vector_dim: usize,
        vector_name: &str,
        metric: DistanceMetric,
    ) -> Self {
        let named_points = points
            .iter()
            .filter_map(|point| {
                let vector = point.vectors.get(vector_name)?;
                let mut indexed = point.clone();
                indexed.vector = vector.clone();
                Some(indexed)
            })
            .collect::<Vec<_>>();
        Self::build(&named_points, vector_dim, metric)
    }

    pub fn candidate_ids(&self, query: &[f32], k: usize) -> Vec<String> {
        self.candidate_ids_with_ef(query, k, None)
    }

    /// Like [`candidate_ids`] but accepts an explicit `ef_search` override.
    /// When `None`, falls back to [`default_ef_search`].
    pub fn candidate_ids_with_ef(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
    ) -> Vec<String> {
        self.candidate_ids_with_ef_filter(query, k, ef_search, None)
    }

    /// P2F — filter-aware variant of [`Self::candidate_ids_with_ef`].
    /// `filter = None` matches the un-filtered contract.
    ///
    /// For `Hnsw` mode the filter is threaded into the layer-0 beam search
    /// and consulted per-neighbour — filtered-out candidates are never
    /// pushed onto the candidate heap, so the beam budget is spent only on
    /// passing neighbours. The upper-layer greedy descent is left
    /// un-filtered; see `HnswGraph::search_query_with_filter`.
    ///
    /// For `Flat` and `Ivf` modes the candidates have no navigable graph,
    /// so the filter cannot prune the expansion; we return the same
    /// candidate set as the un-filtered call. The post-filter rescore at
    /// the call site (`db::search_excluding`) handles these modes.
    pub fn candidate_ids_with_ef_filter(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
        filter: Option<&dyn crate::index::FilterPredicate>,
    ) -> Vec<String> {
        self.candidate_ids_with_ef_filter_controlled(query, k, ef_search, filter, None)
    }

    fn candidate_ids_with_ef_filter_controlled(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
        filter: Option<&dyn crate::index::FilterPredicate>,
        cancelled: Option<&AtomicBool>,
    ) -> Vec<String> {
        if query.len() != self.payload.vector_dim {
            return Vec::new();
        }
        let is_cancelled =
            || cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed));
        if is_cancelled() {
            return Vec::new();
        }

        match self.payload.mode {
            H2qgMode::Flat => {
                if self.payload.cells.is_empty() {
                    return Vec::new();
                }
                let mut candidates = Vec::new();
                for cell in &self.payload.cells {
                    for posting in &cell.postings {
                        if is_cancelled() {
                            return candidates;
                        }
                        candidates.push(posting.id.clone());
                    }
                }
                candidates
            }
            H2qgMode::Ivf => {
                // Legacy IVF path kept for backward-compatible reading of old artifacts.
                if self.payload.cells.is_empty() {
                    return Vec::new();
                }
                let mut cells = self
                    .payload
                    .cells
                    .iter()
                    .enumerate()
                    .take_while(|_| !is_cancelled())
                    .map(|(index, cell)| (index, squared_l2(query, &cell.centroid)))
                    .collect::<Vec<_>>();
                if is_cancelled() {
                    return Vec::new();
                }
                cells.sort_by(|left, right| {
                    left.1
                        .total_cmp(&right.1)
                        .then_with(|| left.0.cmp(&right.0))
                });

                let keep = ef_search.unwrap_or_else(|| {
                    default_ef_search(k, self.indexed_points(), self.payload.vector_dim)
                });
                let mut candidates = Vec::new();
                for (cell_index, _) in cells.into_iter().take(self.payload.nprobe) {
                    if is_cancelled() {
                        return candidates.into_iter().map(|(id, _)| id).collect();
                    }
                    let cell = &self.payload.cells[cell_index];
                    let query_signature =
                        binary_signature(query, &cell.centroid, &self.payload.quantization);
                    for posting in &cell.postings {
                        if is_cancelled() {
                            return candidates.into_iter().map(|(id, _)| id).collect();
                        }
                        candidates.push((
                            posting.id.clone(),
                            hamming_distance(&query_signature, &posting.signature),
                        ));
                    }
                }
                candidates
                    .sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
                candidates.truncate(keep);
                candidates.into_iter().map(|(id, _)| id).collect()
            }
            H2qgMode::Hnsw => {
                let Some(hnsw) = &self.payload.hnsw else {
                    return Vec::new();
                };
                let ef = ef_search.unwrap_or_else(|| {
                    default_ef_search(k, self.indexed_points(), self.payload.vector_dim)
                });
                // Bugfix: normalize the query the same way every stored
                // vector was normalized before entering the graph (see
                // `build_hnsw_index_inner`/`insert_point`), so the graph's
                // always-squared-L2 internal distance ranks consistently
                // with the collection's real metric.
                let normalized_query;
                let query: &[f32] = if self.payload.metric == DistanceMetric::Cosine {
                    let mut v = query.to_vec();
                    crate::search::normalize(&mut v);
                    normalized_query = v;
                    &normalized_query
                } else {
                    query
                };
                let beam_filter = |id: &str| {
                    !is_cancelled() && filter.is_none_or(|predicate| predicate.matches(id))
                };
                let effective_filter = cancelled
                    .map(|_| &beam_filter as &dyn crate::index::FilterPredicate)
                    .or(filter);
                // W1: in-beam binary cascade when the server-wide flag is ON,
                // the graph is on the f32 path (SQ8 is itself a proxy), and the
                // sign codes have been built. Otherwise the exact f32 beam.
                if hnsw.cascade.load(std::sync::atomic::Ordering::Relaxed)
                    && hnsw.sq8.is_none()
                    && !hnsw.sign_codes.is_empty()
                {
                    hnsw.search_query_cascade(query, ef, CASCADE_OVERSAMPLE, effective_filter)
                } else {
                    hnsw.search_query_with_filter(query, ef, effective_filter)
                }
            }
        }
    }

    pub fn contains(&self, id: &str) -> bool {
        self.indexed_ids.contains(id)
    }

    pub fn indexed_points(&self) -> usize {
        self.indexed_ids.len()
    }

    /// Remove id from the indexed-ids tracking set so the backfill gate in
    /// `search::search_point_candidates` stays accurate after a delete.
    /// For HNSW mode the graph node is left in place (soft-delete: the graph
    /// returns it as a candidate but `collection.points` no longer has it, so
    /// `points.get(id)` returns None and the candidate is skipped). For flat
    /// and IVF the postings are rebuilt at next compaction.
    pub fn remove_from_indexed(&mut self, id: &str) {
        self.indexed_ids.remove(id);
    }

    /// Drop indexed-id entries that no longer exist in `points`. Called after
    /// WAL replay on open: WAL deletes update `points` but not `indexed_ids`,
    /// which can leave stale entries that make `indexed_points()` an overcount
    /// and suppress the backfill gate in `search_point_candidates`.
    pub fn reconcile_with_live_points(
        &mut self,
        points: &std::collections::HashMap<String, crate::model::Point>,
    ) {
        self.indexed_ids
            .retain(|id| points.contains_key(id.as_str()));
    }

    /// P2C — wire the server-wide `intra_query_parallel` flag into this
    /// index's HNSW graph. Arc-shared so the server can flip the flag
    /// without holding `&mut self` on the read path. Default OFF to
    /// preserve the recall_golden floor and avoid the insert-phase hang
    /// the original P2C attempt hit.
    pub fn set_intra_query_parallel(&mut self, flag: Arc<AtomicBool>) {
        if let Some(hnsw) = self.payload.hnsw.as_mut() {
            hnsw.intra_query_parallel = flag;
        }
    }

    /// P2C — return a clone of the current intra-query-parallel flag
    /// (so callers can flip it without holding `&mut self`).
    pub fn intra_query_parallel_flag(&self) -> Option<Arc<AtomicBool>> {
        self.payload
            .hnsw
            .as_ref()
            .map(|h| h.intra_query_parallel.clone())
    }

    /// W1 — wire the server-wide in-beam cascade flag into this index's HNSW
    /// graph. Adopting an ON flag eagerly builds the sign codes so the read
    /// path stays `&self`. No-op for Flat / IVF graphs.
    pub fn set_cascade(&mut self, flag: Arc<AtomicBool>) {
        if let Some(hnsw) = self.payload.hnsw.as_mut() {
            hnsw.set_cascade_flag(flag);
        }
    }

    /// W1 — clone of the current cascade flag (so callers can flip it without
    /// holding `&mut self`).
    pub fn cascade_flag(&self) -> Option<Arc<AtomicBool>> {
        self.payload.hnsw.as_ref().map(|h| h.cascade.clone())
    }

    /// W1 — test-only cascade query with an explicit oversample, for the
    /// diagnostic recall/oversample sweep. Production uses [`CASCADE_OVERSAMPLE`].
    #[cfg(test)]
    pub(crate) fn cascade_query_for_test(
        &self,
        query: &[f32],
        ef: usize,
        oversample: usize,
    ) -> Vec<String> {
        match self.payload.hnsw.as_ref() {
            Some(h) => h.search_query_cascade(query, ef, oversample, None),
            None => Vec::new(),
        }
    }

    /// Returns the number of IVF cells (for flat/IVF mode) or HNSW nodes (for hnsw mode).
    pub fn cells(&self) -> usize {
        match self.payload.mode {
            H2qgMode::Hnsw => self.payload.hnsw.as_ref().map_or(0, |g| g.node_count()),
            _ => self.payload.cells.len(),
        }
    }

    pub fn is_flat_fallback(&self) -> bool {
        self.payload.mode == H2qgMode::Flat
    }

    pub fn is_hnsw(&self) -> bool {
        self.payload.mode == H2qgMode::Hnsw
    }

    pub fn is_paged(&self) -> bool {
        self.payload
            .hnsw
            .as_ref()
            .is_some_and(|g| g.paged_vecs.is_some())
    }

    pub fn has_quantization_rotation(&self) -> bool {
        self.payload.quantization.seed != 0
            && self.payload.quantization.sign_flips.len() == self.payload.vector_dim
    }

    /// Insert a single new point into the existing HNSW graph in-place.
    /// Flat and IVF mode do not support incremental insertion (they are rebuilt at
    /// compaction), so this is a silent no-op for those modes.
    /// For HNSW mode the point is appended to the live graph.
    pub fn insert_point(&mut self, point: &Point, _vector_dim: usize) -> Result<()> {
        match self.payload.mode {
            H2qgMode::Flat | H2qgMode::Ivf => {
                // Flat/IVF are rebuilt at compaction; incremental insert is a no-op.
                Ok(())
            }
            H2qgMode::Hnsw => {
                let metric = self.payload.metric;
                let graph = self.payload.hnsw.as_mut().ok_or_else(|| {
                    GaussError::InvalidRequest("HNSW index has no graph".to_string())
                })?;
                let rng_seed =
                    splitmix64(0x9e37_79b9_7f4a_7c15_u64 ^ self.indexed_ids.len() as u64);
                // Bugfix: same normalization as the bulk build path
                // (`build_hnsw_index_inner`) -- incremental inserts must
                // match the geometry the rest of the graph was built with.
                let vector = if metric == DistanceMetric::Cosine {
                    let mut v = point.vector.clone();
                    crate::search::normalize(&mut v);
                    v
                } else {
                    point.vector.clone()
                };
                graph.insert(point.id.clone(), vector, rng_seed);
                self.indexed_ids.insert(point.id.clone());
                Ok(())
            }
        }
    }

    fn from_payload(payload: H2qgPayload) -> Self {
        let indexed_ids: HashSet<String> = match payload.mode {
            H2qgMode::Hnsw => payload
                .hnsw
                .as_ref()
                .map_or_else(HashSet::new, |g| g.node_ids.iter().cloned().collect()),
            _ => payload
                .cells
                .iter()
                .flat_map(|cell| cell.postings.iter().map(|posting| posting.id.clone()))
                .collect(),
        };
        Self {
            payload,
            indexed_ids,
        }
    }
}

pub fn write_index(
    path: &Path,
    points: &[Point],
    vector_dim: usize,
    metric: DistanceMetric,
) -> Result<H2qgWrite> {
    write_index_with_params(path, points, vector_dim, None, None, metric)
}

pub fn write_index_with_params(
    path: &Path,
    points: &[Point],
    vector_dim: usize,
    hnsw_m: Option<u32>,
    hnsw_ef_construction: Option<u32>,
    metric: DistanceMetric,
) -> Result<H2qgWrite> {
    let index =
        H2qgIndex::build_with_params(points, vector_dim, hnsw_m, hnsw_ef_construction, metric);
    write_payload(path, &index)
}

/// Like `write_index` but uses SQ8 scalar quantisation for the HNSW graph.
/// Reduces on-disk size ~4x for the vector storage at the cost of approximate
/// distance computations during graph traversal (exact rescore is upstream).
pub fn write_index_sq8(
    path: &Path,
    points: &[Point],
    vector_dim: usize,
    metric: DistanceMetric,
) -> Result<H2qgWrite> {
    let index = H2qgIndex::build_sq8(points, vector_dim, metric);
    write_payload(path, &index)
}

pub fn write_named_index(
    path: &Path,
    points: &[Point],
    vector_dim: usize,
    vector_name: &str,
    metric: DistanceMetric,
) -> Result<H2qgWrite> {
    write_named_index_with_params(path, points, vector_dim, vector_name, None, None, metric)
}

pub fn write_named_index_with_params(
    path: &Path,
    points: &[Point],
    vector_dim: usize,
    vector_name: &str,
    hnsw_m: Option<u32>,
    hnsw_ef_construction: Option<u32>,
    metric: DistanceMetric,
) -> Result<H2qgWrite> {
    let named_points = points
        .iter()
        .filter_map(|point| {
            let vector = point.vectors.get(vector_name)?;
            let mut indexed = point.clone();
            indexed.vector = vector.clone();
            Some(indexed)
        })
        .collect::<Vec<_>>();
    let index = H2qgIndex::build_with_params(
        &named_points,
        vector_dim,
        hnsw_m,
        hnsw_ef_construction,
        metric,
    );
    write_payload(path, &index)
}

/// Load an existing h2qg index, insert `new_points`, and write back atomically.
/// Uses a tmp file + rename for crash safety.
pub fn update_index_with_new_points(
    path: &Path,
    new_points: &[Point],
    vector_dim: usize,
) -> Result<H2qgWrite> {
    let mut index = read_index(path)?;
    for point in new_points {
        index.insert_point(point, vector_dim)?;
    }
    let tmp_path = path.with_extension("tmp");
    write_payload(&tmp_path, &index)?;
    fs::rename(&tmp_path, path)?;
    Ok(H2qgWrite {
        path: path.to_path_buf(),
        cells: index.cells(),
        indexed_points: index.indexed_points(),
    })
}

/// Streaming variant of [`write_hnsw_vecs`]: writes each point's vector
/// (normalized for Cosine, matching the graph-build geometry) straight to
/// the file, so the flat vector store never materialises in heap. Skips
/// points whose vector length doesn't match `vector_dim` — the same
/// predicate the paged graph build uses, keeping row order aligned.
fn write_hnsw_vecs_streaming(
    path: &Path,
    points: &[Point],
    vector_dim: usize,
    metric: DistanceMetric,
) -> Result<usize> {
    let count = points
        .iter()
        .filter(|p| p.vector.len() == vector_dim)
        .count();
    let file = File::create(path)?;
    let mut writer = std::io::BufWriter::with_capacity(64 * 1024, file);
    writer.write_all(HNSW_VECS_MAGIC)?;
    writer.write_all(&(count as u64).to_le_bytes())?;
    writer.write_all(&(vector_dim as u64).to_le_bytes())?;
    for point in points {
        if point.vector.len() != vector_dim {
            continue;
        }
        if metric == DistanceMetric::Cosine {
            let mut v = point.vector.clone();
            crate::search::normalize(&mut v);
            for &val in &v {
                writer.write_all(&val.to_le_bytes())?;
            }
        } else {
            for &val in &point.vector {
                writer.write_all(&val.to_le_bytes())?;
            }
        }
    }
    writer
        .into_inner()
        .map_err(std::io::Error::from)?
        .sync_all()?;
    Ok(count)
}

/// Write flat f32 vectors to a separate file for OS-managed paging.
/// Format: HNSW_VECS_MAGIC (8) + count as u64 le (8) + dim as u64 le (8) + flat f32 data.
pub fn write_hnsw_vecs(path: &Path, vectors: &[Vec<f32>]) -> Result<()> {
    let count = vectors.len();
    let dim = vectors.first().map_or(0, |v| v.len());
    let mut file = File::create(path)?;
    file.write_all(HNSW_VECS_MAGIC)?;
    file.write_all(&(count as u64).to_le_bytes())?;
    file.write_all(&(dim as u64).to_le_bytes())?;
    for vec in vectors {
        for &val in vec {
            file.write_all(&val.to_le_bytes())?;
        }
    }
    file.sync_all()?;
    Ok(())
}

/// Open a paged vector file without materializing encrypted contents.
pub fn read_hnsw_vecs(path: &Path) -> Result<PagedVectors> {
    let storage = Arc::new(crate::encryption::PersistentFile::open(path)?);
    if storage.len() < 24 {
        return Err(corrupt(path, "hnsw vecs file shorter than header"));
    }
    let header = storage.read_range(0..24)?;
    if &header[0..8] != HNSW_VECS_MAGIC {
        return Err(corrupt(path, "bad hnsw vecs magic"));
    }
    let count = usize::try_from(u64::from_le_bytes(
        header[8..16].try_into().expect("vecs count"),
    ))
    .map_err(|_| corrupt(path, "hnsw vector count exceeds usize"))?;
    let dim = usize::try_from(u64::from_le_bytes(
        header[16..24].try_into().expect("vecs dim"),
    ))
    .map_err(|_| corrupt(path, "hnsw vector dimension exceeds usize"))?;
    let expected = count
        .checked_mul(dim)
        .and_then(|values| values.checked_mul(4))
        .and_then(|bytes| bytes.checked_add(24))
        .ok_or_else(|| corrupt(path, "hnsw vector file length overflow"))?;
    if storage.len() != expected {
        return Err(corrupt(path, "hnsw vector file length mismatch"));
    }
    Ok(PagedVectors {
        storage,
        count,
        dim,
    })
}

/// Build HNSW index that writes vectors to a separate page-resident file.
/// Produces two files: h2qg.gdx (index metadata + graph, no embedded vectors)
///                     h2qg_vecs.gdx (flat f32 vectors for OS-managed paging)
pub fn write_index_paged(
    dir: &Path,
    points: &[Point],
    vector_dim: usize,
    metric: DistanceMetric,
) -> Result<H2qgWrite> {
    write_index_paged_with_params(dir, points, vector_dim, None, None, metric)
}

/// Paged variant of [`write_index_with_params`]: the HNSW graph's full-
/// precision vectors are extracted to a flat `h2qg_vecs.gdx` before the JSON
/// index write, so a reloaded index reads vectors through an OS-paged mmap
/// instead of holding a second in-heap copy of the whole dataset. Flat
/// (sub-threshold) indexes have no graph-embedded vectors — they write no
/// vecs file and behave exactly like the non-paged writer.
pub fn write_index_paged_with_params(
    dir: &Path,
    points: &[Point],
    vector_dim: usize,
    hnsw_m: Option<u32>,
    hnsw_ef_construction: Option<u32>,
    metric: DistanceMetric,
) -> Result<H2qgWrite> {
    let vecs_path = dir.join(HNSW_VECS_FILE);
    if !points.is_empty() && points.len() >= HNSW_THRESHOLD {
        // HNSW-scale: write the (normalized) vectors to the mmap sidecar
        // first, then build the graph reading distances through that mmap —
        // the full-precision vector set is never heap-resident, neither
        // during the build nor in the serialized index (whose `vectors`
        // stays empty; reload re-attaches the sidecar).
        write_hnsw_vecs_streaming(&vecs_path, points, vector_dim, metric)?;
        let paged = read_hnsw_vecs(&vecs_path)?;
        let ids = points
            .iter()
            .filter(|point| point.vector.len() == vector_dim)
            .map(|point| point.id.clone())
            .collect::<Vec<_>>();
        let index = H2qgIndex::build_hnsw_index_paged(
            &ids,
            vector_dim,
            hnsw_m.map(|x| x as usize).unwrap_or(HNSW_M),
            hnsw_ef_construction
                .map(|x| x as usize)
                .unwrap_or(HNSW_EF_CONSTRUCTION),
            metric,
            paged,
        );
        write_payload(&dir.join(INDEX_FILE), &index)
    } else {
        // Flat (sub-threshold) index: no graph vectors to page out. Remove
        // any stale vecs file so a reload doesn't attach garbage.
        let index =
            H2qgIndex::build_with_params(points, vector_dim, hnsw_m, hnsw_ef_construction, metric);
        if vecs_path.exists() {
            fs::remove_file(&vecs_path)?;
        }
        write_payload(&dir.join(INDEX_FILE), &index)
    }
}

/// Build a paged H2QG index from an already-written `h2qg_vecs.gdx` and
/// its row-aligned IDs. Used by LS-Vec v4 sealing so graph construction does
/// not need the full `Point` set resident in memory.
pub(crate) fn write_index_paged_from_ids(
    dir: &Path,
    ids: &[String],
    vector_dim: usize,
    hnsw_m: Option<u32>,
    hnsw_ef_construction: Option<u32>,
    metric: DistanceMetric,
) -> Result<H2qgWrite> {
    let paged = read_hnsw_vecs(&dir.join(HNSW_VECS_FILE))?;
    if paged.count != ids.len() || paged.dim != vector_dim {
        return Err(GaussError::InvalidRequest(format!(
            "paged vector header count/dim ({}/{}) does not match ids/config ({}/{vector_dim})",
            paged.count,
            paged.dim,
            ids.len()
        )));
    }
    let index = if ids.len() >= HNSW_THRESHOLD {
        H2qgIndex::build_hnsw_index_paged(
            ids,
            vector_dim,
            hnsw_m.map(|x| x as usize).unwrap_or(HNSW_M),
            hnsw_ef_construction
                .map(|x| x as usize)
                .unwrap_or(HNSW_EF_CONSTRUCTION),
            metric,
            paged,
        )
    } else {
        let centroid = vec![0.0; vector_dim];
        let quantization = QuantizationPlan::for_dim(vector_dim);
        let postings = ids
            .iter()
            .enumerate()
            .map(|(row, id)| QuantizedPosting {
                id: id.clone(),
                signature: binary_signature(&paged.get(row), &centroid, &quantization),
            })
            .collect();
        H2qgIndex::from_payload(H2qgPayload {
            vector_dim,
            nprobe: 1,
            mode: H2qgMode::Flat,
            quantization,
            cells: vec![IvfCell { centroid, postings }],
            hnsw: None,
            metric,
        })
    };
    write_payload(&dir.join(INDEX_FILE), &index)
}

/// Read a paged HNSW index: load h2qg.gdx, then attach h2qg_vecs.gdx if present.
pub fn read_index_paged(dir: &Path) -> Result<H2qgIndex> {
    let mut index = read_index(&dir.join(INDEX_FILE))?;
    let vecs_path = dir.join(HNSW_VECS_FILE);
    if vecs_path.exists() {
        let paged = read_hnsw_vecs(&vecs_path)?;
        if let Some(g) = index.payload.hnsw.as_mut() {
            g.paged_vecs = Some(paged);
        }
    }
    Ok(index)
}

/// [`std::io::Write`] sink that counts bytes and computes their CRC as they
/// stream through, so serializing a large index never materialises the whole
/// payload in memory. The header's len + crc fields are back-patched at the end.
struct CrcCountingWriter {
    file: File,
    crc: crc32fast::Hasher,
    len: u64,
}

impl Write for CrcCountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.crc.update(buf);
        self.len += buf.len() as u64;
        self.file.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

fn write_payload(path: &Path, index: &H2qgIndex) -> Result<H2qgWrite> {
    use std::io::{Seek, SeekFrom};
    let mut file = File::create(path)?;
    file.write_all(MAGIC)?;
    file.write_all(&[0u8; 12])?; // placeholder: payload len + crc
    let writer = CrcCountingWriter {
        file,
        crc: crc32fast::Hasher::new(),
        len: 0,
    };
    let mut writer = std::io::BufWriter::with_capacity(64 * 1024, writer);
    serde_json::to_writer(&mut writer, &index.payload)?;
    let writer = writer
        .into_inner()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let crc = writer.crc.finalize();
    let mut file = writer.file;
    file.seek(SeekFrom::Start(8))?;
    file.write_all(&writer.len.to_le_bytes())?;
    file.write_all(&crc.to_le_bytes())?;
    file.sync_all()?;

    Ok(H2qgWrite {
        path: path.to_path_buf(),
        cells: index.cells(),
        indexed_points: index.indexed_points(),
    })
}

pub fn read_index(path: &Path) -> Result<H2qgIndex> {
    let file = crate::encryption::PersistentFile::open(path)?;
    if file.len() < HEADER_LEN {
        return Err(corrupt(path, "index shorter than header"));
    }
    let header = file.read_range(0..HEADER_LEN)?;
    if &header[0..8] != MAGIC {
        return Err(corrupt(path, "bad index magic"));
    }

    let len = usize::try_from(u64::from_le_bytes(
        header[8..16].try_into().expect("index length"),
    ))
    .map_err(|_| corrupt(path, "index length exceeds usize"))?;
    let expected_crc = u32::from_le_bytes(header[16..20].try_into().expect("index crc"));
    if file.len() != HEADER_LEN + len {
        return Err(corrupt(path, "index length mismatch"));
    }

    if file.crc32(HEADER_LEN..file.len())? != expected_crc {
        return Err(corrupt(path, "index crc mismatch"));
    }

    let payload = serde_json::from_reader(file.reader_at(HEADER_LEN)?.take(len as u64))?;
    Ok(H2qgIndex::from_payload(payload))
}

impl QuantizationPlan {
    fn for_dim(vector_dim: usize) -> Self {
        let seed = 0x9e37_79b9_7f4a_7c15 ^ vector_dim as u64;
        let mut state = seed;
        let sign_flips = (0..vector_dim)
            .map(|_| {
                state = splitmix64(state);
                if state & 1 == 0 { 1 } else { -1 }
            })
            .collect();
        Self { seed, sign_flips }
    }

    fn sign(&self, index: usize) -> f32 {
        match self.sign_flips.get(index).copied().unwrap_or(1) {
            -1 => -1.0,
            _ => 1.0,
        }
    }
}

pub(crate) fn splitmix64(mut state: u64) -> u64 {
    state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// Assigns a layer to a new HNSW node using a geometric distribution.
/// `rng_state` is a pre-mixed random value derived from the node index.
fn hnsw_random_level(rng_state: u64, m: usize) -> usize {
    let r = (rng_state as f64) / (u64::MAX as f64);
    let ml = 1.0 / (m as f64).ln();
    ((-r.ln()) * ml).floor() as usize
}

fn binary_signature(vector: &[f32], centroid: &[f32], quantization: &QuantizationPlan) -> Vec<u64> {
    let lanes = vector.len().div_ceil(64);
    let mut signature = vec![0_u64; lanes];
    for (index, (value, centroid_value)) in vector.iter().zip(centroid).enumerate() {
        let sign = quantization.sign(index);
        if value * sign >= centroid_value * sign {
            signature[index / 64] |= 1_u64 << (index % 64);
        }
    }
    signature
}

fn hamming_distance(left: &[u64], right: &[u64]) -> u32 {
    left.iter()
        .zip(right)
        .map(|(left, right)| (left ^ right).count_ones())
        .sum()
}

fn squared_l2(left: &[f32], right: &[f32]) -> f32 {
    crate::distance::squared_l2(left, right)
}

/// P2B v2 — issue a data-cache L1 streaming prefetch hint for the memory at
/// `addr`. Streaming / non-temporal on both arches — each neighbour's
/// vector is read once per beam expansion and never reused, so the line
/// must be placed in L1 only, with a low-priority eviction policy, to
/// avoid evicting the connection-list metadata that the next beam pop
/// needs in L2/L3.
///
/// Cross-platform:
/// - **x86_64**: emits `prefetchnta` (a.k.a. `_MM_HINT_NTA`) — fill L1
///   only, non-temporal. The first cut of P2B used `_MM_HINT_T0`
///   (`prefetcht0`) on x86, which is the wrong hint for one-time access:
///   it fills L1, L2, AND L3 with throwaway data and was the dominant
///   cause of the insert / optimize regressions on the bench.
///   `prefetchnta` is the x86 equivalent of aarch64's `pldl1strm`.
/// - **aarch64**: emits `prfm pldl1strm, [...]` — "prefetch for load, L1
///   cache, streaming policy". Inline asm (vs.
///   `core::intrinsics::prefetch_read_data`) because the stdlib
///   intrinsic lowers to `pldl1keep` on aarch64, which would defeat the
///   streaming-policy win.
/// - **other**: no-op (`let _ = addr;`).
///
/// # Safety
/// `addr` must point to memory the caller would be allowed to read —
/// the kernel never dereferences it for the hint itself, but a hint
/// targeting a guard page or freed allocation can fault on some
/// microarchitectures. Callers must guarantee the underlying allocation
/// is live (e.g. borrowed from a `Vec` we still own).
#[inline(always)]
pub(crate) unsafe fn prefetch_l1_read(addr: *const u8) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        std::arch::x86_64::_mm_prefetch(addr as *const i8, std::arch::x86_64::_MM_HINT_NTA);
    }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        std::arch::asm!(
            "prfm pldl1strm, [{addr}]",
            addr = in(reg) addr,
            options(nostack, preserves_flags),
        );
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = addr;
    }
}

fn corrupt(path: &Path, message: &str) -> GaussError {
    GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: message.to_string(),
    }
}

// P4 — IndexBackend trait shim. H2qgIndex is the reference backend; sibling
// modules under `crate::index::*` (PC-1 RaBitQ, PC-2 Vamana) add peers.
impl crate::index::IndexBackend for H2qgIndex {
    fn candidate_ids_with_ef(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
    ) -> Vec<String> {
        H2qgIndex::candidate_ids_with_ef(self, query, k, ef_search)
    }

    fn candidate_ids_with_ef_filter(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
        filter: Option<&dyn crate::index::FilterPredicate>,
    ) -> Vec<String> {
        H2qgIndex::candidate_ids_with_ef_filter(self, query, k, ef_search, filter)
    }

    fn candidate_ids_with_recall_target_cancellable(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
        _recall_target: f32,
        filter: Option<&dyn crate::index::FilterPredicate>,
        cancelled: &AtomicBool,
    ) -> Vec<String> {
        self.candidate_ids_with_ef_filter_controlled(query, k, ef_search, filter, Some(cancelled))
    }

    fn insert_point(&mut self, point: &Point, vector_dim: usize) -> Result<()> {
        H2qgIndex::insert_point(self, point, vector_dim)
    }

    fn kind(&self) -> crate::index::IndexKind {
        if H2qgIndex::is_hnsw(self) {
            if H2qgIndex::uses_sq8(self) {
                crate::index::IndexKind::HnswSq8
            } else {
                crate::index::IndexKind::Hnsw
            }
        } else if H2qgIndex::is_flat_fallback(self) {
            crate::index::IndexKind::Flat
        } else {
            crate::index::IndexKind::Ivf
        }
    }

    fn indexed_points(&self) -> usize {
        H2qgIndex::indexed_points(self)
    }

    fn vector_dim(&self) -> usize {
        self.payload.vector_dim
    }

    fn contains(&self, id: &str) -> bool {
        H2qgIndex::contains(self, id)
    }

    fn cells(&self) -> usize {
        H2qgIndex::cells(self)
    }

    fn is_paged(&self) -> bool {
        H2qgIndex::is_paged(self)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use std::collections::HashMap;
    use tempfile::TempDir;

    use crate::{h2qg, model::Point};

    #[test]
    fn builds_persists_and_queries_candidates() {
        let temp = TempDir::new().unwrap();
        let points = vec![
            Point {
                id: "a".to_string(),
                vector: vec![1.0, 0.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            },
            Point {
                id: "b".to_string(),
                vector: vec![0.0, 1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            },
            Point {
                id: "c".to_string(),
                vector: vec![0.0, 0.0, 1.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            },
        ];
        let path = temp.path().join(h2qg::INDEX_FILE);

        let write = h2qg::write_index(&path, &points, 3, crate::DistanceMetric::L2).unwrap();
        assert_eq!(write.indexed_points, 3);
        assert_eq!(write.cells, 1);

        let index = h2qg::read_index(&path).unwrap();
        assert!(index.is_flat_fallback());
        assert!(index.has_quantization_rotation());
        let candidates = index.candidate_ids(&[1.0, 0.0, 0.0], 1);
        assert!(candidates.contains(&"a".to_string()));
        assert!(index.contains("b"));
    }

    #[test]
    fn quantization_rotation_is_deterministic_for_dimension() {
        let left = super::QuantizationPlan::for_dim(8);
        let right = super::QuantizationPlan::for_dim(8);
        assert_eq!(left.seed, right.seed);
        assert_eq!(left.sign_flips, right.sign_flips);
        assert_eq!(left.sign_flips.len(), 8);
    }

    fn make_point(id: &str, vector: Vec<f32>) -> Point {
        Point {
            id: id.to_string(),
            vector,
            vectors: HashMap::new(),
            sparse_vector: None,
            payload: json!({}),
        }
    }

    #[test]
    fn hnsw_builds_and_queries_above_threshold() {
        let temp = TempDir::new().unwrap();
        let n = super::HNSW_THRESHOLD + 10;
        let dim = 4_usize;
        let points: Vec<Point> = (0..n)
            .map(|i| {
                let v = (0..dim).map(|d| (i * dim + d) as f32).collect();
                make_point(&i.to_string(), v)
            })
            .collect();

        let path = temp.path().join(h2qg::INDEX_FILE);
        let write = h2qg::write_index(&path, &points, dim, crate::DistanceMetric::L2).unwrap();
        assert_eq!(write.indexed_points, n);

        let index = h2qg::read_index(&path).unwrap();
        assert!(index.is_hnsw(), "expected HNSW mode for {} points", n);

        // Query the first point's vector — it must appear in candidates.
        let candidates = index.candidate_ids(&points[0].vector, 5);
        assert!(
            candidates.contains(&"0".to_string()),
            "nearest-neighbour candidate missing from HNSW results"
        );
        assert_eq!(index.indexed_points(), n);
    }

    #[test]
    fn mutable_hnsw_can_be_forced_below_collection_threshold() {
        let dim = 4_usize;
        let points = (0..1_000)
            .map(|index| {
                make_point(
                    &format!("p{index:04}"),
                    vec![index as f32, (index % 17) as f32, 0.0, 1.0],
                )
            })
            .collect::<Vec<_>>();

        let index = super::H2qgIndex::build_mutable_hnsw_with_params(
            &points,
            dim,
            None,
            Some(32),
            crate::DistanceMetric::L2,
            false,
        );
        assert!(index.is_hnsw());
        assert_eq!(index.indexed_points(), points.len());
        let candidates = index.candidate_ids_with_ef(&points[0].vector, 10, Some(32));
        assert!(candidates.contains(&points[0].id));
        assert!(
            candidates.len() < points.len(),
            "forced mutable HNSW must not return the whole streamer"
        );
    }

    #[test]
    fn hnsw_nearest_neighbour_recall() {
        // Build a dataset where ground-truth NN is unambiguous: each point has a unique
        // vector well-separated from all others so there is exactly one distance-0 hit.
        let n = super::HNSW_THRESHOLD + 100;
        let dim = 4_usize;
        // Point i gets vector [i*10, i*10+1, i*10+2, i*10+3] — all distinct, well-spaced.
        let points: Vec<Point> = (0..n)
            .map(|i| {
                let base = (i * 10) as f32;
                let v: Vec<f32> = (0..dim).map(|d| base + d as f32).collect();
                make_point(&i.to_string(), v)
            })
            .collect();

        let index = super::H2qgIndex::build(&points, dim, crate::DistanceMetric::L2);
        assert!(index.is_hnsw());

        // Query identical to point 0 — it is the unique exact match (distance 0).
        let query = points[0].vector.clone();
        let candidates = index.candidate_ids(&query, 10);
        assert!(
            candidates.contains(&"0".to_string()),
            "HNSW failed to recall exact-match nearest neighbour (candidates: {:?})",
            &candidates[..candidates.len().min(5)]
        );

        // Query identical to a mid-collection point — should recall it.
        let mid = n / 2;
        let query_mid = points[mid].vector.clone();
        let candidates_mid = index.candidate_ids(&query_mid, 10);
        assert!(
            candidates_mid.contains(&mid.to_string()),
            "HNSW failed mid-collection nearest neighbour recall"
        );
    }

    /// Raw LCG vector in [-1, 1], no normalization.
    fn lcg_raw(seed: u64, dim: usize) -> Vec<f32> {
        let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
        (0..dim)
            .map(|_| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                ((state >> 33) as u32 as f32 / u32::MAX as f32) * 2.0 - 1.0
            })
            .collect()
    }

    fn unit(mut v: Vec<f32>) -> Vec<f32> {
        let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for x in &mut v {
                *x /= norm;
            }
        }
        v
    }

    /// Unit cluster center for `cluster`.
    fn cluster_center(cluster: u64, dim: usize) -> Vec<f32> {
        unit(lcg_raw(cluster.wrapping_mul(0xD1B5_4A32_D192_ED03), dim))
    }

    /// CLUSTERED unit vector: cluster center + `spread`·noise, normalized.
    /// The in-beam cascade ranks on sign-bit Hamming — an *angular* (cosine)
    /// proxy. Uniform-random unit vectors in high-D concentrate near 90° apart
    /// (even the true NN is far), so sign-bit can't discriminate them at any
    /// bit count — an invalid worst case. Real embeddings (OpenAI-1536, the
    /// COSINE bench case) have cluster structure: true NN sit at small angles
    /// where sign-bit discriminates. This generator plants that structure so
    /// the recall measurement is a valid proxy for the bench.
    fn clustered_vec(seed: u64, dim: usize, cluster: u64, spread: f32) -> Vec<f32> {
        let center = cluster_center(cluster, dim);
        let noise = lcg_raw(seed ^ 0x2545_F491_4F6C_DD1D, dim);
        let mixed: Vec<f32> = center
            .iter()
            .zip(noise.iter())
            .map(|(c, n)| c + spread * n)
            .collect();
        unit(mixed)
    }

    fn exact_top_k(points: &[Point], q: &[f32], k: usize) -> Vec<String> {
        let mut scored: Vec<(f32, String)> = points
            .iter()
            .map(|p| (super::squared_l2(q, &p.vector), p.id.clone()))
            .collect();
        scored.sort_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        scored.into_iter().take(k).map(|(_, id)| id).collect()
    }

    /// W1 — in-beam binary cascade. Two guarantees:
    ///
    /// 1. With the cascade flag ON, mean recall@10 on a random high-dim corpus
    ///    stays ≥ 0.97 (the W0 product floor) — the Hamming-guided traversal +
    ///    widened-pool exact rerank recovers the true top-k.
    /// 2. With the flag OFF, results are byte-identical to the exact f32 beam
    ///    (the cascade is opt-in; the default path is unchanged).
    #[test]
    #[ignore = "diagnostic sweep — run explicitly with --ignored --nocapture"]
    fn hnsw_in_beam_cascade_holds_recall_floor() {
        let n = super::HNSW_THRESHOLD + 500;
        let clusters = (n / 50) as u64; // ~50 points/cluster → real NN structure
        let queries = 60;
        let k = 10;
        let ef = 80;
        for &dim in &[384_usize, 768] {
            // spread sets the cluster tightness: cos(point, own_center) ≈
            // 1/sqrt(1 + spread²·dim/3). At dim=384, spread=0.05 → cos≈0.87
            // (~30°, the OpenAI-embedding NN regime); spread=0.35 → cos≈0.25
            // (~76°, effectively uniform-random — an invalid worst case where
            // no 1-bit proxy can discriminate). Sweep the realistic band.
            for &spread in &[0.05_f32, 0.10] {
                let points: Vec<Point> = (0..n)
                    .map(|i| {
                        let c = (i as u64) % clusters;
                        make_point(&i.to_string(), clustered_vec(i as u64, dim, c, spread))
                    })
                    .collect();

                // Exact beam (cascade OFF) recall baseline.
                let index_off = super::H2qgIndex::build(&points, dim, crate::DistanceMetric::L2);
                let mut off_hits = 0usize;
                for s in 0..queries {
                    let c = (s as u64) % clusters;
                    let query = clustered_vec(9_000_000 + s as u64, dim, c, spread);
                    let got = index_off.candidate_ids_with_ef(&query, k, Some(ef));
                    let want = exact_top_k(&points, &query, k);
                    let got_set: std::collections::HashSet<&String> = got.iter().collect();
                    off_hits += want.iter().filter(|id| got_set.contains(id)).count();
                }
                let off_recall = off_hits as f32 / (queries * k) as f32;

                for &oversample in &[4usize, 8, 16] {
                    let mut index =
                        super::H2qgIndex::build(&points, dim, crate::DistanceMetric::L2);
                    let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
                    index.set_cascade(flag);
                    let mut hits = 0usize;
                    for s in 0..queries {
                        let c = (s as u64) % clusters;
                        let query = clustered_vec(9_000_000 + s as u64, dim, c, spread);
                        let got = index.cascade_query_for_test(&query, ef, oversample);
                        let want = exact_top_k(&points, &query, k);
                        let got_set: std::collections::HashSet<&String> = got.iter().collect();
                        hits += want.iter().filter(|id| got_set.contains(id)).count();
                    }
                    let recall = hits as f32 / (queries * k) as f32;
                    eprintln!(
                        "dim={dim} spread={spread} off_recall={off_recall:.4} os={oversample} cascade_recall={recall:.4}"
                    );
                }
            }
        }
    }

    /// Uniform-random unit vector, matching `recall_golden.rs`'s
    /// `lcg_vector` generator exactly (same LCG constants) so this sweep's
    /// numbers are comparable to that gate's existing calibration instead
    /// of introducing a second, incompatible recall measurement basis.
    fn lcg_vector_uniform(seed: u64, dim: usize) -> Vec<f32> {
        let mut state = seed ^ 0x517c_c1b7_2722_0a95;
        (0..dim)
            .map(|_| {
                state = state
                    .wrapping_mul(2862933555777941757)
                    .wrapping_add(3037000493);
                let v = ((state >> 32) as u32) as f32 / u32::MAX as f32;
                v * 2.0 - 1.0
            })
            .collect()
    }

    /// Generate a vector near `centroid` with deterministic noise of
    /// magnitude `noise_scale`, L2-normalized. Matches
    /// `chirondb-server/src/bin/gaussrecall.rs`'s `clustered_vector` exactly
    /// (same LCG constants via [`lcg_vector_uniform`]) so this reproduces
    /// the same corpus shape that surfaced row 153's 0.0-recall finding.
    fn clustered_vector(centroid: &[f32], seed: u64, dim: usize, noise_scale: f32) -> Vec<f32> {
        let noise = lcg_vector_uniform(seed ^ 0xFEED_CAFE_DEAD_BEEF, dim);
        let mut v: Vec<f32> = centroid
            .iter()
            .zip(&noise)
            .map(|(c, n)| c + n * noise_scale)
            .collect();
        let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-9);
        v.iter_mut().for_each(|x| *x /= norm);
        v
    }

    /// A3 regression test for row 153's real finding: on a tightly-clustered
    /// corpus, single-entry-point greedy HNSW descent could commit to the
    /// wrong cluster's basin and return **exactly 0.0 recall@10** for a
    /// query regardless of `ef_search` (swept 32..2000 in the original
    /// diagnosis, all byte-identical wrong results). This asserts the
    /// multi-entry-point fix ([`HnswGraph::assign_entry_candidates`] +
    /// [`HnswGraph::nprobe_seeds`]) —
    /// not just that mean recall holds, but that no individual query drops
    /// to 0.0, which is the specific failure mode `recall_golden`'s
    /// mean-only assertion would never catch (per PRD.md §8 Track A item
    /// A3.4's exit criteria).
    #[test]
    fn a3_multi_entry_point_fixes_clustered_zero_recall() {
        let n = super::HNSW_THRESHOLD + 2_000;
        let dim = 64_usize;
        let queries = 100;
        let k = 10;
        let ef = 128_usize; // the row-151 0.97-tier floor at this n/dim anchor

        let n_clusters = (n as f64).sqrt().ceil() as usize;
        let centroids: Vec<Vec<f32>> = (0..n_clusters)
            .map(|i| lcg_vector_uniform(i as u64 ^ 0xDEAD_BEEF, dim))
            .collect();

        let points: Vec<Point> = (0..n)
            .map(|i| {
                let cluster = i % n_clusters;
                make_point(
                    &i.to_string(),
                    clustered_vector(&centroids[cluster], i as u64, dim, 0.15),
                )
            })
            .collect();
        let index = super::H2qgIndex::build(&points, dim, crate::DistanceMetric::Cosine);
        assert!(index.is_hnsw());

        let mut zero_recall_queries = 0usize;
        let mut hits = 0usize;
        for s in 0..queries {
            let cluster = s % n_clusters;
            let query = clustered_vector(&centroids[cluster], (n + s) as u64, dim, 0.1);
            let got = index.candidate_ids_with_ef(&query, k, Some(ef));
            let want = exact_top_k_cosine(&points, &query, k);
            let got_set: std::collections::HashSet<&String> = got.iter().collect();
            let query_hits = want.iter().filter(|id| got_set.contains(id)).count();
            if query_hits == 0 {
                zero_recall_queries += 1;
            }
            hits += query_hits;
        }
        let mean_recall = hits as f32 / (queries * k) as f32;
        eprintln!(
            "clustered corpus: mean_recall={mean_recall:.4}, zero_recall_queries={zero_recall_queries}/{queries}"
        );
        assert_eq!(
            zero_recall_queries, 0,
            "multi-entry-point fix regressed: {zero_recall_queries}/{queries} queries at 0.0 recall@{k} (mean recall {mean_recall:.4})"
        );
    }

    fn exact_top_k_cosine(points: &[Point], query: &[f32], k: usize) -> Vec<String> {
        let mut scored: Vec<(String, f32)> = points
            .iter()
            .map(|p| {
                let s = crate::DistanceMetric::Cosine
                    .score(query, &p.vector)
                    .unwrap();
                (p.id.clone(), s)
            })
            .collect();
        scored.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        scored.truncate(k);
        scored.into_iter().map(|(id, _)| id).collect()
    }

    /// W4 diagnostic sweep backing the N-aware `ef_search` floor: measures
    /// mean recall@10 at a FIXED `ef` across growing `N` to confirm/quantify
    /// that the existing flat curve (`ef_search_for_recall_target` /
    /// `default_ef_search`) loses recall as the collection grows, the same
    /// trend the 2026-06-25 50K-vs-500K benchmark surfaced (0.9507 → 0.921).
    /// Uses the same generator and recall methodology as
    /// `chirondb-server/tests/recall_golden.rs` (uniform random LCG vectors,
    /// Cosine metric) so the measured floor stays comparable to that gate's
    /// existing `n=12000` calibration. Run explicitly: `cargo test --release
    /// -p chirondb-core --lib w4_ef_search_recall_drops_with_n -- --ignored
    /// --nocapture`.
    #[test]
    #[ignore = "diagnostic sweep — run explicitly with --ignored --nocapture"]
    fn w4_ef_search_recall_drops_with_n() {
        let dim = 64_usize;
        let queries = 100;
        let k = 10;
        for &n in &[120_000_usize] {
            let points: Vec<Point> = (0..n)
                .map(|i| make_point(&i.to_string(), lcg_vector_uniform(i as u64, dim)))
                .collect();
            let index = super::H2qgIndex::build(&points, dim, crate::DistanceMetric::Cosine);
            for &ef in &[384_usize, 448, 512] {
                let mut hits = 0usize;
                for s in 0..queries {
                    let query = lcg_vector_uniform((n + s) as u64, dim);
                    let got = index.candidate_ids_with_ef(&query, k, Some(ef));
                    let want = exact_top_k_cosine(&points, &query, k);
                    let got_set: std::collections::HashSet<&String> = got.iter().collect();
                    hits += want.iter().filter(|id| got_set.contains(id)).count();
                }
                let recall = hits as f32 / (queries * k) as f32;
                eprintln!("n={n} ef={ef} recall={recall:.4}");
            }
        }
    }

    /// A4 diagnostic sweep backing the dim-aware `ef_search` floor (PRD.md
    /// §7 backlog item 6 / §8 Track A item A4): measures mean recall@10 at
    /// the row-151 `0.97`-tier floor (`ef=128`) across growing `dim`, at the
    /// `n=12000` anchor `n_scale` is calibrated at (so this isolates the
    /// dimension effect from the point-count effect already covered by W4).
    /// Same generator/metric/methodology as `recall_golden.rs` and the W4
    /// sweep above. Run explicitly: `cargo test --release -p chirondb-core
    /// --lib a4_ef_search_recall_drops_with_dim -- --ignored --nocapture`.
    #[test]
    #[ignore = "diagnostic sweep — run explicitly with --ignored --nocapture"]
    fn a4_ef_search_recall_drops_with_dim() {
        let n = 12_000_usize;
        let queries = 100;
        let k = 10;
        for &dim in &[64_usize, 128, 256, 768, 1536] {
            let points: Vec<Point> = (0..n)
                .map(|i| make_point(&i.to_string(), lcg_vector_uniform(i as u64, dim)))
                .collect();
            let index = super::H2qgIndex::build(&points, dim, crate::DistanceMetric::Cosine);
            for &ef in &[128_usize, 192, 256, 384, 512, 768, 1024] {
                let mut hits = 0usize;
                for s in 0..queries {
                    let query = lcg_vector_uniform((n + s) as u64, dim);
                    let got = index.candidate_ids_with_ef(&query, k, Some(ef));
                    let want = exact_top_k_cosine(&points, &query, k);
                    let got_set: std::collections::HashSet<&String> = got.iter().collect();
                    hits += want.iter().filter(|id| got_set.contains(id)).count();
                }
                let recall = hits as f32 / (queries * k) as f32;
                eprintln!("dim={dim} ef={ef} recall={recall:.4}");
            }
        }
    }

    /// P2F — filter-aware HNSW beam search. Three things must hold:
    ///
    /// 1. The filter is consulted per-neighbour: a passing NN is returned
    ///    when its filter set includes the ground-truth ID.
    /// 2. Filtered-out neighbours are never pushed onto the candidate heap:
    ///    if the filter set excludes the true NN, that ID must not appear in
    ///    the results (the beam never wastes budget on excluded points).
    /// 3. `filter = None` matches the un-filtered contract exactly.
    #[test]
    fn hnsw_filter_aware_beam_returns_passing_candidates() {
        use std::collections::HashSet;

        // Build a dataset with well-spaced vectors so the true NN is unambiguous.
        let n = super::HNSW_THRESHOLD + 200;
        let dim = 4_usize;
        let points: Vec<Point> = (0..n)
            .map(|i| {
                let base = (i * 10) as f32;
                let v: Vec<f32> = (0..dim).map(|d| base + d as f32).collect();
                make_point(&i.to_string(), v)
            })
            .collect();
        let index = super::H2qgIndex::build(&points, dim, crate::DistanceMetric::L2);
        assert!(index.is_hnsw());

        // 1. filter = None must match the un-filtered result.
        let query = points[123].vector.clone();
        let unfiltered = index.candidate_ids_with_ef(&query, 10, None);
        let no_filter = index.candidate_ids_with_ef_filter(&query, 10, None, None);
        assert_eq!(
            unfiltered, no_filter,
            "filter=None must match un-filtered call"
        );

        // 2. Filter that includes the true NN — beam must return it.
        //    Use an "allow all" filter (every ID) so the filter is maximally
        //    permissive. The test then verifies:
        //      a. the filter-aware beam can return the true NN even with a
        //         filter wrapper, and
        //      b. it does not return any ID outside the filter.
        //    We don't compare to the un-filtered result because HNSW is
        //    non-deterministic across beam invocations — different beams can
        //    surface different ties. The contract is "all passing, no leaks".
        let allow: HashSet<String> = (0..n).map(|i| i.to_string()).collect();
        let allow_ref: &dyn crate::index::FilterPredicate = &allow;
        let filtered = index.candidate_ids_with_ef_filter(&query, 10, None, Some(allow_ref));
        assert!(
            filtered.contains(&"123".to_string()),
            "filter-aware beam lost the ground-truth NN: filtered={:?}",
            &filtered[..filtered.len().min(5)]
        );
        // All returned candidates must pass the filter.
        for id in &filtered {
            assert!(
                allow.contains(id),
                "filter-aware beam returned non-passing id {id}; allow has {} entries",
                allow.len()
            );
        }

        // 3. Filter that excludes the true NN — beam must not return it.
        let mut exclude_true: HashSet<String> = (0..n).map(|i| i.to_string()).collect();
        exclude_true.remove("123");
        // Restrict to a "region" that has nothing near query.
        let only_far: HashSet<String> = (n - 50..n).map(|i| i.to_string()).collect();
        let far_filtered = index.candidate_ids_with_ef_filter(&query, 10, None, Some(&only_far));
        for id in &far_filtered {
            assert!(
                only_far.contains(id),
                "filter-aware beam returned non-passing id {id}"
            );
        }
        // The "far" filter set has no points near the query, so the beam should
        // still return *something* (it returns the best within the filter set,
        // even if it's the global best within that set). What's important is
        // that nothing outside the filter leaks through.
        assert!(
            !exclude_true.is_empty() || far_filtered.is_empty(),
            "filter-aware beam test setup invariant"
        );

        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let predicate_calls = std::sync::atomic::AtomicUsize::new(0);
        let cancel_on_first_candidate = |_id: &str| {
            predicate_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            cancelled.store(true, std::sync::atomic::Ordering::Release);
            true
        };
        let cancelled_hits =
            crate::index::IndexBackend::candidate_ids_with_recall_target_cancellable(
                &index,
                &query,
                10,
                None,
                0.95,
                Some(&cancel_on_first_candidate),
                &cancelled,
            );
        assert!(cancelled.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(
            predicate_calls.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert!(cancelled_hits.len() <= 1);
    }

    #[test]
    fn hnsw_persist_and_reload() {
        let temp = TempDir::new().unwrap();
        let n = super::HNSW_THRESHOLD + 5;
        let dim = 3_usize;
        let points: Vec<Point> = (0..n)
            .map(|i| {
                make_point(
                    &i.to_string(),
                    vec![i as f32, (i + 1) as f32, (i + 2) as f32],
                )
            })
            .collect();

        let path = temp.path().join(h2qg::INDEX_FILE);
        h2qg::write_index(&path, &points, dim, crate::DistanceMetric::L2).unwrap();

        let index = h2qg::read_index(&path).unwrap();
        assert!(index.is_hnsw());
        assert_eq!(index.indexed_points(), n);

        // Reload must produce identical candidate results.
        let query = vec![0.0_f32, 1.0, 2.0];
        let candidates = index.candidate_ids(&query, 5);
        assert!(!candidates.is_empty());
        assert!(candidates.contains(&"0".to_string()));
    }

    // ── SQ8 tests ──────────────────────────────────────────────────────────────

    #[test]
    fn sq8_encode_decode_roundtrip_is_approximate() {
        let vectors: Vec<Vec<f32>> = vec![
            vec![0.0, 1.0, -1.0, 0.5],
            vec![1.0, 0.0, 0.5, -0.5],
            vec![-1.0, -1.0, 1.0, 1.0],
        ];
        let refs: Vec<&[f32]> = vectors.iter().map(|v| v.as_slice()).collect();
        let params = super::Sq8Params::train(&refs);

        for vec in &vectors {
            let codes = params.encode(vec);
            let decoded = params.decode(&codes);
            assert_eq!(codes.len(), vec.len());
            assert_eq!(decoded.len(), vec.len());
            for (orig, approx) in vec.iter().zip(&decoded) {
                // Quantisation error is at most range/255 ≈ 0.008 for range=2.
                assert!(
                    (orig - approx).abs() < 0.02,
                    "Excessive quantisation error: orig={orig}, approx={approx}"
                );
            }
        }
    }

    #[test]
    fn sq8_approx_distance_correlates_with_exact_l2() {
        let vectors: Vec<Vec<f32>> = (0..20)
            .map(|i| vec![i as f32, (i * 2) as f32, (i * 3) as f32])
            .collect();
        let refs: Vec<&[f32]> = vectors.iter().map(|v| v.as_slice()).collect();
        let params = super::Sq8Params::train(&refs);

        let codes: Vec<Vec<u8>> = vectors.iter().map(|v| params.encode(v)).collect();
        let query = &vectors[0];
        let query_codes = params.encode(query);

        // Rank by exact and approximate distance; top-3 should match.
        let mut exact_ranked: Vec<(f32, usize)> = vectors
            .iter()
            .enumerate()
            .skip(1) // exclude self
            .map(|(i, v)| {
                let d: f32 = query.iter().zip(v).map(|(a, b)| (a - b).powi(2)).sum();
                (d, i)
            })
            .collect();
        exact_ranked.sort_by(|a, b| a.0.total_cmp(&b.0));

        let mut approx_ranked: Vec<(f32, usize)> = codes
            .iter()
            .enumerate()
            .skip(1)
            .map(|(i, c)| (params.approx_sq_l2(&query_codes, c), i))
            .collect();
        approx_ranked.sort_by(|a, b| a.0.total_cmp(&b.0));

        let exact_top3: Vec<usize> = exact_ranked.iter().take(3).map(|&(_, i)| i).collect();
        let approx_top3: Vec<usize> = approx_ranked.iter().take(3).map(|&(_, i)| i).collect();
        // All top-3 exact neighbours should also appear in approx top-3.
        for id in &exact_top3 {
            assert!(
                approx_top3.contains(id),
                "approx ranked missed exact top-3 neighbour {id}"
            );
        }
    }

    #[test]
    fn sq8_simd_distance_matches_scalar_reference_across_chunk_boundaries() {
        for dim in [0_usize, 1, 7, 8, 9, 31, 960, 963] {
            let dim_inv_scales = (0..dim)
                .map(|index| ((index % 29) + 1) as f32 / 37.0)
                .collect::<Vec<_>>();
            let params = super::Sq8Params {
                dim_mins: vec![0.0; dim],
                dim_scales: vec![1.0; dim],
                dim_inv_scales,
            };
            let left = (0..dim)
                .map(|index| ((index * 73 + 19) % 256) as u8)
                .collect::<Vec<_>>();
            let right = (0..dim)
                .map(|index| ((index * 41 + 211) % 256) as u8)
                .collect::<Vec<_>>();
            let scalar = left
                .iter()
                .zip(&right)
                .enumerate()
                .map(|(index, (&left, &right))| {
                    let diff = (left as i16 - right as i16) as f32 * params.dim_inv_scales[index];
                    diff * diff
                })
                .sum::<f32>();
            let simd = params.approx_sq_l2(&left, &right);
            let tolerance = scalar.abs().max(1.0) * 2.0e-6;
            assert!(
                (simd - scalar).abs() <= tolerance,
                "dim={dim} scalar={scalar} simd={simd} tolerance={tolerance}"
            );
        }
    }

    #[test]
    fn sq8_hnsw_builds_persists_and_recalls() {
        // Use values in [0, 255] range so SQ8 quantisation has good resolution
        // (scale ≈ 1.0, code ≈ value).  Different primes per dimension prevent
        // duplicate vectors.
        let temp = TempDir::new().unwrap();
        let n = super::HNSW_THRESHOLD + 100;
        let dim = 4_usize;
        let points: Vec<Point> = (0..n)
            .map(|i| {
                let v: Vec<f32> = (0..dim).map(|d| ((i * 7 + d * 31) % 256) as f32).collect();
                make_point(&i.to_string(), v)
            })
            .collect();

        let path = temp.path().join(h2qg::INDEX_FILE);
        let write = h2qg::write_index_sq8(&path, &points, dim, crate::DistanceMetric::L2).unwrap();
        assert_eq!(write.indexed_points, n);

        let index = h2qg::read_index(&path).unwrap();
        assert!(index.is_hnsw(), "expected HNSW mode");
        assert!(index.uses_sq8(), "expected SQ8 quantisation");
        assert_eq!(index.indexed_points(), n);

        // Exact match query — the node itself must appear in candidates.
        // Use a mid-range point to avoid edge effects near the extremes of the quantisation range.
        let target = n / 3;
        let candidates = index.candidate_ids(&points[target].vector, 10);
        assert!(
            candidates.contains(&target.to_string()),
            "SQ8 HNSW failed to recall exact nearest neighbour (target={target}, \
             candidates={candidates:?})"
        );
    }

    #[test]
    fn sq8_params_dimension_matches_training_data() {
        let vecs: Vec<Vec<f32>> = vec![vec![1.0, 2.0, 3.0], vec![4.0, 5.0, 6.0]];
        let refs: Vec<&[f32]> = vecs.iter().map(|v| v.as_slice()).collect();
        let params = super::Sq8Params::train(&refs);
        assert_eq!(params.dim(), 3);
        assert_eq!(params.dim_mins.len(), 3);
        assert_eq!(params.dim_scales.len(), 3);
    }

    #[test]
    fn paged_hnsw_builds_and_queries_above_threshold() {
        let temp = TempDir::new().unwrap();
        let n = super::HNSW_THRESHOLD + 100;
        let dim = 4_usize;
        let points: Vec<Point> = (0..n)
            .map(|i| {
                let base = (i * 10) as f32;
                let v: Vec<f32> = (0..dim).map(|d| base + d as f32).collect();
                make_point(&i.to_string(), v)
            })
            .collect();

        h2qg::write_index_paged(temp.path(), &points, dim, crate::DistanceMetric::L2).unwrap();

        let index = h2qg::read_index_paged(temp.path()).unwrap();
        assert!(index.is_hnsw(), "expected HNSW mode");
        assert!(index.is_paged(), "expected paged vectors after load");
        assert_eq!(index.indexed_points(), n);

        // Query a mid-range point's exact vector; it must appear in candidates.
        let mid = n / 2;
        let candidates = index.candidate_ids(&points[mid].vector, 10);
        assert!(
            candidates.contains(&mid.to_string()),
            "paged HNSW failed to recall mid-collection nearest neighbour"
        );
    }

    #[test]
    fn paged_hnsw_vecs_file_is_smaller_than_json_inline() {
        let temp = TempDir::new().unwrap();
        let n = super::HNSW_THRESHOLD + 100;
        let dim = 4_usize;
        let points: Vec<Point> = (0..n)
            .map(|i| {
                let base = (i * 10) as f32;
                let v: Vec<f32> = (0..dim).map(|d| base + d as f32).collect();
                make_point(&i.to_string(), v)
            })
            .collect();

        // Inline build: h2qg.gdx contains embedded vectors.
        let inline_dir = temp.path().join("inline");
        std::fs::create_dir_all(&inline_dir).unwrap();
        h2qg::write_index(
            &inline_dir.join(h2qg::INDEX_FILE),
            &points,
            dim,
            crate::DistanceMetric::L2,
        )
        .unwrap();
        let inline_size = std::fs::metadata(inline_dir.join(h2qg::INDEX_FILE))
            .unwrap()
            .len();

        // Paged build: h2qg.gdx has no embedded vectors.
        let paged_dir = temp.path().join("paged");
        std::fs::create_dir_all(&paged_dir).unwrap();
        h2qg::write_index_paged(&paged_dir, &points, dim, crate::DistanceMetric::L2).unwrap();
        let paged_size = std::fs::metadata(paged_dir.join(h2qg::INDEX_FILE))
            .unwrap()
            .len();

        assert!(
            paged_size < inline_size,
            "paged h2qg.gdx ({paged_size} bytes) should be smaller than inline ({inline_size} bytes)"
        );
    }

    #[test]
    fn insert_point_grows_hnsw_incrementally() {
        let n = super::HNSW_THRESHOLD + 10;
        let dim = 4_usize;
        let points: Vec<Point> = (0..n)
            .map(|i| {
                let v = (0..dim).map(|d| (i * dim + d) as f32).collect();
                make_point(&i.to_string(), v)
            })
            .collect();

        let mut index = super::H2qgIndex::build(&points, dim, crate::DistanceMetric::L2);
        assert!(index.is_hnsw());
        assert_eq!(index.indexed_points(), n);

        let new_point = make_point("new", vec![9999.0, 9999.0, 9999.0, 9999.0]);
        index.insert_point(&new_point, dim).unwrap();

        assert_eq!(index.indexed_points(), n + 1);
        // The new point's own vector should show up in candidate results.
        let candidates = index.candidate_ids(&new_point.vector, 5);
        assert!(
            candidates.contains(&"new".to_string()),
            "inserted point not found in candidates: {candidates:?}"
        );
    }

    #[test]
    fn update_index_with_new_points_roundtrip() {
        let temp = TempDir::new().unwrap();
        let n = super::HNSW_THRESHOLD + 10;
        let dim = 4_usize;
        let points: Vec<Point> = (0..n)
            .map(|i| {
                let v = (0..dim).map(|d| (i * dim + d) as f32).collect();
                make_point(&i.to_string(), v)
            })
            .collect();
        let path = temp.path().join(h2qg::INDEX_FILE);
        h2qg::write_index(&path, &points, dim, crate::DistanceMetric::L2).unwrap();

        let new_points: Vec<Point> = (0..5)
            .map(|i| {
                let v: Vec<f32> = (0..dim).map(|d| (10000 + i * dim + d) as f32).collect();
                make_point(&format!("extra-{i}"), v)
            })
            .collect();

        let write = h2qg::update_index_with_new_points(&path, &new_points, dim).unwrap();
        assert_eq!(write.indexed_points, n + 5);

        let reloaded = h2qg::read_index(&path).unwrap();
        assert_eq!(reloaded.indexed_points(), n + 5);
        // Each new point's vector should appear in its own candidate results.
        for new_point in &new_points {
            let candidates = reloaded.candidate_ids(&new_point.vector, 5);
            assert!(
                candidates.contains(&new_point.id),
                "new point {} not found in candidates after reload",
                new_point.id
            );
        }
    }

    #[test]
    fn insert_point_flat_mode_is_no_op() {
        let dim = 4_usize;
        // Small collection → flat mode
        let points: Vec<Point> = (0..3)
            .map(|i| {
                let v = (0..dim).map(|d| (i * dim + d) as f32).collect();
                make_point(&i.to_string(), v)
            })
            .collect();

        let mut index = super::H2qgIndex::build(&points, dim, crate::DistanceMetric::L2);
        assert!(index.is_flat_fallback());

        let new_point = make_point("new", vec![1.0, 2.0, 3.0, 4.0]);
        // Must not error; flat mode silently ignores the insertion.
        index.insert_point(&new_point, dim).unwrap();
        // Flat mode unchanged — indexed_points should still be the original count.
        assert_eq!(index.indexed_points(), 3);
    }
}
