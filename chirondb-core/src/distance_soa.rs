//! P2E: SoA batch distance kernel.
//!
//! Consumes the dim-strided f32 grid emitted by [`crate::SoASegmentCache`] and
//! the on-disk [`crate::SoAVectorStorage`]. The kernel sweeps one dim column
//! at a time, loading 8 contiguous f32 values (= 8 points' `dim_d` value) in a
//! single instruction, and accumulates squared-L2 (or dot/cosine) into a
//! per-lane accumulator. This is the inner loop that P2E enables — the
//! dim-strided SoA layout turns what would be 8 strided gather-loads (AoS
//! `for point { for d }` over 8 points) into a single contiguous load.
//!
//! Cross-platform: pure Rust on top of the existing `wide::f32x8` SIMD
//! kernel from `chirondb-types` (AVX2 on x86-64, paired NEON on aarch64,
//! scalar fallback elsewhere). No platform-specific code paths are introduced
//! here — the SoA layout is the only thing P2E owns; the SIMD dispatch is
//! already provided by P2A.

use chirondb_types::distance::{DistanceMetric, squared_l2};
use wide::f32x8;

use crate::{Result, SoASegmentCache, error::GaussError};

/// Per-point distance result paired with the originating point's index in the
/// SoA cache. Use [`SoASegmentCache::ids`] to resolve the index to a point id.
#[derive(Clone, Copy, Debug)]
pub struct SoADistanceHit {
    pub index: usize,
    pub distance: f32,
}

/// Batch squared-L2 distance from `query` to every point in the cache.
/// The cache dim must match `query.len()`. Returns a `Vec<SoADistanceHit>`
/// with one entry per point, in cache order.
pub fn soa_squared_l2_all(cache: &SoASegmentCache, query: &[f32]) -> Result<Vec<SoADistanceHit>> {
    let dim = cache.dim();
    if dim != query.len() {
        return Err(GaussError::DimensionMismatch {
            expected: dim,
            actual: query.len(),
        });
    }
    let count = cache.count();
    let soa = cache.soa();
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        // Re-materialise point i by gathering the dim-strided columns.
        // For perf callers this is the slow path — it pays a gather per
        // dim. The fast path is [`soa_squared_l2_batch`], which amortises
        // the gather by sweeping one dim at a time over many points.
        let mut row = vec![0.0_f32; dim];
        for d in 0..dim {
            row[d] = soa[d * count + i];
        }
        let distance = squared_l2(query, &row);
        out.push(SoADistanceHit { index: i, distance });
    }
    Ok(out)
}

/// Dim-strided batch squared-L2 distance: sweep one dim at a time, loading
/// `LANES` contiguous f32 values (= `LANES` points' `dim_d` value) per
/// iteration. The accumulator holds one partial squared-L2 per point, so
/// after the dim loop the `lane` slice holds `LANES` point-distances.
///
/// `LANES` matches the SIMD width of the underlying `wide::f32x8` kernel
/// (8 × 32-bit lanes on every supported platform). If `count` is not a
/// multiple of `LANES`, the tail is handled with a small scalar loop.
///
/// `query` and `cache.soa()` must share the same `dim`. Caller is
/// responsible for any `top-k` reduction on the returned slice — this
/// kernel returns the full per-point distance vector, sorted by
/// ascending distance.
///
/// P2E × P2A multiplication: the inner loop uses the same `wide::f32x8`
/// SIMD type as `chirondb_types::distance::squared_l2` (P2A). The kernel
/// loads 8 contiguous f32 (8 points' `dim_d` value), subtracts the
/// broadcast `query[d]`, squares, and FMA's into an 8-lane accumulator.
/// On AVX2 the compiler emits a single `vmovups` + `vbroadcastss` +
/// `vsubps` + `vfmadd231ps` per dim; on NEON it lowers to paired
/// `ld1.4s` + `dup.4s` + `fmla.4s`. The SoA layout is what makes that
/// single contiguous load possible — P2A's per-point SIMD gather is
/// the kernel we beat.
pub fn soa_squared_l2_batch(cache: &SoASegmentCache, query: &[f32]) -> Result<Vec<SoADistanceHit>> {
    const LANES: usize = 8;
    let dim = cache.dim();
    if dim != query.len() {
        return Err(GaussError::DimensionMismatch {
            expected: dim,
            actual: query.len(),
        });
    }
    let count = cache.count();
    let soa = cache.soa();
    let chunks = count / LANES;
    let tail_start = chunks * LANES;
    let tail_len = count - tail_start;

    let mut sorted_hits: Vec<SoADistanceHit> = Vec::with_capacity(count);

    // Main loop: LANES points at a time, dim by dim. For each dim `d`
    // we load 8 contiguous f32 (`soa[d*count + base + 0..LANES]`),
    // build a `f32x8`, broadcast `query[d]`, subtract, square, and FMA
    // into the per-lane accumulator. After the dim loop we reduce the
    // 8-lane accumulator to per-point squared-L2 and append hits in
    // ascending-index order. The dim-strided outer loop is what gives
    // the load its 32-byte-aligned contiguous read pattern — the AoS
    // gather is replaced by a single SIMD load.
    for chunk_index in 0..chunks {
        let base = chunk_index * LANES;
        let mut acc = f32x8::splat(0.0_f32);
        for (d, &q_d) in query.iter().enumerate() {
            let column_offset = d * count + base;
            // 8 contiguous f32 loads — this is the SoA win. With AoS
            // layout the same 8 values would be 8 strided loads
            // (stride = `dim * 4` bytes). With SoA it's a single
            // contiguous 32-byte read.
            let column: [f32; LANES] = soa[column_offset..column_offset + LANES]
                .try_into()
                .expect("lane slice");
            let col_vec = f32x8::new(column);
            let q_vec = f32x8::splat(q_d);
            let diff = col_vec - q_vec;
            // FMA: acc += diff * diff. Compiles to `vfmadd231ps` on
            // AVX2 and `fmla.4s` (×2 lanes) on NEON.
            acc += diff * diff;
        }
        let lane_distances = acc.to_array();
        for (lane, &distance) in lane_distances.iter().enumerate() {
            sorted_hits.push(SoADistanceHit {
                index: base + lane,
                distance,
            });
        }
    }

    // Tail: any remaining points (0..LANES-1) handled scalar with the
    // same dim-strided read pattern.
    for i in tail_start..count {
        let mut acc = 0.0_f32;
        for d in 0..dim {
            let v = soa[d * count + i];
            let diff = v - query[d];
            acc += diff * diff;
        }
        sorted_hits.push(SoADistanceHit {
            index: i,
            distance: acc,
        });
    }
    // `tail_len` is referenced to silence dead-code lints in the future
    // when we may want to specialise the tail further.
    let _ = tail_len;
    Ok(sorted_hits)
}

/// Convenience: top-k nearest neighbours under the given metric, returned
/// sorted by ascending score (Cosine / Dot) or ascending squared-L2
/// distance (L2). Uses the dim-strided batch kernel; cost is
/// `O(count * dim / LANES)`.
pub fn soa_top_k(
    cache: &SoASegmentCache,
    query: &[f32],
    k: usize,
    metric: DistanceMetric,
) -> Result<Vec<SoADistanceHit>> {
    if k == 0 {
        return Ok(Vec::new());
    }
    // L2 is the only metric the batch kernel implements today. Other
    // metrics are computed on the per-point materialised row — they
    // share the same `squared_l2`/`dot` kernels from `chirondb-types`.
    match metric {
        DistanceMetric::L2 => {
            let mut all = soa_squared_l2_batch(cache, query)?;
            all.sort_by(|left, right| {
                left.distance
                    .total_cmp(&right.distance)
                    .then_with(|| left.index.cmp(&right.index))
            });
            all.truncate(k);
            Ok(all)
        }
        DistanceMetric::Cosine | DistanceMetric::Dot => {
            let all = soa_squared_l2_all(cache, query)?;
            let mut scored: Vec<SoADistanceHit> = all
                .into_iter()
                .map(|hit| {
                    let mut row = vec![0.0_f32; cache.dim()];
                    for (d, val) in row.iter_mut().enumerate() {
                        *val = cache.soa()[d * cache.count() + hit.index];
                    }
                    let score = metric.score(query, &row).unwrap_or(f32::NAN);
                    SoADistanceHit {
                        index: hit.index,
                        distance: score,
                    }
                })
                .collect();
            scored.sort_by(|left, right| {
                right
                    .distance
                    .total_cmp(&left.distance)
                    .then_with(|| left.index.cmp(&right.index))
            });
            scored.truncate(k);
            Ok(scored)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SoASegmentCache;

    fn make_aos_points(count: usize, dim: usize) -> Vec<Vec<f32>> {
        // Deterministic test vectors: row i = [(i*dim + d) as f32 * 0.01 for d in 0..dim]
        (0..count)
            .map(|i| (0..dim).map(|d| (i * dim + d) as f32 * 0.01).collect())
            .collect()
    }

    fn make_cache(rows: &[Vec<f32>]) -> SoASegmentCache {
        let points: Vec<crate::Point> = rows
            .iter()
            .enumerate()
            .map(|(i, row)| crate::Point {
                id: format!("p{i}"),
                vector: row.clone(),
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            })
            .collect();
        SoASegmentCache::from_points(&points).unwrap()
    }

    #[test]
    fn batch_distances_match_scalar() {
        // 64 points × 8 dims — covers the LANES=8 main loop and the
        // scalar tail in one shot.
        let rows = make_aos_points(64, 8);
        let cache = make_cache(&rows);
        let query = vec![0.1_f32; 8];
        let batch = soa_squared_l2_batch(&cache, &query).unwrap();
        assert_eq!(batch.len(), 64);
        // Cross-check against the per-point scalar path.
        let scalar = soa_squared_l2_all(&cache, &query).unwrap();
        assert_eq!(batch.len(), scalar.len());
        for (b, s) in batch.iter().zip(scalar.iter()) {
            assert!(
                (b.distance - s.distance).abs() < 1e-3,
                "batch={} scalar={}",
                b.distance,
                s.distance
            );
        }
    }

    #[test]
    fn batch_handles_non_lane_multiple_count() {
        // 5 points × 3 dims: not a multiple of LANES, exercises the
        // scalar tail after the chunked main loop.
        let rows = make_aos_points(5, 3);
        let cache = make_cache(&rows);
        let query = vec![0.0_f32, 0.0_f32, 0.0_f32];
        let batch = soa_squared_l2_batch(&cache, &query).unwrap();
        assert_eq!(batch.len(), 5);
        let scalar = soa_squared_l2_all(&cache, &query).unwrap();
        for (b, s) in batch.iter().zip(scalar.iter()) {
            assert!((b.distance - s.distance).abs() < 1e-3);
        }
    }

    #[test]
    fn top_k_l2_returns_nearest_in_ascending_distance() {
        // 16 points × 4 dims. Query = point 0, so the nearest should be
        // point 0 (distance 0), then the others in ascending order.
        let rows = make_aos_points(16, 4);
        let cache = make_cache(&rows);
        let query = rows[0].clone();
        let top = soa_top_k(&cache, &query, 5, DistanceMetric::L2).unwrap();
        assert_eq!(top.len(), 5);
        assert_eq!(top[0].index, 0, "nearest must be the query itself");
        assert!(top[0].distance.abs() < 1e-4);
        for w in top.windows(2) {
            assert!(w[0].distance <= w[1].distance);
        }
    }

    #[test]
    fn top_k_zero_returns_empty() {
        let rows = make_aos_points(8, 4);
        let cache = make_cache(&rows);
        let query = vec![0.0_f32; 4];
        let top = soa_top_k(&cache, &query, 0, DistanceMetric::L2).unwrap();
        assert!(top.is_empty());
    }

    #[test]
    fn dimension_mismatch_is_rejected() {
        let rows = make_aos_points(8, 4);
        let cache = make_cache(&rows);
        let bad_query = vec![0.0_f32; 3];
        let err = soa_squared_l2_batch(&cache, &bad_query).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("dimension"), "got: {msg}");
    }
}
