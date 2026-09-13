use serde::{Deserialize, Serialize};
use wide::f32x8;

use crate::error::{GaussError, Result};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DistanceMetric {
    L2,
    #[default]
    Cosine,
    Dot,
}

impl DistanceMetric {
    pub fn score(self, query: &[f32], vector: &[f32]) -> Result<f32> {
        if query.len() != vector.len() {
            return Err(GaussError::DimensionMismatch {
                expected: query.len(),
                actual: vector.len(),
            });
        }

        Ok(match self {
            Self::L2 => -l2(query, vector),
            Self::Cosine => cosine(query, vector),
            Self::Dot => dot(query, vector),
        })
    }
}

// ---------------------------------------------------------------------------
// Phase 2A (P2A): cross-platform SIMD distance kernels
// ---------------------------------------------------------------------------
//
// Layering (top → bottom = fastest → most portable):
//
//   1. `#[cfg(target_arch = "x86_64")] squared_l2_avx2_fma` / `dot_avx2_fma`
//      — hand-tuned 4x-unrolled `_mm256_fmadd_ps` (one `vfmadd231ps` per FMA
//        unit per cycle, two FMA units on Skylake+ ⇒ peak 2 FMA/cycle/core).
//        Gated at compile time on `target_arch = "x86_64"` so the rest of
//        the crate still builds clean on aarch64 / wasm / etc.
//
//   2. `squared_l2_wide` / `dot_wide`
//      — portable `wide::f32x8` chunked-8 path. On aarch64 NEON this lowers
//        to `fmla.4s` (FMA) and is at hardware peak; on x86-64 without
//        AVX2/FMA detected it lowers to scalar / SSE. **This is the
//        universal fallback.**
//
//   3. Scalar tail — handles the `n % 8` remainder for non-multiple-of-8
//      dims, present in every branch.
//
// Dispatch discipline:
//   - compile-time: `#[cfg(target_arch = "x86_64")]` gates the AVX2 kernel
//     itself, so the rest of the crate still builds on non-x86.
//   - runtime: `is_x86_feature_detected!("avx2")` + `"fma"` picks the
//     kernel per call. Both checks are ~1 ns each (cached atomic load at
//     program startup), so we don't bother memoising — a 1536-dim distance
//     is ~192 FMAs per kernel call, dwarfing the dispatch cost.
//
// Expected lift on Linux x86_64 prod: ~30–50% on AVX2+FMA-capable hosts
// (e.g. Cascade Lake / Sapphire Rapids / Zen3+) where the existing wide
// path lowers to mul+add with no rounding fusion. On Mac aarch64 dev
// hardware the wide path is already FMA and the new branch is a no-op.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,fma")]
#[inline]
unsafe fn hsum256_ps(v: core::arch::x86_64::__m256) -> f32 {
    use core::arch::x86_64::*;
    // Canonical AVX2 horizontal sum: extract high 128-bit half, add to low
    // half, then sum the 4 lanes of the 128-bit result via
    // movehdup + movehl + add_ss. Each step is a single µop and the whole
    // reduction is ~5 cycles — cheap relative to the 192+ FMAs of a
    // 1536-dim distance.
    let hi = _mm256_extractf128_ps(v, 1);
    let lo = _mm256_castps256_ps128(v);
    let sum128 = _mm_add_ps(lo, hi);
    let shuf = _mm_movehdup_ps(sum128);
    let sums = _mm_add_ps(sum128, shuf);
    let shuf2 = _mm_movehl_ps(sums, sums);
    let result = _mm_add_ss(sums, shuf2);
    _mm_cvtss_f32(result)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,fma")]
unsafe fn squared_l2_avx2_fma(a: &[f32], b: &[f32]) -> f32 {
    use core::arch::x86_64::*;
    // SAFETY: callers gate AVX2/FMA at runtime, and every pointer offset is
    // bounded by `chunks`, which is derived from the equal-length slices.
    unsafe {
        const LANES: usize = 8;
        let n = a.len();
        debug_assert_eq!(b.len(), n, "AVX2 kernel assumes equal-length slices");
        let chunks = n / LANES;

        // 4x unroll → 4 independent FMA dependency chains → saturates both
        // FMA units on Skylake+ (2 FMA/cycle/core peak). 32 elements per
        // iteration keeps the 8 YMM registers in the sweet spot; >4x
        // unroll starts to spill or stall on the 2 FMA pipes.
        let mut acc0 = _mm256_setzero_ps();
        let mut acc1 = _mm256_setzero_ps();
        let mut acc2 = _mm256_setzero_ps();
        let mut acc3 = _mm256_setzero_ps();

        let a_ptr = a.as_ptr();
        let b_ptr = b.as_ptr();

        let unroll_chunks = chunks / 4;
        for i in 0..unroll_chunks {
            let base = i * 32;
            let a0 = _mm256_loadu_ps(a_ptr.add(base));
            let a1 = _mm256_loadu_ps(a_ptr.add(base + 8));
            let a2 = _mm256_loadu_ps(a_ptr.add(base + 16));
            let a3 = _mm256_loadu_ps(a_ptr.add(base + 24));
            let b0 = _mm256_loadu_ps(b_ptr.add(base));
            let b1 = _mm256_loadu_ps(b_ptr.add(base + 8));
            let b2 = _mm256_loadu_ps(b_ptr.add(base + 16));
            let b3 = _mm256_loadu_ps(b_ptr.add(base + 24));
            let d0 = _mm256_sub_ps(a0, b0);
            let d1 = _mm256_sub_ps(a1, b1);
            let d2 = _mm256_sub_ps(a2, b2);
            let d3 = _mm256_sub_ps(a3, b3);
            acc0 = _mm256_fmadd_ps(d0, d0, acc0);
            acc1 = _mm256_fmadd_ps(d1, d1, acc1);
            acc2 = _mm256_fmadd_ps(d2, d2, acc2);
            acc3 = _mm256_fmadd_ps(d3, d3, acc3);
        }

        // Drain the unroll remainder (0..3 leftover chunks) into acc0.
        let unrolled_end = unroll_chunks * 4;
        for i in unrolled_end..chunks {
            let base = i * 8;
            let av = _mm256_loadu_ps(a_ptr.add(base));
            let bv = _mm256_loadu_ps(b_ptr.add(base));
            let d = _mm256_sub_ps(av, bv);
            acc0 = _mm256_fmadd_ps(d, d, acc0);
        }

        // Tree-reduce the 4 accumulators (independent → no dep chain).
        let acc = _mm256_add_ps(_mm256_add_ps(acc0, acc1), _mm256_add_ps(acc2, acc3));
        let mut total = hsum256_ps(acc);

        // Scalar tail for non-multiple-of-8 dims.
        let tail_start = chunks * LANES;
        for j in tail_start..n {
            let d = a[j] - b[j];
            total += d * d;
        }
        total
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,fma")]
unsafe fn dot_avx2_fma(a: &[f32], b: &[f32]) -> f32 {
    use core::arch::x86_64::*;
    // SAFETY: callers gate AVX2/FMA at runtime, and every pointer offset is
    // bounded by `chunks`, which is derived from the equal-length slices.
    unsafe {
        const LANES: usize = 8;
        let n = a.len();
        debug_assert_eq!(b.len(), n, "AVX2 kernel assumes equal-length slices");
        let chunks = n / LANES;

        let mut acc0 = _mm256_setzero_ps();
        let mut acc1 = _mm256_setzero_ps();
        let mut acc2 = _mm256_setzero_ps();
        let mut acc3 = _mm256_setzero_ps();

        let a_ptr = a.as_ptr();
        let b_ptr = b.as_ptr();

        let unroll_chunks = chunks / 4;
        for i in 0..unroll_chunks {
            let base = i * 32;
            let a0 = _mm256_loadu_ps(a_ptr.add(base));
            let a1 = _mm256_loadu_ps(a_ptr.add(base + 8));
            let a2 = _mm256_loadu_ps(a_ptr.add(base + 16));
            let a3 = _mm256_loadu_ps(a_ptr.add(base + 24));
            let b0 = _mm256_loadu_ps(b_ptr.add(base));
            let b1 = _mm256_loadu_ps(b_ptr.add(base + 8));
            let b2 = _mm256_loadu_ps(b_ptr.add(base + 16));
            let b3 = _mm256_loadu_ps(b_ptr.add(base + 24));
            acc0 = _mm256_fmadd_ps(a0, b0, acc0);
            acc1 = _mm256_fmadd_ps(a1, b1, acc1);
            acc2 = _mm256_fmadd_ps(a2, b2, acc2);
            acc3 = _mm256_fmadd_ps(a3, b3, acc3);
        }

        let unrolled_end = unroll_chunks * 4;
        for i in unrolled_end..chunks {
            let base = i * 8;
            let av = _mm256_loadu_ps(a_ptr.add(base));
            let bv = _mm256_loadu_ps(b_ptr.add(base));
            acc0 = _mm256_fmadd_ps(av, bv, acc0);
        }

        let acc = _mm256_add_ps(_mm256_add_ps(acc0, acc1), _mm256_add_ps(acc2, acc3));
        let mut total = hsum256_ps(acc);

        let tail_start = chunks * LANES;
        for j in tail_start..n {
            total += a[j] * b[j];
        }
        total
    }
}

/// Squared L2 distance — hot inner loop for the HNSW graph build and the
/// exact-rescore path.
///
/// P2A dispatch: x86-64 with AVX2+FMA detected at runtime → hand-tuned
/// 4x-unrolled `vfmadd231ps` kernel; else the portable `wide::f32x8`
/// chunked-8 path (NEON on aarch64 lowers to `fmla.4s` and is at
/// hardware peak). Scalar tail handles non-multiple-of-8 dims in both.
pub fn squared_l2(a: &[f32], b: &[f32]) -> f32 {
    // Slice to the common prefix so both branches see equal-length inputs.
    let n = a.len().min(b.len());
    let a = &a[..n];
    let b = &b[..n];

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("fma") {
            // SAFETY: `is_x86_feature_detected!` returned true for both
            // "avx2" and "fma", so the `#[target_feature(enable =
            // "avx2,fma")]`-gated kernel is callable on this CPU.
            return unsafe { squared_l2_avx2_fma(a, b) };
        }
    }
    squared_l2_wide(a, b)
}

/// Portable `wide::f32x8` squared L2 — universal fallback. On aarch64
/// this lowers to NEON `fmla.4s` (FMA) and is at hardware peak; on
/// x86-64 without AVX2+FMA detected it lowers to scalar / SSE.
fn squared_l2_wide(a: &[f32], b: &[f32]) -> f32 {
    const LANES: usize = 8;
    let n = a.len();
    let chunks = n / LANES;
    let mut acc = f32x8::splat(0.0);

    for i in 0..chunks {
        let base = i * LANES;
        let av: [f32; LANES] = a[base..base + LANES].try_into().expect("lane slice");
        let bv: [f32; LANES] = b[base..base + LANES].try_into().expect("lane slice");
        let d = f32x8::new(av) - f32x8::new(bv);
        acc += d * d;
    }
    let mut total = acc.reduce_add();
    for i in (chunks * LANES)..n {
        let d = a[i] - b[i];
        total += d * d;
    }
    total
}

/// Hamming distance over packed binary vectors stored as `u64` words.
/// Used by Phase 4 RaBitQ binary quantisation and any future bitwise index.
/// Compiles to the CPU `popcnt` instruction on x86-64 (SSE4.2+) and the NEON
/// `cnt` instruction on aarch64; `u64::count_ones` is the idiomatic stable-Rust
/// portal to those intrinsics. Falls back to software popcount on platforms
/// without hardware support — still correct, just slower.
pub fn hamming_popcount(a: &[u64], b: &[u64]) -> u32 {
    let n = a.len().min(b.len());
    let mut acc: u32 = 0;
    for i in 0..n {
        acc += (a[i] ^ b[i]).count_ones();
    }
    acc
}

fn l2(a: &[f32], b: &[f32]) -> f32 {
    squared_l2(a, b).sqrt()
}

/// Dot product. P2A: same x86-64 AVX2+FMA dispatch as `squared_l2`; the wide
/// path is the fallback (aarch64 NEON `fmla.4s` is already at peak).
pub fn dot(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    let a = &a[..n];
    let b = &b[..n];

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("fma") {
            // SAFETY: see `squared_l2` — both features detected.
            return unsafe { dot_avx2_fma(a, b) };
        }
    }
    dot_wide(a, b)
}

fn dot_wide(a: &[f32], b: &[f32]) -> f32 {
    const LANES: usize = 8;
    let n = a.len();
    let chunks = n / LANES;
    let mut acc = f32x8::splat(0.0);

    for i in 0..chunks {
        let base = i * LANES;
        let av: [f32; LANES] = a[base..base + LANES].try_into().expect("lane slice");
        let bv: [f32; LANES] = b[base..base + LANES].try_into().expect("lane slice");
        acc += f32x8::new(av) * f32x8::new(bv);
    }
    let mut total = acc.reduce_add();
    for i in (chunks * LANES)..n {
        total += a[i] * b[i];
    }
    total
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let numerator = dot(a, b);
    let left_norm = dot(a, a).sqrt();
    let right_norm = dot(b, b).sqrt();
    if left_norm == 0.0 || right_norm == 0.0 {
        0.0
    } else {
        numerator / (left_norm * right_norm)
    }
}

#[cfg(test)]
mod tests {
    use super::DistanceMetric;

    #[test]
    fn cosine_scores_identical_vectors_highest() {
        let same = DistanceMetric::Cosine
            .score(&[1.0, 0.0], &[1.0, 0.0])
            .unwrap();
        let orthogonal = DistanceMetric::Cosine
            .score(&[1.0, 0.0], &[0.0, 1.0])
            .unwrap();
        assert!(same > orthogonal);
    }

    #[test]
    fn l2_uses_negative_distance_for_top_k_sorting() {
        let near = DistanceMetric::L2.score(&[0.0, 0.0], &[1.0, 0.0]).unwrap();
        let far = DistanceMetric::L2.score(&[0.0, 0.0], &[4.0, 0.0]).unwrap();
        assert!(near > far);
    }

    // P2A: directly exercise the AVX2+FMA kernel on x86-64 hosts that
    // expose the feature, comparing it against the wide fallback on the
    // same inputs. On non-x86_64 hosts the test is compiled out — the
    // kernel doesn't exist there. On x86_64 without the feature, the
    // test is a no-op (eprintln + early return) so CI on a stripped VM
    // still passes.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx2_fma_kernel_matches_wide_parity() {
        if !(is_x86_feature_detected!("avx2") && is_x86_feature_detected!("fma")) {
            eprintln!("skip: avx2/fma not detected on this host");
            return;
        }

        // Cover chunk-aligned, tail-only, and large dims. Mixed seeds so we
        // hit different bit patterns; FMA single-rounding means the AVX2
        // result is *closer* to a f64 reference than the wide result, so
        // the |avx2 - wide| tolerance is generous enough to absorb the
        // mul+add double-rounding drift on the wide side.
        for dim in [
            0usize, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 128, 384, 768, 1024, 1536, 2048,
        ] {
            for seed in 0u64..3 {
                let mut sa: u64 =
                    0x1111_1111 ^ seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ dim as u64;
                let mut sb: u64 =
                    0x2222_2222 ^ seed.wrapping_mul(0xBF58_476D_1CE4_E5B9) ^ dim as u64;
                let a: Vec<f32> = (0..dim)
                    .map(|_| {
                        sa = sa.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                        (((sa >> 32) as u32) as f32 / u32::MAX as f32) * 2.0 - 1.0
                    })
                    .collect();
                let b: Vec<f32> = (0..dim)
                    .map(|_| {
                        sb = sb.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                        (((sb >> 32) as u32) as f32 / u32::MAX as f32) * 2.0 - 1.0
                    })
                    .collect();

                let avx2_l2 = unsafe { super::squared_l2_avx2_fma(&a, &b) };
                let wide_l2 = super::squared_l2_wide(&a, &b);
                let scale_l2 = avx2_l2.abs().max(wide_l2.abs()).max(1.0);
                assert!(
                    (avx2_l2 - wide_l2).abs() <= 1e-3 * scale_l2,
                    "squared_l2 dim={dim} seed={seed}: avx2={avx2_l2} wide={wide_l2}"
                );

                let avx2_dot = unsafe { super::dot_avx2_fma(&a, &b) };
                let wide_dot = super::dot_wide(&a, &b);
                let scale_dot = avx2_dot.abs().max(wide_dot.abs()).max(1.0);
                assert!(
                    (avx2_dot - wide_dot).abs() <= 1e-3 * scale_dot,
                    "dot dim={dim} seed={seed}: avx2={avx2_dot} wide={wide_dot}"
                );
            }
        }
    }
}
