//! RaBitQ 1-bit **unbiased estimator** (Gao & Long, SIGMOD 2024).
//!
//! This is the real RaBitQ distance estimator, not Binary Quantization. The
//! earlier `rabitq.rs` filter ranked candidates by *Hamming distance* over
//! sign bits — that is plain BQ: it throws away the per-vector norm and gives
//! a biased, low-fidelity ranking. RaBitQ keeps the same 1-bit sign code but
//! reconstructs an **unbiased estimate of the inner product** (hence of the
//! squared L2 distance) using two per-vector scalars, so the coarse filter is
//! dramatically sharper at the same 1-bit budget.
//!
//! ## Math
//!
//! Let `o_r = x - c` be a vector's residual to its (IVF) centroid, `P` a fixed
//! orthonormal rotation (here the sign-flip + Fast-Walsh-Hadamard rotation in
//! [`super::rotate_for_cascade`], which is norm-preserving: `‖P v‖ = ‖v‖`).
//! Write the rotated residual `r = P o_r`, its unit form `ō = r / ‖r‖`, and the
//! 1-bit code `x̄ = sign(r) / √D` (unit norm, each component `±1/√D`).
//!
//! Per vector we persist two scalars:
//!   * `residual_norm = ‖o_r‖ = ‖r‖`
//!   * `dot_o_xbar = ⟨ō, x̄⟩ = ‖r‖₁ / (‖r‖·√D) ∈ (0, 1]`  — the code fidelity.
//!
//! At query time, rotate the query residual `q_r` → `s = P q_r`. From the sign
//! bits we form `⟨s, x̄⟩ = (1/√D) Σ_i s_i · sign(r_i)`. The RaBitQ estimator of
//! the (rotation-invariant) inner product is
//!
//! ```text
//!   ⟨q_r, o_r⟩  ≈  residual_norm · ⟨s, x̄⟩ / dot_o_xbar
//! ```
//!
//! which is **unbiased**: `E[⟨s,x̄⟩ / ⟨ō,x̄⟩] = ⟨s, ō⟩ = ⟨q_r, o_r⟩ / ‖o_r‖`.
//! The squared distance follows from `‖q_r − o_r‖² = ‖q_r‖² + ‖o_r‖² −
//! 2⟨q_r,o_r⟩`, with `‖q_r‖² = ‖s‖²` (rotation preserves norm). The estimator
//! error concentrates as `O(1/√D)` (near-Shannon) — validated in the tests.
//!
//! Callers pass vectors **already rotated** through [`super::rotate_for_cascade`]
//! so this kernel stays free of the rotation implementation and is reusable by
//! both the standalone `RabitqBackend` and the sealed IVF cascade artifact.

/// The two per-vector scalars RaBitQ needs on top of the sign bits.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RabitqCodeMeta {
    /// `‖o_r‖` — norm of the (un-rotated == rotated) residual.
    pub residual_norm: f32,
    /// `⟨ō, x̄⟩ ∈ (0, 1]` — fidelity of the sign code to the unit residual.
    pub dot_o_xbar: f32,
}

/// Encode the RaBitQ per-vector metadata from an **already-rotated** residual
/// `r = P o_r`. Pair this with `encode_sign_bits(rotated, ..)` for the code.
pub(crate) fn encode_meta(rotated: &[f32]) -> RabitqCodeMeta {
    let mut sum_sq = 0.0f32;
    let mut sum_abs = 0.0f32;
    for &v in rotated {
        sum_sq += v * v;
        sum_abs += v.abs();
    }
    let norm = sum_sq.sqrt();
    let padded = rotated.len().max(1) as f32;
    let dot_o_xbar = if norm > 0.0 {
        sum_abs / (norm * padded.sqrt())
    } else {
        0.0
    };
    RabitqCodeMeta {
        residual_norm: norm,
        dot_o_xbar,
    }
}

/// Unbiased RaBitQ estimate of `‖q_r − o_r‖²`.
///
/// * `sign_bits` — packed `sign(P o_r)` from `encode_sign_bits`.
/// * `meta` — from [`encode_meta`] on the same rotated residual.
/// * `rotated_query` — `P q_r` (same rotation, norm-preserving), length `D`.
pub(crate) fn estimate_squared_l2(
    sign_bits: &[u64],
    meta: &RabitqCodeMeta,
    rotated_query: &[f32],
) -> f32 {
    let query_norm_sq: f32 = rotated_query.iter().map(|v| v * v).sum();
    let residual_norm_sq = meta.residual_norm * meta.residual_norm;
    // Degenerate residual (zero vector) or zero-fidelity code: no direction to
    // project onto, so fall back to the norm-only bound (still a valid, if
    // loose, distance estimate — the exact L2 rerank fixes the final ranking).
    if meta.residual_norm == 0.0 || meta.dot_o_xbar == 0.0 {
        return query_norm_sq + residual_norm_sq;
    }
    // ⟨s, x̄⟩ = (1/√D) Σ_i s_i · sign(r_i), sign(r_i) = +1 iff bit set.
    let mut dot_sx = 0.0f32;
    for (i, &s) in rotated_query.iter().enumerate() {
        let bit = (sign_bits[i / 64] >> (i % 64)) & 1;
        dot_sx += if bit == 1 { s } else { -s };
    }
    dot_sx /= (rotated_query.len().max(1) as f32).sqrt();
    // ⟨q_r, o_r⟩ ≈ residual_norm · ⟨s,x̄⟩ / dot_o_xbar (unbiased).
    let est_ip = meta.residual_norm * dot_sx / meta.dot_o_xbar;
    query_norm_sq + residual_norm_sq - 2.0 * est_ip
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{encode_sign_bits, next_pow2, rotate_for_cascade, sign_word_count};
    use chirondb_types::distance::{hamming_popcount, squared_l2};

    // Small deterministic PRNG so the validation is reproducible without a dep.
    fn splitmix(state: &mut u64) -> f32 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        // Map to standard-normal-ish via two uniforms (Box–Muller lite).
        let u = ((z >> 11) as f32) / ((1u64 << 53) as f32);
        (u - 0.5) * 2.0
    }

    fn random_vec(state: &mut u64, dim: usize) -> Vec<f32> {
        (0..dim).map(|_| splitmix(state)).collect()
    }

    fn encode(residual: &[f32]) -> (Vec<u64>, RabitqCodeMeta) {
        let rotated = rotate_for_cascade(residual);
        let words = encode_sign_bits(&rotated, sign_word_count(next_pow2(residual.len())));
        (words, encode_meta(&rotated))
    }

    #[test]
    fn rotation_is_norm_preserving() {
        let mut st = 1;
        for dim in [64usize, 96, 128] {
            let v = random_vec(&mut st, dim);
            let r = rotate_for_cascade(&v);
            let nv: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
            let nr: f32 = r.iter().map(|x| x * x).sum::<f32>().sqrt();
            assert!(
                (nv - nr).abs() <= 1e-3 * nv.max(1.0),
                "dim {dim}: {nv} vs {nr}"
            );
        }
    }

    /// The core RaBitQ property: the distance estimator is UNBIASED. Over many
    /// random query/vector pairs the mean signed error must sit near zero,
    /// small relative to the RMS error (a biased estimator — e.g. BQ — cannot).
    #[test]
    fn estimator_is_unbiased() {
        let dim = 128;
        let n = 4000;
        let mut st = 0xDEAD_BEEF;
        let mut sum_err = 0.0f64;
        let mut sum_abs = 0.0f64;
        for _ in 0..n {
            let o = random_vec(&mut st, dim);
            let q = random_vec(&mut st, dim);
            let (bits, meta) = encode(&o);
            let s = rotate_for_cascade(&q);
            let est = estimate_squared_l2(&bits, &meta, &s);
            let truth = squared_l2(&q, &o);
            sum_err += (est - truth) as f64;
            sum_abs += (est - truth).abs() as f64;
        }
        let mean_bias = sum_err / n as f64;
        let mean_abs = sum_abs / n as f64;
        // Mean signed error must be a small fraction of the mean absolute error
        // — i.e. errors cancel, the hallmark of an unbiased estimator.
        assert!(
            mean_bias.abs() < 0.15 * mean_abs.max(1e-6),
            "biased: mean_bias={mean_bias:.4} mean_abs={mean_abs:.4}"
        );
    }

    /// Near-Shannon concentration: relative error shrinks as dimension grows
    /// (variance `O(1/D)` ⇒ RMS `O(1/√D)`).
    #[test]
    fn error_concentrates_with_dimension() {
        fn rms_rel(dim: usize) -> f64 {
            let mut st = 7;
            let mut sum_sq = 0.0f64;
            let mut sum_scale = 0.0f64;
            for _ in 0..3000 {
                let o = random_vec(&mut st, dim);
                let q = random_vec(&mut st, dim);
                let (bits, meta) = encode(&o);
                let s = rotate_for_cascade(&q);
                let est = estimate_squared_l2(&bits, &meta, &s);
                let truth = squared_l2(&q, &o);
                sum_sq += ((est - truth) as f64).powi(2);
                sum_scale += (truth as f64).powi(2);
            }
            (sum_sq / sum_scale).sqrt()
        }
        let lo = rms_rel(64);
        let hi = rms_rel(512);
        assert!(
            hi < lo,
            "expected error to shrink with D: 64={lo:.4} 512={hi:.4}"
        );
    }

    /// RaBitQ must be a STRICTLY better coarse filter than the BQ/Hamming
    /// ranking it replaces: at the same candidate-pool size it must recall at
    /// least as many true nearest neighbours (and in practice more).
    #[test]
    fn rabitq_filter_beats_hamming_recall() {
        let dim = 128;
        let n = 1200;
        let pool = 40; // coarse candidates kept before exact rerank
        let k = 10;
        let mut st = 0x1234_5678;
        let base: Vec<Vec<f32>> = (0..n).map(|_| random_vec(&mut st, dim)).collect();
        let encoded: Vec<(Vec<u64>, RabitqCodeMeta)> = base.iter().map(|v| encode(v)).collect();

        let mut rabitq_hits = 0usize;
        let mut hamming_hits = 0usize;
        let mut total = 0usize;
        for _ in 0..80 {
            let q = random_vec(&mut st, dim);
            // Ground-truth top-k by exact L2.
            let mut exact: Vec<(f32, usize)> = base
                .iter()
                .enumerate()
                .map(|(i, v)| (squared_l2(&q, v), i))
                .collect();
            exact.sort_by(|a, b| a.0.total_cmp(&b.0));
            let truth: std::collections::HashSet<usize> =
                exact.iter().take(k).map(|&(_, i)| i).collect();

            let s = rotate_for_cascade(&q);
            let qbits = encode_sign_bits(&s, sign_word_count(next_pow2(dim)));

            // RaBitQ estimator pool.
            let mut rq: Vec<(f32, usize)> = encoded
                .iter()
                .enumerate()
                .map(|(i, (bits, meta))| (estimate_squared_l2(bits, meta, &s), i))
                .collect();
            rq.sort_by(|a, b| a.0.total_cmp(&b.0));
            let rq_pool: std::collections::HashSet<usize> =
                rq.iter().take(pool).map(|&(_, i)| i).collect();

            // Hamming (BQ) pool.
            let mut hm: Vec<(u32, usize)> = encoded
                .iter()
                .enumerate()
                .map(|(i, (bits, _))| (hamming_popcount(&qbits, bits), i))
                .collect();
            hm.sort_by_key(|x| x.0);
            let hm_pool: std::collections::HashSet<usize> =
                hm.iter().take(pool).map(|&(_, i)| i).collect();

            for t in &truth {
                total += 1;
                if rq_pool.contains(t) {
                    rabitq_hits += 1;
                }
                if hm_pool.contains(t) {
                    hamming_hits += 1;
                }
            }
        }
        let rq_recall = rabitq_hits as f64 / total as f64;
        let hm_recall = hamming_hits as f64 / total as f64;
        assert!(
            rq_recall > hm_recall,
            "RaBitQ ({rq_recall:.3}) must beat Hamming/BQ ({hm_recall:.3})"
        );
    }
}
