//! Phase 2 (perf push): distance-kernel equivalence and reference checks.
//!
//! Locks in:
//!   - `squared_l2` matches a naive reference impl over randomized inputs
//!     (catches future SIMD/dispatch refactors that subtly change semantics).
//!   - `hamming_popcount` matches a naive count-bit-XOR reference.
//!
//! Both kernels are SIMD-leaning today (chunked-8 fp32 + `u64::count_ones`).
//! When Phase 4 wires `hamming_popcount` into RaBitQ asymmetric distance, this
//! test is the contract.

use chirondb_types::distance::{DistanceMetric, dot, hamming_popcount, squared_l2};

fn lcg_f32(state: &mut u64) -> f32 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
    let v = ((*state >> 32) as u32) as f32 / u32::MAX as f32;
    v * 2.0 - 1.0
}

fn lcg_u64(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(2862933555777941757)
        .wrapping_add(3037000493);
    *state
}

fn naive_squared_l2(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    let mut acc = 0.0f64;
    for i in 0..n {
        let d = (a[i] - b[i]) as f64;
        acc += d * d;
    }
    acc as f32
}

fn naive_hamming(a: &[u64], b: &[u64]) -> u32 {
    let n = a.len().min(b.len());
    let mut acc: u32 = 0;
    for i in 0..n {
        let x = a[i] ^ b[i];
        for bit in 0..64 {
            if (x >> bit) & 1 == 1 {
                acc += 1;
            }
        }
    }
    acc
}

#[test]
fn squared_l2_matches_naive_reference() {
    // Sweep dims that hit chunk-aligned, tail-only, and large vectors.
    for dim in [1usize, 7, 8, 9, 64, 128, 384, 1024, 1536] {
        let mut state_a: u64 = 0xDEADBEEF ^ (dim as u64);
        let mut state_b: u64 = 0xCAFEBABE ^ (dim as u64);
        let a: Vec<f32> = (0..dim).map(|_| lcg_f32(&mut state_a)).collect();
        let b: Vec<f32> = (0..dim).map(|_| lcg_f32(&mut state_b)).collect();

        let got = squared_l2(&a, &b);
        let ref_val = naive_squared_l2(&a, &b);
        let scale = ref_val.abs().max(1.0);
        let abs_err = (got - ref_val).abs();
        assert!(
            abs_err <= 1e-4 * scale,
            "dim={dim}: got={got} ref={ref_val} abs_err={abs_err}"
        );
    }
}

#[test]
fn squared_l2_zero_when_vectors_equal() {
    let a = vec![1.0f32, -2.0, 0.5, 7.5, -1.25, 3.0, 0.0, 9.9];
    assert_eq!(squared_l2(&a, &a), 0.0);
}

#[test]
fn squared_l2_handles_mismatched_length() {
    let a = vec![1.0, 2.0, 3.0, 4.0, 5.0];
    let b = vec![1.0, 2.0, 3.0];
    // Compares the first 3 elements — both impls take the min length.
    assert_eq!(squared_l2(&a, &b), 0.0);
    assert_eq!(squared_l2(&a, &b), naive_squared_l2(&a, &b));
}

#[test]
fn hamming_popcount_matches_naive_reference() {
    for words in [1usize, 4, 16, 64, 256, 1024] {
        let mut state_a: u64 = 0x517CC1B7 ^ (words as u64);
        let mut state_b: u64 = 0x27220A95 ^ (words as u64);
        let a: Vec<u64> = (0..words).map(|_| lcg_u64(&mut state_a)).collect();
        let b: Vec<u64> = (0..words).map(|_| lcg_u64(&mut state_b)).collect();

        let got = hamming_popcount(&a, &b);
        let ref_val = naive_hamming(&a, &b);
        assert_eq!(got, ref_val, "words={words}: got={got} ref={ref_val}");
    }
}

fn naive_dot(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    let mut acc = 0.0f64;
    for i in 0..n {
        acc += (a[i] as f64) * (b[i] as f64);
    }
    acc as f32
}

#[test]
fn dot_matches_naive_reference() {
    // M3-004: confirms wide::f32x8 dispatch is numerically equivalent to scalar.
    for dim in [1usize, 7, 8, 9, 16, 64, 128, 384, 768, 1024, 1536] {
        let mut state_a: u64 = 0xA5A5A5A5 ^ (dim as u64);
        let mut state_b: u64 = 0x5A5A5A5A ^ (dim as u64);
        let a: Vec<f32> = (0..dim).map(|_| lcg_f32(&mut state_a)).collect();
        let b: Vec<f32> = (0..dim).map(|_| lcg_f32(&mut state_b)).collect();

        let got = dot(&a, &b);
        let ref_val = naive_dot(&a, &b);
        let scale = ref_val.abs().max(1.0);
        let abs_err = (got - ref_val).abs();
        assert!(
            abs_err <= 1e-4 * scale,
            "dim={dim}: got={got} ref={ref_val} abs_err={abs_err}"
        );
    }
}

#[test]
fn distance_metric_cosine_matches_scalar_reference() {
    // Cosine in DistanceMetric uses `dot` three times — confirms the SIMD
    // path composes correctly through the metric facade.
    for dim in [64usize, 256, 768, 1536] {
        let mut state_a: u64 = 0xC05111E0 ^ (dim as u64);
        let mut state_b: u64 = 0xC05111E1 ^ (dim as u64);
        let a: Vec<f32> = (0..dim).map(|_| lcg_f32(&mut state_a)).collect();
        let b: Vec<f32> = (0..dim).map(|_| lcg_f32(&mut state_b)).collect();

        let got = DistanceMetric::Cosine.score(&a, &b).unwrap();
        // Reference: scalar dot divided by L2 norms.
        let n = naive_dot(&a, &b);
        let la = naive_dot(&a, &a).sqrt();
        let lb = naive_dot(&b, &b).sqrt();
        let ref_val = n / (la * lb);
        assert!(
            (got - ref_val).abs() <= 1e-3,
            "dim={dim}: got={got} ref={ref_val}"
        );
    }
}

#[test]
fn hamming_popcount_zero_when_equal_and_all_when_inverse() {
    let v = vec![
        0xFFFF_FFFF_FFFF_FFFFu64,
        0xAAAA_5555_AAAA_5555,
        0x1234_5678_9ABC_DEF0,
    ];
    assert_eq!(hamming_popcount(&v, &v), 0);

    let inv: Vec<u64> = v.iter().map(|x| !x).collect();
    assert_eq!(hamming_popcount(&v, &inv), (v.len() as u32) * 64);
}
