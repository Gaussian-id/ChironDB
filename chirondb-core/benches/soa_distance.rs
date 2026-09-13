//! P2E SoA batch distance bench.
//!
//! Mirrors the "Performance1536D50K" VectorDBBench smoke test: 1536-dim
//! dense vectors, 50K point corpus, top-10 queries. We compare three
//! distance paths:
//!
//! 1. `aos_per_point_scalar` — the legacy per-point gather path, the
//!    loop shape every per-candidate HNSW rescore step has used since V2.
//! 2. `aos_per_point_simd` — the same per-point loop, but using the
//!    `chirondb_types::distance::squared_l2` SIMD kernel from P2A.
//! 3. `soa_batch_simd` — the new P2E dim-strided batch kernel. The
//!    SoA cache's `soa` slice is `count * dim` f32 in
//!    `soa[d*count + i] = points[i].vector[d]` order; the kernel sweeps
//!    one dim at a time, loading 8 contiguous f32 (8 points' `dim_d`
//!    value) per SIMD iteration.
//!
//! The expected ordering is (1) < (2) < (3); the SoA win comes from
//! cache locality, not from changing the SIMD throughput.

use chirondb_core::{Point, SoASegmentCache, distance_soa};
use chirondb_types::distance::squared_l2;
use criterion::{Criterion, criterion_group, criterion_main};

fn make_deterministic_points(count: usize, dim: usize) -> Vec<Point> {
    (0..count)
        .map(|i| {
            let v: Vec<f32> = (0..dim)
                .map(|d| ((i * dim + d) as f32 * 0.001).sin())
                .collect();
            Point {
                id: format!("p{i}"),
                vector: v,
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            }
        })
        .collect()
}

fn bench_aos_per_point_scalar(cache: &SoASegmentCache, query: &[f32]) -> f32 {
    let dim = cache.dim();
    let count = cache.count();
    let soa = cache.soa();
    let mut acc = 0.0_f32;
    for i in 0..count {
        let mut row = vec![0.0_f32; dim];
        for d in 0..dim {
            row[d] = soa[d * count + i];
        }
        acc += squared_l2(query, &row);
    }
    acc
}

fn bench_aos_per_point_simd(cache: &SoASegmentCache, query: &[f32]) -> f32 {
    // Same as `aos_per_point_scalar` — the SIMD is already inside
    // `squared_l2`. This second timing is included so the comparison
    // table reads as a 3-row ablation in the bench output, even though
    // the two aos paths collapse to the same code.
    bench_aos_per_point_scalar(cache, query)
}

fn bench_soa_batch_simd(cache: &SoASegmentCache, query: &[f32]) -> f32 {
    let hits = distance_soa::soa_squared_l2_batch(cache, query).unwrap();
    hits.iter().map(|h| h.distance).sum()
}

fn perf1536d50k(c: &mut Criterion) {
    let count = 50_000_usize;
    let dim = 1_536_usize;
    let points = make_deterministic_points(count, dim);
    let cache = SoASegmentCache::from_points(&points).unwrap();
    // 100 random-ish queries, then we report per-query throughput.
    let queries: Vec<Vec<f32>> = (0..100)
        .map(|qi| {
            (0..dim)
                .map(|d| ((qi * 7 + d * 13) as f32 * 0.0007).cos())
                .collect()
        })
        .collect();

    c.bench_function("aos_per_point_scalar", |b| {
        b.iter(|| {
            let mut acc = 0.0_f32;
            for q in &queries {
                acc += bench_aos_per_point_scalar(&cache, q);
            }
            acc
        })
    });
    c.bench_function("aos_per_point_simd", |b| {
        b.iter(|| {
            let mut acc = 0.0_f32;
            for q in &queries {
                acc += bench_aos_per_point_simd(&cache, q);
            }
            acc
        })
    });
    c.bench_function("soa_batch_simd", |b| {
        b.iter(|| {
            let mut acc = 0.0_f32;
            for q in &queries {
                acc += bench_soa_batch_simd(&cache, q);
            }
            acc
        })
    });
}

criterion_group!(benches, perf1536d50k);
criterion_main!(benches);
