// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use math::fields::f128::BaseElement;
use rand_utils::rand_value;
use utils::uninit_vector;
use winter_crypto::{
    build_merkle_nodes,
    concurrent,
    hashers::Blake3_256,
    hashers::{Rp64_256, Rp_64_1, Rp_64_2, Rp_64_3, Rp_64_4, Rp_64_5},
    Hasher,
};

type Blake3 = Blake3_256<BaseElement>;
type Blake3Digest = <Blake3 as Hasher>::Digest;

type Rp64_256Digest = <Rp64_256 as Hasher>::Digest;
type Rp64_256Digest1 = <Rp_64_1 as Hasher>::Digest;
type Rp64_256Digest2 = <Rp_64_2 as Hasher>::Digest;
type Rp64_256Digest3 = <Rp_64_3 as Hasher>::Digest;
type Rp64_256Digest4 = <Rp_64_4 as Hasher>::Digest;
type Rp64_256Digest5 = <Rp_64_5 as Hasher>::Digest;

pub fn merkle_tree_construction(c: &mut Criterion) {
    let mut merkle_group = c.benchmark_group("merkle tree construction");

    static BATCH_SIZES: [usize; 3] = [65536, 131072, 262144];

    for size in &BATCH_SIZES {
        let data: Vec<Blake3Digest> = {
            let mut res = unsafe { uninit_vector(*size) };
            for i in 0..*size {
                res[i] = Blake3::hash(&rand_value::<u128>().to_le_bytes());
            }
            res
        };
        merkle_group.bench_with_input(BenchmarkId::new("sequential", size), &data, |b, i| {
            b.iter(|| build_merkle_nodes::<Blake3>(&i))
        });
        merkle_group.bench_with_input(BenchmarkId::new("concurrent", size), &data, |b, i| {
            b.iter(|| concurrent::build_merkle_nodes::<Blake3>(&i))
        });
    }
}

pub fn merkle_tree_construction0(c: &mut Criterion) {
    let mut merkle_group = c.benchmark_group(
        "merkle tree construction hash_rp64_256 (FB) (FB) (FB) (FB) (FB) (FB) (FB)",
    );

    static BATCH_SIZES: [usize; 3] = [65536, 131072, 262144];

    for size in &BATCH_SIZES {
        let data: Vec<Rp64_256Digest> = {
            let mut res = unsafe { uninit_vector(*size) };
            for i in 0..*size {
                res[i] = Rp64_256::hash(&rand_value::<u64>().to_le_bytes());
            }
            res
        };
        merkle_group.bench_with_input(BenchmarkId::new("sequential", size), &data, |b, i| {
            b.iter(|| build_merkle_nodes::<Rp64_256>(&i))
        });
        merkle_group.bench_with_input(BenchmarkId::new("concurrent", size), &data, |b, i| {
            b.iter(|| concurrent::build_merkle_nodes::<Rp64_256>(&i))
        });
    }
}

pub fn merkle_tree_construction1(c: &mut Criterion) {
    let mut merkle_group =
        c.benchmark_group("merkle tree construction hash_rp64_256 (F) (FB) (F) (FB) (F) (FB) (F)");

    static BATCH_SIZES: [usize; 3] = [65536, 131072, 262144];

    for size in &BATCH_SIZES {
        let data: Vec<Rp64_256Digest1> = {
            let mut res = unsafe { uninit_vector(*size) };
            for i in 0..*size {
                res[i] = Rp_64_1::hash(&rand_value::<u64>().to_le_bytes());
            }
            res
        };
        merkle_group.bench_with_input(BenchmarkId::new("sequential", size), &data, |b, i| {
            b.iter(|| build_merkle_nodes::<Rp_64_1>(&i))
        });
        merkle_group.bench_with_input(BenchmarkId::new("concurrent", size), &data, |b, i| {
            b.iter(|| concurrent::build_merkle_nodes::<Rp_64_1>(&i))
        });
    }
}

pub fn merkle_tree_construction2(c: &mut Criterion) {
    let mut merkle_group =
        c.benchmark_group("merkle tree construction hash_rp64_1 (F) (I) (F) (I) (F) (I) (F)");

    static BATCH_SIZES: [usize; 3] = [65536, 131072, 262144];

    for size in &BATCH_SIZES {
        let data: Vec<Rp64_256Digest2> = {
            let mut res = unsafe { uninit_vector(*size) };
            for i in 0..*size {
                res[i] = Rp_64_2::hash(&rand_value::<u64>().to_le_bytes());
            }
            res
        };
        merkle_group.bench_with_input(BenchmarkId::new("sequential", size), &data, |b, i| {
            b.iter(|| build_merkle_nodes::<Rp_64_2>(&i))
        });
        merkle_group.bench_with_input(BenchmarkId::new("concurrent", size), &data, |b, i| {
            b.iter(|| concurrent::build_merkle_nodes::<Rp_64_2>(&i))
        });
    }
}
pub fn merkle_tree_construction3(c: &mut Criterion) {
    let mut merkle_group = c.benchmark_group("merkle tree construction hash_rp64_2 (F) (I) (F) (I) (F) (I) (F) (I) (F) (I) (F) (I) (F) (I) (F)");

    static BATCH_SIZES: [usize; 3] = [65536, 131072, 262144];

    for size in &BATCH_SIZES {
        let data: Vec<Rp64_256Digest3> = {
            let mut res = unsafe { uninit_vector(*size) };
            for i in 0..*size {
                res[i] = Rp_64_3::hash(&rand_value::<u64>().to_le_bytes());
            }
            res
        };
        merkle_group.bench_with_input(BenchmarkId::new("sequential", size), &data, |b, i| {
            b.iter(|| build_merkle_nodes::<Rp_64_3>(&i))
        });
        merkle_group.bench_with_input(BenchmarkId::new("concurrent", size), &data, |b, i| {
            b.iter(|| concurrent::build_merkle_nodes::<Rp_64_3>(&i))
        });
    }
}
pub fn merkle_tree_construction4(c: &mut Criterion) {
    let mut merkle_group =
        c.benchmark_group("merkle tree construction  hash_rp64_4 (F) (F) (F) (FB') (F) (F) (F)");

    static BATCH_SIZES: [usize; 3] = [65536, 131072, 262144];

    for size in &BATCH_SIZES {
        let data: Vec<Rp64_256Digest4> = {
            let mut res = unsafe { uninit_vector(*size) };
            for i in 0..*size {
                res[i] = Rp_64_4::hash(&rand_value::<u64>().to_le_bytes());
            }
            res
        };
        merkle_group.bench_with_input(BenchmarkId::new("sequential", size), &data, |b, i| {
            b.iter(|| build_merkle_nodes::<Rp_64_4>(&i))
        });
        merkle_group.bench_with_input(BenchmarkId::new("concurrent", size), &data, |b, i| {
            b.iter(|| concurrent::build_merkle_nodes::<Rp_64_4>(&i))
        });
    }
}
pub fn merkle_tree_construction5(c: &mut Criterion) {
    let mut merkle_group =
        c.benchmark_group("merkle tree construction hash_rp64_5 (F) (F) (FB') (FB') (FB') (F) (F)");

    static BATCH_SIZES: [usize; 3] = [65536, 131072, 262144];

    for size in &BATCH_SIZES {
        let data: Vec<Rp64_256Digest5> = {
            let mut res = unsafe { uninit_vector(*size) };
            for i in 0..*size {
                res[i] = Rp_64_5::hash(&rand_value::<u64>().to_le_bytes());
            }
            res
        };
        merkle_group.bench_with_input(BenchmarkId::new("sequential", size), &data, |b, i| {
            b.iter(|| build_merkle_nodes::<Rp_64_5>(&i))
        });
        merkle_group.bench_with_input(BenchmarkId::new("concurrent", size), &data, |b, i| {
            b.iter(|| concurrent::build_merkle_nodes::<Rp_64_5>(&i))
        });
    }
}
criterion_group!(
    merkle_group,
    merkle_tree_construction,
    merkle_tree_construction0,
    merkle_tree_construction1,
    merkle_tree_construction2,
    merkle_tree_construction3,
    merkle_tree_construction4,
    merkle_tree_construction5
);
criterion_main!(merkle_group);
