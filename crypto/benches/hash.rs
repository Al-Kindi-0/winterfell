// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use math::fields::f128;
use rand_utils::rand_value;
use winter_crypto::{
    hashers::{Blake3_256, Rp64_256, Sha3_256, Xhash},
    Hasher,
};

type Blake3 = Blake3_256<f128::BaseElement>;
type Blake3Digest = <Blake3 as Hasher>::Digest;

type Sha3 = Sha3_256<f128::BaseElement>;
type Sha3Digest = <Sha3 as Hasher>::Digest;

type Rp64_256Digest = <Rp64_256 as Hasher>::Digest;
type XhashDigest = <Xhash as Hasher>::Digest;

fn blake3(c: &mut Criterion) {
    let v: [Blake3Digest; 2] = [Blake3::hash(&[1u8]), Blake3::hash(&[2u8])];
    c.bench_function("hash_blake3 (cached)", |bench| {
        bench.iter(|| Blake3::merge(black_box(&v)))
    });

    c.bench_function("hash_blake3 (random)", |b| {
        b.iter_batched(
            || {
                [
                    Blake3::hash(&rand_value::<u64>().to_le_bytes()),
                    Blake3::hash(&rand_value::<u64>().to_le_bytes()),
                ]
            },
            |state| Blake3::merge(&state),
            BatchSize::SmallInput,
        )
    });
}

fn sha3(c: &mut Criterion) {
    let v: [Sha3Digest; 2] = [Sha3::hash(&[1u8]), Sha3::hash(&[2u8])];
    c.bench_function("hash_sha3 (cached)", |bench| {
        bench.iter(|| Sha3::merge(black_box(&v)))
    });

    c.bench_function("hash_sha3 (random)", |b| {
        b.iter_batched(
            || {
                [
                    Sha3::hash(&rand_value::<u64>().to_le_bytes()),
                    Sha3::hash(&rand_value::<u64>().to_le_bytes()),
                ]
            },
            |state| Sha3::merge(&state),
            BatchSize::SmallInput,
        )
    });
}

fn rescue256(c: &mut Criterion) {
    let v: [Rp64_256Digest; 2] = [Rp64_256::hash(&[1u8]), Rp64_256::hash(&[2u8])];
    c.bench_function("hash_rp64_256 (cached)", |bench| {
        bench.iter(|| Rp64_256::merge(black_box(&v)))
    });

    c.bench_function("hash_rp64_256 (random)", |b| {
        b.iter_batched(
            || {
                [
                    Rp64_256::hash(&rand_value::<u64>().to_le_bytes()),
                    Rp64_256::hash(&rand_value::<u64>().to_le_bytes()),
                ]
            },
            |state| Rp64_256::merge(&state),
            BatchSize::SmallInput,
        )
    });
}

fn xhash(c: &mut Criterion) {
    let v: [XhashDigest; 2] = [Xhash::hash(&[1u8]), Xhash::hash(&[2u8])];
    c.bench_function("hash_xhash (cached)", |bench| {
        bench.iter(|| Xhash::merge(black_box(&v)))
    });

    c.bench_function("hash_xhash (random)", |b| {
        b.iter_batched(
            || {
                [
                    Xhash::hash(&rand_value::<u64>().to_le_bytes()),
                    Xhash::hash(&rand_value::<u64>().to_le_bytes()),
                ]
            },
            |state| Xhash::merge(&state),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(hash_group, rescue256, xhash, blake3, sha3);
criterion_main!(hash_group);
