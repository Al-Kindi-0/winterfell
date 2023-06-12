// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

use rand_utils::rand_value;
use winter_crypto::{
    hashers::{Rp64_256, Xhash12, Xhash8},
    Hasher,
};

type Rp64_256Digest = <Rp64_256 as Hasher>::Digest;
type XhashDigest8 = <Xhash8 as Hasher>::Digest;
type XhashDigest12 = <Xhash12 as Hasher>::Digest;

//type Blake3 = Blake3_256<f128::BaseElement>;
//type Blake3Digest = <Blake3 as Hasher>::Digest;

//type Sha3 = Sha3_256<f128::BaseElement>;
//type Sha3Digest = <Sha3 as Hasher>::Digest;
//fn blake3(c: &mut Criterion) {
//let v: [Blake3Digest; 2] = [Blake3::hash(&[1u8]), Blake3::hash(&[2u8])];
//c.bench_function("hash_blake3 (cached)", |bench| {
//bench.iter(|| Blake3::merge(black_box(&v)))
//});

//c.bench_function("hash_blake3 (random)", |b| {
//b.iter_batched(
//|| {
//[
//Blake3::hash(&rand_value::<u64>().to_le_bytes()),
//Blake3::hash(&rand_value::<u64>().to_le_bytes()),
//]
//},
//|state| Blake3::merge(&state),
//BatchSize::SmallInput,
//)
//});
//}

//fn sha3(c: &mut Criterion) {
//let v: [Sha3Digest; 2] = [Sha3::hash(&[1u8]), Sha3::hash(&[2u8])];
//c.bench_function("hash_sha3 (cached)", |bench| {
//bench.iter(|| Sha3::merge(black_box(&v)))
//});

//c.bench_function("hash_sha3 (random)", |b| {
//b.iter_batched(
//|| {
//[
//Sha3::hash(&rand_value::<u64>().to_le_bytes()),
//Sha3::hash(&rand_value::<u64>().to_le_bytes()),
//]
//},
//|state| Sha3::merge(&state),
//BatchSize::SmallInput,
//)
//});
//}

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

fn xhash8(c: &mut Criterion) {
    let v: [XhashDigest8; 2] = [Xhash8::hash(&[1u8]), Xhash8::hash(&[2u8])];
    c.bench_function("hash_xhash8 (cached)", |bench| {
        bench.iter(|| Xhash8::merge(black_box(&v)))
    });

    c.bench_function("hash_xhash8 (random)", |b| {
        b.iter_batched(
            || {
                [
                    Xhash8::hash(&rand_value::<u64>().to_le_bytes()),
                    Xhash8::hash(&rand_value::<u64>().to_le_bytes()),
                ]
            },
            |state| Xhash8::merge(&state),
            BatchSize::SmallInput,
        )
    });
}

fn xhash12(c: &mut Criterion) {
    let v: [XhashDigest12; 2] = [Xhash12::hash(&[1u8]), Xhash12::hash(&[2u8])];
    c.bench_function("hash_xhash12 (cached)", |bench| {
        bench.iter(|| Xhash12::merge(black_box(&v)))
    });

    c.bench_function("hash_xhash12 (random)", |b| {
        b.iter_batched(
            || {
                [
                    Xhash12::hash(&rand_value::<u64>().to_le_bytes()),
                    Xhash12::hash(&rand_value::<u64>().to_le_bytes()),
                ]
            },
            |state| Xhash12::merge(&state),
            BatchSize::SmallInput,
        )
    });
}
criterion_group!(hash_group, rescue256, xhash8, xhash12);
criterion_main!(hash_group);
