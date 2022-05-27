// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
//use math::fields::f128;
use rand_utils::{rand_value, rand_array, rand_vector};
/*
use winter_crypto::{
    hashers::{Sha3_256, Blake3_256, Rp62_248}
};
*/
use winter_crypto::{
    hashers::{Rp64_256, Rp_64_1, Rp_64_2, Rp_64_3, Rp_64_4, Rp_64_5},
    Hasher,
    
    
};
use math::{batch_inversion, batch_inversion_mut, FieldElement,};
/*
type Blake3 = Blake3_256<f128::BaseElement>;
type Blake3Digest = <Blake3 as Hasher>::Digest;

type Sha3 = Sha3_256<f128::BaseElement>;
type Sha3Digest = <Sha3 as Hasher>::Digest;

type Rp62_248Digest = <Rp62_248 as Hasher>::Digest;
*/

type Rp64_256Digest = <Rp64_256 as Hasher>::Digest;
type Rp64_256Digest1 = <Rp_64_1 as Hasher>::Digest;
type Rp64_256Digest2 = <Rp_64_2 as Hasher>::Digest;
type Rp64_256Digest3 = <Rp_64_3 as Hasher>::Digest;
type Rp64_256Digest4 = <Rp_64_4 as Hasher>::Digest;
type Rp64_256Digest5 = <Rp_64_5 as Hasher>::Digest;
/*
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

fn rescue248(c: &mut Criterion) {
    let v: [Rp62_248Digest; 2] = [Rp62_248::hash(&[1u8]), Rp62_248::hash(&[2u8])];
    c.bench_function("hash_rp62_248 (cached)", |bench| {
        bench.iter(|| Rp62_248::merge(black_box(&v)))
    });

    c.bench_function("hash_rp62_248 (random)", |b| {
        b.iter_batched(
            || {
                [
                    Rp62_248::hash(&rand_value::<u64>().to_le_bytes()),
                    Rp62_248::hash(&rand_value::<u64>().to_le_bytes()),
                ]
            },
            |state| Rp62_248::merge(&state),
            BatchSize::SmallInput,
        )
    });
}
*/
fn rescue256(c: &mut Criterion) {
    let v: [Rp64_256Digest; 2] = [Rp64_256::hash(&[1u8]), Rp64_256::hash(&[2u8])];
    c.bench_function(
        "hash_rp64_256 (FB) (FB) (FB) (FB) (FB) (FB) (FB) (cached)",
        |bench| bench.iter(|| Rp64_256::merge(black_box(&v))),
    );

    c.bench_function(
        "hash_rp64_256 (FB) (FB) (FB) (FB) (FB) (FB) (FB) (random)",
        |b| {
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
        },
    );
}

fn rescue256_1(c: &mut Criterion) {
    let v: [Rp64_256Digest1; 2] = [Rp_64_1::hash(&[1u8]), Rp_64_1::hash(&[2u8])];
    c.bench_function(
        "hash_rp64_1 (F) (FB) (F) (FB) (F) (FB) (F) (cached)",
        |bench| bench.iter(|| Rp_64_1::merge(black_box(&v))),
    );

    c.bench_function("hash_rp64_1 (F) (FB) (F) (FB) (F) (FB) (F) (random)", |b| {
        b.iter_batched(
            || {
                [
                    Rp_64_1::hash(&rand_value::<u64>().to_le_bytes()),
                    Rp_64_1::hash(&rand_value::<u64>().to_le_bytes()),
                ]
            },
            |state| Rp_64_1::merge(&state),
            BatchSize::SmallInput,
        )
    });
}
fn rescue256_2(c: &mut Criterion) {
    let v: [Rp64_256Digest2; 2] = [Rp_64_2::hash(&[1u8]), Rp_64_2::hash(&[2u8])];
    c.bench_function("hash_rp64_2 (F) (I) (F) (I) (F) (I) (F)(cached)", |bench| {
        bench.iter(|| Rp_64_2::merge(black_box(&v)))
    });

    c.bench_function("hash_rp64_2 (F) (I) (F) (I) (F) (I) (F)(random)", |b| {
        b.iter_batched(
            || {
                [
                    Rp_64_2::hash(&rand_value::<u64>().to_le_bytes()),
                    Rp_64_2::hash(&rand_value::<u64>().to_le_bytes()),
                ]
            },
            |state| Rp_64_2::merge(&state),
            BatchSize::SmallInput,
        )
    });
}
fn rescue256_3(c: &mut Criterion) {
    let v: [Rp64_256Digest3; 2] = [Rp_64_3::hash(&[1u8]), Rp_64_3::hash(&[2u8])];
    c.bench_function(
        "hash_rp64_3 (F) (I) (F) (I) (F) (I) (F) (I) (F) (I) (F) (I) (F) (I) (F)(cached)",
        |bench| bench.iter(|| Rp_64_3::merge(black_box(&v))),
    );

    c.bench_function(
        "hash_rp64_3 (F) (I) (F) (I) (F) (I) (F) (I) (F) (I) (F) (I) (F) (I) (F)(random)",
        |b| {
            b.iter_batched(
                || {
                    [
                        Rp_64_3::hash(&rand_value::<u64>().to_le_bytes()),
                        Rp_64_3::hash(&rand_value::<u64>().to_le_bytes()),
                    ]
                },
                |state| Rp_64_3::merge(&state),
                BatchSize::SmallInput,
            )
        },
    );
}

fn rescue256_4(c: &mut Criterion) {
    let v: [Rp64_256Digest4; 2] = [Rp_64_4::hash(&[1u8]), Rp_64_4::hash(&[2u8])];
    c.bench_function(
        "hash_rp64_4 (F) (F) (F) (FB') (F) (F) (F)(cached)",
        |bench| bench.iter(|| Rp_64_4::merge(black_box(&v))),
    );

    c.bench_function("hash_rp64_4 (F) (F) (F) (FB') (F) (F) (F)(random)", |b| {
        b.iter_batched(
            || {
                [
                    Rp_64_4::hash(&rand_value::<u64>().to_le_bytes()),
                    Rp_64_4::hash(&rand_value::<u64>().to_le_bytes()),
                ]
            },
            |state| Rp_64_4::merge(&state),
            BatchSize::SmallInput,
        )
    });
}

fn rescue256_5(c: &mut Criterion) {
    let v: [Rp64_256Digest5; 2] = [Rp_64_5::hash(&[1u8]), Rp_64_5::hash(&[2u8])];
    c.bench_function(
        "hash_rp64_5 (F) (F) (FB') (FB') (FB') (F) (F) (cached)",
        |bench| bench.iter(|| Rp_64_5::merge(black_box(&v))),
    );

    c.bench_function(
        "hash_rp64_5 (F) (F) (FB') (FB') (FB') (F) (F)(random)",
        |b| {
            b.iter_batched(
                || {
                    [
                        Rp_64_5::hash(&rand_value::<u64>().to_le_bytes()),
                        Rp_64_5::hash(&rand_value::<u64>().to_le_bytes()),
                    ]
                },
                |state| Rp_64_5::merge(&state),
                BatchSize::SmallInput,
            )
        },
    );
}

fn rescue256_permutation(c: &mut Criterion) {
    use math::{fields::f64::BaseElement};
    use rayon::prelude::*;
    pub const BATCH_SIZE: usize = 1 << 5;


    let mut v = [
        BaseElement::new(4568812 as u64),
        BaseElement::new(4542812 as u64),
        BaseElement::new(4568412 as u64),
        BaseElement::new(4756812 as u64),
        BaseElement::new(4567812 as u64),
        BaseElement::new(4568312 as u64),
        BaseElement::new(4568132 as u64),
        BaseElement::new(4563812 as u64),
        BaseElement::new(4506812 as u64),
        BaseElement::new(4568012 as u64),
        BaseElement::new(4516812 as u64),
        BaseElement::new(4526812 as u64),
    ];
    let mut a1: Vec<[BaseElement;12]> = vec![];
    for _ in 0..10000{
        let s: [BaseElement;12] = rand_array();
        a1.push(s);
    }
    c.bench_function("hash_rp64 (FB) (FB) (FB) (FB) (FB) (FB) (FB) Permutation: Naive MDS (Original) mul", |bench| {

        bench.iter(|| {
            a1.par_iter_mut()
                .for_each(|a| {Rp64_256::apply_permutation(black_box( a));})
        })
    });
    c.bench_function("hash_rp64 (FB) (FB) (FB) (FB) (FB) (FB) (FB) Permutation: FFT MDS (Original) mul", |bench| {
        bench.iter(|| {
            a1.par_iter_mut()
                .for_each(|a| {Rp64_256::apply_permutation_freq_original(black_box( a));})
        })
    });
    c.bench_function("hash_rp64 (FB) (FB) (FB) (FB) (FB) (FB) (FB) Permutation: FFT MDS (New) mul", |bench| {
        bench.iter(|| {
            a1.par_iter_mut()
                .for_each(|a| {Rp64_256::apply_permutation_freq(black_box( a));})
        })
    });
    c.bench_function("hash_rp64 (FB) (FB) (FB) (FB) (FB) (FB) (FB) Permutation: FFT MDS (New) inlined", |bench| {
        bench.iter(|| {
            a1.par_iter_mut()
                .for_each(|a| {Rp64_256::apply_permutation_freq_light(black_box( a));})
        })
    });
    c.bench_function("hash_rp64 (FB) (FB) (FB) (FB) (FB) (FB) (FB) Permutation: FFT MDS (New) inlined + SIMD", |bench| {
        bench.iter(|| {
            a1.par_iter_mut()
                .for_each(|a| {Rp64_256::apply_permutation_freq_light_simd(black_box( a));})
        })
    });
}

fn rescue256_1_permutation(c: &mut Criterion) {
    use math::{fields::f64::BaseElement};
    use rayon::prelude::*;
    pub const BATCH_SIZE: usize = 1 << 5;


    let mut v = [
        BaseElement::new(4568812 as u64),
        BaseElement::new(4542812 as u64),
        BaseElement::new(4568412 as u64),
        BaseElement::new(4756812 as u64),
        BaseElement::new(4567812 as u64),
        BaseElement::new(4568312 as u64),
        BaseElement::new(4568132 as u64),
        BaseElement::new(4563812 as u64),
        BaseElement::new(4506812 as u64),
        BaseElement::new(4568012 as u64),
        BaseElement::new(4516812 as u64),
        BaseElement::new(4526812 as u64),
    ];
    c.bench_function("hash_rp64_1 (F) (FB) (F) (FB) (F) (FB) (F) Permutation: Naive MDS mul", |bench| {
        bench.iter(|| {Rp_64_1::apply_permutation(black_box(&mut v))
        })
    });
    c.bench_function("hash_rp64_1 (F) (FB) (F) (FB) (F) (FB) (F) Permutation: FFT MDS mul", |bench| {
        bench.iter(|| Rp_64_1::apply_permutation_freq(black_box(&mut v)))
    });
}

fn rescue256_2_permutation(c: &mut Criterion) {
    use math::{fields::f64::BaseElement};
    use rayon::prelude::*;


    let mut v = [
        BaseElement::new(4568812 as u64),
        BaseElement::new(4542812 as u64),
        BaseElement::new(4568412 as u64),
        BaseElement::new(4756812 as u64),
        BaseElement::new(4567812 as u64),
        BaseElement::new(4568312 as u64),
        BaseElement::new(4568132 as u64),
        BaseElement::new(4563812 as u64),
        BaseElement::new(4506812 as u64),
        BaseElement::new(4568012 as u64),
        BaseElement::new(4516812 as u64),
        BaseElement::new(4526812 as u64),
    ];
    c.bench_function("hash_rp64_2 (F) (I) (F) (I) (F) (I) (F) Permutation: Naive MDS mul", |bench| {
        bench.iter(|| {Rp_64_2::apply_permutation(black_box(&mut v))
        })
    });
    c.bench_function("hash_rp64_2 (F) (I) (F) (I) (F) (I) (F) Permutation: FFT MDS mul", |bench| {
        bench.iter(|| Rp_64_2::apply_permutation_freq(black_box(&mut v)))
    });
}

fn rescue256_3_permutation(c: &mut Criterion) {
    use math::{fields::f64::BaseElement};
    use rayon::prelude::*;
    pub const BATCH_SIZE: usize = 1 << 5;


    let mut v = [[
        BaseElement::new(4568812 as u64),
        BaseElement::new(4542812 as u64),
        BaseElement::new(4568412 as u64),
        BaseElement::new(4756812 as u64),
        BaseElement::new(4567812 as u64),
        BaseElement::new(4568312 as u64),
        BaseElement::new(4568132 as u64),
        BaseElement::new(4563812 as u64),
        BaseElement::new(4506812 as u64),
        BaseElement::new(4568012 as u64),
        BaseElement::new(4516812 as u64),
        BaseElement::new(4526812 as u64),
    ]; BATCH_SIZE];
    c.bench_function("hash_rp64_3 Permutation serial", |bench| {
        bench.iter(|| {
            v.iter_mut()
                .for_each(|state| Rp_64_3::apply_permutation(black_box(state)))
        })
    });
    c.bench_function("hash_rp64_3 Permutation Batch inversion", |bench| {
        bench.iter(|| Rp_64_3::apply_permutation_batch(black_box(&mut v)))
    });
    c.bench_function("hash_rp64_3 Permutation Batch inversion (+ FFT-based multiplication)", |bench| {
        bench.iter(|| Rp_64_3::apply_permutation_batch_freq(black_box(&mut v)))
    });
}


fn rescue256_4_permutation(c: &mut Criterion) {
    use math::{fields::f64::BaseElement};
    use rayon::prelude::*;


    let mut v = [
        BaseElement::new(4568812 as u64),
        BaseElement::new(4542812 as u64),
        BaseElement::new(4568412 as u64),
        BaseElement::new(4756812 as u64),
        BaseElement::new(4567812 as u64),
        BaseElement::new(4568312 as u64),
        BaseElement::new(4568132 as u64),
        BaseElement::new(4563812 as u64),
        BaseElement::new(4506812 as u64),
        BaseElement::new(4568012 as u64),
        BaseElement::new(4516812 as u64),
        BaseElement::new(4526812 as u64),
    ];
    c.bench_function("hash_rp64_4 (F) (F) (F) (FB') (F) (F) (F) Permutation: Naive MDS mul", |bench| {
        bench.iter(|| {Rp_64_4::apply_permutation(black_box(&mut v))
        })
    });
    c.bench_function("hash_rp64_4 (F) (F) (F) (FB') (F) (F) (F) Permutation: FFT MDS mul", |bench| {
        bench.iter(|| Rp_64_4::apply_permutation_freq(black_box(&mut v)))
    });
}
fn rescue256_5_permutation(c: &mut Criterion) {
    use math::{fields::f64::BaseElement};
    use rayon::prelude::*;


    let mut v = [
        BaseElement::new(4568812 as u64),
        BaseElement::new(4542812 as u64),
        BaseElement::new(4568412 as u64),
        BaseElement::new(4756812 as u64),
        BaseElement::new(4567812 as u64),
        BaseElement::new(4568312 as u64),
        BaseElement::new(4568132 as u64),
        BaseElement::new(4563812 as u64),
        BaseElement::new(4506812 as u64),
        BaseElement::new(4568012 as u64),
        BaseElement::new(4516812 as u64),
        BaseElement::new(4526812 as u64),
    ];
    c.bench_function("hash_rp64_5 (F) (F) (FB') (FB') (FB') (F) (F) Permutation: Naive MDS mul", |bench| {
        bench.iter(|| {Rp_64_5::apply_permutation(black_box(&mut v))
        })
    });
    c.bench_function("hash_rp64_5 (F) (F) (FB') (FB') (FB') (F) (F) Permutation: FFT MDS mul", |bench| {
        bench.iter(|| Rp_64_5::apply_permutation_freq(black_box(&mut v)))
    });
}


//criterion_group!(hash_group, blake3, sha3, rescue248, rescue256);
criterion_group!(
    hash_group,
    rescue256_permutation,
    rescue256_1_permutation,
    rescue256_2_permutation,
    rescue256_3_permutation,
    rescue256_4_permutation,
    rescue256_5_permutation,
    rescue256,
    rescue256_1,
    rescue256_2,
    rescue256_3,
    rescue256_4,
    rescue256_5
);
criterion_main!(hash_group);
