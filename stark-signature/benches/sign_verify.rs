// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use math::fields::f64::BaseElement;
use stark_signature::SecretKey;

fn sign(c: &mut Criterion) {
    c.bench_function("Signing", |b| {
        b.iter_batched(
            || {
                let sk = SecretKey::default();
                sk
            },
            |sk| sk.sign([BaseElement::new(0); 4]),
            BatchSize::SmallInput,
        )
    });
}

fn verify(c: &mut Criterion) {
    c.bench_function("Verifying", |b| {
        b.iter_batched(
            || {
                let sk = SecretKey::default();
                (sk.compute_public_key(), sk.sign([BaseElement::new(0); 4]))
                
            },
            |(pk, signature)| pk.verify([BaseElement::new(0); 4], &signature),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(group, sign, verify);
criterion_main!(group);
