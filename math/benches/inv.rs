// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{criterion_group, criterion_main, Criterion};
use rand_utils::rand_value;
use winter_math::{
    fields::f64::BaseElement as BaseElement64,
    FieldElement,
};

// SEQUENTIAL OPS
// ================================================================================================
pub fn field_ops(c: &mut Criterion, field_name: &str) {
    let mut group = c.benchmark_group(format!("op/{}", field_name));

    group.bench_function("inv64", |bench| {
        let x: BaseElement64 = rand_value();
        bench.iter(|| BaseElement64::inv(x))
    });

    group.bench_function("inv64_gcd", |bench| {
        let mut x: BaseElement64 = rand_value();
        bench.iter(|| x.inv_gcd())
    });


}

// GENERIC BENCHMARK RUNNER
// ================================================================================================

fn bench_field_ops(c: &mut Criterion) {
    field_ops(c, "inversion");
}

// CRITERION BOILERPLATE
// ================================================================================================

criterion_group!(field_group, bench_field_ops);
criterion_main!(field_group);