// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use math::fields::f64::BaseElement;
use math::{batch_inversion, batch_inversion_mut, FieldElement};
use rand_utils::rand_value;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

fn plain_in_parallel_inversion(c: &mut Criterion) {
    use rand_utils::rand_vector;

    let a1: Vec<BaseElement> = rand_vector(100);
    let a2: Vec<BaseElement> = rand_vector(1000);
    let a3: Vec<BaseElement> = rand_vector(10000);

    c.bench_function("A 100 plain inversions in parallel",
   |bench| bench.iter(|| {
            a1.par_iter()
                .for_each(|a| {black_box(a.inv());})
   }));

    c.bench_function("A 1000 plain inversions in parallel",
   |bench| bench.iter(|| {
            a2.par_iter()
                .for_each(|a| {black_box(a.inv());})
   }));
    
   c.bench_function("A 10000 plain inversions in parallel",
   |bench| bench.iter(|| {
            a3.par_iter()
                .for_each(|a| {black_box(a.inv());})
   }));


}
fn batch_inversion_out_of_place(c: &mut Criterion) {
    let mut v = [BaseElement::ZERO; 100];
    for i in 0..100 {
        v[i] = BaseElement::new(rand_value::<u64>());
    }
    let mut w = [BaseElement::ZERO; 1000];
    for i in 0..1000 {
        w[i] = BaseElement::new(rand_value::<u64>());
    }
    let mut x = [BaseElement::ZERO; 10000];
    for i in 0..10000 {
        x[i] = BaseElement::new(rand_value::<u64>());
    }

    c.bench_function("Batch inversion out of place for 100 elements", |bench| {
        bench.iter(|| batch_inversion(&v))
    });
    c.bench_function("Batch inversion out of place for 1000 elements", |bench| {
        bench.iter(|| batch_inversion(&w))
    });
    c.bench_function("Batch inversion out of place for 10000 elements", |bench| {
        bench.iter(|| batch_inversion(&x))
    });
}

fn batch_inversion_in_place(c: &mut Criterion) {
    
    let mut v = [BaseElement::ZERO; 100];
    for i in 0..100 {
        v[i] = BaseElement::new(rand_value::<u64>());
    }
    let mut w = [BaseElement::ZERO; 1000];
    for i in 0..1000 {
        w[i] = BaseElement::new(rand_value::<u64>());
    }
    let mut x = [BaseElement::ZERO; 10000];
    for i in 0..10000 {
        x[i] = BaseElement::new(rand_value::<u64>());
    }

    c.bench_function("Batch inversion in place for 100 elements", |bench| {
        bench.iter(|| batch_inversion_mut(&mut v))
    });
    c.bench_function("Batch inversion in place for 1000 elements", |bench| {
        bench.iter(|| batch_inversion_mut(&mut w))
    });
    c.bench_function("Batch inversion in place for 10000 elements", |bench| {
        bench.iter(|| batch_inversion_mut(&mut x))
    });
}

criterion_group!(
    group,
    plain_in_parallel_inversion,
    batch_inversion_out_of_place,
    batch_inversion_in_place,
);
criterion_main!(group);
