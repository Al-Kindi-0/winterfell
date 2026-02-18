// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use examples::mock72::Mock72Prover;
use winterfell::{
    crypto::hashers::Poseidon2, BatchingMethod, FieldExtension, ProofOptions, Prover,
};

const TRACE_SIZES: [usize; 3] = [65_536, 131_072, 262_144];

fn mock72(c: &mut Criterion) {
    let mut group = c.benchmark_group("mock72_poseidon2");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    let options = ProofOptions::new(
        32,
        8,
        16,
        FieldExtension::Quadratic,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );

    let prover = Mock72Prover::<Poseidon2>::new(options);

    for &trace_length in TRACE_SIZES.iter() {
        group.bench_function(BenchmarkId::from_parameter(trace_length), |bench| {
            bench.iter_batched(
                || prover.build_trace(trace_length),
                |trace| {
                    let _proof = prover.prove(trace).unwrap();
                },
                BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

criterion_group!(mock72_group, mock72);
criterion_main!(mock72_group);
