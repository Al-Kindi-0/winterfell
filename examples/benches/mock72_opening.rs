// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::{
    sync::OnceLock,
    time::{Duration, Instant},
};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use examples::mock72::Mock72Prover;
mod bench_config;
use bench_config::{env_usize, trace_sizes};
use tracing::{Id, Subscriber};
use tracing_subscriber::{
    layer::{Context, SubscriberExt},
    registry::LookupSpan,
    EnvFilter, Layer,
};
use winterfell::{
    crypto::hashers::Poseidon2, BatchingMethod, FieldExtension, ProofOptions, Prover,
};

// Captures the duration of the `opening` span emitted by the prover.
#[derive(Clone, Default)]
struct OpeningTimer {
    nanos: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl OpeningTimer {
    fn take(&self) -> Duration {
        let ns = self.nanos.swap(0, std::sync::atomic::Ordering::SeqCst);
        Duration::from_nanos(ns)
    }
}

impl<S> Layer<S> for OpeningTimer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, _attrs: &tracing::span::Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            if span.metadata().name() == "opening" {
                span.extensions_mut().insert(Instant::now());
            }
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(&id) {
            if span.metadata().name() == "opening" {
                if let Some(start) = span.extensions().get::<Instant>() {
                    let elapsed = start.elapsed();
                    self.nanos
                        .store(elapsed.as_nanos() as u64, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }
    }
}

fn init_tracing(timer: OpeningTimer) {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let registry = tracing_subscriber::registry::Registry::default().with(filter).with(timer);
        tracing::subscriber::set_global_default(registry).expect("failed to init tracing");
    });
}

fn mock72_opening(c: &mut Criterion) {
    let mut group = c.benchmark_group("mock72_poseidon2_opening");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    let options = ProofOptions::new(
        env_usize("WINTERFELL_QUERIES", 32),
        env_usize("WINTERFELL_BLOWUP", 8),
        env_usize("WINTERFELL_GRINDING", 16) as u32,
        FieldExtension::Quadratic,
        env_usize("WINTERFELL_FOLDING", 8),
        env_usize("WINTERFELL_FRI_REMAINDER_DEGREE", 31),
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );

    let prover = Mock72Prover::<Poseidon2>::new(options);

    let timer = OpeningTimer::default();
    init_tracing(timer.clone());

    let trace_sizes = trace_sizes();
    for &trace_length in trace_sizes.iter() {
        group.bench_function(BenchmarkId::from_parameter(trace_length), |bench| {
            bench.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let trace = prover.build_trace(trace_length);
                    let _proof = prover.prove(trace).unwrap();
                    total += timer.take();
                }
                total
            });
        });
    }

    group.finish();
}

criterion_group!(mock72_opening_group, mock72_opening);
criterion_main!(mock72_opening_group);
