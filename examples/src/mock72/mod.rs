// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::marker::PhantomData;
use std::time::Instant;

use tracing::{field, info_span};
use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement},
    Proof, ProofOptions, Prover, Trace, VerifierError,
};

use crate::{Example, ExampleOptions, HashFunction};

mod air;
use air::Mock72Air;

mod prover;
pub use prover::Mock72Prover;

mod trace_table;

// CONSTANTS AND TYPES
// ================================================================================================

const MAIN_TRACE_WIDTH: usize = 72;
const AUX_TRACE_WIDTH: usize = 8;
const NUM_AUX_RANDS: usize = 1;

type Blake3_192 = winterfell::crypto::hashers::Blake3_192<BaseElement>;
type Blake3_256 = winterfell::crypto::hashers::Blake3_256<BaseElement>;
type Sha3_256 = winterfell::crypto::hashers::Sha3_256<BaseElement>;
type Poseidon2_256 = winterfell::crypto::hashers::Poseidon2;
type Rp64_256 = winterfell::crypto::hashers::Rp64_256;
type RpJive64_256 = winterfell::crypto::hashers::RpJive64_256;

// MOCK 72/8 EXAMPLE
// ================================================================================================

pub fn get_example(
    options: &ExampleOptions,
    trace_length: usize,
) -> Result<Box<dyn Example>, String> {
    let (options, hash_fn) = options.to_proof_options(32, 8);

    match hash_fn {
        HashFunction::Blake3_192 => {
            Ok(Box::new(Mock72Example::<Blake3_192>::new(trace_length, options)))
        },
        HashFunction::Blake3_256 => {
            Ok(Box::new(Mock72Example::<Blake3_256>::new(trace_length, options)))
        },
        HashFunction::Sha3_256 => {
            Ok(Box::new(Mock72Example::<Sha3_256>::new(trace_length, options)))
        },
        HashFunction::Poseidon2_256 => {
            Ok(Box::new(Mock72Example::<Poseidon2_256>::new(trace_length, options)))
        },
        HashFunction::Rp64_256 => {
            Ok(Box::new(Mock72Example::<Rp64_256>::new(trace_length, options)))
        },
        HashFunction::RpJive64_256 => {
            Ok(Box::new(Mock72Example::<RpJive64_256>::new(trace_length, options)))
        },
    }
}

pub struct Mock72Example<H: ElementHasher> {
    options: ProofOptions,
    trace_length: usize,
    result: BaseElement,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> Mock72Example<H> {
    pub fn new(trace_length: usize, options: ProofOptions) -> Self {
        assert!(trace_length >= 8, "trace length must be at least 8");
        assert!(trace_length.is_power_of_two(), "trace length must be a power of 2");

        let now = Instant::now();
        let result = BaseElement::new((trace_length - 1) as u64);
        println!(
            "Prepared mock trace (main: {}, aux: {}) with length {} in {} ms",
            MAIN_TRACE_WIDTH,
            AUX_TRACE_WIDTH,
            trace_length,
            now.elapsed().as_millis()
        );

        Mock72Example {
            options,
            trace_length,
            result,
            _hasher: PhantomData,
        }
    }
}

impl<H: ElementHasher> Example for Mock72Example<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    fn prove(&self) -> Proof {
        println!(
            "Generating proof for mock trace (main: {}, aux: {}) with length {}",
            MAIN_TRACE_WIDTH, AUX_TRACE_WIDTH, self.trace_length
        );

        let prover = Mock72Prover::<H>::new(self.options.clone());

        let trace = info_span!(
            "generate_execution_trace",
            num_cols = MAIN_TRACE_WIDTH,
            steps = field::Empty
        )
        .in_scope(|| {
            let trace = prover.build_trace(self.trace_length);
            tracing::Span::current().record("steps", trace.length());
            trace
        });

        prover.prove(trace).unwrap()
    }

    fn verify(&self, proof: Proof) -> Result<(), VerifierError> {
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);

        winterfell::verify::<Mock72Air, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            self.result,
            &acceptable_options,
        )
    }

    fn verify_with_wrong_inputs(&self, proof: Proof) -> Result<(), VerifierError> {
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);

        winterfell::verify::<Mock72Air, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            self.result + BaseElement::ONE,
            &acceptable_options,
        )
    }
}
