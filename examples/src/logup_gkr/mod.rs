// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::marker::PhantomData;

use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher, MerkleTree},
    math::fields::f64::BaseElement,
    Proof, ProofOptions, Prover, VerifierError,
};

use crate::{Example, ExampleOptions, HashFunction};

mod air;
use air::LogUpGkrAir;

mod prover;
use prover::LogUpGkrProver;

#[cfg(test)]
mod tests;

// CONSTANTS AND TYPES
// ================================================================================================

type Blake3_192 = winterfell::crypto::hashers::Blake3_192<BaseElement>;
type Blake3_256 = winterfell::crypto::hashers::Blake3_256<BaseElement>;
type Sha3_256 = winterfell::crypto::hashers::Sha3_256<BaseElement>;
type Rp64_256 = winterfell::crypto::hashers::Rp64_256;
type RpJive64_256 = winterfell::crypto::hashers::RpJive64_256;

// EXAMPLE
// ================================================================================================

pub fn get_example(
    options: &ExampleOptions,
    trace_length: usize,
    num_witness_columns: usize,
) -> Result<Box<dyn Example>, String> {
    let (options, hash_fn) = options.to_proof_options(28, 2);

    match hash_fn {
        HashFunction::Blake3_192 => Ok(Box::new(LogUpGkr::<Blake3_192>::new(
            trace_length,
            num_witness_columns,
            options,
        ))),
        HashFunction::Blake3_256 => Ok(Box::new(LogUpGkr::<Blake3_256>::new(
            trace_length,
            num_witness_columns,
            options,
        ))),
        HashFunction::Sha3_256 => {
            Ok(Box::new(LogUpGkr::<Sha3_256>::new(trace_length, num_witness_columns, options)))
        },
        HashFunction::Rp64_256 => {
            Ok(Box::new(LogUpGkr::<Rp64_256>::new(trace_length, num_witness_columns, options)))
        },
        HashFunction::RpJive64_256 => Ok(Box::new(LogUpGkr::<RpJive64_256>::new(
            trace_length,
            num_witness_columns,
            options,
        ))),
    }
}

#[derive(Clone, Debug)]
struct LogUpGkr<H: ElementHasher<BaseField = BaseElement>> {
    trace_len: usize,
    num_witness_columns: usize,
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher<BaseField = BaseElement>> LogUpGkr<H> {
    fn new(trace_len: usize, num_witness_columns: usize, options: ProofOptions) -> Self {
        assert!(trace_len < u32::MAX.try_into().unwrap());
        assert!(num_witness_columns % 2 == 1, "number of witness columns should be odd");

        Self {
            trace_len,
            num_witness_columns,
            options,
            _hasher: PhantomData,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl<H> Example for LogUpGkr<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync + Send,
{
    fn prove(&self) -> Proof {
        // create a prover
        let prover = LogUpGkrProver::<H>::new(self.options.clone());

        let trace = prover.build_trace(self.trace_len, self.num_witness_columns);

        // generate the proof
        prover.prove(trace).unwrap()
    }

    fn verify(&self, proof: Proof) -> Result<(), VerifierError> {
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);

        winterfell::verify::<LogUpGkrAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            (),
            &acceptable_options,
        )
    }

    fn verify_with_wrong_inputs(&self, proof: Proof) -> Result<(), VerifierError> {
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        winterfell::verify::<LogUpGkrAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            (),
            &acceptable_options,
        )
    }
}
