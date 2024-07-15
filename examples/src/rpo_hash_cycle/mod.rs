// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::marker::PhantomData;
use std::time::Instant;

use tracing::{field, info_span};
use winterfell::{
    crypto::{hashers::Rp64_256, DefaultRandomCoin, ElementHasher, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement},
    Proof, ProofOptions, Prover, Trace, VerifierError,
};

use crate::{Blake3_192, Blake3_256, Example, ExampleOptions, HashFunction, Rpo256, Sha3_256};

mod air;
use air::{PublicInputs, RescueAir, DIGEST_RANGE, NUM_ROUNDS, STATE_WIDTH, TRACE_WIDTH};

mod prover;
use prover::RpoProver;

#[cfg(test)]
mod tests;


// RESCUE HASH CHAIN EXAMPLE
// ================================================================================================

pub fn get_example(
    options: &ExampleOptions,
    chain_length: usize,
) -> Result<Box<dyn Example>, String> {
    let (options, hash_fn) = options.to_proof_options(80, 8);

    match hash_fn {
        HashFunction::Blake3_192 => {
            Ok(Box::new(RpoExample::<Blake3_192>::new(chain_length, options)))
        },
        HashFunction::Blake3_256 => {
            Ok(Box::new(RpoExample::<Blake3_256>::new(chain_length, options)))
        },
        HashFunction::Sha3_256 => {
            Ok(Box::new(RpoExample::<Sha3_256>::new(chain_length, options)))
        },
        HashFunction::Rp64_256 => {
            Ok(Box::new(RpoExample::<Rpo256>::new(chain_length, options)))
        },
        _ => Err("The specified hash function cannot be used with this example.".to_string()),
    }
}

pub struct RpoExample<H: ElementHasher> {
    options: ProofOptions,
    chain_length: usize,
    seed: [BaseElement; 4],
    result: [BaseElement; 4],
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> RpoExample<H> {
    pub fn new(chain_length: usize, options: ProofOptions) -> Self {
        assert!(chain_length.is_power_of_two(), "chain length must a power of 2");
        let seed = [BaseElement::from(42u8), BaseElement::from(43u8), BaseElement::from(2u8), BaseElement::from(3u8)];

        // compute the sequence of hashes using external implementation of Rescue hash
        let now = Instant::now();
        let result = compute_hash_chain(seed, chain_length);
        println!("hash result {:?}", result);
        println!(
            "Computed a chain of {} Rescue hashes in {} ms",
            chain_length,
            now.elapsed().as_millis(),
        );

        RpoExample {
            options,
            chain_length,
            seed,
            result,
            _hasher: PhantomData,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl<H: ElementHasher> Example for RpoExample<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    fn prove(&self) -> Proof {
        // generate the execution trace
        println!("Generating proof for computing a chain of {} Rescue hashes", self.chain_length);

        // create a prover
        let prover = RpoProver::<H>::new(self.options.clone());

        // generate execution trace
        let trace =
            info_span!("generate_execution_trace", num_cols = TRACE_WIDTH, steps = field::Empty)
                .in_scope(|| {
                    let trace = prover.build_trace(self.seed, self.chain_length);
                    tracing::Span::current().record("steps", trace.length());
                    trace
                });

        // generate the proof
        prover.prove(trace).unwrap()
    }

    fn verify(&self, proof: Proof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs { seed: self.seed, result: self.result };
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        winterfell::verify::<RescueAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
    }

    fn verify_with_wrong_inputs(&self, proof: Proof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            seed: self.seed,
            result: [self.result[0], self.result[1] + BaseElement::ONE, self.result[0], self.result[1] + BaseElement::ONE],
        };
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        winterfell::verify::<RescueAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
    }
}

// HELPER FUNCTIONS
// ================================================================================================
fn compute_hash_chain(seed: [BaseElement; 4], length: usize) -> [BaseElement; 4] {
    let mut values = seed;
    let mut result = [BaseElement::ZERO; 4];
    for _ in 0..length {
        hash(values, &mut result);
        values.copy_from_slice(&result);
    }
    result
}
// HASH FUNCTION
// ================================================================================================

/// Implementation of Rescue hash function with a 4 element state and 14 rounds. Accepts a
/// 2-element input, and returns a 2-element digest.
pub fn hash(value: [BaseElement; 4], result: &mut [BaseElement]) {
    let mut state = [BaseElement::ZERO; STATE_WIDTH];
    state[DIGEST_RANGE].copy_from_slice(&value);
    for i in 0..NUM_ROUNDS {
        Rp64_256::apply_round(&mut state, i);
    }
    result.copy_from_slice(&state[DIGEST_RANGE]);
}


