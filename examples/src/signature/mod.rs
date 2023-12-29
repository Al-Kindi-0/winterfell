// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::marker::PhantomData;
use core_utils::AsBytes;

use rand_utils::rand_value;

use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher},
    math::{fields::f128::BaseElement, FieldElement},
    ProofOptions, Prover, StarkProof, VerifierError,
};

#[allow(clippy::module_inception)]
pub(crate) mod rescue;

mod air;
use air::{PublicInputs, RescueAir};

mod prover;
use prover::RescueProver;

// CONSTANTS
// ================================================================================================

const CYCLE_LENGTH: usize = 16;
const NUM_HASH_ROUNDS: usize = 14;
const TRACE_WIDTH: usize = 4;
const TRACE_LEN: usize = 16;
const PADDED_TRACE_LEN: usize = 1024;
const NUM_PADDING_ROWS: usize = PADDED_TRACE_LEN - TRACE_LEN;

// RESCUE-BASED SIGNATURE SCHEME
// ================================================================================================

pub struct SecretKey<H: ElementHasher<BaseField = BaseElement>> {
    sk: [BaseElement; 2],
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

pub struct PublicKey<H: ElementHasher<BaseField = BaseElement>> {
    pk: [BaseElement; 2],
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

pub struct KeyPair<H: ElementHasher<BaseField = BaseElement>> {
    pk: PublicKey<H>,
    sk: SecretKey<H>,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> KeyPair<H>
where
    H: ElementHasher<BaseField = BaseElement>,
{
    pub fn new(options: ProofOptions) -> Self {
        let sk = [rand_value(), rand_value()];
        let sk = SecretKey {
            sk,
            options: options.clone(),
            _hasher: PhantomData,
        };
        let pk = compute_hash(sk.sk);
        let pk = PublicKey {
            pk,
            options: options.clone(),
            _hasher: PhantomData,
        };
        Self {
            pk,
            sk,
            _hasher: PhantomData,
        }
    }

    pub fn verify(
        &self,
        message: [BaseElement; 2],
        signature: StarkProof,
    ) -> Result<(), VerifierError> {
        self.pk.verify(message, signature)
    }

    pub fn sign(&self, message: [BaseElement; 2]) -> StarkProof {
        self.sk.sign(message)
    }
}

impl<H: ElementHasher> SecretKey<H>
where
    H: ElementHasher<BaseField = BaseElement>,
{
    pub fn sign(&self, message: [BaseElement; 2]) -> StarkProof {
        // create a prover
        let prover = RescueProver::<H>::new(self.options.clone());

        // generate the execution trace
        let trace = prover.build_trace(self.sk, message);

        // generate the proof
        prover.prove(trace).unwrap()
    }
}

impl<H: ElementHasher> PublicKey<H>
where
    H: ElementHasher<BaseField = BaseElement>,
{
    pub fn verify(
        &self,
        message: [BaseElement; 2],
        signature: StarkProof,
    ) -> Result<(), VerifierError> {
        let meta: Vec<u8> = message.into_iter().flat_map(|m| (m.as_bytes()).to_owned()).collect();
        let trace_info = signature.get_trace_info();
        assert_eq!(meta, trace_info.meta());

        let pub_inputs = PublicInputs {
            pub_key: [self.pk[0], self.pk[1]],
        };
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![self.options.clone()]);
        winterfell::verify::<RescueAir, H, DefaultRandomCoin<H>>(
            signature,
            pub_inputs,
            &acceptable_options,
        )
    }
}

#[test]
fn test_signature() {
    use winterfell::FieldExtension;
    let trace_len = CYCLE_LENGTH;
    let num_fri_queries = 28;
    let final_poly_degree = 31;
    let fold_factor = 4;
    let blowup = 8;
    let grinding_factor = 0;
    let options = ProofOptions::new(
        num_fri_queries,
        blowup,
        grinding_factor,
        FieldExtension::None,
        fold_factor,
        final_poly_degree,
    );

    let padded_trace_length = air::_minimal_padded_trace_len(
        trace_len,
        num_fri_queries,
        final_poly_degree + 1,
        fold_factor,
        blowup,
    );
    assert_eq!(padded_trace_length, PADDED_TRACE_LEN);

    let key_pair = KeyPair::<crate::Blake3_256>::new(options);
    let message = [rand_value(), rand_value()];

    let signature = key_pair.sk.sign(message);

    key_pair.pk.verify(message, signature.clone()).unwrap();
}

// HELPER FUNCTIONS
// ================================================================================================
fn compute_hash(input: [BaseElement; 2]) -> [BaseElement; 2] {
    let mut result = [BaseElement::ZERO; 2];

    rescue::hash(input, &mut result);

    result
}
