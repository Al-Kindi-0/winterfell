



// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use air::ZkParameters;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use winterfell::{
    crypto::{hashers::Rp64_256, MerkleTree}, matrix::ColMatrix, AuxRandElements, ConstraintCompositionCoefficients,
    DefaultConstraintEvaluator, DefaultTraceLde, StarkDomain, Trace, TraceInfo, TracePolyTable,
    TraceTable,
};

use crate::utils::rescue::{CYCLE_LENGTH, NUM_ROUNDS};

use super::{
    air::{HASH_CYCLE_LEN, TRACE_WIDTH}, BaseElement, DefaultRandomCoin, ElementHasher, FieldElement, PhantomData, ProofOptions, Prover, PublicInputs, RescueAir
};

// RESCUE PROVER
// ================================================================================================

pub struct RpoProver<H: ElementHasher> {
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> RpoProver<H> {
    pub fn new(options: ProofOptions) -> Self {
        Self { options, _hasher: PhantomData }
    }

    pub fn build_trace(
        &self,
        seed: [BaseElement; 4],
        iterations: usize,
    ) -> TraceTable<BaseElement> {
        // allocate memory to hold the trace table
        let trace_length = iterations * CYCLE_LENGTH;
        let mut trace = TraceTable::new(TRACE_WIDTH, trace_length);

        trace.fill(
            |state| {
                // initialize first state of the computation
                state[0] = BaseElement::ZERO;
                state[1] = BaseElement::ZERO;
                state[2] = BaseElement::ZERO;
                state[3] = BaseElement::ZERO;
                state[4] = seed[0];
                state[5] = seed[1];
                state[6] = seed[2];
                state[7] = seed[3];
                state[8] = BaseElement::ZERO;
                state[9] = BaseElement::ZERO;
                state[10] = BaseElement::ZERO;
                state[11] = BaseElement::ZERO;
            },
            |step, state| {
                // execute the transition function for all steps
                //
                // for the first 7 steps in every cycle, compute a single round of
                // RPO hash; for the remaining round, just carry over the values
                // in the first and last four registers to the next step
                if (step % HASH_CYCLE_LEN) < NUM_ROUNDS {
                    Rp64_256::apply_round(state.try_into().unwrap(), step % HASH_CYCLE_LEN);
                } else {
                    state[0] = BaseElement::ZERO;
                state[1] = BaseElement::ZERO;
                state[2] = BaseElement::ZERO;
                state[3] = BaseElement::ZERO;
                state[8] = BaseElement::ZERO;
                state[9] = BaseElement::ZERO;
                state[10] = BaseElement::ZERO;
                state[11] = BaseElement::ZERO;
                }
            },
        );

        trace
    }
}

impl<H: ElementHasher> Prover for RpoProver<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    type BaseField = BaseElement;
    type Air = RescueAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = H;
    type VC = MerkleTree<H>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last_step = trace.length() - 1;
        PublicInputs {
            seed: [trace.get(4, 0), trace.get(5, 0), trace.get(6, 0), trace.get(7, 0)],
            result: [
                trace.get(4, last_step),
                trace.get(5, last_step),
                trace.get(6, last_step),
                trace.get(7, last_step),
            ],
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        zk_parameters: Option<ZkParameters>
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        let mut prng = ChaCha20Rng::from_entropy();
        DefaultTraceLde::new(trace_info, main_trace, domain, zk_parameters, &mut prng)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}






