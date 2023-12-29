// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    rescue, BaseElement, DefaultRandomCoin, ElementHasher, FieldElement, PhantomData, ProofOptions,
    Prover, PublicInputs, RescueAir, CYCLE_LENGTH, NUM_HASH_ROUNDS, PADDED_TRACE_LEN,
};
use core_utils::AsBytes;
use rand_utils::rand_value;
use winterfell::{
    matrix::ColMatrix, AuxTraceRandElements, ConstraintCompositionCoefficients,
    DefaultConstraintEvaluator, DefaultTraceLde, StarkDomain, TraceInfo, TracePolyTable,
    TraceTable,
};

// RESCUE PROVER
// ================================================================================================

pub struct RescueProver<H: ElementHasher> {
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> RescueProver<H> {
    pub fn new(options: ProofOptions) -> Self {
        Self {
            options,
            _hasher: PhantomData,
        }
    }

    pub fn build_trace(
        &self,
        sk: [BaseElement; 2],
        message: [BaseElement; 2],
    ) -> TraceTable<BaseElement> {
        // allocate memory to hold the trace table
        // we need only CYCLE_LENGTH many rows to accomodate the hash computation. The remaining
        // rows are filled with random values for zero-knowledge.
        // TODO: determine this in a more precise manner given the security target.
        let trace_length = PADDED_TRACE_LEN;
        let mut trace = TraceTable::new(4, trace_length);
        let meta: Vec<u8> = message.into_iter().flat_map(|m| (m.as_bytes()).to_owned()).collect();
        trace.set_meta(meta);
        trace.fill(
            |state| {
                // initialize first state of the computation
                state[0] = sk[0];
                state[1] = sk[1];
                state[2] = BaseElement::ZERO;
                state[3] = BaseElement::ZERO;
            },
            |step, state| {
                // execute the transition function for all steps
                //
                // for the first 14 steps in every cycle, compute a single round of
                // Rescue hash; for the remaining 2 rounds, just carry over the values
                // in the first two registers to the next step.
                // For the rest of the trace, fill with random values.
                if (step  ) < NUM_HASH_ROUNDS {
                    rescue::apply_round(state, step);
                } else if step >= CYCLE_LENGTH{
                    state[0] = rand_value();
                    state[1] = rand_value();
                    state[2] = rand_value();
                    state[3] = rand_value();
                }
                else {
                    state[2] = BaseElement::ZERO;
                    state[3] = BaseElement::ZERO;
                }
            },
        );

        trace
    }
}

impl<H: ElementHasher> Prover for RescueProver<H>
where
    H: ElementHasher<BaseField = BaseElement>,
{
    type BaseField = BaseElement;
    type Air = RescueAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = H;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last_step = CYCLE_LENGTH - 1;
        PublicInputs {
            pub_key: [trace.get(0, last_step), trace.get(1, last_step)],
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
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: AuxTraceRandElements<E>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}
