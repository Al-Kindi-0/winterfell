// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use air::ZkParameters;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use winterfell::{
    crypto::{
        hashers::{Rp64_256, ARK1},
        MerkleTree,
    },
    matrix::ColMatrix,
    AuxRandElements, ConstraintCompositionCoefficients, DefaultConstraintEvaluator,
    DefaultTraceLde, StarkDomain, Trace, TraceInfo, TracePolyTable, TraceTable,
};

use crate::utils::rescue::{CYCLE_LENGTH, NUM_ROUNDS};

use super::{
    air::{apply_mds, HASH_CYCLE_LEN, STATE_WIDTH, TRACE_WIDTH},
    BaseElement, DefaultRandomCoin, ElementHasher, FieldElement, PhantomData, ProofOptions, Prover,
    PublicInputs, RescueAir,
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

                let mut state_init = [BaseElement::ZERO; 3 * STATE_WIDTH];
                state_init[4] = seed[0];
                state_init[5] = seed[1];
                state_init[6] = seed[2];
                state_init[7] = seed[3];

                apply_second_linear_layer_and_cube(&mut state_init, &ARK1[0]);

                let mut state_nxt = [BaseElement::ZERO; STATE_WIDTH];
                state_nxt.clone_from_slice(&state_init[..STATE_WIDTH]);
                Rp64_256::apply_round(&mut state_nxt, 0);

                cube_next_state(&mut state_init, &state_nxt);

                state.iter_mut().zip(state_init).for_each(|(s, s_i)| *s = s_i);
            },
            |step, state| {
                // execute the transition function for all steps
                //
                // for the first 7 steps in every cycle, compute a single round of
                // RPO hash; for the remaining round, just carry over the values
                // in the first and last four registers to the next step
                if (step % HASH_CYCLE_LEN) < NUM_ROUNDS - 1 {
                    let mut state_hash = [BaseElement::ZERO; STATE_WIDTH];
                    state_hash.copy_from_slice(&state[..STATE_WIDTH]);
                    Rp64_256::apply_round(&mut state_hash, step % HASH_CYCLE_LEN);
                    state
                        .iter_mut()
                        .take(STATE_WIDTH)
                        .zip(state_hash)
                        .for_each(|(s, s_h)| *s = s_h);

                    apply_second_linear_layer_and_cube(state, &ARK1[(step + 1) % HASH_CYCLE_LEN]);

                    let mut state_hash_nxt = [BaseElement::ZERO; STATE_WIDTH];
                    state_hash_nxt.copy_from_slice(&state[..STATE_WIDTH]);
                    Rp64_256::apply_round(&mut state_hash_nxt, (step + 1) % HASH_CYCLE_LEN);

                    cube_next_state(state, &state_hash_nxt);
                } else if (step % HASH_CYCLE_LEN) < NUM_ROUNDS {
                    let mut state_hash = [BaseElement::ZERO; STATE_WIDTH];
                    state_hash.copy_from_slice(&state[..STATE_WIDTH]);
                    Rp64_256::apply_round(&mut state_hash, step % HASH_CYCLE_LEN);
                    state
                        .iter_mut()
                        .take(STATE_WIDTH)
                        .zip(state_hash)
                        .for_each(|(s, s_h)| *s = s_h);

                    let mut state_nxt = [BaseElement::ZERO; STATE_WIDTH];
                    //(&state_nxt[STATE_WIDTH..2*STATE_WIDTH]).copy_from_slice(&state[..STATE_WIDTH]);
                    for i in 0..4 {
                        state_nxt[i + 4] = state[i + 4]
                    }
                    cube_next_state(state, &state_nxt);
                } else {
                    state[0] = BaseElement::ZERO;
                    state[1] = BaseElement::ZERO;
                    state[2] = BaseElement::ZERO;
                    state[3] = BaseElement::ZERO;
                    state[8] = BaseElement::ZERO;
                    state[9] = BaseElement::ZERO;
                    state[10] = BaseElement::ZERO;
                    state[11] = BaseElement::ZERO;

                    apply_second_linear_layer_and_cube(state, &ARK1[0]);

                    let mut state_nxt = [BaseElement::ZERO; STATE_WIDTH];
                    state_nxt.clone_from_slice(&state[..STATE_WIDTH]);
                    Rp64_256::apply_round(&mut state_nxt, 0);

                    cube_next_state(state, &state_nxt);
                }
            },
        );

        //for step in 0..trace_length {
            //let mut target = [BaseElement::ZERO; 3 * STATE_WIDTH];
            //trace.read_row_into(step, &mut target);
            //println!("step {step} trace is {:?}", target);
        //}

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
        zk_parameters: Option<ZkParameters>,
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

#[inline(always)]
fn apply_pow3<E: FieldElement + From<BaseElement>>(state: &mut [E; STATE_WIDTH]) {
    state.iter_mut().for_each(|v| {
        let t2 = v.square();
        *v *= t2;
    });
}

#[inline(always)]
fn apply_second_linear_layer_and_cube<E: FieldElement + From<BaseElement>>(
    state: &mut [E],
    ark: &[E],
) {
    let mut result = [E::ZERO; STATE_WIDTH];
    result.copy_from_slice(&state[..STATE_WIDTH]);

    apply_mds(&mut result);

    // add constants
    for i in 0..STATE_WIDTH {
        result[i] += ark[i];
    }

    apply_pow3(&mut result);

    state
        .iter_mut()
        .skip(STATE_WIDTH)
        .take(STATE_WIDTH)
        .zip(result)
        .for_each(|(s, r)| *s = r);
}

#[inline(always)]
fn cube_next_state<E: FieldElement + From<BaseElement>>(state_cur: &mut [E], state_nxt: &[E]) {
    let mut result = [E::ZERO; STATE_WIDTH];
    result.copy_from_slice(&state_nxt[..STATE_WIDTH]);

    apply_pow3(&mut result);

    state_cur
        .iter_mut()
        .skip(2 * STATE_WIDTH)
        .take(STATE_WIDTH)
        .zip(result)
        .for_each(|(s, r)| *s = r);
}
