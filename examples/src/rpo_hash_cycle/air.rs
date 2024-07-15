use std::{ops::Range, os::linux::raw::stat};

use crate::utils::{are_equal, is_zero, not, EvaluationResult};
use crypto::hashers::{ARK1, ARK2, MDS};
use winterfell::{
    crypto,
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

// CONSTANTS
// ================================================================================================

/// Specifies steps on which Rescue transition function is applied.
const CYCLE_MASK: [BaseElement; HASH_CYCLE_LEN] = [
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ZERO,
];

pub const HASH_CYCLE_LEN: usize = 8;
pub const TRACE_WIDTH: usize = 3 * 12;

/// Sponge state is set to 12 field elements or 96 bytes; 8 elements are reserved for rate and
/// the remaining 4 elements are reserved for capacity.
pub const STATE_WIDTH: usize = 12;

/// The output of the hash function is a digest which consists of 4 field elements or 32 bytes.
///
/// The digest is returned from state elements 4, 5, 6, and 7 (the first four elements of the
/// rate portion).
pub const DIGEST_RANGE: Range<usize> = 4..8;

/// The number of rounds is set to 7 to target 128-bit security level with 40% security margin;
/// computed using algorithm 7 from <https://eprint.iacr.org/2020/1143.pdf>
pub const NUM_ROUNDS: usize = 7;

pub struct PublicInputs {
    pub seed: [BaseElement; 4],
    pub result: [BaseElement; 4],
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.result.to_vec()
    }
}

pub struct RescueAir {
    context: AirContext<BaseElement>,
    seed: [BaseElement; 4],
    result: [BaseElement; 4],
}

impl Air for RescueAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            // Apply RPO rounds.
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(3, vec![HASH_CYCLE_LEN]),
        ];
        assert_eq!(TRACE_WIDTH, trace_info.width());
        let context = AirContext::new(trace_info, degrees, 16, options);
        RescueAir {
            context,
            result: pub_inputs.result,
            seed: pub_inputs.seed,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        // expected state width is 12 field elements
        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        // split periodic values into hash_flag and Rescue round constants
        let hash_flag = periodic_values[0];
        let ark = &periodic_values[1..];

        // when hash_flag = 1, constraints for Rescue round are enforced
        //rescue::enforce_round(result, current, next, ark, hash_flag);
        enforce_rpo_round_2(frame, result, ark, hash_flag);

        // when hash_flag = 0, constraints for copying hash values to the next
        // step are enforced.
        let copy_flag = not(hash_flag);
        enforce_hash_copy(result, current, next, copy_flag);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // Assert starting and ending values of the hash chain
        let initial_step = 0;
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, initial_step, Self::BaseField::ZERO),
            Assertion::single(1, initial_step, Self::BaseField::ZERO),
            Assertion::single(2, initial_step, Self::BaseField::ZERO),
            Assertion::single(3, initial_step, Self::BaseField::ZERO),
            Assertion::single(4, initial_step, self.seed[0]),
            Assertion::single(5, initial_step, self.seed[1]),
            Assertion::single(6, initial_step, self.seed[2]),
            Assertion::single(7, initial_step, self.seed[3]),
            Assertion::single(8, initial_step, Self::BaseField::ZERO),
            Assertion::single(9, initial_step, Self::BaseField::ZERO),
            Assertion::single(10, initial_step, Self::BaseField::ZERO),
            Assertion::single(11, initial_step, Self::BaseField::ZERO),
            Assertion::single(4, last_step, self.result[0]),
            Assertion::single(5, last_step, self.result[1]),
            Assertion::single(6, last_step, self.result[2]),
            Assertion::single(7, last_step, self.result[3]),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut result = vec![CYCLE_MASK.to_vec()];
        result.append(&mut get_round_constants());
        result
    }

    type GkrProof = ();

    type GkrVerifier = ();
}

// HELPER EVALUATORS
// ------------------------------------------------------------------------------------------------

/// when flag = 1, enforces that the next state of the computation is defined like so:
/// - the first four registers are equal to the values from the previous step
/// - the last four registers are equal to 0
fn enforce_hash_copy<E: FieldElement>(result: &mut [E], current: &[E], next: &[E], flag: E) {
    result.agg_constraint(0, flag, is_zero(next[0]));
    result.agg_constraint(1, flag, is_zero(next[1]));
    result.agg_constraint(2, flag, is_zero(next[2]));
    result.agg_constraint(3, flag, is_zero(next[3]));
    result.agg_constraint(4, flag, are_equal(current[4], next[4]));
    result.agg_constraint(5, flag, are_equal(current[5], next[5]));
    result.agg_constraint(6, flag, are_equal(current[6], next[6]));
    result.agg_constraint(7, flag, are_equal(current[7], next[7]));
    result.agg_constraint(8, flag, is_zero(next[8]));
    result.agg_constraint(9, flag, is_zero(next[9]));
    result.agg_constraint(10, flag, is_zero(next[10]));
    result.agg_constraint(11, flag, is_zero(next[11]));
}

/// Enforces constraints for a single round of the Rescue Prime Optimized hash functions when
/// flag = 1 using the provided round constants.
pub fn enforce_rpo_round<E: FieldElement + From<BaseElement>>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    ark: &[E],
    flag: E,
) {
    // compute the state that should result from applying the first 5 operations of the RPO round to
    // the current hash state.
    let mut step1 = [E::ZERO; STATE_WIDTH];
    step1.copy_from_slice(frame.current());
    apply_mds(&mut step1);
    // add constants
    for i in 0..STATE_WIDTH {
        step1[i] += ark[i];
    }
    apply_sbox(&mut step1);
    apply_mds(&mut step1);
    // add constants
    for i in 0..STATE_WIDTH {
        step1[i] += ark[STATE_WIDTH + i];
    }

    // compute the state that should result from applying the inverse of the last operation of the
    // RPO round to the next step of the computation.
    let mut step2 = [E::ZERO; STATE_WIDTH];
    step2.copy_from_slice(frame.next());
    apply_sbox(&mut step2);

    // make sure that the results are equal.
    for i in 0..STATE_WIDTH {
        result.agg_constraint(i, flag, are_equal(step2[i], step1[i]));
    }
}

#[inline(always)]
fn apply_sbox<E: FieldElement + From<BaseElement>>(state: &mut [E; STATE_WIDTH]) {
    state.iter_mut().for_each(|v| {
        let t2 = v.square();
        let t4 = t2.square();
        *v *= t2 * t4;
    });
}

#[inline(always)]
pub fn apply_mds<E: FieldElement + From<BaseElement>>(state: &mut [E; STATE_WIDTH]) {
    let mut result = [E::ZERO; STATE_WIDTH];
    result.iter_mut().zip(MDS).for_each(|(r, mds_row)| {
        state.iter().zip(mds_row).for_each(|(&s, m)| {
            *r += E::from(m) * s;
        });
    });
    *state = result
}

/// Returns RPO round constants arranged in column-major form.
pub fn get_round_constants() -> Vec<Vec<BaseElement>> {
    let mut constants = Vec::new();
    for _ in 0..(STATE_WIDTH * 2) {
        constants.push(vec![BaseElement::ZERO; HASH_CYCLE_LEN]);
    }

    #[allow(clippy::needless_range_loop)]
    for i in 0..HASH_CYCLE_LEN - 1 {
        for j in 0..STATE_WIDTH {
            constants[j][i] = ARK1[i][j];
            constants[j + STATE_WIDTH][i] = ARK2[i][j];
        }
    }

    constants
}

#[inline(always)]
fn apply_first_linear_layer_and_cube<E: FieldElement + From<BaseElement>>(
    state: &mut [E; 3 * STATE_WIDTH],
    ark: &[E],
) {
    let mut step1 = [E::ZERO; STATE_WIDTH];
    step1.copy_from_slice(&state[..STATE_WIDTH]);

    apply_mds(&mut step1);

    // add constants
    for i in 0..STATE_WIDTH {
        step1[i] += ark[i];
    }

    //apply_pow3(&mut result);

    state
        .iter()
        .skip(STATE_WIDTH)
        .take(STATE_WIDTH)
        .zip(step1.iter_mut())
        .for_each(|(&s_3, r)| *r *= s_3 * s_3);

    apply_mds(&mut step1);

    // add constants
    for i in 0..STATE_WIDTH {
        step1[i] += ark[STATE_WIDTH + i];
    }

    let mut result2 = [E::ZERO; STATE_WIDTH];
    let state2 = state.clone();

    state2
        .iter()
        .take(STATE_WIDTH)
        .zip(state.iter().skip(2 * STATE_WIDTH).zip(result2.iter_mut()))
        .for_each(|(&next, (&cur, res))| *res = cur * cur * next)
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
    state: &mut [E; 3 * STATE_WIDTH],
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
}

pub fn enforce_rpo_round_2<E: FieldElement + From<BaseElement>>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    ark: &[E],
    flag: E,
) {
    // 1) (M.x + k)^3 == frame.current()[STATE_WIDTH + i..2*STATE_WIDTH]

    // compute the state that should result from applying the linear map (i.e., MDS multiplication plus
    // constant addition)
    let mut step1 = [E::ZERO; STATE_WIDTH];
    step1.copy_from_slice(&frame.current()[..STATE_WIDTH]);

    apply_mds(&mut step1);

    // add constants
    for i in 0..STATE_WIDTH {
        step1[i] += ark[i];
    }

    // Enforce second set of constraints i.e., that (M.x + k)^3 == frame.current()[STATE_WIDTH + i..2*STATE_WIDTH]
    for i in 0..STATE_WIDTH {
        result.agg_constraint(
            i + STATE_WIDTH,
            flag,
            are_equal(frame.current()[STATE_WIDTH + i], step1[i].exp(3_u32.into())),
        );
    }

    // 2) (M.x + k)^3 * (M.x + k)^3 * (M.x + k) ==

    // (M.x + k)^3 * (M.x + k)^3 * (M.x + k)
    step1
        .iter_mut()
        .zip(frame.current().iter().skip(STATE_WIDTH).take(STATE_WIDTH))
        .for_each(|(r, &s_3)| *r *= s_3 * s_3);

    apply_mds(&mut step1);

    for i in 0..STATE_WIDTH {
        step1[i] += ark[STATE_WIDTH + i];
    }

    // y * x * x (= y^7)
    let mut step2 = [E::ZERO; STATE_WIDTH];
    step2
        .iter_mut()
        .zip(
            frame
                .next()
                .iter()
                .take(STATE_WIDTH)
                .zip(frame.current().iter().skip(2 * STATE_WIDTH)),
        )
        .for_each(|(res, (&next, &cur))| *res = cur * cur * next);
    for i in 0..STATE_WIDTH {
        result.agg_constraint(i, flag, are_equal(step2[i], step1[i]));
    }

    // 3) y^3 = x
    for i in 0..STATE_WIDTH {
        result.agg_constraint(
            i + 2 * STATE_WIDTH,
            flag,
            are_equal(frame.current()[2 * STATE_WIDTH + i], frame.next()[i].exp(3_u32.into())),
        );
    }
}
