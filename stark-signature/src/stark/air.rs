// CONSTANTS
// ================================================================================================

use std::ops::Range;

use air::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use crypto::hashers::{ARK1, ARK2, MDS};
use math::{fields::f64::BaseElement, FieldElement, StarkField, ToElements};

pub const HASH_CYCLE_LEN: usize = 8;
pub const TRACE_WIDTH: usize = 12;

/// Sponge state is set to 12 field elements or 96 bytes; 8 elements are reserved for rate and
/// the remaining 4 elements are reserved for capacity.
pub const STATE_WIDTH: usize = 12;

/// The output of the hash function is a digest which consists of 4 field elements or 32 bytes.
///
/// The digest is returned from state elements 4, 5, 6, and 7 (the first four elements of the
/// rate portion).
pub const DIGEST_RANGE: Range<usize> = 4..8;
pub const DIGEST_SIZE: usize = DIGEST_RANGE.end - DIGEST_RANGE.start;

/// The number of rounds is set to 7 to target 128-bit security level with 40% security margin;
/// computed using algorithm 7 from <https://eprint.iacr.org/2020/1143.pdf>
pub const NUM_ROUNDS: usize = 7;

pub struct PublicInputs {
    pub pub_key: [BaseElement; DIGEST_SIZE],
    pub msg: [BaseElement; DIGEST_SIZE],
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut res = self.pub_key.to_vec();
        res.extend_from_slice(&self.msg.to_vec());
        res
    }
}

pub struct RescueAir {
    context: AirContext<BaseElement>,
    pub_key: [BaseElement; DIGEST_SIZE],
}

impl Air for RescueAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    type GkrProof = ();
    type GkrVerifier = ();

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            // Apply RPO rounds.
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
        ];
        assert_eq!(TRACE_WIDTH, trace_info.width());
        let context = AirContext::new(trace_info, degrees, 4, options);
        let context = context.set_num_transition_exemptions(1);
        RescueAir { context, pub_key: pub_inputs.pub_key }
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

        let ark = &periodic_values[0..];

        enforce_rpo_round(frame, result, ark);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // Assert that the public key is the correct one
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(4, last_step, self.pub_key[0]),
            Assertion::single(5, last_step, self.pub_key[1]),
            Assertion::single(6, last_step, self.pub_key[2]),
            Assertion::single(7, last_step, self.pub_key[3]),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        get_round_constants()
    }
}

// HELPER EVALUATORS
// ------------------------------------------------------------------------------------------------

/// Enforces constraints for a single round of the Rescue Prime Optimized hash functions.
pub fn enforce_rpo_round<E: FieldElement + From<BaseElement>>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    ark: &[E],
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
        result.agg_constraint(i, are_equal(step2[i], step1[i]));
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
fn apply_mds<E: FieldElement + From<BaseElement>>(state: &mut [E; STATE_WIDTH]) {
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

// CONSTRAINT EVALUATION HELPERS
// ================================================================================================

/// Returns zero only when a == b.
pub fn are_equal<E: FieldElement>(a: E, b: E) -> E {
    a - b
}

// TRAIT TO SIMPLIFY CONSTRAINT AGGREGATION
// ================================================================================================

pub trait EvaluationResult<E> {
    fn agg_constraint(&mut self, index: usize, value: E);
}

impl<E: FieldElement> EvaluationResult<E> for [E] {
    fn agg_constraint(&mut self, index: usize, value: E) {
        self[index] += value;
    }
}

impl<E: FieldElement> EvaluationResult<E> for Vec<E> {
    fn agg_constraint(&mut self, index: usize, value: E) {
        self[index] += value;
    }
}

// TRACE
// ================================================================================================

pub fn apply_round(state: &mut [BaseElement; STATE_WIDTH], round: usize) {
    // apply first half of Rescue round
    apply_mds(state);
    add_constants(state, &ARK1[round]);
    apply_sbox(state);

    // apply second half of Rescue round
    apply_mds(state);
    add_constants(state, &ARK2[round]);
    apply_inv_sbox(state);
}

fn add_constants(state: &mut [BaseElement; STATE_WIDTH], ark: &[BaseElement; STATE_WIDTH]) {
    state.iter_mut().zip(ark).for_each(|(s, &k)| *s += k);
}

#[inline(always)]
fn apply_inv_sbox(state: &mut [BaseElement; STATE_WIDTH]) {
    // compute base^10540996611094048183 using 72 multiplications per array element
    // 10540996611094048183 = b1001001001001001001001001001000110110110110110110110110110110111

    // compute base^10
    let mut t1 = *state;
    t1.iter_mut().for_each(|t| *t = t.square());

    // compute base^100
    let mut t2 = t1;
    t2.iter_mut().for_each(|t| *t = t.square());

    // compute base^100100
    let t3 = exp_acc::<BaseElement, STATE_WIDTH, 3>(t2, t2);

    // compute base^100100100100
    let t4 = exp_acc::<BaseElement, STATE_WIDTH, 6>(t3, t3);

    // compute base^100100100100100100100100
    let t5 = exp_acc::<BaseElement, STATE_WIDTH, 12>(t4, t4);

    // compute base^100100100100100100100100100100
    let t6 = exp_acc::<BaseElement, STATE_WIDTH, 6>(t5, t3);

    // compute base^1001001001001001001001001001000100100100100100100100100100100
    let t7 = exp_acc::<BaseElement, STATE_WIDTH, 31>(t6, t6);

    // compute base^1001001001001001001001001001000110110110110110110110110110110111
    for (i, s) in state.iter_mut().enumerate() {
        let a = (t7[i].square() * t6[i]).square().square();
        let b = t1[i] * t2[i] * *s;
        *s = a * b;
    }
}

#[inline(always)]
fn exp_acc<B: StarkField, const N: usize, const M: usize>(base: [B; N], tail: [B; N]) -> [B; N] {
    let mut result = base;
    for _ in 0..M {
        result.iter_mut().for_each(|r| *r = r.square());
    }
    result.iter_mut().zip(tail).for_each(|(r, t)| *r *= t);
    result
}
