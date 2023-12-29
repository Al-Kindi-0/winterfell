// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{rescue, BaseElement, FieldElement, ProofOptions, CYCLE_LENGTH, TRACE_WIDTH};
use crate::{utils::{are_equal, is_zero, not, EvaluationResult}, signature::NUM_PADDING_ROWS};
use winterfell::{
    math::ToElements, Air, AirContext, Assertion, EvaluationFrame, TraceInfo,
    TransitionConstraintDegree,
};

// CONSTANTS
// ================================================================================================

/// Specifies steps on which Rescue transition function is applied.
const CYCLE_MASK: [BaseElement; CYCLE_LENGTH] = [
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ZERO,
    BaseElement::ZERO,
];

// RESCUE AIR
// ================================================================================================

pub struct PublicInputs {
    pub pub_key: [BaseElement; 2],
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.pub_key.to_vec()
    }
}

pub struct RescueAir {
    context: AirContext<BaseElement>,
    pub_key: [BaseElement; 2],
}

impl Air for RescueAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(3, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![CYCLE_LENGTH]),
        ];
        assert_eq!(TRACE_WIDTH, trace_info.width());

        // Set the number of exemption points. This is equal to `trace_length - CYCLE_LENGTH`
        let context = AirContext::new(trace_info, degrees, 2, options);
        let context = context.set_num_transition_exemptions(NUM_PADDING_ROWS);

        RescueAir {
            context,
            pub_key: pub_inputs.pub_key,
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
        // expected state width is 4 field elements
        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        // split periodic values into hash_flag and Rescue round constants
        let hash_flag = periodic_values[0];
        let ark = &periodic_values[1..];

        // when hash_flag = 1, constraints for Rescue round are enforced
        rescue::enforce_round(result, current, next, ark, hash_flag);

        // when hash_flag = 0, constraints for copying hash values to the next
        // step are enforced.
        let copy_flag = not(hash_flag);
        enforce_hash_copy(result, current, next, copy_flag);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // Assert starting and ending values of the hash chain
        let step = CYCLE_LENGTH - 1;
        vec![
            Assertion::single(0, step, self.pub_key[0]),
            Assertion::single(1, step, self.pub_key[1]),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut result = vec![CYCLE_MASK.to_vec()];
        result.append(&mut rescue::get_round_constants());
        result
    }
}

// HELPER EVALUATORS
// ------------------------------------------------------------------------------------------------

/// when flag = 1, enforces that the next state of the computation is defined like so:
/// - the first two registers are equal to the values from the previous step
/// - the other two registers are equal to 0
fn enforce_hash_copy<E: FieldElement>(result: &mut [E], current: &[E], next: &[E], flag: E) {
    result.agg_constraint(0, flag, are_equal(current[0], next[0]));
    result.agg_constraint(1, flag, are_equal(current[1], next[1]));
    result.agg_constraint(2, flag, is_zero(next[2]));
    result.agg_constraint(3, flag, is_zero(next[3]));
}

/// Computes the number of blinding rows needed in order to achieve zero-knowledge.
pub fn _num_blinding_rows(
    trace_len: usize,
    num_fri_queries: usize,
    final_poly_size: usize,
    fold_factor: usize,
    blowup: usize,
) -> usize {
    let num_fri_layers = {
        let mut i = 1;
        let mut divisor = fold_factor;

        while (blowup * trace_len) / divisor > final_poly_size {
            divisor *= fold_factor;
            i += 1;
        }
        i
    };

    let num_fri_openings = num_fri_queries * num_fri_layers * fold_factor + final_poly_size;
    //z and gz
    let iop_openings = 2;

    num_fri_openings + iop_openings
}

/// Computes the minimal trace length required to accomodate the original trace and the additional
/// blinding rows.
pub fn _minimal_padded_trace_len(
    trace_len: usize,
    num_fri_queries: usize,
    final_poly_size: usize,
    fold_factor: usize,
    blowup: usize,
) -> usize {
    let mut padded_trace_len = trace_len;

    while _num_blinding_rows(padded_trace_len, num_fri_queries, final_poly_size, fold_factor, blowup)
        > padded_trace_len
    {
        padded_trace_len *= 2;
    }
    
    2*padded_trace_len
}
