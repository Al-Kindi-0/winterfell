// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{
    math::ExtensionOf, Air, AirContext, Assertion, AuxRandElements, EvaluationFrame, TraceInfo,
    TransitionConstraintDegree,
};

use super::{BaseElement, FieldElement, ProofOptions, AUX_TRACE_WIDTH, MAIN_TRACE_WIDTH};
use crate::utils::are_equal;

// MOCK 72/8 AIR
// ================================================================================================

pub struct Mock72Air {
    context: AirContext<BaseElement>,
    result: BaseElement,
}

impl Air for Mock72Air {
    type BaseField = BaseElement;
    type PublicInputs = BaseElement;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: BaseElement, options: ProofOptions) -> Self {
        let main_degrees = vec![TransitionConstraintDegree::new(1); MAIN_TRACE_WIDTH];
        let aux_degrees = vec![TransitionConstraintDegree::new(1); AUX_TRACE_WIDTH];
        assert_eq!(MAIN_TRACE_WIDTH + AUX_TRACE_WIDTH, trace_info.width());

        Mock72Air {
            context: AirContext::new_multi_segment(
                trace_info,
                main_degrees,
                aux_degrees,
                2,
                1,
                options,
            ),
            result: pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        debug_assert_eq!(MAIN_TRACE_WIDTH, current.len());
        debug_assert_eq!(MAIN_TRACE_WIDTH, next.len());

        for i in 0..MAIN_TRACE_WIDTH {
            result[i] = are_equal(next[i], current[i] + E::ONE);
        }
    }

    fn evaluate_aux_transition<F, E>(
        &self,
        _main_frame: &EvaluationFrame<F>,
        aux_frame: &EvaluationFrame<E>,
        _periodic_values: &[F],
        _aux_rand_elements: &AuxRandElements<E>,
        result: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>,
    {
        let aux_current = aux_frame.current();
        let aux_next = aux_frame.next();

        debug_assert_eq!(AUX_TRACE_WIDTH, aux_current.len());
        debug_assert_eq!(AUX_TRACE_WIDTH, aux_next.len());

        for i in 0..AUX_TRACE_WIDTH {
            result[i] = are_equal(aux_next[i], aux_current[i]);
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, Self::BaseField::ZERO),
            Assertion::single(0, last_step, self.result),
        ]
    }

    fn get_aux_assertions<E>(&self, aux_rand_elements: &AuxRandElements<E>) -> Vec<Assertion<E>>
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        let seed = aux_rand_elements.rand_elements()[0];
        vec![Assertion::single(0, 0, seed)]
    }
}
