// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{
    math::{fields::f64::BaseElement, ExtensionOf, FieldElement},
    Air, AirContext, Assertion, AuxRandElements, EvaluationFrame, TraceInfo,
    TransitionConstraintDegree,
};

use super::ProofOptions;

pub(crate) struct LogUpAir {
    context: AirContext<BaseElement, ()>,
}

impl Air for LogUpAir {
    type BaseField = BaseElement;
    type PublicInputs = ();

    fn new(trace_info: TraceInfo, _pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let num_witness_columns = trace_info.main_segment_width() - 2;
        let aux_constraints_degrees = (0..((num_witness_columns + 1) / 2))
            .map(|_| TransitionConstraintDegree::new(3))
            .collect();
        Self {
            context: AirContext::new_multi_segment(
                trace_info,
                _pub_inputs,
                vec![TransitionConstraintDegree::new(1)],
                aux_constraints_degrees,
                1,
                0,
                options,
            ),
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField, ()> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current()[0];
        let next = frame.next()[0];

        // increments by 1
        result[0] = next - current - E::ONE;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![Assertion::single(0, 0, BaseElement::ZERO)]
    }

    fn evaluate_aux_transition<F, E>(
        &self,
        main_frame: &EvaluationFrame<F>,
        aux_frame: &EvaluationFrame<E>,
        _periodic_values: &[F],
        aux_rand_elements: &AuxRandElements<E>,
        result: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>,
    {
        let main_current = &main_frame.current()[..];
        let aux_current = aux_frame.current();
        let alpha = aux_rand_elements.rand_elements()[0];

        result
            .iter_mut()
            .skip(1)
            .zip(aux_current.iter())
            .zip(main_current.chunks(2))
            .for_each(|((res, aux_col), pair_witness_col)| {
                let x0 = pair_witness_col[0];
                let x1 = pair_witness_col[1];
                *res = (E::from(x0) - alpha) * (E::from(x1) - alpha) * *aux_col - E::ONE;
            });

        // missing the column for the univariate sum-check IOP
    }

    fn get_aux_assertions<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        _aux_rand_elements: &AuxRandElements<E>,
    ) -> Vec<Assertion<E>> {
        vec![]
    }
}
