// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use air::{
    Air, EvaluationFrame, GkrRandElements, LagrangeConstraintsCompositionCoefficients,
    LagrangeKernelConstraints, LagrangeKernelEvaluationFrame, LagrangeKernelRandElements,
    LogUpGkrEvaluator,
};
use math::{batch_inversion, FieldElement};

use crate::{inner_product, StarkDomain, TraceLde};

pub struct SColumnConstraints<'a, E: FieldElement, A: Air<BaseField = E::BaseField>> {
    air: &'a A,
    openings: Vec<E>,
    batching_randomness: Vec<E>,
    cc_coef: E,
}

impl<'a, E, A> SColumnConstraints<'a, E, A>
where
    E: FieldElement,
    A: Air<BaseField = E::BaseField>,
{
    pub fn new(air: &'a A, logup_rand: &GkrRandElements<E>, cc_coef: E) -> Self {
        let GkrRandElements {
            lagrange_kernel_eval_point: _,
            openings_combining_randomness,
            openings,
            oracles: _,
        } = logup_rand;

        Self {
            air,
            openings: openings.to_vec(),
            batching_randomness: openings_combining_randomness.to_vec(),
            cc_coef,
        }
    }

    /// Evaluates the transition and boundary constraints. Specifically, the constraint evaluations
    /// are divided by their corresponding divisors, and the resulting terms are linearly combined
    /// using the composition coefficients.
    ///
    /// Writes the evaluations in `combined_evaluations_acc` at the corresponding (constraint
    /// evaluation) domain index.
    pub fn evaluate_constraints<T>(
        &self,
        trace: &T,
        domain: &StarkDomain<E::BaseField>,
        combined_evaluations_acc: &mut [E],
    ) where
        T: TraceLde<E>,
    {
        let evaluator = self.air.get_logup_gkr_evaluator::<E>();
        let lde_shift = domain.ce_to_lde_blowup().trailing_zeros();
        let trans_constraints_divisor =
            compute_s_col_divisor::<E>(domain.ce_domain_size(), domain, self.air.trace_length());
        let s_col_idx = trace.trace_info().aux_segment_width() - 2;
        let l_col_idx = trace.trace_info().aux_segment_width() - 1;
        let mut main_frame = EvaluationFrame::new(trace.trace_info().main_trace_width());
        let mut aux_frame = EvaluationFrame::new(trace.trace_info().aux_segment_width());

        let c = self.openings[0] + inner_product(&self.batching_randomness, &self.openings[1..]);
        let mean = c / E::from(E::BaseField::from(trace.trace_info().length() as u32));

        for step in 0..domain.ce_domain_size() {
            trace.read_aux_trace_frame_into(step, &mut aux_frame);
            trace.read_main_trace_frame_into(step << lde_shift, &mut main_frame);

            let s_cur = aux_frame.current()[s_col_idx];
            let s_nxt = aux_frame.next()[s_col_idx];
            let l_cur = aux_frame.current()[l_col_idx];

            let query = evaluator.build_query(&main_frame, &[]);

            let batched_claim =
                E::from(query[0]) + inner_product(&query[1..], &self.batching_randomness);

            let rhs = s_cur - mean + batched_claim * l_cur;
            let lhs = s_nxt;

            combined_evaluations_acc[step] +=
                (rhs - lhs) * self.cc_coef.mul_base(trans_constraints_divisor[step]);
        }
    }
}

fn compute_s_col_divisor<E: FieldElement>(
    ce_domain_size: usize,
    domain: &StarkDomain<E::BaseField>,
    trace_length: usize,
) -> Vec<E::BaseField> {
    let degree = trace_length as u32;
    let mut result = Vec::with_capacity(ce_domain_size);

    for row in 0..ce_domain_size {
        let x = domain.get_ce_x_at(row);
        let x = x.exp((degree as u32).into()) - E::BaseField::ONE;

        result.push(x);
    }
    batch_inversion(&result)
}

/// Contains a specific strategy for evaluating the Lagrange kernel boundary and transition
/// constraints where the divisors' evaluation is batched.
///
/// Specifically, [`batch_inversion`] is used to reduce the number of divisions performed.
pub struct LagrangeKernelConstraintsBatchEvaluator<E: FieldElement> {
    lagrange_kernel_constraints: LagrangeKernelConstraints<E>,
    rand_elements: LagrangeKernelRandElements<E>,
}

impl<E: FieldElement> LagrangeKernelConstraintsBatchEvaluator<E> {
    /// Constructs a new [`LagrangeConstraintsBatchEvaluator`].
    pub fn new<A: Air>(
        air: &A,
        lagrange_kernel_rand_elements: LagrangeKernelRandElements<E>,
        lagrange_composition_coefficients: LagrangeConstraintsCompositionCoefficients<E>,
    ) -> Self
    where
        E: FieldElement<BaseField = A::BaseField>,
    {
        Self {
            lagrange_kernel_constraints: air
                .get_lagrange_kernel_constraints(
                    lagrange_composition_coefficients,
                    &lagrange_kernel_rand_elements,
                )
                .expect("expected Lagrange kernel constraints to be present"),
            rand_elements: lagrange_kernel_rand_elements,
        }
    }

    /// Evaluates the transition and boundary constraints. Specifically, the constraint evaluations
    /// are divided by their corresponding divisors, and the resulting terms are linearly combined
    /// using the composition coefficients.
    ///
    /// Writes the evaluations in `combined_evaluations_acc` at the corresponding (constraint
    /// evaluation) domain index.
    pub fn evaluate_constraints<T>(
        &self,
        trace: &T,
        domain: &StarkDomain<E::BaseField>,
        combined_evaluations_acc: &mut [E],
    ) where
        T: TraceLde<E>,
    {
        let lde_shift = domain.ce_to_lde_blowup().trailing_zeros();
        let trans_constraints_divisors = LagrangeKernelTransitionConstraintsDivisor::new(
            self.lagrange_kernel_constraints.transition.num_constraints(),
            domain,
        );
        let boundary_divisors_inv = self.compute_boundary_divisors_inv(domain);

        let mut frame = LagrangeKernelEvaluationFrame::new_empty();

        for step in 0..domain.ce_domain_size() {
            // compute Lagrange kernel frame
            trace.read_lagrange_kernel_frame_into(
                step << lde_shift,
                self.lagrange_kernel_constraints.lagrange_kernel_col_idx,
                &mut frame,
            );

            // Compute the combined transition and boundary constraints evaluations for this row
            let combined_evaluations = {
                let mut combined_evaluations = E::ZERO;

                // combine transition constraints
                for trans_constraint_idx in
                    0..self.lagrange_kernel_constraints.transition.num_constraints()
                {
                    let numerator = self
                        .lagrange_kernel_constraints
                        .transition
                        .evaluate_ith_numerator(&frame, &self.rand_elements, trans_constraint_idx);
                    let inv_divisor = trans_constraints_divisors
                        .get_inverse_divisor_eval(trans_constraint_idx, step);

                    combined_evaluations += numerator * inv_divisor;
                }

                // combine boundary constraints
                {
                    let boundary_numerator =
                        self.lagrange_kernel_constraints.boundary.evaluate_numerator_at(&frame);

                    combined_evaluations += boundary_numerator * boundary_divisors_inv[step];
                }

                combined_evaluations
            };

            combined_evaluations_acc[step] += combined_evaluations;
        }
    }

    // HELPERS
    // ---------------------------------------------------------------------------------------------

    /// Computes the inverse boundary divisor at every point of the constraint evaluation domain.
    /// That is, returns a vector of the form `[1 / div_0, ..., 1 / div_n]`, where `div_i` is the
    /// divisor for the Lagrange kernel boundary constraint at the i'th row of the constraint
    /// evaluation domain.
    fn compute_boundary_divisors_inv(&self, domain: &StarkDomain<E::BaseField>) -> Vec<E> {
        let mut boundary_denominator_evals = Vec::with_capacity(domain.ce_domain_size());
        for step in 0..domain.ce_domain_size() {
            let domain_point = domain.get_ce_x_at(step);
            let boundary_denominator = self
                .lagrange_kernel_constraints
                .boundary
                .evaluate_denominator_at(domain_point.into());
            boundary_denominator_evals.push(boundary_denominator);
        }

        batch_inversion(&boundary_denominator_evals)
    }
}

/// Holds all the transition constraint inverse divisor evaluations over the constraint evaluation
/// domain.
///
/// [`LagrangeKernelTransitionConstraintsDivisor`] takes advantage of some structure in the
/// divisors' evaluations. Recall that the divisor for the i'th transition constraint is `x^(2^i) -
/// 1`. When substituting `x` for each value of the constraint evaluation domain, for constraints
/// `i>0`, the divisor evaluations "wrap-around" such that some values repeat. For example,
///
/// i=0: no repetitions
/// i=1: the first half of the buffer is equal to the second half
/// i=2: each 1/4th of the buffer are equal
/// i=3: each 1/8th of the buffer are equal
/// ...
/// Therefore, we only compute the non-repeating section of the buffer in each iteration, and index
/// into it accordingly.
struct LagrangeKernelTransitionConstraintsDivisor<E: FieldElement> {
    divisor_evals_inv: Vec<E>,

    // Precompute the indices into `divisors_evals_inv` of the slices that correspond to each
    // transition constraint.
    //
    // For example, for a CE domain size `n=8`, `slice_indices_precomputes = [0, 8, 12, 14]`, such
    // that transition constraint `idx` owns the range:
    // idx=0: [0, 8)
    // idx=1: [8, 12)
    // idx=2: [12, 14)
    slice_indices_precomputes: Vec<usize>,
}

impl<E: FieldElement> LagrangeKernelTransitionConstraintsDivisor<E> {
    pub fn new(
        num_lagrange_transition_constraints: usize,
        domain: &StarkDomain<E::BaseField>,
    ) -> Self {
        let divisor_evals_inv = {
            let divisor_evaluator = TransitionDivisorEvaluator::<E>::new(
                num_lagrange_transition_constraints,
                domain.offset(),
            );

            // The number of divisor evaluations is
            // `ce_domain_size + ce_domain_size/2 + ce_domain_size/4 + ... + ce_domain_size/(log(ce_domain_size)-1)`,
            // which is slightly smaller than `ce_domain_size * 2`
            let mut divisor_evals: Vec<E> = Vec::with_capacity(domain.ce_domain_size() * 2);

            for trans_constraint_idx in 0..num_lagrange_transition_constraints {
                let num_non_repeating_denoms =
                    domain.ce_domain_size() / 2_usize.pow(trans_constraint_idx as u32);

                for step in 0..num_non_repeating_denoms {
                    let divisor_eval =
                        divisor_evaluator.evaluate_ith_divisor(trans_constraint_idx, domain, step);

                    divisor_evals.push(divisor_eval.into());
                }
            }

            batch_inversion(&divisor_evals)
        };

        let slice_indices_precomputes = {
            let num_indices = num_lagrange_transition_constraints + 1;
            let mut slice_indices_precomputes = Vec::with_capacity(num_indices);

            slice_indices_precomputes.push(0);

            let mut current_slice_len = domain.ce_domain_size();
            for i in 1..num_indices {
                let next_precompute_index = slice_indices_precomputes[i - 1] + current_slice_len;
                slice_indices_precomputes.push(next_precompute_index);

                current_slice_len /= 2;
            }

            slice_indices_precomputes
        };

        Self {
            divisor_evals_inv,
            slice_indices_precomputes,
        }
    }

    /// Returns the evaluation `1 / divisor`, where `divisor` is the divisor for the given
    /// transition constraint, at the given row of the constraint evaluation domain
    pub fn get_inverse_divisor_eval(&self, trans_constraint_idx: usize, row_idx: usize) -> E {
        let inv_divisors_slice_for_constraint =
            self.get_transition_constraint_slice(trans_constraint_idx);

        inv_divisors_slice_for_constraint[row_idx % inv_divisors_slice_for_constraint.len()]
    }

    // HELPERS
    // ---------------------------------------------------------------------------------------------

    /// Returns a slice containing all the inverse divisor evaluations for the given transition
    /// constraint.
    fn get_transition_constraint_slice(&self, trans_constraint_idx: usize) -> &[E] {
        let start = self.slice_indices_precomputes[trans_constraint_idx];
        let end = self.slice_indices_precomputes[trans_constraint_idx + 1];

        &self.divisor_evals_inv[start..end]
    }
}

/// Encapsulates the efficient evaluation of the Lagrange kernel transition constraints divisors.
///
/// `s` stands for the domain offset (i.e. coset shift element). The key concept in this
/// optimization is to realize that the computation of the first transition constraint divisor can
/// be reused for all the other divisors (call the evaluations `d`).
///
/// Specifically, each subsequent transition constraint divisor evaluation is equivalent to
/// multiplying an element `d` by a fixed number. For example, the multiplier for the transition
/// constraints are:
///
/// - transition constraint 1's multiplier: s
/// - transition constraint 2's multiplier: s^3
/// - transition constraint 3's multiplier: s^7
/// - transition constraint 4's multiplier: s^15
/// - ...
///
/// This is what `s_precomputes` stores.
///
/// Finally, recall that the ith Lagrange kernel divisor is `x^(2^i) - 1`.
/// [`TransitionDivisorEvaluator`] is only concerned with values of `x` in the constraint evaluation
/// domain, where the j'th element is `s * g^j`, where `g` is the group generator. To understand the
/// implementation of [`Self::evaluate_ith_divisor`], plug in `x = s * g^j` into `x^(2^i) - 1`.
pub struct TransitionDivisorEvaluator<E: FieldElement> {
    s_precomputes: Vec<E::BaseField>,
}

impl<E: FieldElement> TransitionDivisorEvaluator<E> {
    /// Constructs a new [`TransitionDivisorEvaluator`]
    pub fn new(num_lagrange_transition_constraints: usize, domain_offset: E::BaseField) -> Self {
        let s_precomputes = {
            // s_precomputes = [1, s, s^3, s^7, s^15, ...] (where s = domain_offset)
            let mut s_precomputes = Vec::with_capacity(num_lagrange_transition_constraints);

            let mut s_exp = E::BaseField::ONE;
            for _ in 0..num_lagrange_transition_constraints {
                s_precomputes.push(s_exp);
                s_exp = s_exp * s_exp * domain_offset;
            }

            s_precomputes
        };

        Self { s_precomputes }
    }

    /// Evaluates the divisor of the `trans_constraint_idx`'th transition constraint. See
    /// [`TransitionDivisorEvaluator`] for a more in-depth description of the algorithm.
    pub fn evaluate_ith_divisor(
        &self,
        trans_constraint_idx: usize,
        domain: &StarkDomain<E::BaseField>,
        ce_domain_step: usize,
    ) -> E::BaseField {
        let domain_idx = ((1 << trans_constraint_idx) * ce_domain_step) % domain.ce_domain_size();

        self.s_precomputes[trans_constraint_idx] * domain.get_ce_x_at(domain_idx)
            - E::BaseField::ONE
    }
}
