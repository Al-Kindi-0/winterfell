// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{
    crypto::MerkleTree, matrix::ColMatrix, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, PartitionOptions, StarkDomain, Trace, TraceInfo, TracePolyTable,
};

use super::{
    air::Mock72Air, trace_table::Mock72TraceTable, BaseElement, DefaultRandomCoin, ElementHasher,
    FieldElement, PhantomData, ProofOptions, Prover, AUX_TRACE_WIDTH,
};

// MOCK PROVER
// ================================================================================================

pub struct Mock72Prover<H: ElementHasher>
where
    H: Sync,
{
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> Mock72Prover<H>
where
    H: Sync,
{
    pub fn new(options: ProofOptions) -> Self {
        Self { options, _hasher: PhantomData }
    }

    /// Builds a simple execution trace with 72 columns where each column increments by 1 per step.
    pub fn build_trace(&self, trace_length: usize) -> Mock72TraceTable<BaseElement> {
        assert!(trace_length >= 8, "trace length must be at least 8");
        assert!(trace_length.is_power_of_two(), "trace length must be a power of 2");

        let mut trace = Mock72TraceTable::new(trace_length);
        trace.fill(
            |state| {
                for (i, value) in state.iter_mut().enumerate() {
                    *value = BaseElement::new(i as u64);
                }
            },
            |_, state| {
                for value in state.iter_mut() {
                    *value += BaseElement::ONE;
                }
            },
        );

        trace
    }
}

impl<H: ElementHasher + Sync> Prover for Mock72Prover<H>
where
    H: ElementHasher<BaseField = BaseElement>,
{
    type BaseField = BaseElement;
    type Air = Mock72Air;
    type Trace = Mock72TraceTable<BaseElement>;
    type HashFn = H;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, H, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> BaseElement {
        let last_step = trace.length() - 1;
        trace.get(0, last_step)
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn build_aux_trace<E>(
        &self,
        trace: &Self::Trace,
        aux_rand_elements: &AuxRandElements<E>,
    ) -> ColMatrix<E>
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        let trace_length = trace.length();
        let seed = aux_rand_elements.rand_elements()[0];

        let mut aux_columns = vec![vec![E::ZERO; trace_length]; AUX_TRACE_WIDTH];
        for col in 0..AUX_TRACE_WIDTH {
            let value = seed + E::from(BaseElement::new(col as u64));
            for row in 0..trace_length {
                aux_columns[col][row] = value;
            }
        }

        ColMatrix::new(aux_columns)
    }
}
