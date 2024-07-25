use crate::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, RandomCoin},
    math::{fields::f64::BaseElement, ExtensionOf, FieldElement},
    matrix::ColMatrix,
    DefaultConstraintEvaluator, DefaultTraceLde, Prover, ProverGkrProof, StarkDomain,
    TracePolyTable,
};
use air::{
    Air, AirContext, Assertion, AuxRandElements, ConstraintCompositionCoefficients, FieldExtension,
    GkrRandElements, LagrangeKernelRandElements, LogUpGkrOracle, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use crypto::MerkleTree;

use super::*;

#[test]
fn test_logup_gkr() {
    let trace = LogUpGkrSimple::new(2_usize.pow(10), 0);

    let prover = LogUpGkrSimpleProver::new(0);

    let _proof = prover.prove(trace).unwrap();

 
    // libc_println!("proof {:?}", _proof);
}

// LagrangeComplexTrace
// =================================================================================================

#[derive(Clone, Debug)]
struct LogUpGkrSimple {
    // dummy main trace
    main_trace: ColMatrix<BaseElement>,
    info: TraceInfo,
}

impl LogUpGkrSimple {
    fn new(trace_len: usize, aux_segment_width: usize) -> Self {
        assert!(trace_len < u32::MAX.try_into().unwrap());

        let table: Vec<BaseElement> =
            (0..trace_len).map(|idx| BaseElement::from(idx as u32)).collect();
        let mut multiplicity: Vec<BaseElement> =
            (0..trace_len).map(|_idx| BaseElement::ZERO).collect();
        multiplicity[0] = BaseElement::new(3 * trace_len as u64 - 3 * 4);
        multiplicity[1] = BaseElement::new(3 * 4);

        let mut values_0: Vec<BaseElement> = (0..trace_len).map(|_idx| BaseElement::ZERO).collect();

        for i in 0..4 {
            //values_0[i] = BaseElement::ZERO;
            values_0[i + 4] = BaseElement::ONE;
        }

        let mut values_1: Vec<BaseElement> = (0..trace_len).map(|_idx| BaseElement::ZERO).collect();

        for i in 0..4 {
            //values_0[i] = BaseElement::ZERO;
            values_1[i + 4] = BaseElement::ONE;
        }

        let mut values_2: Vec<BaseElement> = (0..trace_len).map(|_idx| BaseElement::ZERO).collect();

        for i in 0..4 {
            //values_0[i] = BaseElement::ZERO;
            values_2[i + 4] = BaseElement::ONE;
        }

        Self {
            main_trace: ColMatrix::new(vec![table, multiplicity, values_0, values_1, values_2]),
            info: TraceInfo::new_multi_segment(5, aux_segment_width, 0, trace_len, vec![]),
        }
    }

    fn len(&self) -> usize {
        self.main_trace.num_rows()
    }
}

impl Trace for LogUpGkrSimple {
    type BaseField = BaseElement;

    fn info(&self) -> &TraceInfo {
        &self.info
    }

    fn main_segment(&self) -> &ColMatrix<Self::BaseField> {
        &self.main_trace
    }

    fn read_main_frame(&self, row_idx: usize, frame: &mut EvaluationFrame<Self::BaseField>) {
        let next_row_idx = row_idx + 1;
        self.main_trace.read_row_into(row_idx, frame.current_mut());
        self.main_trace.read_row_into(next_row_idx % self.len(), frame.next_mut());
    }
}

// AIR
// =================================================================================================

struct LagrangeKernelComplexAir {
    context: AirContext<BaseElement>,
}

impl Air for LagrangeKernelComplexAir {
    type BaseField = BaseElement;
    // `GkrProof` is log(trace_len) for this dummy example, so that the verifier knows how many aux
    // random variables to generate
    type GkrProof = ();
    type GkrVerifier = ();

    type PublicInputs = ();
    type LogUpGkrEvaluator = PlainLogUpGkrEval<Self::BaseField>;

    fn new(trace_info: TraceInfo, _pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        Self {
            context: AirContext::with_logup_gkr(
                trace_info,
                vec![TransitionConstraintDegree::new(1)],
                vec![],
                1,
                0,
                None,
                options,
            ),
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: math::FieldElement<BaseField = Self::BaseField>>(
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
        _main_frame: &EvaluationFrame<F>,
        _aux_frame: &EvaluationFrame<E>,
        _periodic_values: &[F],
        _aux_rand_elements: &AuxRandElements<E>,
        _result: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>,
    {
        // do nothing
    }

    fn get_aux_assertions<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        _aux_rand_elements: &AuxRandElements<E>,
    ) -> Vec<Assertion<E>> {
        vec![]
    }

    fn get_gkr_proof_verifier<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
    ) -> Self::GkrVerifier {
        ()
    }

    fn get_logup_gkr_evaluator<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
    ) -> Self::LogUpGkrEvaluator {
        PlainLogUpGkrEval::default()
    }
}

#[derive(Clone, Default)]
pub struct PlainLogUpGkrEval<B: FieldElement> {
    _field: PhantomData<B>,
}

impl LogUpGkrEvaluator for PlainLogUpGkrEval<BaseElement> {
    type BaseField = BaseElement;

    type PublicInputs = ();

    type Query<E: FieldElement<BaseField = Self::BaseField>> = Vec<E>;

    fn get_oracles(&self) -> Vec<LogUpGkrOracle<Self::BaseField>> {
        let committed_0 = LogUpGkrOracle::CurrentRow(0);
        let committed_1 = LogUpGkrOracle::CurrentRow(1);
        let committed_2 = LogUpGkrOracle::CurrentRow(2);
        let committed_3 = LogUpGkrOracle::CurrentRow(3);
        let committed_4 = LogUpGkrOracle::CurrentRow(4);
        vec![committed_0, committed_1, committed_2, committed_3, committed_4]
    }

    fn get_num_rand_values(&self) -> usize {
        1
    }

    fn get_num_fractions(&self) -> usize {
        4
    }

    fn max_degree(&self) -> usize {
        3
    }

    fn build_query<E>(&self, frame: &EvaluationFrame<E>, _periodic_values: &[E]) -> Self::Query<E>
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        let cur = frame.current();
        cur.to_vec()
    }

    fn evaluate_query<F, E>(
        &self,
        query: &Self::Query<F>,
        rand_values: &[E],
        numerator: &mut [E],
        denominator: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>,
    {
        assert_eq!(numerator.len(), 4);
        assert_eq!(denominator.len(), 4);
        assert_eq!(query.len(), 5);
        numerator[0] = E::from(query[1]);
        numerator[1] = E::ONE;
        numerator[2] = E::ONE;
        numerator[3] = E::ONE;

        denominator[0] = rand_values[0] - E::from(query[0]);
        denominator[1] = -(rand_values[0] - E::from(query[2]));
        denominator[2] = -(rand_values[0] - E::from(query[3]));
        denominator[3] = -(rand_values[0] - E::from(query[4]));
    }

    fn compute_claim<E>(&self, _inputs: &Self::PublicInputs, _rand_values: &[E]) -> E
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        E::ZERO
    }
}
// LagrangeComplexProver
// ================================================================================================

struct LogUpGkrSimpleProver {
    aux_trace_width: usize,
    options: ProofOptions,
}

impl LogUpGkrSimpleProver {
    fn new(aux_trace_width: usize) -> Self {
        Self {
            aux_trace_width,
            options: ProofOptions::new(1, 2, 0, FieldExtension::None, 2, 1),
        }
    }
}

impl Prover for LogUpGkrSimpleProver {
    type BaseField = BaseElement;
    type Air = LagrangeKernelComplexAir;
    type Trace = LogUpGkrSimple;
    type HashFn = Blake3_256<BaseElement>;
    type VC = MerkleTree<Blake3_256<BaseElement>>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, LagrangeKernelComplexAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> <<Self as Prover>::Air as Air>::PublicInputs {
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>)
    where
        E: math::FieldElement<BaseField = Self::BaseField>,
    {
        DefaultTraceLde::new(trace_info, main_trace, domain)
    }

    fn new_evaluator<'a, E>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E>
    where
        E: math::FieldElement<BaseField = Self::BaseField>,
    {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn generate_gkr_proof<E>(
        &self,
        main_trace: &Self::Trace,
        public_coin: &mut Self::RandomCoin,
    ) -> (ProverGkrProof<Self>, GkrRandElements<E>)
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        let main_trace = main_trace.main_segment();
        let log_trace_len = main_trace.num_rows().ilog2() as usize;
        let lagrange_kernel_rand_elements = {
            let mut rand_elements = Vec::with_capacity(log_trace_len);
            for _ in 0..log_trace_len {
                rand_elements.push(public_coin.draw().unwrap());
            }

            LagrangeKernelRandElements::new(rand_elements)
        };

        ((), GkrRandElements::new(lagrange_kernel_rand_elements, Vec::new()))
    }

    fn build_aux_trace<E>(
        &self,
        main_trace: &Self::Trace,
        aux_rand_elements: &AuxRandElements<E>,
    ) -> ColMatrix<E>
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        let main_trace = main_trace.main_segment();
        let lagrange_kernel_rand_elements = aux_rand_elements
            .lagrange()
            .expect("expected lagrange random elements to be present.");

        let mut columns = Vec::new();

        // First all other auxiliary columns
        let rand_summed = lagrange_kernel_rand_elements.iter().fold(E::ZERO, |acc, &r| acc + r);
        for _ in 1..self.aux_trace_width {
            // building a dummy auxiliary column
            let column = main_trace
                .get_column(0)
                .iter()
                .map(|row_val| rand_summed.mul_base(*row_val))
                .collect();

            columns.push(column);
        }

        // then build the Lagrange kernel column
        {
            let r = &lagrange_kernel_rand_elements;

            let mut lagrange_col = Vec::with_capacity(main_trace.num_rows());

            for row_idx in 0..main_trace.num_rows() {
                let mut row_value = E::ONE;
                for (bit_idx, &r_i) in r.iter().enumerate() {
                    if row_idx & (1 << bit_idx) == 0 {
                        row_value *= E::ONE - r_i;
                    } else {
                        row_value *= r_i;
                    }
                }
                lagrange_col.push(row_value);
            }

            columns.push(lagrange_col);
        }

        ColMatrix::new(columns)
    }
}
