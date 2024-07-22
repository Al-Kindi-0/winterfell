use std::marker::PhantomData;

use air::{AuxRandElements, ConstraintCompositionCoefficients, ProofOptions, TraceInfo, ZkParameters};
use crypto::{DefaultRandomCoin, ElementHasher, Hasher, SaltedMerkleTree};
use math::{fields::f64::BaseElement, FieldElement};
use prover::{
    matrix::ColMatrix, DefaultConstraintEvaluator, DefaultTraceLde, Prover, StarkDomain, Trace,
    TracePolyTable, TraceTable,
};
use rand::{
    distributions::{Distribution, Standard},
    SeedableRng,
};
use rand_chacha::ChaCha20Rng;
use utils::{Deserializable, Serializable};

use super::air::{apply_round, PublicInputs, RescueAir, DIGEST_SIZE, HASH_CYCLE_LEN};

// RESCUE PROVER
// ================================================================================================

pub struct RpoSignatureProver<H: ElementHasher>
where
    H: Sync,
{
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher + Sync> RpoSignatureProver<H> {
    pub fn new(options: ProofOptions) -> Self {
        Self { options, _hasher: PhantomData }
    }

    pub fn build_trace(
        &self,
        sk: [BaseElement; DIGEST_SIZE],
        msg: [BaseElement; DIGEST_SIZE],
    ) -> TraceTable<BaseElement> {
        let trace_length = HASH_CYCLE_LEN;
        let mut target = vec![];
        msg.write_into(&mut target);
        let mut trace = TraceTable::with_meta(12, trace_length, target);

        trace.fill(
            |state| {
                // initialize first state of the computation
                state[0] = BaseElement::ZERO;
                state[1] = BaseElement::ZERO;
                state[2] = BaseElement::ZERO;
                state[3] = BaseElement::ZERO;
                state[4] = sk[0];
                state[5] = sk[1];
                state[6] = sk[2];
                state[7] = sk[3];
                state[8] = BaseElement::ZERO;
                state[9] = BaseElement::ZERO;
                state[10] = BaseElement::ZERO;
                state[11] = BaseElement::ZERO;
            },
            |step, state| {
                apply_round(state.try_into().unwrap(), step);
            },
        );
        trace
    }
}

impl<H: ElementHasher> Prover for RpoSignatureProver<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
    Standard: Distribution<<H as Hasher>::Digest>,
{
    type BaseField = BaseElement;
    type Air = RescueAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = H;
    type VC = SaltedMerkleTree<H>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last_step = trace.length() - 1;
        let source = trace.meta_data().to_vec();
        let msg = <[BaseElement; DIGEST_SIZE]>::read_from_bytes(&source).unwrap();
        PublicInputs {
            pub_key: [
                trace.get(4, last_step),
                trace.get(5, last_step),
                trace.get(6, last_step),
                trace.get(7, last_step),
            ],
            msg,
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
