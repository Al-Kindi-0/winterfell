use std::marker::PhantomData;

use ::air::ProofOptions;
use ::prover::{Proof, Prover};
use air::{
    apply_round, PublicInputs, RescueAir, DIGEST_RANGE, DIGEST_SIZE, NUM_ROUNDS, STATE_WIDTH,
};
use crypto::{DefaultRandomCoin, ElementHasher, Hasher, SaltedMerkleTree};
use math::{fields::f64::BaseElement, FieldElement};
use prover::RpoSignatureProver;
use rand::distributions::{Distribution, Standard};
use verifier::{verify, AcceptableOptions, VerifierError};

mod air;
mod prover;

pub struct RpoSignature<H: ElementHasher> {
    options: ProofOptions,
    _h: PhantomData<H>,
}

impl<H: ElementHasher<BaseField = BaseElement> + Sync> RpoSignature<H>
where
    Standard: Distribution<<H as Hasher>::Digest>,
{
    pub fn new(options: ProofOptions) -> Self {
        RpoSignature { options, _h: PhantomData }
    }

    pub fn sign(&self, sk: [BaseElement; DIGEST_SIZE], msg: [BaseElement; DIGEST_SIZE]) -> Proof {
        // create a prover
        let prover = RpoSignatureProver::<H>::new(self.options.clone());

        // generate execution trace
        let trace = prover.build_trace(sk, msg);

        // generate the proof
        prover.prove(trace).expect("failed to generate the signature")
    }

    pub fn verify(
        &self,
        pub_key: [BaseElement; DIGEST_SIZE],
        msg: [BaseElement; DIGEST_SIZE],
        proof: Proof,
    ) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs { pub_key, msg };
        let acceptable_options = AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        verify::<RescueAir, H, DefaultRandomCoin<H>, SaltedMerkleTree<H>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
    }
}

// HELPER FUNCTIONS
// ================================================================================================

pub fn hash(sk: [BaseElement; DIGEST_SIZE]) -> [BaseElement; DIGEST_SIZE] {
    let mut state = [BaseElement::ZERO; STATE_WIDTH];
    state[DIGEST_RANGE].copy_from_slice(&sk);
    for i in 0..NUM_ROUNDS {
        apply_round(&mut state, i);
    }
    state[DIGEST_RANGE].try_into().unwrap()
}

#[test]
fn test() {
    let sk = [BaseElement::ZERO; DIGEST_SIZE];
    let msg = [BaseElement::ZERO; DIGEST_SIZE];

    let pk = hash(sk);
    let options = ProofOptions::new(89, 8, 0, ::air::FieldExtension::Cubic, 8, 255, true);
    let signature: RpoSignature<crypto::hashers::Rp64_256> = RpoSignature::new(options);

    let s = signature.sign(sk, msg);
    signature.verify(pk, msg, s).expect("msg");
}
