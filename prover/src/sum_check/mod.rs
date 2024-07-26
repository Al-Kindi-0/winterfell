use air::proof::{RoundProof, SumCheckRoundClaim};
use math::FieldElement;
pub use prover::{sum_check_prove_higher_degree, Error as SumCheckProverError, sumcheck_prove_plain};

mod prover;

/// Reduces an old claim to a new claim using the round challenge.
pub fn reduce_claim<E: FieldElement>(
    current_poly: &RoundProof<E>,
    current_round_claim: SumCheckRoundClaim<E>,
    round_challenge: E,
) -> SumCheckRoundClaim<E> {
    // evaluate the round polynomial at the round challenge to obtain the new claim
    let new_claim = current_poly
        .round_poly_coefs
        .evaluate_using_claim(&current_round_claim.claim, &round_challenge);

    // update the evaluation point using the round challenge
    let mut new_partial_eval_point = current_round_claim.eval_point;
    new_partial_eval_point.push(round_challenge);

    SumCheckRoundClaim {
        eval_point: new_partial_eval_point,
        claim: new_claim,
    }
}
