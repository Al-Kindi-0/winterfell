mod error;
use air::proof::{RoundProof, SumCheckRoundClaim};
use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;

pub use self::error::Error;

/// Verifies a round of the sum-check protocol.
pub fn verify_rounds<E, C, H>(
    claim: E,
    round_proofs: &[RoundProof<E>],
    coin: &mut C,
) -> Result<SumCheckRoundClaim<E>, Error>
where
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
{
    let mut round_claim = claim;
    let mut evaluation_point = vec![];
    for round_proof in round_proofs {
        let round_poly_coefs = round_proof.round_poly_coefs.clone();
        coin.reseed(H::hash_elements(&round_poly_coefs.coefficients));

        let r = coin.draw().map_err(|_| Error::FailedToGenerateChallenge)?;

        round_claim = round_proof.round_poly_coefs.evaluate_using_claim(&round_claim, &r);
        evaluation_point.push(r);
    }

    Ok(SumCheckRoundClaim {
        eval_point: evaluation_point,
        claim: round_claim,
    })
}
