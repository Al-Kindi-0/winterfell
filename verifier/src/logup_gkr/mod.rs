mod sum_check;

use air::{
    proof::{
        evaluate_composition_poly, CircuitLayerPolys, FinalLayerProof, FinalOpeningClaim,
        GkrCircuitProof, SumCheckProof, SumCheckRoundClaim,
    },
    LogUpGkrEvaluator,
};
use alloc::vec::Vec;
use crypto::{ElementHasher, RandomCoin};
use math::{polynom::EqFunction, FieldElement};
use sum_check::verify_rounds;
pub use sum_check::Error as SumCheckVerifierError;

#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error("one of the claimed circuit denominators is zero")]
    ZeroOutputDenominator,
    #[error("the output of the fraction circuit is not equal to the expected value")]
    MismatchingCircuitOutput,
    #[error("failed to generate the random challenge")]
    FailedToGenerateChallenge,
    #[error("failed to verify the sum-check proof")]
    FailedToVerifySumCheck(#[from] SumCheckVerifierError),
}

/// Verifies the validity of a GKR proof for a LogUp-GKR relation.
pub fn verify_logup_gkr<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    claim: E,
    evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
    proof: &GkrCircuitProof<E>,
    log_up_randomness: Vec<E>,
    transcript: &mut C,
) -> Result<FinalOpeningClaim<E>, VerifierError> {
    let GkrCircuitProof {
        circuit_outputs,
        before_final_layer_proofs,
        final_layer_proof,
    } = proof;

    let CircuitLayerPolys { numerators, denominators } = circuit_outputs;
    let p0 = numerators.evaluations()[0];
    let p1 = numerators.evaluations()[1];
    let q0 = denominators.evaluations()[0];
    let q1 = denominators.evaluations()[1];

    // make sure that both denominators are not equal to E::ZERO
    if q0 == E::ZERO || q1 == E::ZERO {
        return Err(VerifierError::ZeroOutputDenominator);
    }

    // check that the output matches the expected `claim`
    if (p0 * q1 + p1 * q0) / (q0 * q1) != claim {
        return Err(VerifierError::MismatchingCircuitOutput);
    }

    // generate the random challenge to reduce two claims into a single claim
    let mut evaluations = numerators.evaluations().to_vec();
    evaluations.extend_from_slice(denominators.evaluations());
    transcript.reseed(H::hash_elements(&evaluations));
    let r = transcript.draw().map_err(|_| VerifierError::FailedToGenerateChallenge)?;

    // reduce the claim
    let p_r = p0 + r * (p1 - p0);
    let q_r = q0 + r * (q1 - q0);
    let mut reduced_claim = (p_r, q_r);

    // verify all GKR layers but for the last one
    let num_layers = before_final_layer_proofs.proof.len();
    let mut rand = vec![r];
    for i in 0..num_layers {
        let FinalOpeningClaim { eval_point, openings } = verify_sum_check_intermediate_layers(
            &before_final_layer_proofs.proof[i],
            &rand,
            reduced_claim,
            transcript,
        )?;

        // generate the random challenge to reduce two claims into a single claim
        transcript.reseed(H::hash_elements(&openings));
        let r_layer = transcript.draw().map_err(|_| VerifierError::FailedToGenerateChallenge)?;

        let p0 = openings[0];
        let p1 = openings[1];
        let q0 = openings[2];
        let q1 = openings[3];
        reduced_claim = (p0 + r_layer * (p1 - p0), q0 + r_layer * (q1 - q0));

        // collect the randomness used for the current layer
        let rand_sumcheck = eval_point;
        let mut ext = vec![r_layer];
        ext.extend_from_slice(&rand_sumcheck);
        rand = ext;
    }

    // verify the proof of the final GKR layer and pass final opening claim for verification
    // to the STARK
    verify_sum_check_input_layer(
        evaluator,
        final_layer_proof,
        log_up_randomness,
        &rand,
        reduced_claim,
        transcript,
    )
}

/// Verifies sum-check proofs, as part of the GKR proof, for all GKR layers except for the last one
/// i.e., the circuit input layer.
pub fn verify_sum_check_intermediate_layers<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    proof: &SumCheckProof<E>,
    gkr_eval_point: &[E],
    claim: (E, E),
    transcript: &mut C,
) -> Result<FinalOpeningClaim<E>, VerifierError> {
    // generate challenge to batch sum-checks
    transcript.reseed(H::hash_elements(&[claim.0, claim.1]));
    let r_batch: E = transcript.draw().map_err(|_| VerifierError::FailedToGenerateChallenge)?;

    // compute the claim for the batched sum-check
    let reduced_claim = claim.0 + claim.1 * r_batch;

    let SumCheckProof { openings_claim, round_proofs } = proof;

    let final_round_claim = verify_rounds(reduced_claim, &round_proofs, transcript)?;
    check_final_claim_intermediate_layers(
        final_round_claim,
        openings_claim.clone(),
        gkr_eval_point,
        r_batch,
    )?;

    Ok(openings_claim.clone())
}

fn check_final_claim_intermediate_layers<E: FieldElement>(
    final_round_claim: SumCheckRoundClaim<E>,
    openings_claim: FinalOpeningClaim<E>,
    gkr_eval_point: &[E],
    r_sum_check: E,
) -> Result<(), SumCheckVerifierError> {
    let FinalOpeningClaim { eval_point: eval_point_0, openings } = openings_claim;
    let SumCheckRoundClaim { eval_point: eval_point_1, claim } = final_round_claim;
    assert_eq!(eval_point_0, eval_point_1);

    let p0 = openings[0];
    let p1 = openings[1];
    let q0 = openings[2];
    let q1 = openings[3];

    let eq = EqFunction::new(gkr_eval_point.to_vec()).evaluate(&eval_point_0);

    if (p0 * q1 + p1 * q0 + r_sum_check * q0 * q1) * eq != claim {
        Err(SumCheckVerifierError::FinalEvaluationCheckFailed)
    } else {
        Ok(())
    }
}

/// Verifies the final sum-check proof as part of the GKR proof.
pub fn verify_sum_check_input_layer<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
    proof: &FinalLayerProof<E>,
    log_up_randomness: Vec<E>,
    gkr_eval_point: &[E],
    claim: (E, E),
    transcript: &mut C,
) -> Result<FinalOpeningClaim<E>, VerifierError> {
    let FinalLayerProof { before_merge_proof, after_merge_proof } = proof;

    // generate challenge to batch sum-checks
    transcript.reseed(H::hash_elements(&[claim.0, claim.1]));
    let r_sum_check: E = transcript.draw().map_err(|_| VerifierError::FailedToGenerateChallenge)?;

    // compute the claim for the batched sum-check
    let reduced_claim = claim.0 + claim.1 * r_sum_check;

    let SumCheckRoundClaim { eval_point: rand_merge, claim } =
        verify_rounds(reduced_claim, &before_merge_proof, transcript)?;

    verify_final(
        claim,
        after_merge_proof,
        rand_merge,
        r_sum_check,
        log_up_randomness,
        gkr_eval_point,
        evaluator,
        transcript,
    )
    .map_err(VerifierError::FailedToVerifySumCheck)
}

fn verify_final<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    claim: E,
    after_merge_proof: &SumCheckProof<E>,
    rand_merge: Vec<E>,
    r_sum_check: E,
    log_up_randomness: Vec<E>,
    gkr_eval_point: &[E],
    evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
    transcript: &mut C,
) -> Result<FinalOpeningClaim<E>, SumCheckVerifierError> {
    let SumCheckProof { openings_claim, round_proofs } = after_merge_proof;

    let SumCheckRoundClaim {
        eval_point: evaluation_point,
        claim: claimed_evaluation,
    } = verify_rounds(claim, round_proofs, transcript)?;

    if openings_claim.eval_point != evaluation_point {
        return Err(SumCheckVerifierError::WrongOpeningPoint);
    }

    let mut numerators = vec![E::ZERO; evaluator.get_num_fractions()];
    let mut denominators = vec![E::ZERO; evaluator.get_num_fractions()];

    evaluator.evaluate_query(
        &openings_claim.openings.clone(),
        &log_up_randomness,
        &mut numerators,
        &mut denominators,
    );

    let lagrange_ker = EqFunction::new(gkr_eval_point.to_vec());
    let mut gkr_point = rand_merge.clone();

    gkr_point.extend_from_slice(&openings_claim.eval_point.clone());
    let eq_eval = lagrange_ker.evaluate(&gkr_point);
    let tensored_merge_randomness = EqFunction::ml_at(rand_merge.to_vec()).evaluations().to_vec();
    let expected_evaluation = evaluate_composition_poly(
        &numerators,
        &denominators,
        eq_eval,
        r_sum_check,
        &tensored_merge_randomness,
    );

    if expected_evaluation != claimed_evaluation {
        Err(SumCheckVerifierError::FinalEvaluationCheckFailed)
    } else {
        Ok(openings_claim.clone())
    }
}
