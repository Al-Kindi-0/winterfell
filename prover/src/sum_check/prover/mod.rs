use crate::FieldElement;

use super::reduce_claim;
use air::{
    proof::{
        CompositionPolynomial, FinalClaimBuilder, FinalOpeningClaim, RoundProof, SumCheckProof,
        SumCheckRoundClaim,
    },
    LogUpGkrEvaluator,
};
use alloc::vec::Vec;
use core::marker::PhantomData;
use crypto::{ElementHasher, RandomCoin};
use libc_print::libc_println;
use math::polynom::{EqFunction, MultiLinearPoly, UnivariatePolyEvals};

mod error;
pub use self::error::Error;

/// A struct that contains relevant information for the execution of the multivariate sum-check
/// protocol prover.
/// The sum-check protocol is an interactive protocol (IP) for proving the following relation:
///
/// v = \sum_{(x_0,\cdots, x_{\nu - 1}) \in \{0 , 1\}^{\nu}}
///                     g(f_0((x_0,\cdots, x_{\nu - 1})), \cdots , f_c((x_0,\cdots, x_{\nu - 1})))
///
/// where:
///
/// 1. v ∈ 𝔽 where 𝔽 is a finite field.
/// 2. f_i are multi-linear polynomials i.e., polynomials in 𝔽[X_0, \cdots ,X_{\nu - 1}] with degree
///    at most one in each variable.
/// 3. g is a multivariate polynomial with degree at most d in each variable.
///
/// The Verifier is given commitments to each `f_i` in addition to the claimed sum `v`. The Prover
/// then engages in an IP to convince the Verifier that the above relation holds for the given
/// `f_i` and `v`. More precisely:
///
/// 0. Denote by w(x_0,\cdots, x_{\nu - 1}) := g(f_0((x_0,\cdots, x_{\nu - 1})), \cdots ,
///    f_c((x_0,\cdots, x_{\nu - 1}))).
///
/// 1. In the first round, the Prover sends the polynomial defined by: s_0(X_0) :=
///    \sum_{(x_{1},\cdots, x_{\nu - 1})  w(X_0, x_{1}, \cdots, x_{\nu - 1})
///
/// 2. The Verifier then checks that s_0(0) + s_0(1) = v rejecting if not.
///
/// 3. The Verifier samples a random challenge `r_0 ∈ 𝔽` and sends it to the Prover.
///
/// 4. For each i in 1...(\nu - 1):
///
///   a. The Prover sends the univariate polynomial defined by:
///
/// ```ignore
///         s_i(X_i) := \sum_{(x_{i + 1},\cdots, x_{\nu - 1})
///                                  w(r_0,\cdots, r_{i - 1}, X_i, x_{i + 1}, \cdots, x_{\nu - 1}).
/// ```
///   b. The Verifier checks that s_{i - 1}(r_{i - 1}) = s_{i}(0) + s_{i}(1) rejecting if not.
///   c. The Verifier samples a random challenge `r_i ∈ 𝔽` and sends it to the Prover.
///
/// 5. The Verifier now queries each of the oracles behind the commitments i.e., `f_i` at `(r_0,
///    \cdots , r_{\nu - 1})` to get u_i = f_i(r_0, \cdots , r_{\nu - 1}). The Verifier then accepts
///    if and only if:
///
/// ```ignore
///         s_{\nu - 1}(r_{\nu - 1}) = g(u_0, \cdots , u_{\nu - 1})
/// ```
///
/// A few remarks:
///
/// 1. The degree bound on `g` implies that each of the `s_i` polynomials is a univariate polynomial
///    of degree at most `d`. Thus, the Prover in each round sends `d + 1` values, either the
///    coefficients or the evaluations of `s_i`.
///
/// 2. The Prover has each `f_i` in its evaluation form over the hyper-cube \{0 , 1\}^{\nu}.
///
/// 3. An optimization is for the Prover to not send `s_i(0)` as it can be recovered from the
///    current reduced claim s_{i - 1}(r_{i - 1}) using the relation s_{i}(0) = s_{i}(1) - s_{i -
///    1}(r_{i - 1}). This also means that the Verifier can skip point 4.b.
pub struct SumCheckProver<E, P, C, H, V>
where
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
    V: FinalClaimBuilder<Field = E>,
{
    composition_poly: P,
    final_claim_builder: V,

    _challenger: PhantomData<C>,
}

impl<E, P, C, H, V> SumCheckProver<E, P, C, H, V>
where
    E: FieldElement,
    P: CompositionPolynomial<E>,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
    V: FinalClaimBuilder<Field = E>,
{
    /// Constructs a new [SumCheckProver] given a multivariate composition polynomial.
    /// The multivariate composition polynomial corresponds to the `g` polynomial in the
    /// description of the [SumCheckProver] struct.
    pub fn new(composition_poly: P, final_claim_builder: V) -> Self {
        Self {
            composition_poly,
            final_claim_builder,
            _challenger: PhantomData,
        }
    }

    /// Given an initial claim `claim`, a mutable vector of multi-linear polynomials `mls` and
    /// a number of rounds `num_rounds`, computes `num_rounds` iterations of the sum-check protocol
    /// starting from claim `claim`.
    ///
    /// More specifically, executes the sum-check protocol for the following relation
    ///
    /// v = \sum_{(x_0,\cdots, x_{\nu - 1}) \in \{0 , 1\}^{\nu}}
    ///                     g(f_0((x_0,\cdots, x_{\nu - 1})), \cdots , f_c((x_0,\cdots, x_{\nu -
    /// 1})))
    ///
    /// where:
    ///
    /// 1. `claim` is v.
    /// 2. `mls` is [f_0, ..., f_c].
    /// 3. `self.composition_poly` is g.
    ///
    /// # Errors
    /// Returns an error if:
    /// - No multi-linears were provided.
    /// - Number of rounds is zero or is greater than the number of variables of the multilinears.
    /// - The provided multi-linears have different arities.
    pub fn prove(
        &self,
        claim: E,
        mut mls: Vec<MultiLinearPoly<E>>,
        coin: &mut C,
    ) -> Result<SumCheckProof<E>, Error> {
        let num_rounds = mls[0].num_variables();
        let (SumCheckRoundClaim { eval_point, claim: _claim }, round_proofs) =
            self.prove_rounds(claim, &mut mls, num_rounds, coin)?;

        let openings = mls.iter_mut().map(|ml| ml.evaluations()[0]).collect();
        let openings_claim = self.final_claim_builder.build_claim(openings, &eval_point);

        Ok(SumCheckProof { openings_claim, round_proofs })
    }

    /// Proves a round of the sum-check protocol.
    pub fn prove_rounds(
        &self,
        claim: E,
        mls: &mut [MultiLinearPoly<E>],
        num_rounds: usize,
        coin: &mut C,
    ) -> Result<(SumCheckRoundClaim<E>, Vec<RoundProof<E>>), Error> {
        // there should be at least one multi-linear polynomial provided
        if mls.is_empty() {
            return Err(Error::NoMlsProvided);
        }

        // there should be at least one round to prove
        if num_rounds == 0 {
            return Err(Error::NumRoundsZero);
        }

        // there can not be more rounds than variables of the multi-linears
        let ml_variables = mls[0].num_variables();
        if num_rounds > ml_variables {
            return Err(Error::TooManyRounds);
        }

        // there should at least be one variable for the protocol to be non-trivial
        if ml_variables < 1 {
            return Err(Error::AtLeastOneVariable);
        }

        // all multi-linears should have the same arity
        if !mls.iter().all(|ml| ml.num_variables() == ml_variables) {
            return Err(Error::MlesDifferentArities);
        }

        let mut round_proofs = vec![];

        // setup first round claim
        let mut current_round_claim = SumCheckRoundClaim { eval_point: vec![], claim };

        // run the first round of the protocol
        let round_poly_evals = sumcheck_round(&self.composition_poly, mls);
        let round_poly_coefs = round_poly_evals.to_poly(current_round_claim.claim);

        // reseed with the s_0 polynomial
        coin.reseed(H::hash_elements(&round_poly_coefs.coefficients));
        round_proofs.push(RoundProof { round_poly_coefs });

        for i in 1..num_rounds {
            // generate random challenge r_i for the i-th round
            let round_challenge = coin.draw().map_err(|_| Error::FailedToGenerateChallenge)?;

            // compute the new reduced round claim
            let new_round_claim =
                reduce_claim(&round_proofs[i - 1], current_round_claim, round_challenge);

            // fold each multi-linear using the round challenge
            mls.iter_mut()
                .for_each(|ml| ml.bind_least_significant_variable(round_challenge));

            // run the i-th round of the protocol using the folded multi-linears for the new reduced
            // claim. This basically computes the s_i polynomial.
            let round_poly_evals = sumcheck_round(&self.composition_poly, mls);

            // update the claim
            current_round_claim = new_round_claim;
            let round_poly_coefs = round_poly_evals.to_poly(current_round_claim.claim);

            // reseed with the s_i polynomial
            coin.reseed(H::hash_elements(&round_poly_coefs.coefficients));
            let round_proof = RoundProof { round_poly_coefs };
            round_proofs.push(round_proof);
        }

        // generate the last random challenge
        let round_challenge = coin.draw().map_err(|_| Error::FailedToGenerateChallenge)?;
        // fold each multi-linear using the last random challenge
        mls.iter_mut()
            .for_each(|ml| ml.bind_least_significant_variable(round_challenge));

        let round_claim =
            reduce_claim(&round_proofs[num_rounds - 1], current_round_claim, round_challenge);
        Ok((round_claim, round_proofs))
    }
}

/// Computes the polynomial
///
/// s_i(X_i) := \sum_{(x_{i + 1},\cdots, x_{\nu - 1})
///                                  w(r_0,\cdots, r_{i - 1}, X_i, x_{i + 1}, \cdots, x_{\nu - 1}).
/// where
///
/// w(x_0,\cdots, x_{\nu - 1}) := g(f_0((x_0,\cdots, x_{\nu - 1})),
///                                                       \cdots , f_c((x_0,\cdots, x_{\nu - 1}))).
///
/// Given a degree bound `d_max` for all variables, it suffices to compute the evaluations of `s_i`
/// at `d_max + 1` points. Given that `s_{i}(0) = s_{i}(1) - s_{i - 1}(r_{i - 1})` it is sufficient
/// to compute the evaluations on only `d_max` points.
///
/// The algorithm works by iterating over the variables (x_{i + 1}, \cdots, x_{\nu - 1}) in
/// {0, 1}^{\nu - 1 - i}. For each such tuple, we store the evaluations of the (folded)
/// multi-linears at (0, x_{i + 1}, \cdots, x_{\nu - 1}) and
/// (1, x_{i + 1}, \cdots, x_{\nu - 1}) in two arrays, `evals_zero` and `evals_one`.
/// Using `evals_one`, remember that we optimize evaluating at 0 away, we get the first evaluation
/// i.e., `s_i(1)`.
///
/// For the remaining evaluations, we use the fact that the folded `f_i` is multi-linear and hence
/// we can write
///
/// ```ignore
///     f_i(X_i, x_{i + 1}, \cdots, x_{\nu - 1}) =
///        (1 - X_i) . f_i(0, x_{i + 1}, \cdots, x_{\nu - 1}) +
///        X_i . f_i(1, x_{i + 1}, \cdots, x_{\nu - 1})
/// ```
///
/// Note that we omitted writing the folding randomness for readability.
/// Since the evaluation domain is {0, 1, ... , d_max}, we can compute the evaluations based on
/// the previous one using only additions. This is the purpose of `deltas`, to hold the increments
/// added to each multi-linear to compute the evaluation at the next point, and `evals_x` to hold
/// the current evaluation at `x` in {2, ... , d_max}.
fn sumcheck_round<E: FieldElement, P: CompositionPolynomial<E>>(
    composition_poly: &P,
    mls: &[MultiLinearPoly<E>],
) -> UnivariatePolyEvals<E> {
    let num_ml = mls.len();
    let num_vars = mls[0].num_variables();
    let num_rounds = num_vars - 1;

    let mut evals_zero = vec![E::ZERO; num_ml];
    let mut evals_one = vec![E::ZERO; num_ml];
    let mut deltas = vec![E::ZERO; num_ml];
    let mut evals_x = vec![E::ZERO; num_ml];

    let total_evals = (0..1 << num_rounds).map(|i| {
        for (j, ml) in mls.iter().enumerate() {
            // Holds `f(x_{i+1}, ..., x_v, 0)`
            evals_zero[j] = ml.evaluations()[2 * i];

            // Holds `f(x_{i+1}, ..., x_v, 1)`
            evals_one[j] = ml.evaluations()[2 * i + 1];
        }

        let mut total_evals = vec![E::ZERO; composition_poly.max_degree() as usize];
        total_evals[0] = composition_poly.evaluate(&evals_one);

        evals_zero
            .iter()
            .zip(evals_one.iter().zip(deltas.iter_mut().zip(evals_x.iter_mut())))
            .for_each(|(a0, (a1, (delta, evx)))| {
                *delta = *a1 - *a0;
                *evx = *a1;
            });

        total_evals.iter_mut().skip(1).for_each(|e| {
            evals_x.iter_mut().zip(deltas.iter()).for_each(|(evx, delta)| {
                *evx += *delta;
            });
            *e = composition_poly.evaluate(&evals_x);
        });
        total_evals
    });

    let evaluations = total_evals.fold(
        vec![E::ZERO; composition_poly.max_degree() as usize],
        |mut acc, evals| {
            acc.iter_mut().zip(evals.iter()).for_each(|(a, ev)| *a += *ev);
            acc
        },
    );

    UnivariatePolyEvals { partial_evaluations: evaluations }
}

/// .
///
/// # Errors
///
/// This function will return an error if .
pub fn sum_check_prove_final<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    evaluator: &impl LogUpGkrEvaluator<BaseField = <E as FieldElement>::BaseField>,
    claim: E,
    r_sum_check: E,
    rand_merge: Vec<E>,
    log_up_randomness: Vec<E>,
    merged_mls: &mut Vec<MultiLinearPoly<E>>,
    mls: &mut Vec<MultiLinearPoly<E>>,
    coin: &mut C,
) -> Result<SumCheckProof<E>, Error> {
    let num_rounds = mls[0].num_variables();

    let mut round_proofs = vec![];

    // setup first round claim
    let mut current_round_claim = SumCheckRoundClaim { eval_point: vec![], claim };
    let tensored_merge_randomness = EqFunction::ml_at(rand_merge.to_vec()).evaluations().to_vec();

    // run the first round of the protocol
    let round_poly_evals = sumcheck_round_ver2(
        evaluator.clone(),
        mls,
        &merged_mls,
        &log_up_randomness,
        r_sum_check,
        &tensored_merge_randomness,
    );
    let round_poly_coefs = round_poly_evals.to_poly(current_round_claim.claim);

    // reseed with the s_0 polynomial
    coin.reseed(H::hash_elements(&round_poly_coefs.coefficients));
    round_proofs.push(RoundProof { round_poly_coefs });

    for i in 1..num_rounds {
        // generate random challenge r_i for the i-th round
        let round_challenge = coin.draw().map_err(|_| Error::FailedToGenerateChallenge)?;

        // compute the new reduced round claim
        let new_round_claim =
            reduce_claim(&round_proofs[i - 1], current_round_claim, round_challenge);

        // fold each multi-linear using the round challenge
        mls.iter_mut()
            .for_each(|ml| ml.bind_least_significant_variable(round_challenge));

        merged_mls
            .iter_mut()
            .for_each(|ml| ml.bind_least_significant_variable(round_challenge));

        // run the i-th round of the protocol using the folded multi-linears for the new reduced
        // claim. This basically computes the s_i polynomial.
        let round_poly_evals = sumcheck_round_ver2(
            evaluator.clone(),
            mls,
            merged_mls,
            &log_up_randomness,
            r_sum_check,
            &tensored_merge_randomness,
        );

        // update the claim
        current_round_claim = new_round_claim;

        let round_poly_coefs = round_poly_evals.to_poly(current_round_claim.claim);

        // reseed with the s_i polynomial
        coin.reseed(H::hash_elements(&round_poly_coefs.coefficients));
        let round_proof = RoundProof { round_poly_coefs };
        round_proofs.push(round_proof);
    }

    // generate the last random challenge
    let round_challenge = coin.draw().map_err(|_| Error::FailedToGenerateChallenge)?;

    // fold each multi-linear using the last random challenge
    mls.iter_mut()
        .for_each(|ml| ml.bind_least_significant_variable(round_challenge));
    merged_mls
        .iter_mut()
        .for_each(|ml| ml.bind_least_significant_variable(round_challenge));

    let SumCheckRoundClaim { eval_point, claim: _claim } =
        reduce_claim(&round_proofs[num_rounds - 1], current_round_claim, round_challenge);

    let openings = mls.iter_mut().map(|ml| ml.evaluations()[0]).collect();
    let openings_claim = build_final_claim(openings, eval_point);

    Ok(SumCheckProof { openings_claim, round_proofs })
}

fn build_final_claim<E: FieldElement>(
    openings: Vec<E>,
    eval_point: Vec<E>,
) -> FinalOpeningClaim<E> {
    FinalOpeningClaim { eval_point, openings }
}

fn sumcheck_round_ver2<E: FieldElement>(
    evaluator: impl LogUpGkrEvaluator<BaseField = <E as FieldElement>::BaseField>,
    mls: &[MultiLinearPoly<E>],
    merged_mls: &[MultiLinearPoly<E>],
    log_up_randomness: &[E],
    r_sum_check: E,
    tensored_merge_randomness: &[E],
) -> UnivariatePolyEvals<E> {
    let num_ml = mls.len();
    let num_vars = mls[0].num_variables();
    let num_rounds = num_vars - 1;
    let mut evals_one = vec![E::ZERO; num_ml];
    let mut evals_zero = vec![E::ZERO; num_ml];
    let mut evals_x = vec![E::ZERO; num_ml];

    let mut deltas = vec![E::ZERO; num_ml];

    let mut numerators = vec![E::ZERO; evaluator.get_num_fractions()];
    let mut denominators = vec![E::ZERO; evaluator.get_num_fractions()];

    let total_evals = (0..1 << num_rounds).map(|i| {
        let mut total_evals = vec![E::ZERO; evaluator.max_degree() as usize];

        for (j, ml) in mls.iter().enumerate() {
            // Holds `f(x_{i+1}, ..., x_v, 0)`
            evals_zero[j] = ml.evaluations()[2 * i];

            // Holds `f(x_{i+1}, ..., x_v, 1)`
            evals_one[j] = ml.evaluations()[2 * i + 1];
        }

        let eq_at_zero = merged_mls[4].evaluations()[2 * i];
        let eq_at_one = merged_mls[4].evaluations()[2 * i + 1];

        let p0 = merged_mls[0][2 * i + 1];
        let p1 = merged_mls[1][2 * i + 1];
        let q0 = merged_mls[2][2 * i + 1];
        let q1 = merged_mls[3][2 * i + 1];

        total_evals[0] = (p0 * q1 + p1 * q0 + r_sum_check * q0 * q1) * eq_at_one;

        evals_zero
            .iter()
            .zip(evals_one.iter().zip(deltas.iter_mut().zip(evals_x.iter_mut())))
            .for_each(|(a0, (a1, (delta, evx)))| {
                *delta = *a1 - *a0;
                *evx = *a1;
            });
        let eq_delta = eq_at_one - eq_at_zero;
        let mut eq_x = eq_at_one;

        for e in total_evals.iter_mut().skip(1) {
            evals_x.iter_mut().zip(deltas.iter()).for_each(|(evx, delta)| {
                *evx += *delta;
            });
            eq_x += eq_delta;

            evaluator.evaluate_query(
                &evals_x.clone().into(),
                &log_up_randomness,
                &mut numerators,
                &mut denominators,
            );

            *e = evaluate_composition_poly(
                &numerators,
                &denominators,
                eq_x,
                r_sum_check,
                &tensored_merge_randomness,
            );
        }

        total_evals
    });

    let evaluations =
        total_evals.fold(vec![E::ZERO; evaluator.max_degree() as usize], |mut acc, evals| {
            acc.iter_mut().zip(evals.iter()).for_each(|(a, ev)| *a += *ev);
            acc
        });

    UnivariatePolyEvals { partial_evaluations: evaluations }
}

fn evaluate_composition_poly<E: FieldElement>(
    numerators: &[E],
    denominators: &[E],
    eq_eval: E,
    r_sum_check: E,
    tensored_merge_randomness: &[E],
) -> E {
    let numerators = MultiLinearPoly::from_evaluations(numerators.to_vec()).unwrap();
    let denominators = MultiLinearPoly::from_evaluations(denominators.to_vec()).unwrap();

    let (left_numerators, right_numerators) = numerators.project_least_significant_variable();
    let (left_denominators, right_denominators) = denominators.project_least_significant_variable();

    let eval_left_numerators =
        left_numerators.evaluate_with_lagrange_kernel(&tensored_merge_randomness);
    let eval_right_numerators =
        right_numerators.evaluate_with_lagrange_kernel(&tensored_merge_randomness);

    let eval_left_denominators =
        left_denominators.evaluate_with_lagrange_kernel(&tensored_merge_randomness);
    let eval_right_denominators =
        right_denominators.evaluate_with_lagrange_kernel(&tensored_merge_randomness);

    eq_eval
        * ((eval_left_numerators * eval_right_denominators
            + eval_right_numerators * eval_left_denominators)
            + eval_left_denominators * eval_right_denominators * r_sum_check)
}

pub fn sumcheck_prove_plain<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    num_rounds: usize,
    claim: E,
    r_batch: E,
    p0: &mut MultiLinearPoly<E>,
    p1: &mut MultiLinearPoly<E>,
    q0: &mut MultiLinearPoly<E>,
    q1: &mut MultiLinearPoly<E>,
    eq: &mut MultiLinearPoly<E>,
    transcript: &mut C,
) -> Result<(SumCheckProof<E>, E), Error> {
    let mut round_proofs = vec![];

    let mut claim = claim;
    let mut challenges = vec![];
    for _ in 0..num_rounds {
        let mut eval_point_0 = E::ZERO;
        let mut eval_point_2 = E::ZERO;
        let mut eval_point_3 = E::ZERO;

        let len = p0.num_evaluations() / 2;
        for i in 0..len {
            eval_point_0 +=
                comb_func(&p0[2 * i], &p1[2 * i], &q0[2 * i], &q1[2 * i], &eq[2 * i], &r_batch);
            let p0_delta = p0[2 * i + 1] - p0[2 * i];
            let p1_delta = p1[2 * i + 1] - p1[2 * i];
            let q0_delta = q0[2 * i + 1] - q0[2 * i];
            let q1_delta = q1[2 * i + 1] - q1[2 * i];
            let eq_delta = eq[2 * i + 1] - eq[2 * i];

            let mut p0_evx = p0[2 * i + 1] + p0_delta;
            let mut p1_evx = p1[2 * i + 1] + p1_delta;
            let mut q0_evx = q0[2 * i + 1] + q0_delta;
            let mut q1_evx = q1[2 * i + 1] + q1_delta;
            let mut eq_evx = eq[2 * i + 1] + eq_delta;
            eval_point_2 += comb_func(&p0_evx, &p1_evx, &q0_evx, &q1_evx, &eq_evx, &r_batch);

            p0_evx += p0_delta;
            p1_evx += p1_delta;
            q0_evx += q0_delta;
            q1_evx += q1_delta;
            eq_evx += eq_delta;

            eval_point_3 += comb_func(&p0_evx, &p1_evx, &q0_evx, &q1_evx, &eq_evx, &r_batch);
        }

        let evals = vec![
            claim - eval_point_0, // Optimization applied using the claim to reduce the number of sums computed
            eval_point_2,
            eval_point_3,
        ];
        let poly = UnivariatePolyEvals { partial_evaluations: evals };
        let round_poly_coefs = poly.to_poly(claim);

        // reseed with the s_i polynomial
        transcript.reseed(H::hash_elements(&round_poly_coefs.coefficients));
        let round_proof = RoundProof {
            round_poly_coefs: round_poly_coefs.clone(),
        };

        round_proofs.push(round_proof);

        let round_challenge = transcript.draw().map_err(|_| Error::FailedToGenerateChallenge)?;

        // compute the new reduced round claim
        let new_claim = round_poly_coefs.evaluate_using_claim(&claim, &round_challenge);

        // fold each multi-linear using the round challenge
        p0.bind_least_significant_variable(round_challenge);
        p1.bind_least_significant_variable(round_challenge);
        q0.bind_least_significant_variable(round_challenge);
        q1.bind_least_significant_variable(round_challenge);
        eq.bind_least_significant_variable(round_challenge);

        challenges.push(round_challenge);

        claim = new_claim;
    }

    let openings = vec![p0[0], p1[0], q0[0], q1[0]];

    let final_opening_claim = FinalOpeningClaim { eval_point: challenges, openings };

    Ok((
        SumCheckProof {
            openings_claim: final_opening_claim,
            round_proofs,
        },
        claim,
    ))
}

fn comb_func<E: FieldElement>(p0: &E, p1: &E, q0: &E, q1: &E, eq: &E, r_batch: &E) -> E {
    (*p0 * *q1 + *p1 * *q0 + *r_batch * *q0 * *q1) * *eq
}
