use alloc::vec::Vec;

use air::{
    proof::{
        BeforeFinalLayerProof, CircuitLayer, CircuitLayerPolys, CircuitWire, FinalLayerProof,
        FinalOpeningClaim, GkrCircuitProof, SumCheckProof,
    },
    EvaluationFrame, LogUpGkrEvaluator,
};
use crypto::{ElementHasher, RandomCoin};
use error::GkrProverError;
use math::{
    polynom::{EqFunction, MultiLinearPoly},
    FieldElement,
};

use crate::{matrix::ColMatrix, sum_check_prove_higher_degree, sumcheck_prove_plain, Trace};

mod error;

// EVALUATED CIRCUIT
// ================================================================================================

/// Evaluation of a layered circuit for computing a sum of fractions.
///
/// The circuit computes a sum of fractions based on the formula a / c + b / d = (a * d + b * c) /
/// (c * d) which defines a "gate" ((a, b), (c, d)) --> (a * d + b * c, c * d) upon which the
/// [`EvaluatedCircuit`] is built. Due to the uniformity of the circuit, each of the circuit
/// layers collect all the:
///
/// 1. `a`'s into a [`MultiLinearPoly`] called `left_numerators`.
/// 2. `b`'s into a [`MultiLinearPoly`] called `right_numerators`.
/// 3. `c`'s into a [`MultiLinearPoly`] called `left_denominators`.
/// 4. `d`'s into a [`MultiLinearPoly`] called `right_denominators`.
///
/// The relation between two subsequent layers is given by the formula
///
/// p_0[layer + 1](x_0, x_1, ..., x_{ν - 2}) = p_0[layer](x_0, x_1, ..., x_{ν - 2}, 0) *
/// q_1[layer](x_0, x_1, ..., x_{ν - 2}, 0)
///                                  + p_1[layer](x_0, x_1, ..., x_{ν - 2}, 0) * q_0[layer](x_0,
///                                    x_1, ..., x_{ν - 2}, 0)
///
/// p_1[layer + 1](x_0, x_1, ..., x_{ν - 2}) = p_0[layer](x_0, x_1, ..., x_{ν - 2}, 1) *
/// q_1[layer](x_0, x_1, ..., x_{ν - 2}, 1)
///                                  + p_1[layer](x_0, x_1, ..., x_{ν - 2}, 1) * q_0[layer](x_0,
///                                    x_1, ..., x_{ν - 2}, 1)
///
/// and
///
/// q_0[layer + 1](x_0, x_1, ..., x_{ν - 2}) = q_0[layer](x_0, x_1, ..., x_{ν - 2}, 0) *
/// q_1[layer](x_0, x_1, ..., x_{ν - 1}, 0)                                  
/// q_1[layer + 1](x_0, x_1, ..., x_{ν - 2}) = q_0[layer](x_0, x_1, ..., x_{ν - 2}, 1) *
/// q_1[layer](x_0, x_1, ..., x_{ν - 1}, 1)
///
/// This logic is encoded in [`CircuitWire`].
///
/// This means that layer ν will be the output layer and will consist of four values
/// (p_0[ν - 1], p_1[ν - 1], p_0[ν - 1], p_1[ν - 1]) ∈ 𝔽^ν.
pub struct EvaluatedCircuit<E: FieldElement> {
    layer_polys: Vec<CircuitLayerPolys<E>>,
}

impl<E: FieldElement> EvaluatedCircuit<E> {
    /// Creates a new [`EvaluatedCircuit`] by evaluating the circuit where the input layer is
    /// defined from the main trace columns.
    pub fn new(
        main_trace_columns: &impl Trace<BaseField = E::BaseField>,
        evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
        log_up_randomness: &[E],
    ) -> Result<Self, GkrProverError> {
        let mut layer_polys = Vec::new();

        let mut current_layer =
            Self::generate_input_layer(main_trace_columns, evaluator, log_up_randomness);
        while current_layer.num_wires() > 1 {
            let next_layer = Self::compute_next_layer(&current_layer);

            layer_polys.push(CircuitLayerPolys::from_circuit_layer(current_layer));

            current_layer = next_layer;
        }

        Ok(Self { layer_polys })
    }

    /// Returns a layer of the evaluated circuit.
    ///
    /// Note that the return type is [`LayerPolys`] as opposed to [`Layer`], since the evaluated
    /// circuit is stored in a representation which can be proved using GKR.
    pub fn get_layer(&self, layer_idx: usize) -> &CircuitLayerPolys<E> {
        &self.layer_polys[layer_idx]
    }

    /// Returns all layers of the evaluated circuit, starting from the input layer.
    ///
    /// Note that the return type is a slice of [`CircuitLayerPolys`] as opposed to
    /// [`CircuitLayer`], since the evaluated layers are stored in a representation which can be
    /// proved using GKR.
    pub fn layers(&self) -> &[CircuitLayerPolys<E>] {
        &self.layer_polys
    }

    /// Returns the numerator/denominator polynomials representing the output layer of the circuit.
    pub fn output_layer(&self) -> &CircuitLayerPolys<E> {
        self.layer_polys.last().expect("circuit has at least one layer")
    }

    /// Evaluates the output layer at `query`, where the numerators of the output layer are treated
    /// as evaluations of a multilinear polynomial, and similarly for the denominators.
    pub fn evaluate_output_layer(&self, query: E) -> (E, E) {
        let CircuitLayerPolys { numerators, denominators } = self.output_layer();

        (numerators.evaluate(&[query]), denominators.evaluate(&[query]))
    }

    // HELPERS
    // -------------------------------------------------------------------------------------------

    /// Generates the input layer of the circuit from the main trace columns and some randomness
    /// provided by the verifier.
    fn generate_input_layer(
        main_trace: &impl Trace<BaseField = E::BaseField>,
        evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
        log_up_randomness: &[E],
    ) -> CircuitLayer<E> {
        let num_fractions = evaluator.get_num_fractions();
        let mut input_layer_wires =
            Vec::with_capacity(main_trace.main_segment().num_rows() * num_fractions);
        let mut main_frame = EvaluationFrame::new(main_trace.main_segment().num_cols());

        let mut numerators = vec![E::ZERO; num_fractions];
        let mut denominators = vec![E::ZERO; num_fractions];
        for i in 0..main_trace.main_segment().num_rows() {
            let wires_from_trace_row = {
                main_trace.read_main_frame(i, &mut main_frame);

                let query = evaluator.build_query(&main_frame, &[]);

                evaluator.evaluate_query(
                    &query,
                    log_up_randomness,
                    &mut numerators,
                    &mut denominators,
                );
                let input_gates_values: Vec<CircuitWire<E>> = numerators
                    .iter()
                    .zip(denominators.iter())
                    .map(|(numerator, denominator)| CircuitWire::new(*numerator, *denominator))
                    .collect();
                input_gates_values
            };

            input_layer_wires.extend(wires_from_trace_row);
        }

        CircuitLayer::new(input_layer_wires)
    }

    /// Computes the subsequent layer of the circuit from a given layer.
    fn compute_next_layer(prev_layer: &CircuitLayer<E>) -> CircuitLayer<E> {
        let next_layer_wires = prev_layer
            .wires()
            .chunks_exact(2)
            .map(|input_wires| {
                let left_input_wire = input_wires[0];
                let right_input_wire = input_wires[1];

                // output wire
                left_input_wire + right_input_wire
            })
            .collect();

        CircuitLayer::new(next_layer_wires)
    }
}

// PROVER
// ================================================================================================

/// Evaluates and proves a fractional sum circuit given a set of composition polynomials.
///
/// For the input layer of the circuit, each individual component of the quadruple
/// [p_0, p_1, q_0, q_1] is of the form:
///
/// m(z_0, ... , z_{μ - 1}, x_0, ... , x_{ν - 1}) = \sum_{y ∈ {0,1}^μ} EQ(z, y) * g_{[y]}(f_0(x_0,
/// ... , x_{ν - 1}), ... , f_{κ - 1}(x_0, ... , x_{ν
/// - 1}))
///
/// where:
///
/// 1. μ is the log_2 of the number of different numerator/denominator expressions divided by two.
/// 2. [y] := \sum_{j = 0}^{μ - 1} y_j * 2^j
/// 3. κ is the number of multi-linears (i.e., main trace columns) involved in the computation of
///    the circuit (i.e., virtual bus).
/// 4. ν is the log_2 of the trace length.
///
/// The above `m` is usually referred to as the merge of the individual composed multi-linear
/// polynomials  g_{[y]}(f_0(x_0, ... , x_{ν - 1}), ... , f_{κ - 1}(x_0, ... , x_{ν - 1})).
///
/// The composition polynomials `g` are provided as inputs and then used in order to compute the
/// evaluations of each of the four merge polynomials over {0, 1}^{μ + ν}. The resulting evaluations
/// are then used in order to evaluate the circuit. At this point, the GKR protocol is used to prove
/// the correctness of circuit evaluation. It should be noted that the input layer, which
/// corresponds to the last layer treated by the GKR protocol, is handled differently from the other
/// layers. More specifically, the sum-check protocol used for the input layer is composed of two
/// sum-check protocols, the first one works directly with the evaluations of the `m`'s over {0,
/// 1}^{μ + ν} and runs for μ rounds. After these μ rounds, and using the resulting [`RoundClaim`],
/// we run the second and final sum-check protocol for ν rounds on the composed multi-linear
/// polynomial given by
///
/// \sum_{y ∈ {0,1}^μ} EQ(ρ', y) * g_{[y]}(f_0(x_0, ... , x_{ν - 1}), ... , f_{κ - 1}(x_0, ... ,
/// x_{ν - 1}))
///
/// where ρ' is the randomness sampled during the first sum-check protocol.
///
/// As part of the final sum-check protocol, the openings {f_j(ρ)} are provided as part of a
/// [`FinalOpeningClaim`]. This latter claim will be proven by the STARK prover later on using the
/// auxiliary trace.
pub fn prove_gkr<E: FieldElement>(
    main_trace: &impl Trace<BaseField = E::BaseField>,
    evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
    public_coin: &mut impl RandomCoin<BaseField = E::BaseField>,
) -> Result<GkrCircuitProof<E>, GkrProverError> {
    let num_logup_random_values = evaluator.get_num_rand_values();
    let mut logup_randomness: Vec<E> = Vec::with_capacity(num_logup_random_values);

    for _ in 0..num_logup_random_values {
        logup_randomness.push(public_coin.draw().expect("failed to generate randomness"));
    }

    // evaluate the GKR fractional sum circuit
    let mut circuit = EvaluatedCircuit::new(main_trace, evaluator, &logup_randomness)?;

    // run the GKR prover for all layers except the input layer
    let (before_final_layer_proofs, gkr_claim) =
        prove_intermediate_layers(&mut circuit, public_coin)?;

    // build the MLEs of the relevant main trace columns
    let (main_trace_mls, _periodic_values) =
        build_mls_from_main_trace_segment(evaluator.get_oracles(), main_trace.main_segment())?;

    // run the GKR prover for the input layer
    let num_rounds_before_merge = evaluator.get_num_fractions().ilog2() as usize - 1;

    let final_layer_proof = prove_input_layer(
        evaluator,
        logup_randomness,
        main_trace_mls,
        num_rounds_before_merge,
        gkr_claim,
        &mut circuit,
        public_coin,
    )?;

    // include the circuit output as part of the final proof
    let circuit_outputs = circuit.output_layer();

    Ok(GkrCircuitProof {
        circuit_outputs: circuit_outputs.clone(),
        before_final_layer_proofs,
        final_layer_proof,
    })
}

/// Proves the final GKR layer which corresponds to the input circuit layer.
fn prove_input_layer<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
    log_up_randomness: Vec<E>,
    mut mls: Vec<MultiLinearPoly<E>>,
    num_rounds_merge: usize,
    gkr_claim: GkrClaim<E>,
    circuit: &mut EvaluatedCircuit<E>,
    transcript: &mut C,
) -> Result<FinalLayerProof<E>, GkrProverError> {
    // parse the [GkrClaim] resulting from the previous GKR layer
    let GkrClaim { evaluation_point, claimed_evaluation } = gkr_claim;

    // compute the EQ function at the evaluation point
    let mut poly_x = EqFunction::ml_at(evaluation_point.clone());

    // get the multi-linears of the 4 merge polynomials
    let layer = circuit.get_layer(0);

    // construct the vector of multi-linear polynomials
    let (mut left_numerators, mut right_numerators) =
        layer.numerators.project_least_significant_variable();
    let (mut left_denominators, mut right_denominators) =
        layer.denominators.project_least_significant_variable();

    // run the sumcheck protocol
    let ((before_merge_proof, claim), r_sum_check) = sum_check_prove_num_rounds_degree_3(
        num_rounds_merge,
        claimed_evaluation,
        &mut left_numerators,
        &mut right_numerators,
        &mut left_denominators,
        &mut right_denominators,
        &mut poly_x,
        transcript,
    )?;

    // parse the output of the first sum-check protocol
    let FinalOpeningClaim { eval_point, openings: _ } = before_merge_proof.openings_claim.clone();

    let mut merged_mls =
        vec![left_numerators, right_numerators, left_denominators, right_denominators, poly_x];

    // run the second sum-check protocol
    let after_merge_proof = sum_check_prove_higher_degree(
        evaluator,
        claim,
        r_sum_check,
        eval_point,
        log_up_randomness,
        &mut merged_mls,
        &mut mls,
        transcript,
    )?;

    Ok(FinalLayerProof {
        before_merge_proof: before_merge_proof.round_proofs,
        after_merge_proof,
    })
}

// TODO: Make the multi-linears over the base field and define an operation of folding with a challenge
// in an extension field.
fn build_mls_from_main_trace_segment<E: FieldElement>(
    oracles: Vec<air::LogUpGkrOracle<E::BaseField>>,
    main_trace: &ColMatrix<<E as FieldElement>::BaseField>,
) -> Result<(Vec<MultiLinearPoly<E>>, Vec<Vec<E::BaseField>>), GkrProverError> {
    let mut mls = vec![];
    let mut periodic_values = vec![];

    for oracle in oracles {
        match oracle {
            air::LogUpGkrOracle::CurrentRow(index) => {
                let col = main_trace.get_column(index);
                let values: Vec<E> = col.iter().map(|value| E::from(*value)).collect();
                let ml = MultiLinearPoly::from_evaluations(values).unwrap();
                mls.push(ml)
            },
            air::LogUpGkrOracle::NextRow(index) => {
                let col = main_trace.get_column(index);
                let mut values: Vec<E> = col.iter().map(|value| E::from(*value)).collect();
                if let Some(value) = values.last_mut() {
                    *value = E::ZERO
                }
                values.rotate_left(1);
                let ml = MultiLinearPoly::from_evaluations(values).unwrap();
                mls.push(ml)
            },
            air::LogUpGkrOracle::PeriodicValue(values) => periodic_values.push(values),
        };
    }
    Ok((mls, periodic_values))
}

/// Proves all GKR layers except for input layer.
fn prove_intermediate_layers<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    circuit: &mut EvaluatedCircuit<E>,
    transcript: &mut C,
) -> Result<(BeforeFinalLayerProof<E>, GkrClaim<E>), GkrProverError> {
    // absorb the circuit output layer. This corresponds to sending the four values of the output
    // layer to the verifier. The verifier then replies with a challenge `r` in order to evaluate
    // `p` and `q` at `r` as multi-linears.
    let CircuitLayerPolys { numerators, denominators } = circuit.output_layer();
    let mut evaluations = numerators.evaluations().to_vec();
    evaluations.extend_from_slice(denominators.evaluations());
    transcript.reseed(H::hash_elements(&evaluations));

    // generate the challenge and reduce [p0, p1, q0, q1] to [pr, qr]
    let r = transcript.draw().map_err(|_| GkrProverError::FailedToGenerateChallenge)?;
    let mut claim = circuit.evaluate_output_layer(r);

    let mut proof_layers: Vec<SumCheckProof<E>> = Vec::new();
    let mut rand = vec![r];

    // Loop over all inner layers, from output to input.
    //
    // In a layered circuit, each layer is defined in terms of its predecessor. The first inner
    // layer (starting from the output layer) is the first layer that has a predecessor. Here, we
    // loop over all inner layers in order to iteratively reduce a layer in terms of its successor
    // layer. Note that we don't include the input layer, since its predecessor layer will be
    // reduced in terms of the input layer separately in `prove_final_circuit_layer`.
    for inner_layer in circuit.layers().iter().skip(1).rev().skip(1) {
        // construct the Lagrange kernel evaluated at the previous GKR round randomness
        let mut poly_x = EqFunction::ml_at(rand.clone());

        // construct the vector of multi-linear polynomials
        // TODO: avoid unnecessary allocation
        let (mut left_numerators, mut right_numerators) =
            inner_layer.numerators.project_least_significant_variable();
        let (mut left_denominators, mut right_denominators) =
            inner_layer.denominators.project_least_significant_variable();

        // run the sumcheck protocol
        let ((proof, _), _) = sum_check_prove_num_rounds_degree_3(
            left_numerators.num_variables(),
            claim,
            &mut left_numerators,
            &mut right_numerators,
            &mut left_denominators,
            &mut right_denominators,
            &mut poly_x,
            transcript,
        )?;

        // sample a random challenge to reduce claims
        transcript.reseed(H::hash_elements(&proof.openings_claim.openings));
        let r_layer = transcript.draw().map_err(|_| GkrProverError::FailedToGenerateChallenge)?;

        // reduce the claim
        claim = {
            let left_numerators_opening = proof.openings_claim.openings[0];
            let right_numerators_opening = proof.openings_claim.openings[1];
            let left_denominators_opening = proof.openings_claim.openings[2];
            let right_denominators_opening = proof.openings_claim.openings[3];

            reduce_layer_claim(
                left_numerators_opening,
                right_numerators_opening,
                left_denominators_opening,
                right_denominators_opening,
                r_layer,
            )
        };

        // collect the randomness used for the current layer
        let mut ext = vec![r_layer];
        ext.extend_from_slice(&proof.openings_claim.eval_point);
        rand = ext;

        proof_layers.push(proof);
    }

    Ok((
        BeforeFinalLayerProof { proof: proof_layers },
        GkrClaim {
            evaluation_point: rand,
            claimed_evaluation: claim,
        },
    ))
}

/// Represents a claim to be proven by a subsequent call to the sum-check protocol.
#[derive(Debug)]
pub struct GkrClaim<E: FieldElement> {
    pub evaluation_point: Vec<E>,
    pub claimed_evaluation: (E, E),
}

/// We receive our 4 multilinear polynomials which were evaluated at a random point:
/// `left_numerators` (or `p0`), `right_numerators` (or `p1`), `left_denominators` (or `q0`), and
/// `right_denominators` (or `q1`). We'll call the 4 evaluations at a random point `p0(r)`, `p1(r)`,
/// `q0(r)`, and `q1(r)`, respectively, where `r` is the random point. Note that `r` is a shorthand
/// for a tuple of random values `(r_0, ... r_{l-1})`, where `2^{l + 1}` is the number of wires in
/// the layer.
///
/// It is important to recall how `p0` and `p1` were constructed (and analogously for `q0` and
/// `q1`). They are the `numerators` layer polynomial (or `p`) evaluations `p(0, r)` and `p(1, r)`,
/// obtained from [`MultiLinearPoly::project_least_significant_variable`]. Hence, `[p0, p1]` form
/// the evaluations of polynomial `p'(x_0) = p(x_0, r)`. Then, the round claim for `numerators`,
/// defined as `p(r_layer, r)`, is simply `p'(r_layer)`.
fn reduce_layer_claim<E>(
    left_numerators_opening: E,
    right_numerators_opening: E,
    left_denominators_opening: E,
    right_denominators_opening: E,
    r_layer: E,
) -> (E, E)
where
    E: FieldElement,
{
    // This is the `numerators` layer polynomial `f(x_0) = numerators(x_0, rx_0, ..., rx_{l-1})`,
    // where `rx_0, ..., rx_{l-1}` are the random variables that were sampled during the sumcheck
    // round for this layer.
    let numerators_univariate =
        MultiLinearPoly::from_evaluations(vec![left_numerators_opening, right_numerators_opening])
            .unwrap();

    // This is analogous to `numerators_univariate`, but for the `denominators` layer polynomial
    let denominators_univariate = MultiLinearPoly::from_evaluations(vec![
        left_denominators_opening,
        right_denominators_opening,
    ])
    .unwrap();

    (
        numerators_univariate.evaluate(&[r_layer]),
        denominators_univariate.evaluate(&[r_layer]),
    )
}

/// Runs the sum-check prover used in all but the input layer.
fn sum_check_prove_num_rounds_degree_3<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    num_rounds: usize,
    claim: (E, E),
    p0: &mut MultiLinearPoly<E>,
    p1: &mut MultiLinearPoly<E>,
    q0: &mut MultiLinearPoly<E>,
    q1: &mut MultiLinearPoly<E>,
    eq: &mut MultiLinearPoly<E>,
    transcript: &mut C,
) -> Result<((SumCheckProof<E>, E), E), GkrProverError> {
    // generate challenge to batch two sumchecks
    transcript.reseed(H::hash_elements(&[claim.0, claim.1]));
    let r_batch = transcript.draw().map_err(|_| GkrProverError::FailedToGenerateChallenge)?;
    let claim_ = claim.0 + claim.1 * r_batch;

    let proof = sumcheck_prove_plain(num_rounds, claim_, r_batch, p0, p1, q0, q1, eq, transcript)?;

    Ok((proof, r_batch))
}
