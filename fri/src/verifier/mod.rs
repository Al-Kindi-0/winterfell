// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains an implementation of FRI verifier and associated components.

use crate::{
    folding::fold_positions,
    utils::{map_positions_to_indexes, AdviceProvider},
    FriOptions, VerifierError,
};
use core::{convert::TryInto, marker::PhantomData, mem};
use crypto::{ElementHasher, RandomCoin};
use math::{
    fft, log2,
    polynom::{self, eval},
    FieldElement, StarkField,
};
use utils::collections::Vec;

mod channel;
pub use channel::{DefaultVerifierChannel, VerifierChannel};

// FRI VERIFIER
// ================================================================================================
/// Implements the verifier component of the FRI protocol.
///
/// Given a small number of evaluations of some function *f* over domain *D* and a FRI proof, a
/// FRI verifier determines whether *f* is a polynomial of some bounded degree *d*, such that *d*
/// < |*D*| / 2.
///
/// The verifier is parametrized by the following types:
///
/// * `B` specifies the base field of the STARK protocol.
/// * `E` specifies the field in which the FRI protocol is executed. This can be the same as the
///   base field `B`, but it can also be an extension of the base field in cases when the base
///   field is too small to provide desired security level for the FRI protocol.
/// * `C` specifies the type used to simulate prover-verifier interaction. This type is used
///   as an abstraction for a [FriProof](crate::FriProof). Meaning, the verifier does not consume
///   a FRI proof directly, but reads it via [VerifierChannel] interface.
/// * `H` specifies the Hash function used by the prover to commit to polynomial evaluations.
///
/// Proof verification is performed in two phases: commit phase and query phase.
///
/// # Commit phase
/// During the commit phase, which is executed when the verifier is instantiated via
/// [new()](FriVerifier::new()) function, the verifier receives a list of FRI layer commitments
/// from the prover (via [VerifierChannel]). After each received commitment, the verifier
/// draws a random value α from the entire field, and sends it to the prover. In the
/// non-interactive version of the protocol, α values are derived pseudo-randomly from FRI
/// layer commitments.
///
/// # Query phase
/// During the query phase, which is executed via [verify()](FriVerifier::verify()) function,
/// the verifier sends a set of positions in the domain *D* to the prover, and the prover responds
/// with polynomial evaluations at these positions (together with corresponding Merkle paths)
/// across all FRI layers. The verifier then checks that:
/// * The Merkle paths are valid against the layer commitments the verifier received during
///   the commit phase.
/// * The evaluations are consistent across FRI layers (i.e., the degree-respecting projection
///   was applied correctly).
/// * The degree of the polynomial implied by evaluations at the last FRI layer (the remainder)
///   is smaller than the degree resulting from reducing degree *d* by `folding_factor` at each
///   FRI layer.
pub struct FriVerifier<B, E, C, H>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    C: VerifierChannel<E, Hasher = H>,
    H: ElementHasher<BaseField = B>,
{
    max_poly_degree: usize,
    domain_size: usize,
    domain_generator: B,
    layer_commitments: Vec<H::Digest>,
    layer_alphas: Vec<E>,
    options: FriOptions,
    num_partitions: usize,
    _channel: PhantomData<C>,
}

impl<B, E, C, H> FriVerifier<B, E, C, H>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    C: VerifierChannel<E, Hasher = H>,
    H: ElementHasher<BaseField = B>,
{
    /// Returns a new instance of FRI verifier created from the specified parameters.
    ///
    /// The `max_poly_degree` parameter specifies the highest polynomial degree accepted by the
    /// returned verifier. In combination with `blowup_factor` from the `options` parameter,
    /// `max_poly_degree` also defines the domain over which the tested polynomial is evaluated.
    ///
    /// Creating a FRI verifier executes the commit phase of the FRI protocol from the verifier's
    /// perspective. Specifically, the verifier reads FRI layer commitments from the `channel`,
    /// and for each commitment, updates the `public_coin` with this commitment and then draws
    /// a random value α from the coin.
    ///
    /// The verifier stores layer commitments and corresponding α values in its internal state,
    /// and, thus, an instance of FRI verifier can be used to verify only a single proof.
    ///
    /// # Errors
    /// Returns an error if:
    /// * `max_poly_degree` is inconsistent with the number of FRI layers read from the channel
    ///   and `folding_factor` specified in the `options` parameter.
    /// * An error was encountered while drawing a random α value from the coin.
    pub fn new(
        channel: &mut C,
        public_coin: &mut RandomCoin<B, H>,
        options: FriOptions,
        max_poly_degree: usize,
    ) -> Result<Self, VerifierError> {
        // infer evaluation domain info
        let domain_size = max_poly_degree.next_power_of_two() * options.blowup_factor();
        let domain_generator = B::get_root_of_unity(log2(domain_size));

        let num_partitions = channel.read_fri_num_partitions();

        // read layer commitments from the channel and use them to build a list of alphas
        let layer_commitments = channel.read_fri_layer_commitments();
        let mut layer_alphas = Vec::with_capacity(layer_commitments.len());
        let mut max_degree_plus_1 = max_poly_degree + 1;
        for (depth, commitment) in layer_commitments.iter().enumerate() {
            public_coin.reseed(*commitment);
            let alpha = public_coin.draw().map_err(VerifierError::PublicCoinError)?;
            layer_alphas.push(alpha);

            // make sure the degree can be reduced by the folding factor at all layers
            // but the remainder layer
            if depth != layer_commitments.len() - 1
                && max_degree_plus_1 % options.folding_factor() != 0
            {
                return Err(VerifierError::DegreeTruncation(
                    max_degree_plus_1 - 1,
                    options.folding_factor(),
                    depth,
                ));
            }
            max_degree_plus_1 /= options.folding_factor();
        }

        Ok(FriVerifier {
            max_poly_degree,
            domain_size,
            domain_generator,
            layer_commitments,
            layer_alphas,
            options,
            num_partitions,
            _channel: PhantomData,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns maximum degree of a polynomial accepted by this verifier.
    pub fn max_poly_degree(&self) -> usize {
        self.max_poly_degree
    }

    /// Returns size of the domain over which a polynomial commitment checked by this verifier
    /// has been evaluated.
    ///
    /// The domain size can be computed by rounding `max_poly_degree` to the next power of two
    /// and multiplying the result by the `blowup_factor` from the protocol options.
    pub fn domain_size(&self) -> usize {
        self.domain_size
    }

    /// Returns number of partitions used during FRI proof generation.
    ///
    /// For non-distributed proof generation, number of partitions is usually set to 1.
    pub fn num_partitions(&self) -> usize {
        self.num_partitions
    }

    /// Returns protocol configuration options for this verifier.
    pub fn options(&self) -> &FriOptions {
        &self.options
    }

    // VERIFICATION PROCEDURE
    // --------------------------------------------------------------------------------------------
    /// Executes the query phase of the FRI protocol.
    ///
    /// Returns `Ok(())` if values in the `evaluations` slice represent evaluations of a polynomial
    /// with degree <= `max_poly_degree` at x coordinates specified by the `positions` slice.
    ///
    /// Thus, `positions` parameter represents the positions in the evaluation domain at which the
    /// verifier queries the prover at the first FRI layer. Similarly, the `evaluations` parameter
    /// specifies the evaluations of the polynomial at the first FRI layer returned by the prover
    /// for these positions.
    ///
    /// Evaluations of layer polynomials for all subsequent FRI layers the verifier reads from the
    /// specified `channel`.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The length of `evaluations` is not equal to the length of `positions`.
    /// * An unsupported folding factor was specified by the `options` for this verifier.
    /// * Decommitments to polynomial evaluations don't match the commitment value at any of the
    ///   FRI layers.
    /// * The verifier detects an error in how the degree-respecting projection was applied
    ///   at any of the FRI layers.
    /// * The degree of the remainder at the last FRI layer is greater than the degree implied by
    ///   `max_poly_degree` reduced by the folding factor at each FRI layer.
    pub fn verify(
        &self,
        channel: &mut C,
        evaluations: &[E],
        positions: &[usize],
    ) -> Result<(), VerifierError> {
        if evaluations.len() != positions.len() {
            return Err(VerifierError::NumPositionEvaluationMismatch(
                positions.len(),
                evaluations.len(),
            ));
        }

        // static dispatch for folding factor parameter
        let folding_factor = self.options.folding_factor();
        match folding_factor {
            2 => self.verify_generic::<2>(channel, evaluations, positions),
            4 => self.verify_generic::<4>(channel, evaluations, positions),
            8 => self.verify_generic::<8>(channel, evaluations, positions),
            16 => self.verify_generic::<16>(channel, evaluations, positions),
            _ => Err(VerifierError::UnsupportedFoldingFactor(folding_factor)),
        }
    }

    /// This is the actual implementation of the verification procedure described above, but it
    /// also takes folding factor as a generic parameter N.
    fn verify_generic<const N: usize>(
        &self,
        channel: &mut C,
        evaluations: &[E],
        positions: &[usize],
    ) -> Result<(), VerifierError> {
        // pre-compute roots of unity used in computing x coordinates in the folded domain
        let folding_roots = (0..N)
            .map(|i| {
                self.domain_generator
                    .exp(((self.domain_size / N * i) as u64).into())
            })
            .collect::<Vec<_>>();

        // 1 ----- verify the recursive components of the FRI proof -----------------------------------
        let mut domain_generator = self.domain_generator;
        let mut domain_size = self.domain_size;
        let mut max_degree_plus_1 = self.max_poly_degree + 1;
        let mut positions = positions.to_vec();
        let mut evaluations = evaluations.to_vec();

        for depth in 0..self.options.num_fri_layers(self.domain_size) {
            // determine which evaluations were queried in the folded layer
            let mut folded_positions =
                fold_positions(&positions, domain_size, self.options.folding_factor());
            // determine where these evaluations are in the commitment Merkle tree
            let position_indexes = map_positions_to_indexes(
                &folded_positions,
                domain_size,
                self.options.folding_factor(),
                self.num_partitions,
            );
            // read query values from the specified indexes in the Merkle tree
            let layer_commitment = self.layer_commitments[depth];
            // TODO: add layer depth to the potential error message
            let layer_values = channel.read_layer_queries(&position_indexes, &layer_commitment)?;
            let query_values =
                get_query_values::<E, N>(&layer_values, &positions, &folded_positions, domain_size);
            if evaluations != query_values {
                return Err(VerifierError::InvalidLayerFolding(depth));
            }

            // build a set of x coordinates for each row polynomial
            #[rustfmt::skip]
            let xs = folded_positions.iter().map(|&i| {
                let xe = domain_generator.exp((i as u64).into()) * self.options.domain_offset();
                folding_roots.iter()
                    .map(|&r| E::from(xe * r))
                    .collect::<Vec<_>>().try_into().unwrap()
            })
            .collect::<Vec<_>>();

            // interpolate x and y values into row polynomials
            let row_polys = polynom::interpolate_batch(&xs, &layer_values);

            // calculate the pseudo-random value used for linear combination in layer folding
            let alpha = self.layer_alphas[depth];

            // check that when the polynomials are evaluated at alpha, the result is equal to
            // the corresponding column value
            evaluations = row_polys.iter().map(|p| polynom::eval(p, alpha)).collect();

            // make sure next degree reduction does not result in degree truncation
            if max_degree_plus_1 % N != 0 {
                return Err(VerifierError::DegreeTruncation(
                    max_degree_plus_1 - 1,
                    N,
                    depth,
                ));
            }

            // update variables for the next iteration of the loop
            domain_generator = domain_generator.exp((N as u32).into());
            max_degree_plus_1 /= N;
            domain_size /= N;
            mem::swap(&mut positions, &mut folded_positions);
        }

        // 2 ----- verify the remainder of the FRI proof ----------------------------------------------

        // read the remainder from the channel and make sure it matches with the columns
        // of the previous layer
        let remainder_commitment = self.layer_commitments.last().unwrap();
        let remainder = channel.read_remainder::<N>(remainder_commitment)?;
        for (&position, evaluation) in positions.iter().zip(evaluations) {
            if remainder[position] != evaluation {
                return Err(VerifierError::InvalidRemainderFolding);
            }
        }

        // make sure the remainder values satisfy the degree
        verify_remainder(self.domain_generator, remainder, max_degree_plus_1 - 1)
    }

    // VERIFICATION PROCEDURE QUERY-WISE
    // --------------------------------------------------------------------------------------------
    /// Executes the query phase of the FRI protocol ONE QUERY POSITION AT A TIME.
    ///
    /// Returns `Ok(())` if values in the `evaluations` slice represent evaluations of a polynomial
    /// with degree <= `max_poly_degree` at x coordinates specified by the `positions` slice.
    ///
    /// Thus, `positions` parameter represents the positions in the evaluation domain at which the
    /// verifier queries the prover at the first FRI layer. Similarly, the `evaluations` parameter
    /// specifies the evaluations of the polynomial at the first FRI layer returned by the prover
    /// for these positions.
    ///
    /// Evaluations of layer polynomials for all subsequent FRI layers the verifier reads from the
    /// specified `channel`.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The length of `evaluations` is not equal to the length of `positions`.
    /// * An unsupported folding factor was specified by the `options` for this verifier.
    /// * Decommitments to polynomial evaluations don't match the commitment value at any of the
    ///   FRI layers.
    /// * The verifier detects an error in how the degree-respecting projection was applied
    ///   at any of the FRI layers.
    /// * The degree of the remainder at the last FRI layer is greater than the degree implied by
    ///   `max_poly_degree` reduced by the folding factor at each FRI layer.
    pub fn verify_query(
        &self,
        channel: &mut C,
        evaluations: &[E],
        positions: &[usize],
    ) -> Result<(), VerifierError> {
        if evaluations.len() != positions.len() {
            return Err(VerifierError::NumPositionEvaluationMismatch(
                positions.len(),
                evaluations.len(),
            ));
        }

        // static dispatch for folding factor parameter
        let folding_factor = self.options.folding_factor();
        match folding_factor {
            2 => self.verify_generic_query_2(channel, evaluations, positions),
            4 => self.verify_generic_query_4(channel, evaluations, positions),
            8 => self.verify_generic_query::<8>(channel, evaluations, positions),
            16 => self.verify_generic_query::<16>(channel, evaluations, positions),
            _ => Err(VerifierError::UnsupportedFoldingFactor(folding_factor)),
        }
    }

    /// This is the actual implementation of the verification procedure described above, but it
    /// also takes folding factor as a generic parameter N.
    fn verify_generic_query<const N: usize>(
        &self,
        channel: &mut C,
        evaluations: &[E],
        positions: &[usize],
    ) -> Result<(), VerifierError> {
        // pre-compute roots of unity used in computing x coordinates in the folded domain
        let folding_roots = (0..N)
            .map(|i| {
                self.domain_generator
                    .exp(((self.domain_size / N * i) as u64).into())
            })
            .collect::<Vec<_>>();

        // 1 ----- verify the recursive components of the FRI proof -----------------------------------
        let positions = positions.to_vec();
        let evaluations = evaluations.to_vec();
        let mut final_max_poly_degree_plus_1 = 0;
        let mut final_pos_eval: Vec<(usize, E)> = vec![];
        let mut total_num_hash_trees = 0usize;
        let mut total_num_hash_leaves = 0usize;

        // Get the queries from the channel in a vertical configuration
        let advice_provider = channel.unbatch::<N>(
            &positions,
            self.domain_size,
            self.options.folding_factor(),
            self.layer_commitments.clone(),
        );

        for (index, &position) in positions.iter().enumerate() {
            //println!("Index is {:?}", index);
            let (
                cur_pos,
                evaluation,
                num_hash_trees,
                num_hash_leaves,
                final_max_poly_degree_plus_1_,
            ) = iterate_through_query::<B, E, H, N>(
                &self.layer_commitments,
                &folding_roots,
                &self.layer_alphas,
                &advice_provider,
                position,
                self.options.num_fri_layers(self.domain_size),
                self.domain_size,
                &evaluations[index],
                self.domain_generator,
                self.max_poly_degree + 1,
            )?;

            total_num_hash_trees = num_hash_trees;
            total_num_hash_leaves = num_hash_leaves;
            final_max_poly_degree_plus_1 = final_max_poly_degree_plus_1_;

            final_pos_eval.push((cur_pos, evaluation));
        }
        eprintln!(
            "Number of tree-hashes during FRI verification per query is {:?}",
            total_num_hash_trees
        );

        eprintln!(
            "Number of leaves-hashes during FRI verification per query is {:?}",
            total_num_hash_leaves
        );
        // 2 ----- verify the remainder of the FRI proof ----------------------------------------------

        // read the remainder from the channel and make sure it matches with the columns
        // of the previous layer
        let remainder_commitment = self.layer_commitments.last().unwrap();
        let remainder = channel.read_remainder::<N>(remainder_commitment)?;
        for (pos, eval) in final_pos_eval.iter() {
            if remainder[*pos] != *eval {
                return Err(VerifierError::InvalidRemainderFolding);
            }
        }

        // make sure the remainder values satisfy the degree
        verify_remainder(
            self.domain_generator
                .exp((N.pow(self.options.num_fri_layers(self.domain_size) as u32) as u64).into()),
            remainder,
            final_max_poly_degree_plus_1 - 1,
        )
    }

    /// This is the actual implementation of the verification procedure described above for N=2
    fn verify_generic_query_2(
        &self,
        channel: &mut C,
        evaluations: &[E],
        positions: &[usize],
    ) -> Result<(), VerifierError> {
        // pre-compute roots of unity used in computing x coordinates in the folded domain
        let folding_roots = (0..2)
            .map(|i| {
                self.domain_generator
                    .exp(((self.domain_size / 2 * i) as u64).into())
            })
            .collect::<Vec<_>>();

        // 1 ----- verify the recursive components of the FRI proof -----------------------------------
        let positions = positions.to_vec();
        let evaluations = evaluations.to_vec();
        let mut final_max_poly_degree_plus_1 = self.max_poly_degree + 1;
        let mut final_pos_eval: Vec<(usize, E)> = vec![];

        // Get the queries from the channel in a vertical configuration
        let advice_provider = channel.unbatch::<2>(
            &positions,
            self.domain_size,
            self.options.folding_factor(),
            self.layer_commitments.clone(),
        );

        let mut d_generator = self.domain_generator;
        let mut counter = Counter::new();
        for (index, &position) in positions.iter().enumerate() {
            d_generator = self.domain_generator;
            counter = Counter::new();
            let (
                cur_pos,
                evaluation,
            ) = iterate_through_query_2::<B, E, H>(
                &self.layer_commitments,
                &folding_roots,
                &self.layer_alphas,
                &advice_provider,
                position,
                self.options.num_fri_layers(self.domain_size),
                self.domain_size,
                &evaluations[index],
                &mut d_generator,
                &mut counter,
            )?;

            final_pos_eval.push((cur_pos, evaluation));
        }
        final_max_poly_degree_plus_1 /=
            (2 as usize).pow(self.options.num_fri_layers(self.domain_size) as u32);
         eprintln!(
            "Number of tree-hashes during FRI verification per query is {:?}",
            counter.node_hash
        );

        eprintln!(
            "Number of leaves-hashes during FRI verification per query is {:?}",
            counter.leaves_hash
        );

        eprintln!(
            "# field mul is {:?}, # field exp is {:?}, # ext-field add is {:?}, # ext-field mul is {:?}",
            counter.field_mul, counter.field_exp, counter.field_add_ext, counter.field_mul_ext
        );

        // 2 ----- verify the remainder of the FRI proof ----------------------------------------------

        // read the remainder from the channel and make sure it matches with the columns
        // of the previous layer
        let remainder_commitment = self.layer_commitments.last().unwrap();
        let remainder = channel.read_remainder::<2>(remainder_commitment)?;
        for (pos, eval) in final_pos_eval.iter() {
            if remainder[*pos] != *eval {
                return Err(VerifierError::InvalidRemainderFolding);
            }
        }

        // make sure the remainder values satisfy the degree
        verify_remainder(
            d_generator,
            remainder,
            final_max_poly_degree_plus_1 - 1,
        )
    }

    /// This is the actual implementation of the verification procedure described above for N=4
    fn verify_generic_query_4(
        &self,
        channel: &mut C,
        evaluations: &[E],
        positions: &[usize],
    ) -> Result<(), VerifierError> {
        // pre-compute roots of unity used in computing x coordinates in the folded domain
        let folding_roots = (0..4)
            .map(|i| {
                self.domain_generator
                    .exp(((self.domain_size / 4 * i) as u64).into())
            })
            .collect::<Vec<_>>();

        // 1 ----- verify the recursive components of the FRI proof -----------------------------------
        let positions = positions.to_vec();
        let evaluations = evaluations.to_vec();
        let mut final_max_poly_degree_plus_1 = self.max_poly_degree + 1;
        let mut final_pos_eval: Vec<(usize, E)> = vec![];

        // Get the queries from the channel in a vertical configuration
        let advice_provider = channel.unbatch::<4>(
            &positions,
            self.domain_size,
            self.options.folding_factor(),
            self.layer_commitments.clone(),
        );

        let mut d_generator = self.domain_generator;
        let mut counter = Counter::new();
        for (index, &position) in positions.iter().enumerate() {
            d_generator = self.domain_generator;
            counter = Counter::new();
            let (cur_pos, evaluation) = iterate_through_query_4::<B, E, H>(
                &self.layer_commitments,
                &folding_roots,
                &self.layer_alphas,
                &advice_provider,
                position,
                self.options.num_fri_layers(self.domain_size),
                self.domain_size,
                &evaluations[index],
                &mut d_generator,
                &mut counter,
            )?;

            final_pos_eval.push((cur_pos, evaluation));
        }
        final_max_poly_degree_plus_1 /=
            (4 as usize).pow(self.options.num_fri_layers(self.domain_size) as u32);
        eprintln!(
            "Number of tree-hashes during FRI verification per query is {:?}",
            counter.node_hash
        );

        eprintln!(
            "Number of leaves-hashes during FRI verification per query is {:?}",
            counter.leaves_hash
        );

        eprintln!(
            "# field mul is {:?}, # field exp is {:?}, # ext-field add is {:?}, # ext-field mul is {:?}",
            counter.field_mul, counter.field_exp, counter.field_add_ext, counter.field_mul_ext
        );

        // 2 ----- verify the remainder of the FRI proof ----------------------------------------------

        // read the remainder from the channel and make sure it matches with the columns
        // of the previous layer
        let remainder_commitment = self.layer_commitments.last().unwrap();
        let remainder = channel.read_remainder::<4>(remainder_commitment)?;
        for (pos, eval) in final_pos_eval.iter() {
            if remainder[*pos] != *eval {
                return Err(VerifierError::InvalidRemainderFolding);
            }
        }

        // make sure the remainder values satisfy the degree
        verify_remainder(d_generator, remainder, final_max_poly_degree_plus_1 - 1)
    }
}

// REMAINDER DEGREE VERIFICATION
// ================================================================================================
/// Returns Ok(true) if values in the `remainder` slice represent evaluations of a polynomial
/// with degree <= `max_degree` against a domain of the same size as `remainder`.
fn verify_remainder<B: StarkField, E: FieldElement<BaseField = B>>(
    domain_generator: B,
    mut remainder: Vec<E>,
    max_degree: usize,
) -> Result<(), VerifierError> {
    if max_degree >= remainder.len() - 1 {
        return Err(VerifierError::RemainderDegreeNotValid);
    }

    if max_degree == 0 {
        // make sure the remainder values correspond to a constant polynomial
        if !remainder.windows(2).all(|a| a[0] == a[1]) {
            return Err(VerifierError::RemainderDegreeMismatch(max_degree));
        } else {
            Ok(())
        }
    } else if max_degree == 1 {
        let slope = (remainder[0] - remainder[remainder.len() / 2]) / E::ONE.double();
        let bias = (remainder[0] + remainder[remainder.len() / 2]) / E::ONE.double();

        let failure = remainder.iter().enumerate().any(|(i, pos)| {
            *pos != slope * domain_generator.exp(((i) as u32).into()).into() + bias
        });

        // make sure the degree is valid
        if failure {
            Err(VerifierError::RemainderDegreeMismatch(max_degree))
        } else {
            Ok(())
        }
    } else {
        // interpolate remainder polynomial from its evaluations; we don't shift the domain here
        // because the degree of the polynomial will not change as long as we interpolate over a
        // coset of the original domain.
        let inv_twiddles = fft::get_inv_twiddles(remainder.len());
        fft::interpolate_poly(&mut remainder, &inv_twiddles);
        let poly = remainder;

        // make sure the degree is valid
        if max_degree < polynom::degree_of(&poly) {
            Err(VerifierError::RemainderDegreeMismatch(max_degree))
        } else {
            Ok(())
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================
fn get_query_values<E: FieldElement, const N: usize>(
    values: &[[E; N]],
    positions: &[usize],
    folded_positions: &[usize],
    domain_size: usize,
) -> Vec<E> {
    let row_length = domain_size / N;

    let mut result = Vec::new();
    for position in positions {
        let idx = folded_positions
            .iter()
            .position(|&v| v == position % row_length)
            .unwrap();
        let value = values[idx][position / row_length];
        result.push(value);
    }

    result
}

fn iterate_through_query<B, E, H, const N: usize>(
    layer_commitments: &Vec<H::Digest>,
    folding_roots: &Vec<B>,
    layer_alphas: &Vec<E>,
    advice_provider: &AdviceProvider<H, E, N>,
    position: usize,
    number_of_layers: usize,
    initial_domain_size: usize,
    evaluation: &E,
    domain_generator: B,
    max_degree_plus_1: usize,
) -> Result<(usize, E, usize, usize, usize), VerifierError>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    H: ElementHasher<BaseField = B>,
{
    let mut cur_pos = position;
    let mut evaluation = *evaluation;
    let mut domain_size = initial_domain_size;
    let mut domain_generator = domain_generator;
    let mut max_degree_plus_1 = max_degree_plus_1;
    let domain_offset = B::GENERATOR;
    let mut num_hash_trees = 0usize;
    let mut num_hash_leaves = 0usize;

    for depth in 0..number_of_layers {
        let target_domain_size = domain_size / N;

        let folded_pos = cur_pos % target_domain_size;
        // Assumes the num_partitions == 1
        let position_index = folded_pos;

        let tree_depth = log2(target_domain_size) + 1;

        let query_values = advice_provider
            .get_tree_node(layer_commitments[depth], tree_depth, position_index as u64)
            .unwrap();
        let query_value = query_values[cur_pos / target_domain_size];

        if evaluation != query_value {
            return Err(VerifierError::InvalidLayerFolding(depth));
        }

        #[rustfmt::skip]
        let xe = domain_generator.exp((folded_pos as u64).into()) * (domain_offset);
        let xs: [E; N] = folding_roots
            .iter()
            .map(|&r| E::from(xe * r))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let row_poly = polynom::interpolate(&xs, &query_values, true);

        let alpha = layer_alphas[depth];

        // check that when the polynomials are evaluated at alpha, the result is equal to
        // the corresponding column value
        evaluation = polynom::eval(&row_poly, alpha);

        // make sure next degree reduction does not result in degree truncation
        if max_degree_plus_1 % N != 0 {
            return Err(VerifierError::DegreeTruncation(
                max_degree_plus_1 - 1,
                N,
                depth,
            ));
        }

        // update variables for the next iteration of the loop
        max_degree_plus_1 /= N;
        domain_generator = domain_generator.exp((N as u32).into());
        cur_pos = folded_pos;
        domain_size /= N;

        // Estimate number of hashings required per query
        let degree_of_extension = evaluation.as_bytes().len() / domain_offset.as_bytes().len();
        num_hash_trees += tree_depth as usize - 1;
        num_hash_leaves += (N * degree_of_extension) / 4;

        println!("At depth {:?}", depth);
        println!("# hashes MT is {:?}", num_hash_trees);
        println!("# hashes L is {:?}", num_hash_leaves);
    }
    Ok((
        cur_pos,
        evaluation,
        num_hash_trees,
        num_hash_leaves,
        max_degree_plus_1,
    ))
}

fn iterate_through_query_2<B, E, H>(
    layer_commitments: &Vec<H::Digest>,
    folding_roots: &Vec<B>,
    layer_alphas: &Vec<E>,
    advice_provider: &AdviceProvider<H, E, 2>,
    position: usize,
    number_of_layers: usize,
    initial_domain_size: usize,
    evaluation: &E,
    domain_generator: &mut B,
    counter: &mut Counter,
) -> Result<(usize, E), VerifierError>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    H: ElementHasher<BaseField = B>,
{
    let mut cur_pos = position;
    let mut evaluation = *evaluation;
    let mut domain_size = initial_domain_size;
    let domain_offset = B::GENERATOR;

    for depth in 0..number_of_layers {
        let target_domain_size = domain_size / 2;

        let folded_pos = cur_pos % target_domain_size;
        // Assumes the num_partitions == 1
        let position_index = folded_pos;

        let tree_depth = log2(target_domain_size) + 1;

        let query_values = advice_provider
            .get_tree_node(layer_commitments[depth], tree_depth, position_index as u64)
            .unwrap();
        let query_value = query_values[cur_pos / target_domain_size];

        if evaluation != query_value {
            return Err(VerifierError::InvalidLayerFolding(depth));
        }

        #[rustfmt::skip]
        let xs = (*domain_generator).exp((folded_pos as u64).into()) * (domain_offset);

        counter.field_exp += 1;
        counter.field_mul += 1;

        evaluation = {
            let f_minus_x = query_values[1];
            let f_x = query_values[0];
            let x_star = E::from(xs);
            let alpha = layer_alphas[depth];

            counter.field_inv += 1;
            counter.field_mul += 2;//multiplication by 1/2 constant
            counter.field_mul_ext += 2;
            counter.field_add_ext += 3;

            fri_2(f_x, f_minus_x, x_star, alpha)
        };

        // update variables for the next iteration of the loop
        *domain_generator = (*domain_generator).exp((2 as u32).into());
        cur_pos = folded_pos;
        domain_size /= 2;

        counter.field_exp += 1;

        // Estimate number of hashings required per query
        let degree_of_extension = evaluation.as_bytes().len() / domain_offset.as_bytes().len();
        counter.node_hash += tree_depth as usize - 1;
        counter.leaves_hash += {if degree_of_extension == 2 {1} else {2}};

    }
    Ok((
        cur_pos,
        evaluation,
    ))
}

fn iterate_through_query_4<B, E, H>(
    layer_commitments: &Vec<H::Digest>,
    folding_roots: &Vec<B>,
    layer_alphas: &Vec<E>,
    advice_provider: &AdviceProvider<H, E, 4>,
    position: usize,
    number_of_layers: usize,
    initial_domain_size: usize,
    evaluation: &E,
    domain_generator: &mut B,
    counter: &mut Counter,
) -> Result<(usize, E), VerifierError>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    H: ElementHasher<BaseField = B>,
{
    let mut cur_pos = position;
    let mut evaluation = *evaluation;
    let mut domain_size = initial_domain_size;

    let domain_offset = B::GENERATOR;

    for depth in 0..number_of_layers {
        let target_domain_size = domain_size / 4;

        let folded_pos = cur_pos % target_domain_size;
        // Assumes the num_partitions == 1
        let position_index = folded_pos;

        let tree_depth = log2(target_domain_size) + 1;

        let query_values = advice_provider
            .get_tree_node(layer_commitments[depth], tree_depth, position_index as u64)
            .unwrap();
        let query_value = query_values[cur_pos / target_domain_size];

        if evaluation != query_value {
            return Err(VerifierError::InvalidLayerFolding(depth));
        }

        #[rustfmt::skip]
        let xe = (*domain_generator).exp((folded_pos as u64).into()) * (domain_offset);
        let xs: [E; 2] = [
            E::from(folding_roots[0] * xe),
            E::from(folding_roots[1] * xe),
        ];

        counter.field_exp += 1;
        counter.field_mul += 3;

        evaluation = {
            let f_minus_x = query_values[2];
            let f_x = query_values[0];
            let x_star = xs[0];
            let alpha = layer_alphas[depth];

            let tmp0 = fri_2(f_x, f_minus_x, x_star, alpha);

            counter.field_inv += 1;
            counter.field_mul += 2;//multiplication by 1/2 constant
            counter.field_mul_ext += 2;
            counter.field_add_ext += 3;

            let f_minus_x = query_values[3];
            let f_x = query_values[1];
            let x_star = xs[1];
            let alpha = layer_alphas[depth];

            let tmp1 = fri_2(f_x, f_minus_x, x_star, alpha);

            counter.field_inv += 1;
            counter.field_mul += 2;
            counter.field_mul_ext += 2;
            counter.field_add_ext += 3;

            counter.field_inv += 1;
            counter.field_mul += 4;
            counter.field_mul_ext += 4;
            counter.field_add_ext += 3;

            fri_2(tmp0, tmp1, xs[0] * xs[0], alpha * alpha)
        };

        // update variables for the next iteration of the loop
        (*domain_generator) = (*domain_generator).exp((4 as u32).into());
        cur_pos = folded_pos;
        domain_size /= 4;

        counter.field_exp += 1;

        // Estimate number of hashings required per query
        let degree_of_extension = evaluation.as_bytes().len() / domain_offset.as_bytes().len();
        counter.node_hash += tree_depth as usize - 1;
        counter.leaves_hash += degree_of_extension;
    }

    Ok((cur_pos, evaluation))
}

fn fri_2<E, B>(f_x: E, f_minus_x: E, x_star: E, alpha: E) -> E
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    (f_x + f_minus_x + ((f_x - f_minus_x) * alpha / x_star)) / E::ONE.double()
}

struct Counter {
    leaves_hash: usize,
    node_hash: usize,
    field_mul: usize,
    field_mul_ext: usize,
    field_add_ext: usize,
    field_inv: usize,
    field_exp: usize,
    ext_deg: usize,
}

impl Counter {
    fn new() -> Self {
        Counter {
            leaves_hash: 0,
            node_hash: 0,
            field_mul: 0,
            field_add_ext: 0,
            field_inv: 0,
            field_exp: 0,
            field_mul_ext: 0,
            ext_deg: 0,
        }
    }
}
