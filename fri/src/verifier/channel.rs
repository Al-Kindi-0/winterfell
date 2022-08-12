// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::mem;

use crate::{
    folding::{self, fold_positions},
    utils::{hash_values, map_positions_to_indexes},
    FriProof, VerifierError,
};
//use alloc::vec;
use crypto::{BatchMerkleProof, ElementHasher, Hasher, MerkleTree};
use math::FieldElement;
use utils::{collections::Vec, group_vector_elements, transpose_slice, DeserializationError};

// VERIFIER CHANNEL TRAIT
// ================================================================================================

/// Defines an interface for a channel over which a verifier communicates with a prover.
///
/// This trait abstracts away implementation specifics of the [FriProof] struct. Thus, instead of
/// dealing with FRI proofs directly, the verifier can read the data as if it was sent by the
/// prover via an interactive channel.
///
/// Note: that reading removes the data from the channel. Thus, reading duplicated values from
/// the channel should not be possible.
pub trait VerifierChannel<E: FieldElement> {
    /// Hash function used by the prover to commit to polynomial evaluations.
    type Hasher: ElementHasher<BaseField = E::BaseField>;

    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of partitions used during proof generation.
    fn read_fri_num_partitions(&self) -> usize;

    /// Reads and removes from the channel all FRI layer commitments sent by the prover.
    ///
    /// In the interactive version of the protocol, the prover sends layer commitments to the
    /// verifier one-by-one, and the verifier responds with a value α drawn uniformly at random
    /// from the entire field after each layer commitment is received. In the non-interactive
    /// version, the verifier can read all layer commitments at once, and then generate α values
    /// locally.
    fn read_fri_layer_commitments(
        &mut self,
    ) -> Vec<<<Self as VerifierChannel<E>>::Hasher as Hasher>::Digest>;

    /// Reads and removes from the channel evaluations of the polynomial at the queried positions
    /// for the next FRI layer.
    ///
    /// In the interactive version of the protocol, these evaluations are sent from the prover to
    /// the verifier during the query phase of the FRI protocol.
    ///
    /// It is expected that layer queries and layer proofs at the same FRI layer are consistent.
    /// That is, query values hash into the leaf nodes of corresponding Merkle authentication
    /// paths.
    fn take_next_fri_layer_queries(&mut self) -> Vec<E>;

    /// Reads and removes from the channel Merkle authentication paths for queried evaluations for
    /// the next FRI layer.
    ///
    /// In the interactive version of the protocol, these authentication paths are sent from the
    /// prover to the verifier during the query phase of the FRI protocol.
    ///
    /// It is expected that layer proofs and layer queries at the same FRI layer are consistent.
    /// That is, query values hash into the leaf nodes of corresponding Merkle authentication
    /// paths.
    fn take_next_fri_layer_proof(&mut self) -> BatchMerkleProof<Self::Hasher>;

    /// Reads and removes the remainder (last FRI layer) values from the channel.
    fn take_fri_remainder(&mut self) -> Vec<E>;

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns FRI query values at the specified positions from the current FRI layer and advances
    /// layer pointer by one.
    ///
    /// This also checks if the values are valid against the provided FRI layer commitment.
    ///
    /// # Errors
    /// Returns an error if query values did not match layer commitment.
    fn read_layer_queries<const N: usize>(
        &mut self,
        positions: &[usize],
        commitment: &<<Self as VerifierChannel<E>>::Hasher as Hasher>::Digest,
    ) -> Result<Vec<[E; N]>, VerifierError> {
        let layer_proof = self.take_next_fri_layer_proof();
        MerkleTree::<Self::Hasher>::verify_batch(commitment, positions, &layer_proof)
            .map_err(|_| VerifierError::LayerCommitmentMismatch)?;

        // TODO: make sure layer queries hash into leaves of layer proof

        let layer_queries = self.take_next_fri_layer_queries();
        Ok(group_vector_elements(layer_queries))
    }

    /// Returns FRI remainder values (last FRI layer) read from this channel.
    ///
    /// This also checks whether the remainder is valid against the provided commitment.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Remainder values read from the channel cannot be used to construct a fully-balanced
    ///   Merkle tree.
    /// - If the root of the Merkle tree constructed from the remainder values does not match
    ///   the specified `commitment`.
    fn read_remainder<const N: usize>(
        &mut self,
        commitment: &<<Self as VerifierChannel<E>>::Hasher as Hasher>::Digest,
    ) -> Result<Vec<E>, VerifierError> {
        let remainder = self.take_fri_remainder();

        // build remainder Merkle tree
        let remainder_values = transpose_slice(&remainder);
        let hashed_values = hash_values::<Self::Hasher, E, N>(&remainder_values);
        let remainder_tree = MerkleTree::<Self::Hasher>::new(hashed_values)
            .map_err(|err| VerifierError::RemainderTreeConstructionFailed(format!("{}", err)))?;

        // make sure the root of the tree matches the committed root of the last layer
        if commitment != remainder_tree.root() {
            return Err(VerifierError::RemainderCommitmentMismatch);
        }

        Ok(remainder)
    }
    fn unbatch<const N: usize>(
        &self,
        positions: &[usize],
        domain_size: usize,
        folding_factor: usize,
        layer_commitments: Vec<<<Self as VerifierChannel<E>>::Hasher as Hasher>::Digest>,
    ) -> Vec<Vec<(Vec<<<Self as VerifierChannel<E>>::Hasher as Hasher>::Digest>, [E;N])>>;
}

// DEFAULT VERIFIER CHANNEL IMPLEMENTATION
// ================================================================================================

/// Provides a default implementation of the [VerifierChannel] trait.
///
/// Default verifier channel can be instantiated directly from a [FriProof] struct.
///
/// Though this implementation is primarily intended for testing purposes, it can be used in
/// production use cases as well.
pub struct DefaultVerifierChannel<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>> {
    layer_commitments: Vec<H::Digest>,
    layer_proofs: Vec<BatchMerkleProof<H>>,
    layer_queries: Vec<Vec<E>>,
    remainder: Vec<E>,
    num_partitions: usize,
}

impl<E, H> DefaultVerifierChannel<E, H>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    /// Builds a new verifier channel from the specified [FriProof].
    ///
    /// # Errors
    /// Returns an error if the specified `proof` could not be parsed correctly.
    pub fn new(
        proof: FriProof,
        layer_commitments: Vec<H::Digest>,
        domain_size: usize,
        folding_factor: usize,
    ) -> Result<Self, DeserializationError> {
        let num_partitions = proof.num_partitions();

        let remainder = proof.parse_remainder()?;
        let (layer_queries, layer_proofs) =
            proof.parse_layers::<H, E>(domain_size, folding_factor)?;

        Ok(DefaultVerifierChannel {
            layer_commitments,
            layer_proofs,
            layer_queries,
            remainder,
            num_partitions,
        })
    }

    
}

impl<E, H> VerifierChannel<E> for DefaultVerifierChannel<E, H>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    type Hasher = H;

    fn read_fri_num_partitions(&self) -> usize {
        self.num_partitions
    }

    fn read_fri_layer_commitments(&mut self) -> Vec<H::Digest> {
        self.layer_commitments.drain(..).collect()
    }

    fn take_next_fri_layer_proof(&mut self) -> BatchMerkleProof<H> {
        self.layer_proofs.remove(0)
    }

    fn take_next_fri_layer_queries(&mut self) -> Vec<E> {
        self.layer_queries.remove(0)
    }

    fn take_fri_remainder(&mut self) -> Vec<E> {
        self.remainder.clone()
    }
    
    fn unbatch<const N: usize>(
        &self,
        positions_: &[usize],
        domain_size: usize,
        folding_factor: usize,
        layer_commitments: Vec<H::Digest>
    ) -> Vec<Vec<(Vec<H::Digest>, [E;N])>> {
        let queries = self.layer_queries.clone();
        let mut current_domain_size = domain_size;
        let mut positions = positions_.to_vec();
        //println!("layer_commitments.len() {:?}",layer_commitments);
        let depth = layer_commitments.len() - 1;
        //println!("position_indexes unbatch {:?}",depth);
        let mut result: Vec<Vec<(usize, Vec<<H as Hasher>::Digest>, [E;N])>> = Vec::new();
        for i in 0..depth {
            //let current_domain_size = current_domain_size / folding_factor;
            let mut folded_positions =
                fold_positions(&positions, current_domain_size, folding_factor);
            //eprintln!("The orignal positions' length {:?}",positions.len());
            //eprintln!("The folded positions' length {:?}",folded_positions.len());
            // determine where these evaluations are in the commitment Merkle tree
            let position_indexes = map_positions_to_indexes(
                &folded_positions,
                current_domain_size,
                folding_factor,
                self.num_partitions,
            );
            assert_eq!(position_indexes, folded_positions);
            //println!("position_indexes unbatch {:?}",position_indexes);
            let unbatched_proof = self.layer_proofs[i].unbatch(&position_indexes).unwrap();
            //TODO: Verify Merkle paths 
            let x = group_vector_elements::<E,N>(queries[i].clone());
            //println!("number of queries {:?}", positions.len());
            //let values = queries[i].clone();
            assert_eq!(x.len(),unbatched_proof.len());
            
            //assert_eq!(unbatched_proof.len(), values.len());
            //let partial_result: Vec<(usize,Vec<H::Digest>,E)>;
            let partial_result = {
                let mut partial_result: Vec<_> = Vec::new();
                for j in 0..unbatched_proof.len() {
                    let tmp = (
                        position_indexes[j],
                        unbatched_proof[j].clone(),
                        x[j],
                    );
                    //println!(" x[j] {:?}",x[j]);
                    //println!("values[j] {:?}",values[j]);
                    partial_result.push(tmp);
                }
               partial_result 
            };
            result.push(partial_result);
            mem::swap(&mut positions, &mut folded_positions);
            current_domain_size = current_domain_size / folding_factor;
        }

        let mut final_result: Vec<Vec<(Vec<<H as Hasher>::Digest>, [E;N])>> = Vec::new();
        for p in positions_.iter() {
            let mut current_domain_size = domain_size;
            let current_position = p;

            let query_across_layers = {
                let mut query_across_layers: Vec<(Vec<<H as Hasher>::Digest>, [E;N])> = Vec::new();
                for i in 0..depth {
                    current_domain_size = current_domain_size / folding_factor;
                    let current_position = current_position % current_domain_size;
                    let queries_current_layer = result[i].clone();
                    //println!("current position {:?}",current_position);
                    //println!("result[i] {:?}",queries_current_layer);
                    // Two parent indices can fold to the same child index and thus the two query values can belong to 
                    // the same N-group elements. Thus we should imploy the same logic used in get query values function
                    // This means we should include in result[i] the pairs (folded_index,N-tuple-values)
                
                    let single_query = queries_current_layer
                        .iter()
                        .find(|(i, _, _)| *i == current_position)
                        .unwrap();
                    if single_query.0 == 492{
                        let r: Vec<&usize> = queries_current_layer.iter().map(|(i,_,_)|{i}).collect::<Vec<&usize>>();
                        println!("All queries in this layer {:?}",r);
                    }
                    let single_query = ((*single_query).1.clone(), single_query.2);
                    //println!("single_query {:?}",single_query);
                    query_across_layers.push(single_query);
                    //*current_position = current_folded_position;
                }
                query_across_layers
            };
            final_result.push(query_across_layers);
        }

        assert!(final_result.len() == (*positions_).len());
        assert!(final_result[0].len() == depth);
        final_result
    }
}