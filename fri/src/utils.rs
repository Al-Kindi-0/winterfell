// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crypto::ElementHasher;
use math::FieldElement;
use utils::{collections::{Vec, BTreeMap}, iter_mut, uninit_vector};

#[cfg(feature = "concurrent")]
use utils::iterators::*;

/// Maps positions in the evaluation domain to indexes of commitment Merkle tree.
pub fn map_positions_to_indexes(
    positions: &[usize],
    source_domain_size: usize,
    folding_factor: usize,
    num_partitions: usize,
) -> Vec<usize> {
    // if there was only 1 partition, order of elements in the commitment tree
    // is the same as the order of elements in the evaluation domain
    if num_partitions == 1 {
        return positions.to_vec();
    }

    let target_domain_size = source_domain_size / folding_factor;
    let partition_size = target_domain_size / num_partitions;

    let mut result = Vec::new();
    for position in positions {
        let partition_idx = position % num_partitions;
        let local_idx = (position - partition_idx) / num_partitions;
        let position = partition_idx * partition_size + local_idx;
        result.push(position);
    }

    result
}

/// Maps a position in the evaluation domain to its index in commitment Merkle tree.
pub fn map_position_to_index(
    position: &usize,
    source_domain_size: usize,
    folding_factor: usize,
    num_partitions: usize,
) -> usize {
    // if there was only 1 partition, order of elements in the commitment tree
    // is the same as the order of elements in the evaluation domain
    if num_partitions == 1 {
        return *position;
    }

    let target_domain_size = source_domain_size / folding_factor;
    let partition_size = target_domain_size / num_partitions;

    let partition_idx = position % num_partitions;
    let local_idx = (position - partition_idx) / num_partitions;
    let position = partition_idx * partition_size + local_idx;

    position
}

/// Hashes each of the arrays in the provided slice and returns a vector of resulting hashes.
pub fn hash_values<H, E, const N: usize>(values: &[[E; N]]) -> Vec<H::Digest>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    let mut result: Vec<H::Digest> = unsafe { uninit_vector(values.len()) };
    iter_mut!(result, 1024).zip(values).for_each(|(r, v)| {
        *r = H::hash_elements(v);
    });
    result
}

pub struct AdviceProvider<E,const N: usize> where E: FieldElement{
    sets: BTreeMap<[u8; 32], MerklePathSet<E>>,
}
pub type Word<E: FieldElement> = [E; 4];

pub struct MerklePathSet<E> where E: FieldElement {
    root: Word<E>,
    total_depth: u32,
    paths: BTreeMap<u64, Vec<Word<E>>>,
}

impl<E,const N: usize> AdviceProvider<E,N> where E: FieldElement{
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new advice provider instantiated from the specified program inputs.
    pub fn new(inputs: Vec<Vec<(Vec<Word<E>>, [E; N])>>, commitments: Vec<Word<E>>) -> Self {

        let mut sets = BTreeMap::new();

        for q in inputs.iter(){
            for (q_layer,commit_layer) in q.iter().zip(commitments.iter()){
                sets.insert(commit_layer, q_layer);
            }
        }

        Self {
            sets: BTreeMap::new(),
        }
    }


}