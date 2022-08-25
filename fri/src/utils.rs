// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crypto::{Digest, ElementHasher, Hasher};
use math::FieldElement;
use utils::{
    collections::{BTreeMap, Vec},
    iter_mut, uninit_vector,
};

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

pub struct AdviceProvider<H, E, const N: usize>
where
    H: Hasher,
    E: FieldElement,
{
    sets: BTreeMap<[u8; 32], MerklePathSet<H>>,
    dict: BTreeMap<[u8; 32], [E; N]>,
}

pub struct MerklePathSet<H>
where
    H: Hasher,
{
    root: H::Digest,
    total_depth: u32,
    paths: BTreeMap<u64, Vec<H::Digest>>,
}

impl<H, E, const N: usize> AdviceProvider<H, E, N>
where
    H: ElementHasher<BaseField = E::BaseField>,
    E: FieldElement,
{
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new advice provider instantiated from the specified program inputs.
    pub fn new() -> Self {
        Self {
            sets: BTreeMap::new(),
            dict: BTreeMap::new(),
        }
    }

    pub(crate) fn add(
        &mut self,
        commitment: H::Digest,
        index: usize,
        path: &[H::Digest],
        values: &[E; N],
    ) -> () {
        // Add path to the appropriate set
        match self.sets.get_mut(&commitment.as_bytes()) {
            Some(set) => set.add_path(index as u64, path.to_vec()).unwrap(),
            None => {
                let mut s: MerklePathSet<H> = MerklePathSet::new(path.len() as u32).unwrap();
                s.add_path(index as u64, path.to_vec()).unwrap();
                self.sets.insert(commitment.as_bytes(), s);
            }
        }

        let node = path[0];
        self.dict.insert(node.as_bytes(), *values);
    }

    pub fn get_tree_node(
        &mut self,
        root: H::Digest,
        depth: u32,
        index: u64,
    ) -> Result<[E; N], ExecutionError> {
        // look up the advice set and return an error if none is found
        let advice_set = self
            .sets
            .get(&root.as_bytes())
            .ok_or_else(|| ExecutionError::AdviceSetNotFound(root.as_bytes()))?;

        // get the tree node from the advice set based on depth and index
        let node = advice_set
            .get_node(depth, index)
            .map_err(|_| ExecutionError::AdviceSetLookupFailed)?;

        let values = self.dict.get(&node.as_bytes()).unwrap();
        let digest = H::hash_elements(values);
        //println!("node {:?}", node);
        //println!("digest {:?}", digest);
        //println!("values {:?}", values);

        if digest != node {
            return Err(ExecutionError::InconsistentDigest);
        }

        Ok(*values)
    }
}

impl<H> MerklePathSet<H>
where
    H: Hasher,
{
    pub fn new(depth: u32) -> Result<Self, ()> {
        let root = H::Digest::default();
        let paths = BTreeMap::<u64, Vec<H::Digest>>::new();

        Ok(Self {
            root,
            total_depth: depth,
            paths,
        })
    }
    pub fn add_path(&mut self, index: u64, path: Vec<H::Digest>) -> Result<(), AdviceSetError> {
        let depth = (path.len()) as u32;

        if depth != self.total_depth {
            return Err(AdviceSetError::InvalidDepth(self.total_depth, depth));
        }

        // Actual number of node in tree
        let pos = 2u64.pow(self.total_depth) + index;

        let root_of_current_path = compute_path_root::<H>(&path, depth, index);
        if self.root == H::Digest::default() {
            self.root = root_of_current_path;
        } else if self.root != root_of_current_path {
            return Err(AdviceSetError::InvalidPath());
        }
        self.paths.insert(pos, path);

        Ok(())
    }

    pub fn get_node(&self, depth: u32, index: u64) -> Result<H::Digest, AdviceSetError> {
        if index >= 2u64.pow(self.total_depth) {
            return Err(AdviceSetError::InvalidIndex(self.total_depth, index));
        }
        if depth != self.total_depth {
            return Err(AdviceSetError::InvalidDepth(self.total_depth, depth));
        }

        let pos = 2u64.pow(depth) + index;

        match self.paths.get(&pos) {
            None => Err(AdviceSetError::NodeNotInSet(index)),
            Some(path) => Ok(path[0]),
        }
    }
}

fn is_even(pos: u64) -> bool {
    pos & 1 == 0
}

fn compute_path_root<H: Hasher>(path: &[H::Digest], depth: u32, index: u64) -> H::Digest {
    let mut pos = 2u64.pow(depth) + index;
    let r = (index as usize) & 1;
    let mut comp_hash = H::merge(&[path[r], path[1 - r]]);

    // hash that is obtained after calculating the current hash and path hash
    //let mut comp_hash = H::merge(&[path[0].into(), path[1].into()]).into();

    for path_hash in path.iter().skip(2) {
        pos /= 2;
        comp_hash = calculate_parent_hash::<H>(comp_hash, pos, *path_hash);
    }

    comp_hash
}
fn calculate_parent_hash<H: Hasher>(
    node: H::Digest,
    node_pos: u64,
    sibling: H::Digest,
) -> H::Digest {
    if is_even(node_pos) {
        H::merge(&[node.into(), sibling.into()]).into()
    } else {
        H::merge(&[sibling.into(), node.into()]).into()
    }
}

#[derive(Debug)]
pub enum ExecutionError {
    AdviceSetLookupFailed,
    AdviceSetNotFound([u8; 32]),
    InconsistentDigest,
}

#[derive(Clone, Debug)]
pub enum AdviceSetError {
    DepthTooSmall,
    DepthTooBig(u32),
    NumLeavesNotPowerOfTwo(usize),
    InvalidKey(u64),
    InvalidIndex(u32, u64),
    InvalidDepth(u32, u32),
    InvalidPath(),
    NodeNotInSet(u64),
}
