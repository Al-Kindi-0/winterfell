// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{errors::MerkleTreeError, Hasher};
use utils::{
    collections::{BTreeMap, Vec},
    string::ToString,
    ByteReader, Deserializable, DeserializationError, Serializable,
};

// CONSTANTS
// ================================================================================================

pub(super) const MAX_PATHS: usize = 255;

// BATCH MERKLE PROOF
// ================================================================================================

/// Multiple Merkle paths aggregated into a single proof.
///
/// The aggregation is done in a way which removes all duplicate internal nodes, and thus,
/// it is possible to achieve non-negligible compression as compared to naively concatenating
/// individual Merkle paths. The algorithm is for aggregation is a variation of
/// [Octopus](https://eprint.iacr.org/2017/933).
///
/// Currently, at most 255 paths can be aggregated into a single proof. This limitation is
/// imposed primarily for serialization purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchMerkleProof<H: Hasher> {
    pub(super) leaves: Vec<H::Digest>,
    pub(super) nodes: Vec<Vec<H::Digest>>,
    pub(super) depth: u8,
}

impl<H: Hasher> BatchMerkleProof<H> {
    /// Constructs a batch Merkle proof from individual Merkle authentication paths.
    ///
    /// # Panics
    /// Panics if:
    /// * No paths have been provided (i.e., `paths` is an empty slice).
    /// * More than 255 paths have been provided.
    /// * Number of paths is not equal to the number of indexes.
    /// * Not all paths have the same length.
    pub fn from_paths(paths: &[Vec<H::Digest>], indexes: &[usize]) -> BatchMerkleProof<H> {
        // TODO: optimize this to reduce amount of vector cloning.
        assert!(!paths.is_empty(), "at least one path must be provided");
        assert!(
            paths.len() <= MAX_PATHS,
            "number of paths cannot exceed {}",
            MAX_PATHS
        );
        assert_eq!(
            paths.len(),
            indexes.len(),
            "number of paths must equal number of indexes"
        );

        let depth = paths[0].len();

        // sort indexes in ascending order, and also re-arrange paths accordingly
        let mut path_map = BTreeMap::new();
        for (&index, path) in indexes.iter().zip(paths.iter().cloned()) {
            assert_eq!(depth, path.len(), "not all paths have the same length");
            path_map.insert(index, path);
        }
        let indexes = path_map.keys().cloned().collect::<Vec<_>>();
        let paths = path_map.values().cloned().collect::<Vec<_>>();
        path_map.clear();

        let mut leaves = vec![H::Digest::default(); indexes.len()];
        let mut nodes: Vec<Vec<H::Digest>> = Vec::with_capacity(indexes.len());

        // populate values and the first layer of proof nodes
        let mut i = 0;
        while i < indexes.len() {
            leaves[i] = paths[i][0];
            if indexes.len() > i + 1 && are_siblings(indexes[i], indexes[i + 1]) {
                leaves[i + 1] = paths[i][1];
                nodes.push(vec![]);
                i += 1;
            } else {
                nodes.push(vec![paths[i][1]]);
            }
            path_map.insert(indexes[i] >> 1, paths[i].clone());
            i += 1;
        }

        // populate all remaining layers of proof nodes
        for d in 2..depth {
            let indexes = path_map.keys().cloned().collect::<Vec<_>>();
            let mut next_path_map = BTreeMap::new();

            let mut i = 0;
            while i < indexes.len() {
                let index = indexes[i];
                let path = path_map.get(&index).unwrap();
                if indexes.len() > i + 1 && are_siblings(index, indexes[i + 1]) {
                    i += 1;
                } else {
                    nodes[i].push(path[d]);
                }
                next_path_map.insert(index >> 1, path.clone());
                i += 1;
            }

            core::mem::swap(&mut path_map, &mut next_path_map);
        }

        BatchMerkleProof {
            leaves,
            nodes,
            depth: (depth - 1) as u8,
        }
    }

    /// Computes a node to which all Merkle paths aggregated in this proof resolve.
    ///
    /// # Errors
    /// Returns an error if:
    /// * No indexes were provided (i.e., `indexes` is an empty slice).
    /// * Number of provided indexes is greater than 255.
    /// * Any of the specified `indexes` is greater than or equal to the number of leaves in the
    ///   tree for which this batch proof was generated.
    /// * List of indexes contains duplicates.
    /// * The proof does not resolve to a single root.
    pub fn get_root(&self, indexes: &[usize]) -> Result<H::Digest, MerkleTreeError> {
        if indexes.is_empty() {
            return Err(MerkleTreeError::TooFewLeafIndexes);
        }
        if indexes.len() > MAX_PATHS {
            return Err(MerkleTreeError::TooManyLeafIndexes(
                MAX_PATHS,
                indexes.len(),
            ));
        }

        let mut buf = [H::Digest::default(); 2];
        let mut v = BTreeMap::new();

        // replace odd indexes, offset, and sort in ascending order
        let index_map = super::map_indexes(indexes, self.depth as usize)?;
        let indexes = super::normalize_indexes(indexes);
        if indexes.len() != self.nodes.len() {
            return Err(MerkleTreeError::InvalidProof);
        }

        // for each index use values to compute parent nodes
        let offset = 2usize.pow(self.depth as u32);
        let mut next_indexes: Vec<usize> = Vec::new();
        let mut proof_pointers: Vec<usize> = Vec::with_capacity(indexes.len());
        for (i, index) in indexes.into_iter().enumerate() {
            // copy values of leaf sibling leaf nodes into the buffer
            match index_map.get(&index) {
                Some(&index1) => {
                    if self.leaves.len() <= index1 {
                        return Err(MerkleTreeError::InvalidProof);
                    }
                    buf[0] = self.leaves[index1];
                    match index_map.get(&(index + 1)) {
                        Some(&index2) => {
                            if self.leaves.len() <= index2 {
                                return Err(MerkleTreeError::InvalidProof);
                            }
                            buf[1] = self.leaves[index2];
                            proof_pointers.push(0);
                        }
                        None => {
                            if self.nodes[i].is_empty() {
                                return Err(MerkleTreeError::InvalidProof);
                            }
                            buf[1] = self.nodes[i][0];
                            proof_pointers.push(1);
                        }
                    }
                }
                None => {
                    if self.nodes[i].is_empty() {
                        return Err(MerkleTreeError::InvalidProof);
                    }
                    buf[0] = self.nodes[i][0];
                    match index_map.get(&(index + 1)) {
                        Some(&index2) => {
                            if self.leaves.len() <= index2 {
                                return Err(MerkleTreeError::InvalidProof);
                            }
                            buf[1] = self.leaves[index2];
                        }
                        None => return Err(MerkleTreeError::InvalidProof),
                    }
                    proof_pointers.push(1);
                }
            }

            // hash sibling nodes into their parent
            let parent = H::merge(&buf);

            let parent_index = (offset + index) >> 1;
            v.insert(parent_index, parent);
            next_indexes.push(parent_index);
        }

        // iteratively move up, until we get to the root
        for _ in 1..self.depth {
            let indexes = next_indexes.clone();
            next_indexes.truncate(0);

            let mut i = 0;
            while i < indexes.len() {
                let node_index = indexes[i];
                let sibling_index = node_index ^ 1;

                // determine the sibling
                let sibling: H::Digest;
                if i + 1 < indexes.len() && indexes[i + 1] == sibling_index {
                    sibling = match v.get(&sibling_index) {
                        Some(sibling) => *sibling,
                        None => return Err(MerkleTreeError::InvalidProof),
                    };
                    i += 1;
                } else {
                    let pointer = proof_pointers[i];
                    if self.nodes[i].len() <= pointer {
                        return Err(MerkleTreeError::InvalidProof);
                    }
                    sibling = self.nodes[i][pointer];
                    proof_pointers[i] += 1;
                }

                // get the node from the map of hashed nodes
                let node = match v.get(&node_index) {
                    Some(node) => node,
                    None => return Err(MerkleTreeError::InvalidProof),
                };

                // compute parent node from node and sibling
                if node_index & 1 != 0 {
                    buf[0] = sibling;
                    buf[1] = *node;
                } else {
                    buf[0] = *node;
                    buf[1] = sibling;
                }
                let parent = H::merge(&buf);

                // add the parent node to the next set of nodes
                let parent_index = node_index >> 1;
                v.insert(parent_index, parent);
                next_indexes.push(parent_index);

                i += 1;
            }
        }
        v.remove(&1).ok_or(MerkleTreeError::InvalidProof)
    }

    /// Computes the uncompressed Merkle paths which aggregate to this proof.
    ///
    /// # Errors
    /// Returns an error if:
    /// * No indexes were provided (i.e., `indexes` is an empty slice).
    /// * Number of provided indexes is greater than 255.
    pub fn unbatch(
        batch_proof: BatchMerkleProof<H>,
        indexes: &[usize],
        depth: usize,
    ) -> Result<Vec<Vec<H::Digest>>,MerkleTreeError> {
        if indexes.is_empty() {
            return Err(MerkleTreeError::TooFewLeafIndexes);
        }
        if indexes.len() > MAX_PATHS {
            return Err(MerkleTreeError::TooManyLeafIndexes(
                MAX_PATHS,
                indexes.len(),
            ));
        }
        let mut leaves = batch_proof.leaves.clone();
        leaves.reverse();
        let mut complete_leaves = Vec::with_capacity(1 << (depth + 1));
        for _ in 0..(1 << (depth + 1)) {
            complete_leaves.push(H::Digest::default());
        }
        //println!("Length of complete_leaves {:?}", complete_leaves.len());
        for i in indexes {
            if let Some(leave) = leaves.pop() {
                complete_leaves[*i + (1 << (depth))] = leave;
            } else {
                println!("Error in poping");
            }
        }
        //println!("complete leaves begin {:?}",complete_leaves[9]);
        //println!("complete leaves begin {:?}",complete_leaves[10]);
        // get the queue of nodes in depth first order
        let nodes = batch_proof.nodes;
        let mut flattened_nodes = vec![];
        for i in 0..(1 << depth) {
            for l in &nodes {
                if i < l.len() {
                    flattened_nodes.push(l[i]);
                }
            }
        }
        //println!("nodes {:?}", nodes);
        //println!("flattened nodes {:?}", flattened_nodes);

        //flattened_nodes.reverse();
        // Filling up the intermediate nodes

        //println!(
        //"RESULT IS {:?}",
        //Self::populate_tree(&A, &E, &flattened_nodes, &d, &mut complete_leaves)
        //);

        //println!("initial depth {:?}", d);
        let a = indexes.to_vec();
        let e = batch_proof.leaves;
        let d = depth;

        Self::populate_tree(&a, &e, &flattened_nodes, &d, &mut complete_leaves);

        for i in (1 << depth)..0 {
            complete_leaves[i] = hash_2x1::<H>(complete_leaves[2 * i], complete_leaves[2 * i + 1]);
        }

        let mut result = vec![];
        for i in indexes {
            result.push(get_path::<H>(*i, &complete_leaves).to_vec());
            println!(
                "The proof for index {:?} is {:?}",
                i,
                get_path::<H>(*i, &complete_leaves)
            );
        }
        Ok(result)
    }

    /// The main function to compute all necessary nodes needed for the individual Merkle paths.
    fn populate_tree(
        a: &[usize],
        e: &[H::Digest],
        m: &[H::Digest],
        depth: &usize,
        tree: &mut Vec<H::Digest>,
    ) -> Option<Vec<H::Digest>> {
        let b: Vec<(usize, usize)> = a
            .iter()
            .map(|i| if i % 2 == 0 { (*i, i + 1) } else { (i - 1, *i) })
            .collect();
        let mut e_new = vec![];
        let mut m_new = m.to_owned();
        // E must always have the same length as B
        if e.len() != b.len() {
            return None;
        }

        let mut i = 0;
        // assign generated hashes to a new E that will be used for next iteration
        while i < b.len() {
            if b.len() > 1 && b.get(i) == b.get(i + 1) {
                //println!("We are in duplicate case for {:?}", b.get(i));
                //println!("the tree index is {:?}", a[i] + (1 << depth));
                //println!("the index from a is {:?}", a[i]);
                //println!("I am hashing {:?} and {:?}", e[i], e[i + 1]);
                //println!("and the combined hash is {:?}", hash_2x1(e[i], e[i + 1]));
                //println!("Should be inserted in {:?}", (a[i] + (1 << depth)) / 2);
                e_new.push(hash_2x1::<H>(e[i], e[i + 1]));
                let insert_pos = (a[i] + (1 << depth)) / 2;
                //println!("Hashing parent node of {:?} and {:?} is {:?}",e[i],e[i+1], hash_2x1(e[i],e[i+1]));
                //println!("It should be {:?}",hash_2x1(
                //hash_2x1(leaves[0], leaves[1]),
                //hash_2x1(leaves[2], leaves[3]),
                //));
                tree[insert_pos] = hash_2x1::<H>(e[i], e[i + 1]);

                i += 2;
            } else {
                let head = if !m_new.is_empty() {
                    m_new.remove(0)
                } else {
                    return None;
                };

                if a[i] % 2 == 0 {
                    //println!("We are in the case of poping from stack (e[i],popped)");
                    //println!("Element popped {:?}", head);
                    //println!("Hashed with {:?}", e[i]);
                    //println!("Resulting in {:?}", hash_2x1(e[i], head));
                    e_new.push(hash_2x1::<H>(e[i], head));
                    //println!("Should be inserted in {:?}", (a[i] + (1 << depth)) / 2);
                    let insert_pos = a[i] + (1 << depth);
                    //println!("Case 2: the hash calculated is {:?}", head);
                    //println!("the correct hash is {:?}", leaves[3]);
                    tree[insert_pos ^ 1] = head;
                    tree[insert_pos / 2] = hash_2x1::<H>(e[i], head);
                } else {
                    //println!("We are in the case of poping from stack (popped, e[i])");
                    //println!("Element popped {:?}", head);
                    //println!("Hashed with {:?}", e[i]);
                    //println!("Resulting in {:?}", hash_2x1(head, e[i]));
                    //println!("Should be inserted in {:?}", (a[i] + (1 << depth)) / 2);
                    e_new.push(hash_2x1::<H>(head, e[i]));
                    let insert_pos = a[i] + (1 << depth);
                    //println!("Case 3:insert pos is {:?}", hash_2x1(head, e[i]));
                    tree[insert_pos ^ 1] = head;
                    tree[insert_pos / 2] = hash_2x1::<H>(head, e[i]);
                }
                i += 1;
            }
        }
        // Generate indices for parents of current b
        let mut a_new: Vec<usize> = b.iter().map(|(_, b)| b / 2).collect(); 
        //println!("a_new is {:?}", a_new);
        //a_new.sort_unstable();
        a_new.dedup();

        if (!m_new.is_empty() || e_new.len() > 1) && !a_new.is_empty() {
            let e = e_new.clone();
            e_new = Self::populate_tree(&a_new, &e, &m_new, &(*depth - 1), tree)?;
        }
        Some(e_new)
    }


    // SERIALIZATION / DESERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Converts all internal proof nodes into a vector of bytes.
    ///
    /// # Panics
    /// Panics if:
    /// * The proof contains more than 255 Merkle paths.
    /// * The Merkle paths consist of more than 255 nodes.
    pub fn serialize_nodes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // record total number of node vectors
        assert!(self.nodes.len() <= u8::MAX as usize, "too many paths");
        result.push(self.nodes.len() as u8);

        // record each node vector as individual bytes
        for nodes in self.nodes.iter() {
            assert!(nodes.len() <= u8::MAX as usize, "too many nodes");
            // record the number of nodes, and append all nodes to the paths buffer
            result.push(nodes.len() as u8);
            for node in nodes.iter() {
                result.append(&mut node.to_bytes());
            }
        }

        result
    }

    /// Parses internal nodes from the provided `node_bytes`, and constructs a batch Merkle proof
    /// from these nodes, provided `leaves`, and provided tree `depth`.
    ///
    /// # Errors
    /// Returns an error if:
    /// * No leaves were provided (i.e., `leaves` is an empty slice).
    /// * Number of provided leaves is greater than 255.
    /// * Tree `depth` was set to zero.
    /// * `node_bytes` could not be deserialized into a valid set of internal nodes.
    pub fn deserialize<R: ByteReader>(
        node_bytes: &mut R,
        leaves: Vec<H::Digest>,
        depth: u8,
    ) -> Result<Self, DeserializationError> {
        if depth == 0 {
            return Err(DeserializationError::InvalidValue(
                "tree depth must be greater than zero".to_string(),
            ));
        }
        if leaves.is_empty() {
            return Err(DeserializationError::InvalidValue(
                "at lease one leaf must be provided".to_string(),
            ));
        }
        if leaves.len() > MAX_PATHS {
            return Err(DeserializationError::InvalidValue(format!(
                "number of leaves cannot exceed {}, but {} were provided",
                MAX_PATHS,
                leaves.len()
            )));
        }

        let num_node_vectors = node_bytes.read_u8()? as usize;
        let mut nodes = Vec::with_capacity(num_node_vectors);
        for _ in 0..num_node_vectors {
            // read the number of digests in the vector
            let num_digests = node_bytes.read_u8()? as usize;

            // read the digests and add them to the node vector
            let digests = H::Digest::read_batch_from(node_bytes, num_digests)?;
            nodes.push(digests);
        }

        Ok(BatchMerkleProof {
            leaves,
            nodes,
            depth,
        })
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Two nodes are siblings if index of the left node is even and right node
/// immediately follows the left node.
fn are_siblings(left: usize, right: usize) -> bool {
    left & 1 == 0 && right - 1 == left
}

pub fn get_path<H: Hasher>(index: usize, tree: &[H::Digest]) -> Vec<H::Digest> {
    let mut index = index + tree.len() / 2;
    let mut proof = vec![tree[index]];
    while index > 1 {
        proof.push(tree[index ^ 1]);
        index >>= 1;
    }

    return proof;
}

fn hash_2x1<H: Hasher>(v1: H::Digest, v2: H::Digest) -> H::Digest {
    H::merge(&[v1, v2])
}
