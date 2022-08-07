// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::hash::ByteDigest;

use super::*;
use math::fields::f128::BaseElement;
use proptest::prelude::*;

type Digest256 = crate::hash::ByteDigest<32>;
type Blake3_256 = crate::hash::Blake3_256<BaseElement>;

static LEAVES4: [[u8; 32]; 4] = [
    [
        166, 168, 47, 140, 153, 86, 156, 86, 226, 229, 149, 76, 70, 132, 209, 109, 166, 193, 113,
        197, 42, 116, 170, 144, 74, 104, 29, 110, 220, 49, 224, 123,
    ],
    [
        243, 57, 40, 140, 185, 79, 188, 229, 232, 117, 143, 118, 235, 229, 73, 251, 163, 246, 151,
        170, 14, 243, 255, 127, 175, 230, 94, 227, 214, 5, 89, 105,
    ],
    [
        11, 33, 220, 93, 26, 67, 166, 154, 93, 7, 115, 130, 70, 13, 166, 45, 120, 233, 175, 86,
        144, 110, 253, 250, 67, 108, 214, 115, 24, 132, 45, 234,
    ],
    [
        47, 173, 224, 232, 30, 46, 197, 186, 215, 15, 134, 211, 73, 14, 34, 216, 6, 11, 217, 150,
        90, 242, 8, 31, 73, 85, 150, 254, 229, 244, 23, 231,
    ],
];

static LEAVES8: [[u8; 32]; 8] = [
    [
        115, 29, 176, 48, 97, 18, 34, 142, 51, 18, 164, 235, 236, 96, 113, 132, 189, 26, 70, 93,
        101, 143, 142, 52, 252, 33, 80, 157, 194, 52, 209, 129,
    ],
    [
        52, 46, 37, 214, 24, 248, 121, 199, 229, 25, 171, 67, 65, 37, 98, 142, 182, 72, 202, 42,
        223, 160, 136, 60, 38, 255, 222, 82, 26, 27, 130, 203,
    ],
    [
        130, 43, 231, 0, 59, 228, 152, 140, 18, 33, 87, 27, 49, 190, 44, 82, 188, 155, 163, 108,
        166, 198, 106, 143, 83, 167, 201, 152, 106, 176, 242, 119,
    ],
    [
        207, 158, 56, 143, 28, 146, 238, 47, 169, 32, 166, 97, 163, 238, 171, 243, 33, 209, 120,
        219, 17, 182, 96, 136, 13, 90, 6, 27, 247, 242, 49, 111,
    ],
    [
        179, 64, 123, 119, 226, 139, 161, 127, 36, 251, 218, 88, 20, 217, 212, 85, 112, 85, 185,
        193, 230, 181, 4, 22, 54, 219, 135, 98, 235, 180, 182, 7,
    ],
    [
        101, 240, 19, 44, 43, 213, 31, 138, 39, 26, 82, 147, 255, 96, 234, 51, 105, 6, 233, 144,
        255, 187, 242, 3, 157, 246, 55, 175, 98, 121, 92, 175,
    ],
    [
        25, 96, 149, 179, 94, 8, 170, 214, 169, 135, 12, 212, 224, 157, 182, 127, 233, 93, 151,
        214, 36, 183, 156, 212, 233, 152, 125, 244, 146, 161, 75, 128,
    ],
    [
        247, 43, 130, 141, 234, 172, 61, 187, 109, 31, 56, 30, 14, 232, 92, 158, 48, 161, 108, 234,
        170, 180, 233, 77, 200, 248, 45, 152, 125, 11, 1, 171,
    ],
];

static LEAVES16: [[u8; 32]; 16] = [
    
    [
        115, 29, 176, 48, 97, 18, 34, 142, 51, 18, 164, 235, 236, 96, 113, 132, 189, 26, 70, 93,
        101, 143, 142, 52, 252, 33, 80, 157, 194, 52, 209, 129,
    ],
    [
        52, 46, 37, 214, 24, 248, 121, 199, 229, 25, 171, 67, 65, 37, 98, 142, 182, 72, 202, 42,
        223, 160, 136, 60, 38, 255, 222, 82, 26, 27, 130, 203,
    ],
    [
        130, 43, 231, 0, 59, 228, 152, 140, 18, 33, 87, 27, 49, 190, 44, 82, 188, 155, 163, 108,
        166, 198, 106, 143, 83, 167, 201, 152, 106, 176, 242, 119,
    ],
    [
        207, 158, 56, 143, 28, 146, 238, 47, 169, 32, 166, 97, 163, 238, 171, 243, 33, 209, 120,
        219, 17, 182, 96, 136, 13, 90, 6, 27, 247, 242, 49, 111,
    ],
    [
        179, 64, 123, 119, 226, 139, 161, 127, 36, 251, 218, 88, 20, 217, 212, 85, 112, 85, 185,
        193, 230, 181, 4, 22, 54, 219, 135, 98, 235, 180, 182, 7,
    ],
    [
        101, 240, 19, 44, 43, 213, 31, 138, 39, 26, 82, 147, 255, 96, 234, 51, 105, 6, 233, 144,
        255, 187, 242, 3, 157, 246, 55, 175, 98, 121, 92, 175,
    ],
    [
        25, 96, 149, 179, 94, 8, 170, 214, 169, 135, 12, 212, 224, 157, 182, 127, 233, 93, 151,
        214, 36, 183, 156, 212, 233, 152, 125, 244, 146, 161, 75, 128,
    ],
    [
        247, 43, 130, 141, 234, 172, 61, 187, 109, 31, 56, 30, 14, 232, 92, 158, 48, 161, 108, 234,
        170, 180, 233, 77, 200, 248, 45, 152, 125, 11, 1, 171,
    ],
    [
        115, 29, 176, 48, 97, 18, 34, 142, 51, 18, 164, 235, 236, 96, 113, 132, 189, 26, 70, 93,
        101, 143, 142, 52, 252, 33, 80, 157, 194, 52, 209, 129,
    ],
    [
        52, 46, 37, 214, 24, 248, 121, 199, 229, 25, 171, 67, 65, 37, 98, 142, 182, 72, 202, 42,
        223, 160, 136, 60, 38, 255, 222, 82, 26, 27, 130, 203,
    ],
    [
        130, 43, 231, 0, 59, 228, 152, 140, 18, 33, 87, 27, 49, 190, 44, 82, 188, 155, 163, 108,
        166, 198, 106, 143, 83, 167, 201, 152, 106, 176, 242, 119,
    ],
    [
        207, 158, 56, 143, 28, 146, 238, 47, 169, 32, 166, 97, 163, 238, 171, 243, 33, 209, 120,
        219, 17, 182, 96, 136, 13, 90, 6, 27, 247, 242, 49, 111,
    ],
    [
        179, 64, 123, 119, 226, 139, 161, 127, 36, 251, 218, 88, 20, 217, 212, 85, 112, 85, 185,
        193, 230, 181, 4, 22, 54, 219, 135, 98, 235, 180, 182, 7,
    ],
    [
        101, 240, 19, 44, 43, 213, 31, 138, 39, 26, 82, 147, 255, 96, 234, 51, 105, 6, 233, 144,
        255, 187, 242, 3, 157, 246, 55, 175, 98, 121, 92, 175,
    ],
    [
        25, 96, 149, 179, 94, 8, 170, 214, 169, 135, 12, 212, 224, 157, 182, 127, 233, 93, 151,
        214, 36, 183, 156, 212, 233, 152, 125, 244, 146, 161, 75, 128,
    ],
    [
        247, 43, 130, 141, 234, 172, 61, 187, 109, 31, 56, 30, 14, 232, 92, 158, 48, 161, 108, 234,
        170, 180, 233, 77, 200, 248, 45, 152, 125, 11, 1, 171,
    ],
];

#[test]
fn new_tree() {
    let leaves = Digest256::bytes_as_digests(&LEAVES4).to_vec();
    let tree = MerkleTree::<Blake3_256>::new(leaves.clone()).unwrap();
    assert_eq!(2, tree.depth());
    let root = hash_2x1(
        hash_2x1(leaves[0], leaves[1]),
        hash_2x1(leaves[2], leaves[3]),
    );
    assert_eq!(&root, tree.root());

    let leaves = Digest256::bytes_as_digests(&LEAVES8).to_vec();
    let tree = MerkleTree::<Blake3_256>::new(leaves.clone()).unwrap();
    assert_eq!(3, tree.depth());
    let root = hash_2x1(
        hash_2x1(
            hash_2x1(leaves[0], leaves[1]),
            hash_2x1(leaves[2], leaves[3]),
        ),
        hash_2x1(
            hash_2x1(leaves[4], leaves[5]),
            hash_2x1(leaves[6], leaves[7]),
        ),
    );
    assert_eq!(&root, tree.root());
}

#[test]
fn prove() {
    // depth 4
    let leaves = Digest256::bytes_as_digests(&LEAVES4).to_vec();
    let tree = MerkleTree::<Blake3_256>::new(leaves.clone()).unwrap();

    let proof = vec![leaves[1], leaves[0], hash_2x1(leaves[2], leaves[3])];
    assert_eq!(proof, tree.prove(1).unwrap());

    let proof = vec![leaves[2], leaves[3], hash_2x1(leaves[0], leaves[1])];
    assert_eq!(proof, tree.prove(2).unwrap());

    // depth 5
    let leaves = Digest256::bytes_as_digests(&LEAVES8).to_vec();
    let tree = MerkleTree::<Blake3_256>::new(leaves.clone()).unwrap();

    let proof = vec![
        leaves[1],
        leaves[0],
        hash_2x1(leaves[2], leaves[3]),
        hash_2x1(
            hash_2x1(leaves[4], leaves[5]),
            hash_2x1(leaves[6], leaves[7]),
        ),
    ];
    assert_eq!(proof, tree.prove(1).unwrap());

    let proof = vec![
        leaves[6],
        leaves[7],
        hash_2x1(leaves[4], leaves[5]),
        hash_2x1(
            hash_2x1(leaves[0], leaves[1]),
            hash_2x1(leaves[2], leaves[3]),
        ),
    ];
    assert_eq!(proof, tree.prove(6).unwrap());
}

#[test]
fn verify() {
    // depth 4
    let leaves = Digest256::bytes_as_digests(&LEAVES4).to_vec();
    let tree = MerkleTree::<Blake3_256>::new(leaves).unwrap();
    let proof = tree.prove(1).unwrap();
    assert!(MerkleTree::<Blake3_256>::verify(*tree.root(), 1, &proof).is_ok());

    let proof = tree.prove(2).unwrap();
    assert!(MerkleTree::<Blake3_256>::verify(*tree.root(), 2, &proof).is_ok());

    // depth 5
    let leaves = Digest256::bytes_as_digests(&LEAVES8).to_vec();
    let tree = MerkleTree::<Blake3_256>::new(leaves).unwrap();
    let proof = tree.prove(1).unwrap();
    assert!(MerkleTree::<Blake3_256>::verify(*tree.root(), 1, &proof).is_ok());

    let proof = tree.prove(6).unwrap();
    assert!(MerkleTree::<Blake3_256>::verify(*tree.root(), 6, &proof).is_ok());
}

#[test]
fn prove_batch() {
    let leaves = Digest256::bytes_as_digests(&LEAVES16).to_vec();
    let tree = MerkleTree::<Blake3_256>::new(leaves.clone()).unwrap();
/*
    // 1 index
    let proof = tree.prove_batch(&[1]).unwrap();
    let expected_values = vec![leaves[1]];
    let expected_nodes = vec![vec![
        leaves[0],
        hash_2x1(leaves[2], leaves[3]),
        hash_2x1(
            hash_2x1(leaves[4], leaves[5]),
            hash_2x1(leaves[6], leaves[7]),
        ),
    ]];
    assert_eq!(expected_values, proof.leaves);
    assert_eq!(expected_nodes, proof.nodes);
    assert_eq!(3, proof.depth);

    // 2 indexes
    let proof = tree.prove_batch(&[1, 2]).unwrap();
    let expected_values = vec![leaves[1], leaves[2]];
    let expected_nodes = vec![
        vec![
            leaves[0],
            hash_2x1(
                hash_2x1(leaves[4], leaves[5]),
                hash_2x1(leaves[6], leaves[7]),
            ),
        ],
        vec![leaves[3]],
    ];
    assert_eq!(expected_values, proof.leaves);
    assert_eq!(expected_nodes, proof.nodes);
    assert_eq!(3, proof.depth);

    // 2 indexes on opposite sides
    let proof = tree.prove_batch(&[1, 6]).unwrap();
    let expected_values = vec![leaves[1], leaves[6]];
    let expected_nodes = vec![
        vec![leaves[0], hash_2x1(leaves[2], leaves[3])],
        vec![leaves[7], hash_2x1(leaves[4], leaves[5])],
    ];
    assert_eq!(expected_values, proof.leaves);
    assert_eq!(expected_nodes, proof.nodes);
    assert_eq!(3, proof.depth);
*/
    // 4 indexes on opposite sides
    let proof = tree.prove_batch(&[2,3,8,13]).unwrap();
    let expected_values = vec![leaves[2], leaves[3],leaves[8], leaves[13]];
    let expected_nodes = vec![
        vec![hash_2x1(leaves[0],leaves[1]),hash_2x1(hash_2x1(leaves[4], leaves[5]),hash_2x1(leaves[6],leaves[7]))],

        vec![leaves[9], hash_2x1(leaves[10], leaves[11])],
        vec![leaves[12], hash_2x1(leaves[14], leaves[15])],
    ];
    assert_eq!(expected_values, proof.leaves);
    assert_eq!(expected_nodes, proof.nodes);

    // 3 indexes on opposite sides
    let proof = tree.prove_batch(&[0,2,6]).unwrap();
    let expected_values = vec![leaves[0], leaves[2],leaves[6]];
    let expected_nodes = vec![
        vec![leaves[1],hash_2x1(hash_2x1(hash_2x1(leaves[8], leaves[9]),hash_2x1(leaves[10],leaves[11])),hash_2x1(hash_2x1(leaves[12], leaves[13]),hash_2x1(leaves[14],leaves[15])))],

        vec![leaves[3]],
        vec![leaves[7], hash_2x1(leaves[4], leaves[5])],
    ];
    assert_eq!(expected_values, proof.leaves);
    assert_eq!(expected_nodes[0], proof.nodes[0]);


/*
    // all indexes
    let proof = tree.prove_batch(&[0, 1, 2, 3, 4, 5, 6, 7]).unwrap();
    let expected_nodes: Vec<Vec<Digest256>> = vec![vec![], vec![], vec![], vec![]];
    assert_eq!(leaves, proof.leaves);
    assert_eq!(expected_nodes, proof.nodes);
    assert_eq!(3, proof.depth);
    */
}

#[test]
fn verify_batch() {
    let leaves = Digest256::bytes_as_digests(&LEAVES8).to_vec();
    let tree = MerkleTree::<Blake3_256>::new(leaves).unwrap();

    let proof = tree.prove_batch(&[1]).unwrap();
    assert!(MerkleTree::verify_batch(tree.root(), &[1], &proof).is_ok());
    assert!(MerkleTree::verify_batch(tree.root(), &[2], &proof).is_err());

    let proof = tree.prove_batch(&[1, 2]).unwrap();
    assert!(MerkleTree::verify_batch(tree.root(), &[1, 2], &proof).is_ok());
    assert!(MerkleTree::verify_batch(tree.root(), &[1], &proof).is_err());
    assert!(MerkleTree::verify_batch(tree.root(), &[1, 3], &proof).is_err());
    assert!(MerkleTree::verify_batch(tree.root(), &[1, 2, 3], &proof).is_err());

    let proof = tree.prove_batch(&[1, 6]).unwrap();
    assert!(MerkleTree::verify_batch(tree.root(), &[1, 6], &proof).is_ok());

    let proof = tree.prove_batch(&[1, 3, 6]).unwrap();
    assert!(MerkleTree::verify_batch(tree.root(), &[1, 3, 6], &proof).is_ok());

    let proof = tree.prove_batch(&[0, 1, 2, 3, 4, 5, 6, 7]).unwrap();
    assert!(MerkleTree::verify_batch(tree.root(), &[0, 1, 2, 3, 4, 5, 6, 7], &proof).is_ok());
}

#[test]
fn verify_unbatch() {
    let leaves = Digest256::bytes_as_digests(&LEAVES8).to_vec();
    let tree = MerkleTree::<Blake3_256>::new(leaves).unwrap();

    let proof1 = tree.prove(1).unwrap();
    let proof2 = tree.prove(2).unwrap();
    let proof1_2 = tree.prove_batch(&[1, 2]).unwrap();
    let result = BatchMerkleProof::unbatch(proof1_2, &[1, 2], tree.depth(),&tree).unwrap();

    //assert_eq!(proof1, result[0]);
    //assert_eq!(proof2, result[1]);

    let proof3 = tree.prove(3).unwrap();
    let proof4 = tree.prove(4).unwrap();
    let proof6 = tree.prove(5).unwrap();
    let proof3_4_6 = tree.prove_batch(&[3, 4, 5]).unwrap();
    let result = BatchMerkleProof::unbatch(proof3_4_6, &[3, 4, 5], tree.depth(),&tree).unwrap();

    assert_eq!(proof3, result[0]);
    assert_eq!(proof4, result[1]);
    assert_eq!(proof6, result[2]);

    println!("Here is good!");

    let leaves = vec![
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 250, 122, 37, 16, 28, 83, 249, 224,
            47, 41, 222, 96, 165, 245, 167,
        ],
        [
            87, 243, 106, 177, 201, 249, 155, 45, 3, 253, 190, 127, 63, 195, 153, 47, 11, 67, 207,
            16, 212, 116, 182, 169, 240, 91, 201, 26, 207, 41, 49, 61,
        ],
        [
            38, 180, 55, 126, 139, 37, 141, 241, 84, 109, 58, 188, 2, 53, 105, 30, 32, 101, 5, 229,
            252, 89, 188, 230, 41, 9, 48, 146, 150, 220, 155, 140,
        ],
        [
            17, 69, 143, 1, 194, 237, 169, 26, 24, 222, 220, 94, 111, 25, 64, 97, 92, 174, 208,
            138, 248, 38, 153, 11, 154, 244, 7, 244, 53, 133, 189, 220,
        ],
    ];
    let leaves = Digest256::bytes_as_digests(&leaves).to_vec();
    let tree = MerkleTree::<Blake3_256>::new(leaves).unwrap();

    let proof1 = tree.prove(1).unwrap();
    let proof2 = tree.prove(2).unwrap();
    let proof1_2 = tree.prove_batch(&[1, 2]).unwrap();
    let result = BatchMerkleProof::unbatch(proof1_2, &[1, 2], tree.depth(),&tree).unwrap();

    assert_eq!(proof1, result[0]);
    assert_eq!(proof2, result[1]);

    let proof1 = tree.prove(1).unwrap();
    let proof3 = tree.prove(3).unwrap();
    let proof4 = tree.prove(4).unwrap();
    let proof1_3_4 = tree.prove_batch(&[1, 3, 4]).unwrap();
    let result = BatchMerkleProof::unbatch(proof1_3_4, &[1, 3, 4], tree.depth(),&tree).unwrap();
    println!("Root is {:?}",&tree.root());
    assert_eq!(proof1, result[0]);
    assert_eq!(proof3, result[1]);
    assert_eq!(proof4, result[2]);
}

proptest! {
    #[test]
    fn prove_n_verify(tree in random_blake3_merkle_tree(128),
                      proof_indices in prop::collection::vec(any::<prop::sample::Index>(), 10..20)
    )  {
        for proof_index in proof_indices{
            let proof = tree.prove(proof_index.index(128)).unwrap();
            prop_assert!(MerkleTree::<Blake3_256>::verify(*tree.root(), proof_index.index(128), &proof).is_ok())
        }
    }

    #[test]
    fn prove_batch_n_verify(tree in random_blake3_merkle_tree(128),
                      proof_indices in prop::collection::vec(any::<prop::sample::Index>(), 10..20)
    )  {
        let mut indices: Vec<usize> = proof_indices.iter().map(|idx| idx.index(128)).collect();
        indices.sort_unstable(); indices.dedup();
        let proof = tree.prove_batch(&indices[..]).unwrap();
        prop_assert!(MerkleTree::verify_batch(tree.root(), &indices[..], &proof).is_ok());
    }

    #[test]
    fn batch_proof_from_paths(tree in random_blake3_merkle_tree(128),
                      proof_indices in prop::collection::vec(any::<prop::sample::Index>(), 10..20)
    )  {
        let mut indices: Vec<usize> = proof_indices.iter().map(|idx| idx.index(128)).collect();
        indices.sort_unstable(); indices.dedup();
        let proof1 = tree.prove_batch(&indices[..]).unwrap();

        let mut paths = Vec::new();
        for &idx in indices.iter() {
            paths.push(tree.prove(idx).unwrap());
        }
        let proof2 = BatchMerkleProof::from_paths(&paths, &indices);

        prop_assert!(proof1 == proof2);
    }

    #[test]
    fn unbatch(tree in random_blake3_merkle_tree(8),
                      proof_indices in prop::collection::vec(any::<prop::sample::Index>(), 1..7)
    )  {
        let mut indices: Vec<usize> = proof_indices.iter().map(|idx| idx.index(8)).collect();
        indices.sort_unstable(); indices.dedup();
        let proof1 = tree.prove_batch(&indices[..]).unwrap();

        let mut paths = Vec::new();
        for &idx in indices.iter() {
            paths.push(tree.prove(idx).unwrap());
        }
        //let proof2: BatchMerkleProof<Blake3_256> e is [ByteDigest([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), ByteDigest([118, 173, 73, 160, 213, 42, 44, 135, 178, 8, 142, 86, 77, 183, 116, 138, 158, 249, 244, 111, 25, 237, 83, 26, 228, 244, 108, 205, 12, 101, 129, 104]), ByteDigest([127, 79, 15, 251, 83, 253, 48, 37, 250, 195, 38, 16, 23, 102, 128, 62, 167, 0, 61, 224, 162, 89, 162, 242, 26, 237, 42, 138, 70, 127, 118, 83]), ByteDigest([59, 217, 162, 171, 197, 197, 248, 226, 92, 57, 235, 254, 205, 182, 169, 49, 181, 178, 175, 127, 124, 89, 166, 207, 8, 104, 159, 129, 181, 144, 138, 57]), ByteDigest([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), ByteDigest([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), ByteDigest([73, 138, 142, 124, 2, 188, 44, 122, 252, 89, 139, 9, 122, 208, 101, 131, 110, 168, 78, 14, 223, 43, 240, 137, 84, 16, 150, 135, 17, 214, 181, 78]), ByteDigest([147, 235, 215, 235, 225, 232, 87, 140, 15, 247, 145, 110, 224, 12, 33, 221, 76, 149, 184, 193, 19, 184, 56, 83, 84, 75, 243, 155, 252, 21, 95, 105]), ByteDigest([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), ByteDigest([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), ByteDigest([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), ByteDigest([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), ByteDigest([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), ByteDigest([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), ByteDigest([238, 14, 61, 196, 32, 198, 170, 189, 122, 157, 204, 179, 109, 48, 49, 249, 16, 212, 93, 106, 249, 192, 219, 163, 181, 195, 148, 204, 124, 251, 133, 235]), ByteDigest([39, 96, 19, 53, 38, 166, 122, 101, 248, 137, 128, 245, 1, 14, 139, 137, 44, 198, 10, 20, 189, 170, 42, 215, 53, 6, 117, 5, 161, 204, 167, 197])]= BatchMerkleProof::from_paths(&paths, &indices);
        let p = BatchMerkleProof::unbatch(proof1,&indices.clone(),tree.depth(), &tree).unwrap();

        //println!("p {:?}",p);
        println!("indices {:?}",indices);
        println!("paths {:?}",paths);
        //println!("p[1] {:?}",p[1]);
        //println!("root {:?}",p[0]);
        println!("expected {:?}",tree.root());
        //println!("paths[1][0] {:?}",paths[1][2]);
        //println!(" p[1][] {:?}", p[1][2]);
        prop_assert!(paths == p);
        //prop_assert!(p[0][0] == *tree.root());
        //prop_assert!(proof1 == proof2);
    }
}

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------
fn hash_2x1(v1: Digest256, v2: Digest256) -> Digest256 {
    Blake3_256::merge(&[v1, v2])
}

pub fn random_blake3_merkle_tree(
    leave_count: usize,
) -> impl Strategy<Value = MerkleTree<Blake3_256>> {
    prop::collection::vec(any::<[u8; 32]>(), leave_count).prop_map(|leaves| {
        let leaves = Digest256::bytes_as_digests(&leaves).to_vec();
        MerkleTree::<Blake3_256>::new(leaves).unwrap()
    })
}
