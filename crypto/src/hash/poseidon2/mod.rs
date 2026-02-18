// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::ops::Range;

use math::{fields::f64::BaseElement, FieldElement, StarkField};

use super::{ElementHasher, Hasher};

mod constants;
use constants::{
    ARK_EXT_INITIAL, ARK_EXT_TERMINAL, ARK_INT, MAT_DIAG, NUM_EXTERNAL_ROUNDS_HALF,
    NUM_INTERNAL_ROUNDS,
};

mod digest;
pub use digest::ElementDigest;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Sponge state is set to 12 field elements or 96 bytes; 8 elements are reserved for the rate and
/// the remaining 4 elements are reserved for the capacity.
const STATE_WIDTH: usize = 12;

/// The rate portion of the state is located in elements 0 through 7.
const RATE_RANGE: Range<usize> = 0..8;
const RATE_WIDTH: usize = RATE_RANGE.end - RATE_RANGE.start;

/// The first and second 4-element words of the rate portion.
const RATE0_RANGE: Range<usize> = 0..4;
const RATE1_RANGE: Range<usize> = 4..8;

/// The capacity portion of the state is located in elements 8, 9, 10, and 11.
const CAPACITY_RANGE: Range<usize> = 8..12;

/// The output of the hash function is a digest which consists of 4 field elements or 32 bytes,
/// taken from the first word of the rate portion of the state.
const DIGEST_RANGE: Range<usize> = 0..4;
const DIGEST_SIZE: usize = DIGEST_RANGE.end - DIGEST_RANGE.start;

/// The number of byte chunks defining a field element when hashing a sequence of bytes.
const BINARY_CHUNK_SIZE: usize = 7;

// HASHER IMPLEMENTATION
// ================================================================================================

/// Implementation of [Hasher] trait for Poseidon2 hash function with 256-bit output.
///
/// The implementation follows the original [specification](https://eprint.iacr.org/2023/323) and
/// its accompanying reference [implementation](https://github.com/HorizenLabs/poseidon2).
///
/// The parameters used to instantiate the function are:
/// * Field: 64-bit prime field with modulus 2^64 - 2^32 + 1.
/// * State width: 12 field elements.
/// * Capacity size: 4 field elements.
/// * S-Box degree: 7.
/// * Rounds: There are 2 different types of rounds, called internal and external, and are
///   structured as follows:
///   - Initial External rounds (IE): `add_constants` → `apply_sbox` → `apply_matmul_external`.
///   - Internal rounds: `add_constants` → `apply_sbox` → `apply_matmul_internal`, where the
///     constant addition and sbox application apply only to the first entry of the state.
///   - Terminal External rounds (TE): `add_constants` → `apply_sbox` → `apply_matmul_external`.
///   - An additional `apply_matmul_external` is inserted at the beginning in order to protect
///     against some recent attacks.
///
/// The above parameters target a 128-bit security level. The digest consists of four field elements
/// and it can be serialized into 32 bytes (256 bits).
///
/// ## Hash output consistency
/// Functions [hash_elements()](Poseidon2::hash_elements), [merge()](Poseidon2::merge), and
/// [merge_with_int()](Poseidon2::merge_with_int) are internally consistent. That is, computing
/// a hash for the same set of elements using these functions will always produce the same result.
/// For example, merging two digests using [merge()](Poseidon2::merge) will produce the same result
/// as hashing 8 elements which make up these digests using [hash_elements()](Poseidon2::hash_elements)
/// function.
///
/// However, [hash()](Poseidon2::hash) function is not consistent with functions mentioned above.
/// For example, if we take two field elements, serialize them to bytes and hash them using
/// [hash()](Poseidon2::hash), the result will differ from the result obtained by hashing these
/// elements directly using [hash_elements()](Poseidon2::hash_elements) function. The reason for
/// this difference is that [hash()](Poseidon2::hash) function needs to be able to handle
/// arbitrary binary strings, which may or may not encode valid field elements - and thus,
/// deserialization procedure used by this function is different from the procedure used to
/// deserialize valid field elements.
///
/// Thus, if the underlying data consists of valid field elements, it might make more sense
/// to deserialize them into field elements and then hash them using
/// [hash_elements()](Poseidon2::hash_elements) function rather than hashing the serialized bytes
/// using [hash()](Poseidon2::hash) function.
///
/// ## Domain separation
/// [merge_in_domain()](Poseidon2::merge_in_domain) hashes two digests into one digest with some
/// domain identifier and the current implementation sets the second capacity element to the value
/// of this domain identifier. Using a similar argument to the one formulated for domain separation
/// in Appendix C of the [specifications](https://eprint.iacr.org/2023/1045), one sees that doing
/// so degrades only pre-image resistance, from its initial bound of c.log_2(p), by as much as
/// the log_2 of the size of the domain identifier space. Since pre-image resistance becomes
/// the bottleneck for the security bound of the sponge in overwrite-mode only when it is
/// lower than 2^128, we see that the target 128-bit security level is maintained as long as
/// the size of the domain identifier space, including for padding, is less than 2^128.
///
/// ## Hashing of empty input
/// The current implementation hashes empty input to the zero digest [0, 0, 0, 0]. This has
/// the benefit of requiring no calls to the Poseidon2 permutation when hashing empty input.
#[allow(rustdoc::private_intra_doc_links)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Poseidon2();

impl Hasher for Poseidon2 {
    type Digest = ElementDigest;

    const COLLISION_RESISTANCE: u32 = 128;

    fn hash(bytes: &[u8]) -> Self::Digest {
        // initialize the state with zeroes
        let mut state = [BaseElement::ZERO; STATE_WIDTH];

        // determine the number of field elements needed to encode `bytes` when each field element
        // represents at most 7 bytes.
        let num_field_elem = bytes.len().div_ceil(BINARY_CHUNK_SIZE);

        // set the first capacity element to `RATE_WIDTH + (num_field_elem % RATE_WIDTH)`. We do
        // this to achieve:
        // 1. Domain separating hashing of `[u8]` from hashing of `[Felt]`.
        // 2. Avoiding collisions at the `[Felt]` representation of the encoded bytes.
        state[CAPACITY_RANGE.start] =
            BaseElement::new((RATE_WIDTH + (num_field_elem % RATE_WIDTH)) as u64);

        // initialize a buffer to receive the little-endian elements.
        let mut buf = [0_u8; 8];

        // iterate the chunks of bytes, creating a field element from each chunk and copying it
        // into the state.
        //
        // every time the rate range is filled, a permutation is performed. if the final value of
        // `rate_pos` is not zero, then the chunks count wasn't enough to fill the state range,
        // and an additional permutation must be performed.
        let mut current_chunk_idx = 0_usize;
        // handle the case of an empty `bytes`
        let last_chunk_idx = if num_field_elem == 0 {
            current_chunk_idx
        } else {
            num_field_elem - 1
        };
        let rate_pos = bytes.chunks(BINARY_CHUNK_SIZE).fold(0, |rate_pos, chunk| {
            // copy the chunk into the buffer
            if current_chunk_idx != last_chunk_idx {
                buf[..BINARY_CHUNK_SIZE].copy_from_slice(chunk);
            } else {
                // on the last iteration, we pad `buf` with a 1 followed by as many 0's as are
                // needed to fill it
                buf.fill(0);
                buf[..chunk.len()].copy_from_slice(chunk);
                buf[chunk.len()] = 1;
            }
            current_chunk_idx += 1;

            // set the current rate element to the input. since we take at most 7 bytes, we are
            // guaranteed that the inputs data will fit into a single field element.
            state[RATE_RANGE.start + rate_pos] = BaseElement::new(u64::from_le_bytes(buf));

            // proceed filling the range. if it's full, then we apply a permutation and reset the
            // counter to the beginning of the range.
            if rate_pos == RATE_WIDTH - 1 {
                Self::apply_permutation(&mut state);
                0
            } else {
                rate_pos + 1
            }
        });

        // if we absorbed some elements but didn't apply a permutation to them (would happen when
        // the number of elements is not a multiple of RATE_WIDTH), apply the permutation. we
        // don't need to apply any extra padding because the first capacity element contains a
        // flag indicating the number of field elements constituting the last block when the latter
        // is not divisible by `RATE_WIDTH`.
        if rate_pos != 0 {
            state[RATE_RANGE.start + rate_pos..RATE_RANGE.end].fill(BaseElement::ZERO);
            Self::apply_permutation(&mut state);
        }

        // return the digest portion of the rate as hash result.
        ElementDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        // initialize the state by copying the digest elements into the rate portion of the state
        // (8 total elements), and set the capacity elements to 0.
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[RATE_RANGE].copy_from_slice(ElementDigest::digests_as_elements(values));

        // apply the permutation and return the digest portion of the state
        Self::apply_permutation(&mut state);
        ElementDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        Self::hash_elements(ElementDigest::digests_as_elements(values))
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        // initialize the state as follows:
        // - seed is copied into the first 4 elements of the rate portion of the state.
        // - if the value fits into a single field element, copy it into the fifth rate element and
        //   set the first capacity element to 5.
        // - if the value doesn't fit into a single field element, split it into two field elements,
        //   copy them into rate elements 5 and 6 and set the first capacity element to 6.
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[RATE0_RANGE].copy_from_slice(seed.as_elements());
        state[RATE1_RANGE.start] = BaseElement::new(value);
        if value < BaseElement::MODULUS {
            state[CAPACITY_RANGE.start] = BaseElement::new(5);
        } else {
            state[RATE1_RANGE.start + 1] = BaseElement::new(value / BaseElement::MODULUS);
            state[CAPACITY_RANGE.start] = BaseElement::new(6);
        }

        // apply the permutation and return the digest portion of the rate
        Self::apply_permutation(&mut state);
        ElementDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }
}

impl ElementHasher for Poseidon2 {
    type BaseField = BaseElement;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        // convert the elements into a list of base field elements
        let elements = E::slice_as_base_elements(elements);

        // initialize state to all zeros, except for the first element of the capacity part, which
        // is set to `total_len % RATE_WIDTH`.
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[CAPACITY_RANGE.start] = BaseElement::new((elements.len() % RATE_WIDTH) as u64);

        // absorb elements into the state one by one until the rate portion of the state is filled
        // up; then apply the permutation and start absorbing again; repeat until all elements
        // have been absorbed
        let mut i = 0;
        for &element in elements.iter() {
            state[RATE_RANGE.start + i] = element;
            i += 1;
            if i == RATE_WIDTH {
                Self::apply_permutation(&mut state);
                i = 0;
            }
        }

        // if we absorbed some elements but didn't apply a permutation to them (would happen when
        // the number of elements is not a multiple of RATE_WIDTH), apply the permutation after
        // padding by as many 0 as necessary to make the input length a multiple of the RATE_WIDTH.
        if i > 0 {
            while i != RATE_WIDTH {
                state[RATE_RANGE.start + i] = BaseElement::ZERO;
                i += 1;
            }
            Self::apply_permutation(&mut state);
        }

        // return the digest portion of the state as hash result
        ElementDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }
}

// HASH FUNCTION IMPLEMENTATION
// ================================================================================================

impl Poseidon2 {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Target collision resistance level in bits.
    pub const COLLISION_RESISTANCE: u32 = 128;

    /// Number of initial or terminal external rounds.
    pub const NUM_EXTERNAL_ROUNDS_HALF: usize = NUM_EXTERNAL_ROUNDS_HALF;
    /// Number of internal rounds.
    pub const NUM_INTERNAL_ROUNDS: usize = NUM_INTERNAL_ROUNDS;

    /// Sponge state is set to 12 field elements or 96 bytes; 8 elements are reserved for the rate
    /// and the remaining 4 elements are reserved for the capacity.
    pub const STATE_WIDTH: usize = STATE_WIDTH;

    /// The rate portion of the state is located in elements 0 through 7 (inclusive).
    pub const RATE_RANGE: Range<usize> = RATE_RANGE;

    /// The first 4-element word of the rate portion.
    pub const RATE0_RANGE: Range<usize> = RATE0_RANGE;

    /// The second 4-element word of the rate portion.
    pub const RATE1_RANGE: Range<usize> = RATE1_RANGE;

    /// The capacity portion of the state is located in elements 8, 9, 10, and 11.
    pub const CAPACITY_RANGE: Range<usize> = CAPACITY_RANGE;

    /// The output of the hash function can be read from state elements 0, 1, 2, and 3.
    pub const DIGEST_RANGE: Range<usize> = DIGEST_RANGE;

    /// Matrix used for computing the linear layers of internal rounds.
    pub const MAT_DIAG: [BaseElement; STATE_WIDTH] = MAT_DIAG;

    /// Round constants added to the hasher state.
    pub const ARK_EXT_INITIAL: [[BaseElement; STATE_WIDTH]; NUM_EXTERNAL_ROUNDS_HALF] =
        ARK_EXT_INITIAL;
    pub const ARK_EXT_TERMINAL: [[BaseElement; STATE_WIDTH]; NUM_EXTERNAL_ROUNDS_HALF] =
        ARK_EXT_TERMINAL;
    pub const ARK_INT: [BaseElement; NUM_INTERNAL_ROUNDS] = ARK_INT;

    // HASH FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Returns a hash of the provided sequence of bytes.
    #[inline(always)]
    pub fn hash(bytes: &[u8]) -> ElementDigest {
        <Self as Hasher>::hash(bytes)
    }

    /// Applies the Poseidon2 permutation to the provided state in-place.
    #[inline(always)]
    pub fn apply_permutation(state: &mut [BaseElement; STATE_WIDTH]) {
        // 1. Apply (external) linear layer to the input
        Self::apply_matmul_external(state);

        // 2. Apply initial external rounds to the state
        Self::initial_external_rounds(state);

        // 3. Apply internal rounds to the state
        Self::internal_rounds(state);

        // 4. Apply terminal external rounds to the state
        Self::terminal_external_rounds(state);
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E: FieldElement<BaseField = BaseElement>>(
        elements: &[E],
    ) -> ElementDigest {
        <Self as ElementHasher>::hash_elements(elements)
    }

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees and verification of Merkle paths.
    #[inline(always)]
    pub fn merge(values: &[ElementDigest; 2]) -> ElementDigest {
        <Self as Hasher>::merge(values)
    }

    /// Returns a hash of multiple digests.
    #[inline(always)]
    pub fn merge_many(values: &[ElementDigest]) -> ElementDigest {
        <Self as Hasher>::merge_many(values)
    }

    /// Returns a hash of a digest and a u64 value.
    #[inline(always)]
    pub fn merge_with_int(seed: ElementDigest, value: u64) -> ElementDigest {
        <Self as Hasher>::merge_with_int(seed, value)
    }

    /// Returns a hash of two digests and a domain identifier.
    #[inline(always)]
    pub fn merge_in_domain(values: &[ElementDigest; 2], domain: BaseElement) -> ElementDigest {
        // initialize the state by copying the digest elements into the rate portion of the state
        // (8 total elements), and set the capacity elements to 0.
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[RATE_RANGE].copy_from_slice(ElementDigest::digests_as_elements(values));

        // set the second capacity element to the domain value. The first capacity element is used
        // for padding purposes.
        state[CAPACITY_RANGE.start + 1] = domain;

        // apply the permutation and return the first four elements of the state
        Self::apply_permutation(&mut state);
        ElementDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }

    // POSEIDON2 PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Applies the initial external rounds of the permutation.
    #[allow(clippy::needless_range_loop)]
    #[inline(always)]
    fn initial_external_rounds(state: &mut [BaseElement; STATE_WIDTH]) {
        for r in 0..NUM_EXTERNAL_ROUNDS_HALF {
            Self::add_rc(state, &ARK_EXT_INITIAL[r]);
            Self::apply_sbox(state);
            Self::apply_matmul_external(state);
        }
    }

    /// Applies the internal rounds of the permutation.
    #[allow(clippy::needless_range_loop)]
    #[inline(always)]
    fn internal_rounds(state: &mut [BaseElement; STATE_WIDTH]) {
        for r in 0..NUM_INTERNAL_ROUNDS {
            state[0] += ARK_INT[r];
            state[0] = state[0].exp7();
            Self::matmul_internal(state, MAT_DIAG);
        }
    }

    /// Applies the terminal external rounds of the permutation.
    #[inline(always)]
    #[allow(clippy::needless_range_loop)]
    fn terminal_external_rounds(state: &mut [BaseElement; STATE_WIDTH]) {
        for r in 0..NUM_EXTERNAL_ROUNDS_HALF {
            Self::add_rc(state, &ARK_EXT_TERMINAL[r]);
            Self::apply_sbox(state);
            Self::apply_matmul_external(state);
        }
    }

    /// Applies the M_E (external) linear layer to the state in-place.
    ///
    /// This basically takes any 4 x 4 MDS matrix M and computes the matrix-vector product with
    /// the matrix defined by `[[2M, M, ..., M], [M, 2M, ..., M], ..., [M, M, ..., 2M]]`.
    ///
    /// Given the structure of the above matrix, we can compute the product of the state with
    /// matrix `[M, M, ..., M]` and compute the final result using a few addition.
    #[inline(always)]
    pub fn apply_matmul_external(state: &mut [BaseElement; STATE_WIDTH]) {
        // multiply the state by `[M, M, ..., M]` block-wise
        Self::matmul_m4(state);

        // accumulate column-wise sums
        let number_blocks = STATE_WIDTH / 4;
        let mut stored = [BaseElement::ZERO; 4];
        for j in 0..number_blocks {
            let base = j * 4;
            for l in 0..4 {
                stored[l] += state[base + l];
            }
        }

        // add stored column-sums to each element
        for (i, val) in state.iter_mut().enumerate() {
            *val += stored[i % 4];
        }
    }

    /// Multiplies the state block-wise with a 4 x 4 MDS matrix.
    #[inline(always)]
    fn matmul_m4(state: &mut [BaseElement; STATE_WIDTH]) {
        let t4 = STATE_WIDTH / 4;

        for i in 0..t4 {
            let idx = i * 4;

            let a = state[idx];
            let b = state[idx + 1];
            let c = state[idx + 2];
            let d = state[idx + 3];

            let t0 = a + b;
            let t1 = c + d;
            let two_b = b.double();
            let two_d = d.double();

            let t2 = two_b + t1;
            let t3 = two_d + t0;

            let t4 = t1.double().double() + t3;
            let t5 = t0.double().double() + t2;

            let t6 = t3 + t5;
            let t7 = t2 + t4;

            state[idx] = t6;
            state[idx + 1] = t5;
            state[idx + 2] = t7;
            state[idx + 3] = t4;
        }
    }

    /// Applies the M_I (internal) linear layer to the state in-place.
    ///
    /// The matrix is given by its diagonal entries with the remaining entries set equal to 1.
    /// Hence, given the sum of the state entries, the matrix-vector product is computed using
    /// a multiply-and-add per state entry.
    #[inline(always)]
    pub fn matmul_internal(state: &mut [BaseElement; STATE_WIDTH], mat_diag: [BaseElement; 12]) {
        let mut sum = BaseElement::ZERO;
        for s in state.iter().take(STATE_WIDTH) {
            sum += *s
        }

        for i in 0..state.len() {
            state[i] = state[i] * mat_diag[i] + sum;
        }
    }

    /// Adds the round constants to the state in-place.
    #[inline(always)]
    pub fn add_rc(state: &mut [BaseElement; STATE_WIDTH], ark: &[BaseElement; 12]) {
        state.iter_mut().zip(ark).for_each(|(s, &k)| *s += k);
    }

    /// Applies the S-box (x^7) to each element of the state in-place.
    #[inline(always)]
    pub fn apply_sbox(state: &mut [BaseElement; STATE_WIDTH]) {
        state[0] = state[0].exp7();
        state[1] = state[1].exp7();
        state[2] = state[2].exp7();
        state[3] = state[3].exp7();
        state[4] = state[4].exp7();
        state[5] = state[5].exp7();
        state[6] = state[6].exp7();
        state[7] = state[7].exp7();
        state[8] = state[8].exp7();
        state[9] = state[9].exp7();
        state[10] = state[10].exp7();
        state[11] = state[11].exp7();
    }
}
