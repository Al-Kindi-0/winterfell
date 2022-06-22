// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
//use core_simd::*;

use super::{exp_acc, Digest, ElementHasher, Hasher};
use core::convert::TryInto;
use core::ops::Range;
use math::{fields::f64::{BaseElement, reduce_u96}, FieldElement, StarkField};

mod digest;
pub use digest::ElementDigest;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Sponge state is set to 12 field elements or 768 bytes; 8 elements are reserved for rate and
/// the remaining 4 elements are reserved for capacity.
const STATE_WIDTH: usize = 12;

/// The rate portion of the state is located in elements 4 through 11.
const RATE_RANGE: Range<usize> = 4..12;
const RATE_WIDTH: usize = RATE_RANGE.end - RATE_RANGE.start;

const INPUT1_RANGE: Range<usize> = 4..8;
const INPUT2_RANGE: Range<usize> = 8..12;

/// The capacity portion of the state is located in elements 0, 1, 2, and 3.
const CAPACITY_RANGE: Range<usize> = 0..4;

/// The output of the hash function is a digest which consists of 4 field elements or 32 bytes.
///
/// The digest is returned from state elements 4, 5, 6, and 7 (the first four elements of the
/// rate portion).
const DIGEST_RANGE: Range<usize> = 4..8;
const DIGEST_SIZE: usize = DIGEST_RANGE.end - DIGEST_RANGE.start;

/// The number of rounds is set to 7 to target 128-bit security level with 40% security margin;
/// computed using algorithm 7 from <https://eprint.iacr.org/2020/1143.pdf>
const NUM_ROUNDS: usize = 7;

/// S-Box and Inverse S-Box powers;
/// computed using algorithm 6 from <https://eprint.iacr.org/2020/1143.pdf>
///
/// The constants are defined for tests only because the exponentiations in the code are unrolled
/// for efficiency reasons.
#[cfg(test)]
const ALPHA: u64 = 7;
#[cfg(test)]
const INV_ALPHA: u64 = 10540996611094048183;

// HASHER IMPLEMENTATION
// ================================================================================================

/// Implementation of [Hasher] trait for Rescue Prime hash function with 256-bit output.
///
/// The hash function is implemented according to the Rescue Prime
/// [specifications](https://eprint.iacr.org/2020/1143.pdf) with the following exception:
/// * We set the number of rounds to 7, which implies a 40% security margin instead of the 50%
///   margin used in the specifications (a 50% margin rounds up to 8 rounds). The primary
///   motivation for this is that having the number of rounds be one less than a power of two
///   simplifies AIR design for computations involving the hash function.
/// * We use the first 4 elements of the state (rather than the last 4 elements of the state) for
///   capacity and the remaining 8 elements for rate. The output of the hash function comes from
///   the first four elements of the rate portion of the state (elements 4, 5, 6, and 7). This
///   effectively applies a fixed bit permutation before and after XLIX permutation. We assert
///   without proof that this does not affect security of the construction.
/// * When hashing a sequence of elements, we do not append Fp(1) followed by Fp(0) elements
///   to the end of the sequence as padding. Instead, we initialize the first capacity element
///   to the number of elements to be hashed, and pad the sequence with Fp(0) elements only. This
///   ensures consistency of hash outputs between different hashing methods (see section below).
///   However, it also means that our instantiation of Rescue Prime cannot be used in a stream
///   mode as the number of elements to be hashed must be known upfront.
///
/// The parameters used to instantiate the function are:
/// * Field: 64-bit prime field with modulus 2^64 - 2^32 + 1.
/// * State width: 12 field elements.
/// * Capacity size: 4 field elements.
/// * Number of founds: 7.
/// * S-Box degree: 7.
///
/// The above parameters target 128-bit security level. The digest consists of four field elements
/// and it can be serialized into 32 bytes (256 bits).
///
/// ## Hash output consistency
/// Functions [hash_elements()](Rp64_256::hash_elements), [merge()](Rp64_256::merge), and
/// [merge_with_int()](Rp64_256::merge_with_int) are internally consistent. That is, computing
/// a hash for the same set of elements using these functions will always produce the same
/// result. For example, merging two digests using [merge()](Rp64_256::merge) will produce the
/// same result as hashing 8 elements which make up these digests using
/// [hash_elements()](Rp64_256::hash_elements) function.
///
/// However, [hash()](Rp64_256::hash) function is not consistent with functions mentioned above.
/// For example, if we take two field elements, serialize them to bytes and hash them using
/// [hash()](Rp64_256::hash), the result will differ from the result obtained by hashing these
/// elements directly using [hash_elements()](Rp64_256::hash_elements) function. The reason for
/// this difference is that [hash()](Rp64_256::hash) function needs to be able to handle
/// arbitrary binary strings, which may or may not encode valid field elements - and thus,
/// deserialization procedure used by this function is different from the procedure used to
/// deserialize valid field elements.
///
/// Thus, if the underlying data consists of valid field elements, it might make more sense
/// to deserialize them into field elements and then hash them using
/// [hash_elements()](Rp64_256::hash_elements) function rather then hashing the serialized bytes
/// using [hash()](Rp64_256::hash) function.
pub struct Rp64_256();

impl Hasher for Rp64_256 {
    type Digest = ElementDigest;

    fn hash(bytes: &[u8]) -> Self::Digest {
        // compute the number of elements required to represent the string; we will be processing
        // the string in 7-byte chunks, thus the number of elements will be equal to the number
        // of such chunks (including a potential partial chunk at the end).
        let num_elements = if bytes.len() % 7 == 0 {
            bytes.len() / 7
        } else {
            bytes.len() / 7 + 1
        };

        // initialize state to all zeros, except for the first element of the capacity part, which
        // is set to the number of elements to be hashed. this is done so that adding zero elements
        // at the end of the list always results in a different hash.
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[CAPACITY_RANGE.start] = BaseElement::new(num_elements as u64);

        // break the string into 7-byte chunks, convert each chunk into a field element, and
        // absorb the element into the rate portion of the state. we use 7-byte chunks because
        // every 7-byte chunk is guaranteed to map to some field element.
        let mut i = 0;
        let mut buf = [0_u8; 8];
        for chunk in bytes.chunks(7) {
            if i < num_elements - 1 {
                buf[..7].copy_from_slice(chunk);
            } else {
                // if we are dealing with the last chunk, it may be smaller than 7 bytes long, so
                // we need to handle it slightly differently. we also append a byte with value 1
                // to the end of the string; this pads the string in such a way that adding
                // trailing zeros results in different hash
                let chunk_len = chunk.len();
                buf = [0_u8; 8];
                buf[..chunk_len].copy_from_slice(chunk);
                buf[chunk_len] = 1;
            }

            // convert the bytes into a field element and absorb it into the rate portion of the
            // state; if the rate is filled up, apply the Rescue permutation and start absorbing
            // again from zero index.
            state[RATE_RANGE.start + i] += BaseElement::new(u64::from_le_bytes(buf));
            i += 1;
            if i % RATE_WIDTH == 0 {
                Self::apply_permutation(&mut state);
                i = 0;
            }
        }

        // if we absorbed some elements but didn't apply a permutation to them (would happen when
        // the number of elements is not a multiple of RATE_WIDTH), apply the Rescue permutation.
        // we don't need to apply any extra padding because we injected total number of elements
        // in the input list into the capacity portion of the state during initialization.
        if i > 0 {
            Self::apply_permutation(&mut state);
        }

        // return the first 4 elements of the state as hash result
        ElementDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        // initialize the state by copying the digest elements into the rate portion of the state
        // (8 total elements), and set the first capacity element to 8 (the number of elements to
        // be hashed).
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[RATE_RANGE].copy_from_slice(Self::Digest::digests_as_elements(values));
        state[CAPACITY_RANGE.start] = BaseElement::new(RATE_WIDTH as u64);

        // apply the Rescue permutation and return the first four elements of the state
        Self::apply_permutation(&mut state);
        ElementDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        // initialize the state as follows:
        // - seed is copied into the first 4 elements of the rate portion of the state.
        // - if the value fits into a single field element, copy it into the fifth rate element
        //   and set the first capacity element to 5 (the number of elements to be hashed).
        // - if the value doesn't fit into a single field element, split it into two field
        //   elements, copy them into rate elements 5 and 6, and set the first capacity element
        //   to 6.
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[INPUT1_RANGE].copy_from_slice(seed.as_elements());
        state[INPUT2_RANGE.start] = BaseElement::new(value);
        if value < BaseElement::MODULUS {
            state[CAPACITY_RANGE.start] = BaseElement::new(DIGEST_SIZE as u64 + 1);
        } else {
            state[INPUT2_RANGE.start + 1] = BaseElement::new(value / BaseElement::MODULUS);
            state[CAPACITY_RANGE.start] = BaseElement::new(DIGEST_SIZE as u64 + 2);
        }

        // apply the Rescue permutation and return the first four elements of the state
        Self::apply_permutation(&mut state);
        ElementDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }
}

impl ElementHasher for Rp64_256 {
    type BaseField = BaseElement;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        // convert the elements into a list of base field elements
        let elements = E::as_base_elements(elements);

        // initialize state to all zeros, except for the last element of the capacity part, which
        // is set to the number of elements to be hashed. this is done so that adding zero elements
        // at the end of the list always results in a different hash.
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[CAPACITY_RANGE.start] = BaseElement::new(elements.len() as u64);

        // absorb elements into the state one by one until the rate portion of the state is filled
        // up; then apply the Rescue permutation and start absorbing again; repeat until all
        // elements have been absorbed
        let mut i = 0;
        for &element in elements.iter() {
            state[RATE_RANGE.start + i] += element;
            i += 1;
            if i % RATE_WIDTH == 0 {
                Self::apply_permutation(&mut state);
                i = 0;
            }
        }

        // if we absorbed some elements but didn't apply a permutation to them (would happen when
        // the number of elements is not a multiple of RATE_WIDTH), apply the Rescue permutation.
        // we don't need to apply any extra padding because we injected total number of elements
        // in the input list into the capacity portion of the state during initialization.
        if i > 0 {
            Self::apply_permutation(&mut state);
        }

        // return the first 4 elements of the state as hash result
        ElementDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }
}

// HASH FUNCTION IMPLEMENTATION
// ================================================================================================

impl Rp64_256 {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The number of rounds is set to 7 to target 128-bit security level with 40% security margin.
    pub const NUM_ROUNDS: usize = NUM_ROUNDS;

    /// Sponge state is set to 12 field elements or 768 bytes; 8 elements are reserved for rate and
    /// the remaining 4 elements are reserved for capacity.
    pub const STATE_WIDTH: usize = STATE_WIDTH;

    /// The rate portion of the state is located in elements 4 through 11 (inclusive).
    pub const RATE_RANGE: Range<usize> = RATE_RANGE;

    /// The capacity portion of the state is located in elements 0, 1, 2, and 3.
    pub const CAPACITY_RANGE: Range<usize> = CAPACITY_RANGE;

    /// The output of the hash function can be read from state elements 4, 5, 6, and 7.
    pub const DIGEST_RANGE: Range<usize> = DIGEST_RANGE;

    /// MDS matrix used for computing the linear layer in a Rescue Prime round.
    pub const MDS: [[BaseElement; STATE_WIDTH]; STATE_WIDTH] = MDS;

    /// Inverse of the MDS matrix.
    pub const INV_MDS: [[BaseElement; STATE_WIDTH]; STATE_WIDTH] = INV_MDS;

    /// Round constants added to the hasher state in the first half of the Rescue Prime round.
    pub const ARK1: [[BaseElement; STATE_WIDTH]; NUM_ROUNDS] = ARK1;

    /// Round constants added to the hasher state in the second half of the Rescue Prime round.
    pub const ARK2: [[BaseElement; STATE_WIDTH]; NUM_ROUNDS] = ARK2;

    // RESCUE PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Applies Rescue-XLIX permutation to the provided state.
    pub fn apply_permutation(state: &mut [BaseElement; STATE_WIDTH]) {
        Self::apply_rp_full_round(state, 0);
        Self::apply_rp_full_round(state, 1);
        Self::apply_rp_full_round(state, 2);
        Self::apply_rp_full_round(state, 3);
        Self::apply_rp_full_round(state, 4);
        Self::apply_rp_full_round(state, 5);
        Self::apply_rp_full_round(state, 6);
    }

    /// Rescue-XLIX round function.
    #[inline(always)]
    fn apply_rp_full_round(state: &mut [BaseElement; STATE_WIDTH], round: usize) {
        // apply first half of Rescue round
        Self::apply_sbox(state);
        Self::apply_mds(state);
        Self::add_constants(state, &ARK1[round]);

        // apply second half of Rescue round
        Self::apply_inv_sbox(state);
        Self::apply_mds(state);
        Self::add_constants(state, &ARK2[round]);
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    const MDS_MATRIX_EXPS: [u64; 12] = [0, 0, 1, 0, 3, 5, 1, 8, 12, 3, 16, 10];

    #[inline(always)]
    fn apply_mds(state_: &mut [BaseElement; STATE_WIDTH]) {
        let mut result = [BaseElement::ZERO; STATE_WIDTH];

        let mut state = [0u64; STATE_WIDTH];
        for r in 0..STATE_WIDTH {
            state[r] = state_[r].as_int();
        }

        // This is a hacky way of fully unrolling the loop.
        for r in 0..12 {
            if r < STATE_WIDTH {
                let sum = Self::mds_row_shf(r, &state);
                result[r] = BaseElement::from(sum);
            }
        }

        *state_ = result;
    }

    #[inline(always)]
    fn mds_row_shf(r: usize, v: &[u64; STATE_WIDTH]) -> u128 {
        debug_assert!(r < STATE_WIDTH);
        // The values of MDS_MATRIX_EXPS are known to be small, so we can
        // accumulate all the products for each row and reduce just once
        // at the end (done by the caller).

        // NB: Unrolling this, calculating each term independently, and
        // summing at the end, didn't improve performance for me.
        let mut res = 0u128;

        // This is a hacky way of fully unrolling the loop.
        for i in 0..12 {
            if i < STATE_WIDTH {
                res += (v[(i + r) % STATE_WIDTH] as u128) << Self::MDS_MATRIX_EXPS[i];
            }
        }

        res
    }

    #[inline(always)]
    fn add_constants(state: &mut [BaseElement; STATE_WIDTH], ark: &[BaseElement; STATE_WIDTH]) {
        state.iter_mut().zip(ark).for_each(|(s, &k)| *s += k);
    }

    #[inline(always)]
    fn apply_sbox(state: &mut [BaseElement; STATE_WIDTH]) {
        state[0] = Self::pow_7(state[0]);
        state[1] = Self::pow_7(state[1]);
        state[2] = Self::pow_7(state[2]);
        state[3] = Self::pow_7(state[3]);
        state[4] = Self::pow_7(state[4]);
        state[5] = Self::pow_7(state[5]);
        state[6] = Self::pow_7(state[6]);
        state[7] = Self::pow_7(state[7]);
        state[8] = Self::pow_7(state[8]);
        state[9] = Self::pow_7(state[9]);
        state[10] = Self::pow_7(state[10]);
        state[11] = Self::pow_7(state[11]);
    }

    #[inline(always)]
    fn pow_7(x: BaseElement) -> BaseElement {
        let x2 = x.square();
        let x4 = x2.square();
        let x3 = x * x2;
        x3 * x4
    }

    #[inline(always)]
    fn apply_inv_sbox_new(state: &mut [BaseElement; STATE_WIDTH]) {
        let input = *state;
        let mut last = BaseElement::ONE;
        for (result, &value) in state.iter_mut().zip(input.iter()) {
            *result = last;
            if value != BaseElement::ZERO {
                last *= value;
            }
        }

        last = last.inv();

        for i in (0..input.len()).rev() {
            if input[i] == BaseElement::ZERO {
                state[i] = BaseElement::ZERO;
            } else {
                state[i] *= last;
                last *= input[i];
            }
        }
    }
    #[inline(always)]
    fn apply_inv_sbox(state: &mut [BaseElement; STATE_WIDTH]) {
        // compute base^10540996611094048183 using 72 multiplications per array element
        // 10540996611094048183 = b1001001001001001001001001001000110110110110110110110110110110111

        // compute base^10
        let mut t1 = *state;
        t1.iter_mut().for_each(|t| *t = t.square());

        // compute base^100
        let mut t2 = t1;
        t2.iter_mut().for_each(|t| *t = t.square());

        // compute base^100100
        let t3 = exp_acc::<BaseElement, STATE_WIDTH, 3>(t2, t2);

        // compute base^100100100100
        let t4 = exp_acc::<BaseElement, STATE_WIDTH, 6>(t3, t3);

        // compute base^100100100100100100100100
        let t5 = exp_acc::<BaseElement, STATE_WIDTH, 12>(t4, t4);

        // compute base^100100100100100100100100100100
        let t6 = exp_acc::<BaseElement, STATE_WIDTH, 6>(t5, t3);

        // compute base^1001001001001001001001001001000100100100100100100100100100100
        let t7 = exp_acc::<BaseElement, STATE_WIDTH, 31>(t6, t6);

        // compute base^1001001001001001001001001001000110110110110110110110110110110111
        for (i, s) in state.iter_mut().enumerate() {
            let a = (t7[i].square() * t6[i]).square().square();
            let b = t1[i] * t2[i] * *s;
            *s = a * b;
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////
    /// With FFT-based multiplication
    ///
    /// //////////////////////////////////////////////////////////////////////////////////////////////
    ///
    ///

    //////////////////////////////////////////////////////////////////////////////////////////////////
    /// Using the original matrix
    ///
    /// //////////////////////////////////////////////////////////////////////////////////////////////
    ///
    ///

    /// Applies Rescue-XLIX permutation to the provided state.
    pub fn apply_permutation_freq_original(state: &mut [BaseElement; STATE_WIDTH]) {
        Self::apply_rp_full_round_freq_original(state, 0);
        Self::apply_rp_full_round_freq_original(state, 1);
        Self::apply_rp_full_round_freq_original(state, 2);
        Self::apply_rp_full_round_freq_original(state, 3);
        Self::apply_rp_full_round_freq_original(state, 4);
        Self::apply_rp_full_round_freq_original(state, 5);
        Self::apply_rp_full_round_freq_original(state, 6);
    }

    /// Rescue-XLIX round function.
    #[inline(always)]
    fn apply_rp_full_round_freq_original(state: &mut [BaseElement; STATE_WIDTH], round: usize) {
        // apply first half of Rescue round
        Self::apply_sbox(state);
        Self::apply_mds_freq_original(state);
        Self::add_constants(state, &ARK1[round]);

        // apply second half of Rescue round
        Self::apply_inv_sbox(state);
        Self::apply_mds_freq_original(state);
        Self::add_constants(state, &ARK2[round]);
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////
    /// Using the light-weight-in-frequency-domain matrix
    ///
    /// //////////////////////////////////////////////////////////////////////////////////////////////
    ///
    ///

    /// Applies Rescue-XLIX permutation to the provided state.
    pub fn apply_permutation_freq(state: &mut [BaseElement; STATE_WIDTH]) {
        Self::apply_rp_full_round_freq(state, 0);
        Self::apply_rp_full_round_freq(state, 1);
        Self::apply_rp_full_round_freq(state, 2);
        Self::apply_rp_full_round_freq(state, 3);
        Self::apply_rp_full_round_freq(state, 4);
        Self::apply_rp_full_round_freq(state, 5);
        Self::apply_rp_full_round_freq(state, 6);
    }
    /// Rescue-XLIX round function.
    #[inline(always)]
    fn apply_rp_full_round_freq(state: &mut [BaseElement; STATE_WIDTH], round: usize) {
        // apply first half of Rescue round
        Self::apply_sbox(state);
        Self::apply_mds_freq(state);
        Self::add_constants(state, &ARK1[round]);

        // apply second half of Rescue round
        Self::apply_inv_sbox(state);
        Self::apply_mds_freq(state);
        Self::add_constants(state, &ARK2[round]);
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////
    /// Using the light-weight-in-frequency-domain matrix with inlined operations
    ///
    /// //////////////////////////////////////////////////////////////////////////////////////////////
    ///
    ///

    /// Applies Rescue-XLIX permutation to the provided state.
    pub fn apply_permutation_freq_light(state: &mut [BaseElement; STATE_WIDTH]) {
        Self::apply_rp_full_round_freq_light(state, 0);
        Self::apply_rp_full_round_freq_light(state, 1);
        Self::apply_rp_full_round_freq_light(state, 2);
        Self::apply_rp_full_round_freq_light(state, 3);
        Self::apply_rp_full_round_freq_light(state, 4);
        Self::apply_rp_full_round_freq_light(state, 5);
        Self::apply_rp_full_round_freq_light(state, 6);
    }

    /// Rescue-XLIX round function.
    #[inline(always)]
    fn apply_rp_full_round_freq_light(state: &mut [BaseElement; STATE_WIDTH], round: usize) {
        // apply first half of Rescue round
        Self::apply_sbox(state);
        Self::apply_mds_freq_light(state);
        Self::add_constants(state, &ARK1[round]);

        // apply second half of Rescue round
        Self::apply_inv_sbox(state);
        Self::apply_mds_freq_light(state);
        Self::add_constants(state, &ARK2[round]);
    }
   
    //////////////////////////////////////////////////////////////////////////////////////////////
    /// Helper functions for FFT-based multiplication
    /// 
    /// 
    /// /////////////////////////////////////////////////////////////////////////////////////////
    /// 
    /* TODO: Elaborate more.
    We use split 3 x 4 FFT transform in order to transform our vectors into the frequency domain.
    We use the real FFT to avoid redundant computations. See https://www.mdpi.com/2076-3417/12/9/4700  */
    #[inline(always)]
    fn fft2_real(x: [u64; 2]) -> [i64; 2] {
        return [(x[0] as i64 + x[1] as i64), (x[0] as i64 - x[1] as i64)];
    }

    #[inline(always)]
    fn ifft2_real(y: [i64; 2]) -> [u64; 2] {
        return [(y[0] + y[1]) as u64 >> 1, (y[0] - y[1]) as u64 >> 1];
    }

    #[inline(always)]
    fn fft4_real(x: [u64; 4]) -> (i64, (i64, i64), i64) {
        let [z0, z2] = Self::fft2_real([x[0], x[2]]);
        let [z1, z3] = Self::fft2_real([x[1], x[3]]);
        let y0 = z0 + z1;
        let y1 = (z2, -z3);
        let y2 = z0 - z1;
        return (y0, y1, y2);
    }

    #[inline(always)]
    fn ifft4_real(y: (i64, (i64, i64), i64)) -> [u64; 4] {
        let z0 = (y.0 + y.2) >> 1;
        let z1 = (y.0 - y.2) >> 1;
        let z2 = y.1 .0;
        let z3 = -y.1 .1;

        let [x0, x2] = Self::ifft2_real([z0, z2]);
        let [x1, x3] = Self::ifft2_real([z1, z3]);

        return [x0, x1, x2, x3];
    }
    /*
        #[inline(always)]
        fn fft4x3(x: [u64; 12]) -> ([i64; 3], [(i64, i64); 3], [i64; 3]) {
            let [x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11] = x;
            let (y0, y1, y2) = Self::fft4_real([x0, x3, x6, x9]);
            let (y4, y5, y6) = Self::fft4_real([x1, x4, x7, x10]);
            let (y8, y9, y10) = Self::fft4_real([x2, x5, x8, x11]);

            return ([y0, y4, y8], [y1, y5, y9], [y2, y6, y10]);
        }
    */
    #[inline(always)]
    fn block1(x: [i64; 3], y: [i64; 3]) -> [i64; 3] {
        let [x0, x1, x2] = x;
        let [y0, y1, y2] = y;
        let z0 = x0 * y0 + x1 * y2 + x2 * y1;
        let z1 = x0 * y1 + x1 * y0 + x2 * y2;
        let z2 = x0 * y2 + x1 * y1 + x2 * y0;

        return [z0, z1, z2];
    }

    #[inline(always)]
    fn block2(x: [(i64, i64); 3], y: [(i64, i64); 3]) -> [(i64, i64); 3] {
        let [(x0r, x0i), (x1r, x1i), (x2r, x2i)] = x;
        let [(y0r, y0i), (y1r, y1i), (y2r, y2i)] = y;
        let x0s = x0r + x0i;
        let x1s = x1r + x1i;
        let x2s = x2r + x2i;
        let y0s = y0r + y0i;
        let y1s = y1r + y1i;
        let y2s = y2r + y2i;

        // Compute x0​y0​−ix1​y2​−ix2​y1​ using Karatsuba
        let m0 = (x0r * y0r, x0i * y0i);
        let m1 = (x1r * y2r, x1i * y2i);
        let m2 = (x2r * y1r, x2i * y1i);
        let z0r = (m0.0 - m0.1) + (x1s * y2s - m1.0 - m1.1) + (x2s * y1s - m2.0 - m2.1);
        let z0i = (x0s * y0s - m0.0 - m0.1) + (-m1.0 + m1.1) + (-m2.0 + m2.1);
        let z0 = (z0r, z0i);

        // Compute x0​y1​+x1​y0​−ix2​y2 using Karatsuba
        let m0 = (x0r * y1r, x0i * y1i);
        let m1 = (x1r * y0r, x1i * y0i);
        let m2 = (x2r * y2r, x2i * y2i);
        let z1r = (m0.0 - m0.1) + (m1.0 - m1.1) + (x2s * y2s - m2.0 - m2.1);
        let z1i = (x0s * y1s - m0.0 - m0.1) + (x1s * y0s - m1.0 - m1.1) + (-m2.0 + m2.1);
        let z1 = (z1r, z1i);

        // Compute x0​y2​+x1​y1​+x2​y0​ using Karatsuba
        let m0 = (x0r * y2r, x0i * y2i);
        let m1 = (x1r * y1r, x1i * y1i);
        let m2 = (x2r * y0r, x2i * y0i);
        let z2r = (m0.0 - m0.1) + (m1.0 - m1.1) + (m2.0 - m2.1);
        let z2i = (x0s * y2s - m0.0 - m0.1) + (x1s * y1s - m1.0 - m1.1) + (x2s * y0s - m2.0 - m2.1);
        let z2 = (z2r, z2i);

        return [z0, z1, z2];
    }
    #[inline(always)]
    fn block3(x: [i64; 3], y: [i64; 3]) -> [i64; 3] {
        let [x0, x1, x2] = x;
        let [y0, y1, y2] = y;
        let z0 = x0 * y0 - x1 * y2 - x2 * y1;
        let z1 = x0 * y1 + x1 * y0 - x2 * y2;
        let z2 = x0 * y2 + x1 * y1 + x2 * y0;

        return [z0, z1, z2];
    }

    // The 3*FFT4 representation of the MDS matrix
    const MDS_FREQ_BLOCK_ONE_ORIGINAL: [i64; 3] = [12, 5154, 65801];
    const MDS_FREQ_BLOCK_TWO_ORIGINAL: [(i64, i64); 3] = [(-1, -7), (992, -4094), (65528, -255)];
    const MDS_FREQ_BLOCK_THREE_ORIGINAL: [i64; 3] = [-6, -3042, 65287];

    const MDS_FREQ_BLOCK_ONE: [i64; 3] = [64, 128, 64];
    const MDS_FREQ_BLOCK_TWO: [(i64, i64); 3] = [(4, -2), (-8, 2), (32, 2)];
    const MDS_FREQ_BLOCK_THREE: [i64; 3] = [-4, -32, 8];

    #[inline(always)]
    fn mds_multiply_freq_original(state: [u64; 12]) -> [u64; 12] {
        let [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11] = state;

        let (u0, u1, u2) = Self::fft4_real([s0, s3, s6, s9]);
        let (u4, u5, u6) = Self::fft4_real([s1, s4, s7, s10]);
        let (u8, u9, u10) = Self::fft4_real([s2, s5, s8, s11]);

        let [v0, v4, v8] = Self::block1([u0, u4, u8], Self::MDS_FREQ_BLOCK_ONE_ORIGINAL);
        let [v1, v5, v9] = Self::block2([u1, u5, u9], Self::MDS_FREQ_BLOCK_TWO_ORIGINAL);
        let [v2, v6, v10] = Self::block3([u2, u6, u10], Self::MDS_FREQ_BLOCK_THREE_ORIGINAL);

        let [s0, s3, s6, s9] = Self::ifft4_real((v0, v1, v2));
        let [s1, s4, s7, s10] = Self::ifft4_real((v4, v5, v6));
        let [s2, s5, s8, s11] = Self::ifft4_real((v8, v9, v10));

        return [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11];
    }

    #[inline(always)]
    fn apply_mds_freq_original(state_: &mut [BaseElement; STATE_WIDTH]) {
        let mut result = [BaseElement::ZERO; STATE_WIDTH];

        // Using the linearity of the operations we can split the state into a low||high decomposition
        // and operate on each with no overflow and then combine/reduce the result to a field element.
        let mut state_l = [0u64; STATE_WIDTH];
        let mut state_h = [0u64; STATE_WIDTH];

        for r in 0..STATE_WIDTH {
            let s = state_[r].inner();
            state_h[r] = s >> 32;
            state_l[r] = (s as u32) as u64;
        }

        let state_h = Self::mds_multiply_freq_original(state_h);
        let state_l = Self::mds_multiply_freq_original(state_l);

        for r in 0..STATE_WIDTH {
            let s = state_l[r] as u128 + ((state_h[r] as u128) << 32);
            result[r] = reduce_u96(s);
        }
        *state_ = result;
    }
    #[inline(always)]
    fn mds_multiply_freq(state: [u64; 12]) -> [u64; 12] {
        let [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11] = state;

        let (u0, u1, u2) = Self::fft4_real([s0, s3, s6, s9]);
        let (u4, u5, u6) = Self::fft4_real([s1, s4, s7, s10]);
        let (u8, u9, u10) = Self::fft4_real([s2, s5, s8, s11]);

        let [v0, v4, v8] = Self::block1([u0, u4, u8], Self::MDS_FREQ_BLOCK_ONE);
        let [v1, v5, v9] = Self::block2([u1, u5, u9], Self::MDS_FREQ_BLOCK_TWO);
        let [v2, v6, v10] = Self::block3([u2, u6, u10], Self::MDS_FREQ_BLOCK_THREE);

        let [s0, s3, s6, s9] = Self::ifft4_real((v0, v1, v2));
        let [s1, s4, s7, s10] = Self::ifft4_real((v4, v5, v6));
        let [s2, s5, s8, s11] = Self::ifft4_real((v8, v9, v10));

        return [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11];
    }

    #[inline(always)]
    fn apply_mds_freq(state_: &mut [BaseElement; STATE_WIDTH]) {
        let mut result = [BaseElement::ZERO; STATE_WIDTH];

        // Using the linearity of the operations we can split the state into a low||high decomposition
        // and operate on each with no overflow and then combine/reduce the result to a field element.
        let mut state_l = [0u64; STATE_WIDTH];
        let mut state_h = [0u64; STATE_WIDTH];

        for r in 0..STATE_WIDTH {
            let s = state_[r].inner();
            state_h[r] = s >> 32;
            state_l[r] = (s as u32) as u64;
        }

        let state_h = Self::mds_multiply_freq(state_h);
        let state_l = Self::mds_multiply_freq(state_l);

        for r in 0..STATE_WIDTH {
            let s = state_l[r] as u128 + ((state_h[r] as u128) << 32);
            result[r] = reduce_u96(s);
        }
        //result[0] += state_[0] * BaseElement::from(8u64);
        *state_ = result;
    }

    #[inline(always)]
    fn mds_multiply_freq_light(state: &mut [u64; 12]) -> [u64; 12] {
        let mut fft_s = [0i64; 12];
        let diag_entry = state[0];
        for i in 0..3 {
            let s0 = state[i + 0] as i64;
            let s3 = state[i + 3] as i64;
            let s6 = state[i + 6] as i64;
            let s9 = state[i + 9] as i64;
            let z0 = s0 + s6;
            let z2 = s0 - s6;
            let z1 = s3 + s9;
            let z3 = s9 - s3;

            fft_s[i + 0] = z0 + z1;
            fft_s[i + 3] = z0 - z1;
            fft_s[i + 6] = z2;
            fft_s[i + 9] = z3;
        }

        let x0r = fft_s[6];
        let x0i = fft_s[9];
        let x1r = fft_s[7];
        let x1i = fft_s[10];
        let x2r = fft_s[8];
        let x2i = fft_s[11];

        //let (z0r, z0i) = (x0i + 2*x0r + 16*x1i + x1r - 4*x2i + x2r, 2*x0i - x0r + x1i - 16*x1r + x2i + 4*x2r);
        //let (z1r, z1i) = (-x0i - 4*x0r + x1i + 2*x1r + 16*x2i + x2r, -4*x0i + x0r + 2*x1i - x1r + x2i - 16*x2r);
        //let (z2r, z2i) = (-x0i + 16*x0r - x1i - 4*x1r + x2i + 2*x2r, 16*x0i + x0r - 4*x1i + x1r + 2*x2i - x2r);

        let (z0r, z0i) = (
            x0i + (x0r << 1) + (x1i << 4) + x1r - (x2i << 2) + x2r,
            (x0i << 1) - x0r + x1i - (x1r << 4) + x2i + (x2r << 2),
        );
        let (z1r, z1i) = (
            -x0i - (x0r << 2) + x1i + (x1r << 1) + (x2i << 4) + x2r,
            (x0i << 2) + x0r + (x1i << 1) - x1r + x2i - (x2r << 4),
        );
        let (z2r, z2i) = (
            -x0i + (x0r << 4) - x1i - (x1r << 2) + x2i + (x2r << 1),
            (x0i << 4) + x0r - (x1i << 2) + x1r + (x2i << 1) - x2r,
        );

        fft_s[6] = z0r;
        fft_s[7] = z1r;
        fft_s[8] = z2r;
        fft_s[9] = z0i;
        fft_s[10] = z1i;
        fft_s[11] = z2i;

        // Block1

        let x0 = fft_s[0];
        let x1 = fft_s[1];
        let x2 = fft_s[2];

        let tmp = (x0 + x1 + x2) << 4;
        let z0 = tmp + (x1 << 4);
        let z1 = tmp + (x2 << 4);
        let z2 = tmp + (x0 << 4);
        fft_s[0] = z1;
        fft_s[1] = z2;
        fft_s[2] = z0;

        // Block3
        let x0 = fft_s[3];
        let x1 = fft_s[4];
        let x2 = fft_s[5];

        let z0 = -x0 - (x1 << 1) + (x2 << 3);
        let z1 = -(x0 << 3) - x1 - (x2 << 1);
        let z2 = (x0 << 1) - (x1 << 3) - x2;

        fft_s[3] = z0;
        fft_s[4] = z1;
        fft_s[5] = z2;

        for i in 0..3 {
            let y0 = fft_s[0 + i];
            let y1 = fft_s[3 + i];
            let y2 = fft_s[6 + i];
            let y3 = fft_s[9 + i];

            let z0 = (y0 + y1);
            let z1 = (y0 - y1);
            let z2 = y2;
            let z3 = -y3;

            let x0 = (z0 + z2);
            let x2 = (z0 - z2);
            let x1 = (z1 + z3);
            let x3 = (z1 - z3);

            state[0 + i] = x0 as u64;
            state[3 + i] = x1 as u64;
            state[6 + i] = x2 as u64;
            state[9 + i] = x3 as u64;
        }
        //state[0] += diag_entry * 8;
        return *state;
    }

    #[inline(always)]
    fn apply_mds_freq_light(state_: &mut [BaseElement; STATE_WIDTH]) {
        let mut result = [BaseElement::ZERO; STATE_WIDTH];

        // Using the linearity of the operations we can split the state into a low||high decomposition
        // and operate on each with no overflow and then combine/reduce the result to a field element.
        let mut state_l = [0u64; STATE_WIDTH];
        let mut state_h = [0u64; STATE_WIDTH];

        for r in 0..STATE_WIDTH {
            let s = state_[r].inner();
            state_h[r] = s >> 32;
            state_l[r] = (s as u32) as u64;
        }

        let state_h = Self::mds_multiply_freq_light(&mut state_h);
        let state_l = Self::mds_multiply_freq_light(&mut state_l);

        for r in 0..STATE_WIDTH {
            let s = state_l[r] as u128 + ((state_h[r] as u128) << 32);
            result[r] = reduce_u96(s); 
        }
        *state_ = result;
    }

    /*
     //////////////////////////////////////////////////////////////////////////////////////////////////
    /// Using the light-weight-in-frequency-domain matrix with inlined operations and SIMD
    ///
    /// //////////////////////////////////////////////////////////////////////////////////////////////
    ///
    ///
    
    /// Applies Rescue-XLIX permutation to the provided state.
    pub fn apply_permutation_freq_light_simd(state: &mut [BaseElement; STATE_WIDTH]) {
        Self::apply_rp_full_round_freq_light_simd(state, 0);
        Self::apply_rp_full_round_freq_light_simd(state, 1);
        Self::apply_rp_full_round_freq_light_simd(state, 2);
        Self::apply_rp_full_round_freq_light_simd(state, 3);
        Self::apply_rp_full_round_freq_light_simd(state, 4);
        Self::apply_rp_full_round_freq_light_simd(state, 5);
        Self::apply_rp_full_round_freq_light_simd(state, 6);
    }

    /// Rescue-XLIX round function.
    #[inline(always)]
    fn apply_rp_full_round_freq_light_simd(state: &mut [BaseElement; STATE_WIDTH], round: usize) {
        // apply first half of Rescue round
        Self::apply_sbox(state);
        Self::apply_mds_freq_light_simd(state);
        Self::add_constants(state, &ARK1[round]);

        // apply second half of Rescue round
        Self::apply_inv_sbox(state);
        Self::apply_mds_freq_light_simd(state);
        Self::add_constants(state, &ARK2[round]);
    }

    #[inline(always)]
    fn apply_mds_freq_light_simd(state_: &mut [BaseElement; STATE_WIDTH]) {
        let mut result = [BaseElement::ZERO; STATE_WIDTH];

        let mut state_int = [0u64; STATE_WIDTH];

        for r in 0..STATE_WIDTH {
            let s = state_[r].inner();
            state_int[r] = s;
        }
        let state = Self::mds_multiply_freq_light_simd(&mut state_int);

        for r in 0..STATE_WIDTH {
            result[r] = state[r].into();
        }
        *state_ = result;
    }

    #[inline(always)]
    fn mds_multiply_freq_light_simd(state: &mut [u64; 12]) -> [u128; 12] {
        use core_simd::*;
        let mut fft_s = [u64x2::splat(0); 12];
        let mut state_ = [0u128; 12];
        //let mut fft_s = [0i64; 12];
        let diag_entry = state[0] as u128;
        let vconst0 = u64x2::from_array([0u64, 0u64]);
        let vconst2 = u64x2::from_array([2u64, 2u64]);
        let vconst4 = u64x2::from_array([4u64, 4u64]);
        let vconst8 = u64x2::from_array([8u64, 8u64]);
        let vconst16 = u64x2::from_array([16u64, 16u64]);

        //let s0 = u32x4::from(state[0]);
        //let g = fft_s[0] - s0;
        for i in 0..3 {
            let s0 = u64x2::from_array([state[i + 0] >> 32 as u64, (state[i + 0] as u32) as u64]);
            let s3 = u64x2::from_array([state[i + 3] >> 32 as u64, (state[i + 3] as u32) as u64]);
            let s6 = u64x2::from_array([state[i + 6] >> 32 as u64, (state[i + 6] as u32) as u64]);
            let s9 = u64x2::from_array([state[i + 9] >> 32 as u64, (state[i + 9] as u32) as u64]);
            let z0 = s0 + s6;
            let z2 = s0 - s6;
            let z1 = s3 + s9;
            let z3 = s9 - s3; // sign flipp

            fft_s[i + 0] = z0 + z1;
            fft_s[i + 3] = z0 - z1;
            fft_s[i + 6] = z2;
            fft_s[i + 9] = z3;
        }

        let x0r = fft_s[6];
        let x0i = fft_s[9];
        let x1r = fft_s[7];
        let x1i = fft_s[10];
        let x2r = fft_s[8];
        let x2i = fft_s[11];

        let (z0r, z0i) = (
            x0i + vconst2 * x0r + vconst16 * x1i + x1r - vconst4 * x2i + x2r,
            vconst2 * x0i - x0r + x1i - vconst16 * x1r + x2i + vconst4 * x2r,
        );
        let (z1r, z1i) = (
            x1i - x0i + vconst2 * x1r - vconst4 * x0r + vconst16 * x2i + x2r,
            x0r - vconst4 * x0i + vconst2 * x1i - x1r + x2i - vconst16 * x2r,
        );
        let (z2r, z2i) = (
            vconst16 * x0r - x0i - x1i - vconst4 * x1r + x2i + vconst2 * x2r,
            vconst16 * x0i + x0r - vconst4 * x1i + x1r + vconst2 * x2i - x2r,
        );
        /*
            let (z0r, z0i) = (
                x0i + (x0r << 1) + (x1i << 4) + x1r - (x2i << 2) + x2r,
                (x0i << 1) - x0r + x1i - (x1r << 4) + x2i + (x2r << 2),
            );
            let (z1r, z1i) = (
                -x0i - (x0r << 2) + x1i + (x1r << 1) + (x2i << 4) + x2r,
                (x0i << 2) + x0r + (x1i << 1) - x1r + x2i - (x2r << 4),
            );
            let (z2r, z2i) = (
                -x0i + (x0r << 4) - x1i - (x1r << 2) + x2i + (x2r << 1),
                (x0i << 4) + x0r - (x1i << 2) + x1r + (x2i << 1) - x2r,
            );
        */
        fft_s[6] = z0r;
        fft_s[7] = z1r;
        fft_s[8] = z2r;
        fft_s[9] = z0i;
        fft_s[10] = z1i;
        fft_s[11] = z2i;

        // Block1

        let x0 = fft_s[0];
        let x1 = fft_s[1];
        let x2 = fft_s[2];

        let tmp = (x0 + x1 + x2) * vconst16;
        let z0 = tmp + (x1 * vconst16);
        let z1 = tmp + (x2 * vconst16);
        let z2 = tmp + (x0 * vconst16);
        fft_s[0] = z1;
        fft_s[1] = z2;
        fft_s[2] = z0;

        // Block3
        let x0 = fft_s[3];
        let x1 = fft_s[4];
        let x2 = fft_s[5];

        let z0 = (x2 * vconst8) - x0 - (x1 * vconst2);
        let z1 = vconst0 - (x0 * vconst8) - x1 - (x2 * vconst2);
        let z2 = (x0 * vconst2) - (x1 * vconst8) - x2;

        fft_s[3] = z0;
        fft_s[4] = z1;
        fft_s[5] = z2;

        for i in 0..3 {
            let y0 = fft_s[0 + i];
            let y1 = fft_s[3 + i];
            let y2 = fft_s[6 + i];
            let y3 = fft_s[9 + i];

            let z0 = (y0 + y1);
            let z1 = (y0 - y1);
            let z2 = y2;
            let z3 = vconst0 - y3;

            let x0 = (z0 + z2);
            let x2 = (z0 - z2);
            let x1 = (z1 + z3);
            let x3 = (z1 - z3);

            //let a0: u128 = u32x4::from(x0);
            //let a1: u128 =  u32x4::into(x1);x1;
            //let a2: u128 =  u32x4::into(x2);x2;
            //let a3: u128 =  u32x4::into(x3);x3;
            //simd;
            let tmp = u64x2::to_array(x0);
            let res = ((tmp[0] as u128) << 32) + (tmp[1] as u128);
            state_[0 + i] = res;

            let tmp = u64x2::to_array(x1);
            let res = ((tmp[0] as u128) << 32) + (tmp[1] as u128);
            state_[3 + i] = res;

            let tmp = u64x2::to_array(x2);
            let res = ((tmp[0] as u128) << 32) + (tmp[1] as u128);
            state_[6 + i] = res;

            let tmp = u64x2::to_array(x3);
            let res = ((tmp[0] as u128) << 32) + (tmp[1] as u128);
            state_[9 + i] = res;
        }
        state_[0] += (diag_entry  * 8);
        return state_;
    }
    */
}

// MDS
// ================================================================================================
/// Rescue MDS matrix
/// Computed using algorithm 4 from <https://eprint.iacr.org/2020/1143.pdf>
const MDS: [[BaseElement; STATE_WIDTH]; STATE_WIDTH] = [
    [
        BaseElement::new(2108866337646019936),
        BaseElement::new(11223275256334781131),
        BaseElement::new(2318414738826783588),
        BaseElement::new(11240468238955543594),
        BaseElement::new(8007389560317667115),
        BaseElement::new(11080831380224887131),
        BaseElement::new(3922954383102346493),
        BaseElement::new(17194066286743901609),
        BaseElement::new(152620255842323114),
        BaseElement::new(7203302445933022224),
        BaseElement::new(17781531460838764471),
        BaseElement::new(2306881200),
    ],
    [
        BaseElement::new(3368836954250922620),
        BaseElement::new(5531382716338105518),
        BaseElement::new(7747104620279034727),
        BaseElement::new(14164487169476525880),
        BaseElement::new(4653455932372793639),
        BaseElement::new(5504123103633670518),
        BaseElement::new(3376629427948045767),
        BaseElement::new(1687083899297674997),
        BaseElement::new(8324288417826065247),
        BaseElement::new(17651364087632826504),
        BaseElement::new(15568475755679636039),
        BaseElement::new(4656488262337620150),
    ],
    [
        BaseElement::new(2560535215714666606),
        BaseElement::new(10793518538122219186),
        BaseElement::new(408467828146985886),
        BaseElement::new(13894393744319723897),
        BaseElement::new(17856013635663093677),
        BaseElement::new(14510101432365346218),
        BaseElement::new(12175743201430386993),
        BaseElement::new(12012700097100374591),
        BaseElement::new(976880602086740182),
        BaseElement::new(3187015135043748111),
        BaseElement::new(4630899319883688283),
        BaseElement::new(17674195666610532297),
    ],
    [
        BaseElement::new(10940635879119829731),
        BaseElement::new(9126204055164541072),
        BaseElement::new(13441880452578323624),
        BaseElement::new(13828699194559433302),
        BaseElement::new(6245685172712904082),
        BaseElement::new(3117562785727957263),
        BaseElement::new(17389107632996288753),
        BaseElement::new(3643151412418457029),
        BaseElement::new(10484080975961167028),
        BaseElement::new(4066673631745731889),
        BaseElement::new(8847974898748751041),
        BaseElement::new(9548808324754121113),
    ],
    [
        BaseElement::new(15656099696515372126),
        BaseElement::new(309741777966979967),
        BaseElement::new(16075523529922094036),
        BaseElement::new(5384192144218250710),
        BaseElement::new(15171244241641106028),
        BaseElement::new(6660319859038124593),
        BaseElement::new(6595450094003204814),
        BaseElement::new(15330207556174961057),
        BaseElement::new(2687301105226976975),
        BaseElement::new(15907414358067140389),
        BaseElement::new(2767130804164179683),
        BaseElement::new(8135839249549115549),
    ],
    [
        BaseElement::new(14687393836444508153),
        BaseElement::new(8122848807512458890),
        BaseElement::new(16998154830503301252),
        BaseElement::new(2904046703764323264),
        BaseElement::new(11170142989407566484),
        BaseElement::new(5448553946207765015),
        BaseElement::new(9766047029091333225),
        BaseElement::new(3852354853341479440),
        BaseElement::new(14577128274897891003),
        BaseElement::new(11994931371916133447),
        BaseElement::new(8299269445020599466),
        BaseElement::new(2859592328380146288),
    ],
    [
        BaseElement::new(4920761474064525703),
        BaseElement::new(13379538658122003618),
        BaseElement::new(3169184545474588182),
        BaseElement::new(15753261541491539618),
        BaseElement::new(622292315133191494),
        BaseElement::new(14052907820095169428),
        BaseElement::new(5159844729950547044),
        BaseElement::new(17439978194716087321),
        BaseElement::new(9945483003842285313),
        BaseElement::new(13647273880020281344),
        BaseElement::new(14750994260825376),
        BaseElement::new(12575187259316461486),
    ],
    [
        BaseElement::new(3371852905554824605),
        BaseElement::new(8886257005679683950),
        BaseElement::new(15677115160380392279),
        BaseElement::new(13242906482047961505),
        BaseElement::new(12149996307978507817),
        BaseElement::new(1427861135554592284),
        BaseElement::new(4033726302273030373),
        BaseElement::new(14761176804905342155),
        BaseElement::new(11465247508084706095),
        BaseElement::new(12112647677590318112),
        BaseElement::new(17343938135425110721),
        BaseElement::new(14654483060427620352),
    ],
    [
        BaseElement::new(5421794552262605237),
        BaseElement::new(14201164512563303484),
        BaseElement::new(5290621264363227639),
        BaseElement::new(1020180205893205576),
        BaseElement::new(14311345105258400438),
        BaseElement::new(7828111500457301560),
        BaseElement::new(9436759291445548340),
        BaseElement::new(5716067521736967068),
        BaseElement::new(15357555109169671716),
        BaseElement::new(4131452666376493252),
        BaseElement::new(16785275933585465720),
        BaseElement::new(11180136753375315897),
    ],
    [
        BaseElement::new(10451661389735482801),
        BaseElement::new(12128852772276583847),
        BaseElement::new(10630876800354432923),
        BaseElement::new(6884824371838330777),
        BaseElement::new(16413552665026570512),
        BaseElement::new(13637837753341196082),
        BaseElement::new(2558124068257217718),
        BaseElement::new(4327919242598628564),
        BaseElement::new(4236040195908057312),
        BaseElement::new(2081029262044280559),
        BaseElement::new(2047510589162918469),
        BaseElement::new(6835491236529222042),
    ],
    [
        BaseElement::new(5675273097893923172),
        BaseElement::new(8120839782755215647),
        BaseElement::new(9856415804450870143),
        BaseElement::new(1960632704307471239),
        BaseElement::new(15279057263127523057),
        BaseElement::new(17999325337309257121),
        BaseElement::new(72970456904683065),
        BaseElement::new(8899624805082057509),
        BaseElement::new(16980481565524365258),
        BaseElement::new(6412696708929498357),
        BaseElement::new(13917768671775544479),
        BaseElement::new(5505378218427096880),
    ],
    [
        BaseElement::new(10318314766641004576),
        BaseElement::new(17320192463105632563),
        BaseElement::new(11540812969169097044),
        BaseElement::new(7270556942018024148),
        BaseElement::new(4755326086930560682),
        BaseElement::new(2193604418377108959),
        BaseElement::new(11681945506511803967),
        BaseElement::new(8000243866012209465),
        BaseElement::new(6746478642521594042),
        BaseElement::new(12096331252283646217),
        BaseElement::new(13208137848575217268),
        BaseElement::new(5548519654341606996),
    ],
];

/// Rescue Inverse MDS matrix
/// Computed using algorithm 4 from <https://eprint.iacr.org/2020/1143.pdf> and then
/// inverting the resulting matrix.
const INV_MDS: [[BaseElement; STATE_WIDTH]; STATE_WIDTH] = [
    [
        BaseElement::new(1025714968950054217),
        BaseElement::new(2820417286206414279),
        BaseElement::new(4993698564949207576),
        BaseElement::new(12970218763715480197),
        BaseElement::new(15096702659601816313),
        BaseElement::new(5737881372597660297),
        BaseElement::new(13327263231927089804),
        BaseElement::new(4564252978131632277),
        BaseElement::new(16119054824480892382),
        BaseElement::new(6613927186172915989),
        BaseElement::new(6454498710731601655),
        BaseElement::new(2510089799608156620),
    ],
    [
        BaseElement::new(14311337779007263575),
        BaseElement::new(10306799626523962951),
        BaseElement::new(7776331823117795156),
        BaseElement::new(4922212921326569206),
        BaseElement::new(8669179866856828412),
        BaseElement::new(936244772485171410),
        BaseElement::new(4077406078785759791),
        BaseElement::new(2938383611938168107),
        BaseElement::new(16650590241171797614),
        BaseElement::new(16578411244849432284),
        BaseElement::new(17600191004694808340),
        BaseElement::new(5913375445729949081),
    ],
    [
        BaseElement::new(13640353831792923980),
        BaseElement::new(1583879644687006251),
        BaseElement::new(17678309436940389401),
        BaseElement::new(6793918274289159258),
        BaseElement::new(3594897835134355282),
        BaseElement::new(2158539885379341689),
        BaseElement::new(12473871986506720374),
        BaseElement::new(14874332242561185932),
        BaseElement::new(16402478875851979683),
        BaseElement::new(9893468322166516227),
        BaseElement::new(8142413325661539529),
        BaseElement::new(3444000755516388321),
    ],
    [
        BaseElement::new(14009777257506018221),
        BaseElement::new(18218829733847178457),
        BaseElement::new(11151899210182873569),
        BaseElement::new(14653120475631972171),
        BaseElement::new(9591156713922565586),
        BaseElement::new(16622517275046324812),
        BaseElement::new(3958136700677573712),
        BaseElement::new(2193274161734965529),
        BaseElement::new(15125079516929063010),
        BaseElement::new(3648852869044193741),
        BaseElement::new(4405494440143722315),
        BaseElement::new(15549070131235639125),
    ],
    [
        BaseElement::new(14324333194410783741),
        BaseElement::new(12565645879378458115),
        BaseElement::new(4028590290335558535),
        BaseElement::new(17936155181893467294),
        BaseElement::new(1833939650657097992),
        BaseElement::new(14310984655970610026),
        BaseElement::new(4701042357351086687),
        BaseElement::new(1226379890265418475),
        BaseElement::new(2550212856624409740),
        BaseElement::new(5670703442709406167),
        BaseElement::new(3281485106506301394),
        BaseElement::new(9804247840970323440),
    ],
    [
        BaseElement::new(7778523590474814059),
        BaseElement::new(7154630063229321501),
        BaseElement::new(17790326505487126055),
        BaseElement::new(3160574440608126866),
        BaseElement::new(7292349907185131376),
        BaseElement::new(1916491575080831825),
        BaseElement::new(11523142515674812675),
        BaseElement::new(2162357063341827157),
        BaseElement::new(6650415936886875699),
        BaseElement::new(11522955632464608509),
        BaseElement::new(16740856792338897018),
        BaseElement::new(16987840393715133187),
    ],
    [
        BaseElement::new(14499296811525152023),
        BaseElement::new(118549270069446537),
        BaseElement::new(3041471724857448013),
        BaseElement::new(3827228106225598612),
        BaseElement::new(2081369067662751050),
        BaseElement::new(15406142490454329462),
        BaseElement::new(8943531526276617760),
        BaseElement::new(3545513411057560337),
        BaseElement::new(11433277564645295966),
        BaseElement::new(9558995950666358829),
        BaseElement::new(7443251815414752292),
        BaseElement::new(12335092608217610725),
    ],
    [
        BaseElement::new(184304165023253232),
        BaseElement::new(11596940249585433199),
        BaseElement::new(18170668175083122019),
        BaseElement::new(8318891703682569182),
        BaseElement::new(4387895409295967519),
        BaseElement::new(14599228871586336059),
        BaseElement::new(2861651216488619239),
        BaseElement::new(567601091253927304),
        BaseElement::new(10135289435539766316),
        BaseElement::new(14905738261734377063),
        BaseElement::new(3345637344934149303),
        BaseElement::new(3159874422865401171),
    ],
    [
        BaseElement::new(1134458872778032479),
        BaseElement::new(4102035717681749376),
        BaseElement::new(14030271225872148070),
        BaseElement::new(10312336662487337312),
        BaseElement::new(12938229830489392977),
        BaseElement::new(17758804398255988457),
        BaseElement::new(15482323580054918356),
        BaseElement::new(1010277923244261213),
        BaseElement::new(12904552397519353856),
        BaseElement::new(5073478003078459047),
        BaseElement::new(11514678194579805863),
        BaseElement::new(4419017610446058921),
    ],
    [
        BaseElement::new(2916054498252226520),
        BaseElement::new(9880379926449218161),
        BaseElement::new(15314650755395914465),
        BaseElement::new(8335514387550394159),
        BaseElement::new(8955267746483690029),
        BaseElement::new(16353914237438359160),
        BaseElement::new(4173425891602463552),
        BaseElement::new(14892581052359168234),
        BaseElement::new(17561678290843148035),
        BaseElement::new(7292975356887551984),
        BaseElement::new(18039512759118984712),
        BaseElement::new(5411253583520971237),
    ],
    [
        BaseElement::new(9848042270158364544),
        BaseElement::new(809689769037458603),
        BaseElement::new(5884047526712050760),
        BaseElement::new(12956871945669043745),
        BaseElement::new(14265127496637532237),
        BaseElement::new(6211568220597222123),
        BaseElement::new(678544061771515015),
        BaseElement::new(16295989318674734123),
        BaseElement::new(11782767968925152203),
        BaseElement::new(1359397660819991739),
        BaseElement::new(16148400912425385689),
        BaseElement::new(14440017265059055146),
    ],
    [
        BaseElement::new(1634272668217219807),
        BaseElement::new(16290589064070324125),
        BaseElement::new(5311838222680798126),
        BaseElement::new(15044064140936894715),
        BaseElement::new(15775025788428030421),
        BaseElement::new(12586374713559327349),
        BaseElement::new(8118943473454062014),
        BaseElement::new(13223746794660766349),
        BaseElement::new(13059674280609257192),
        BaseElement::new(16605443174349648289),
        BaseElement::new(13586971219878687822),
        BaseElement::new(16337009014471658360),
    ],
];

// ROUND CONSTANTS
// ================================================================================================

/// Rescue round constants;
/// computed using algorithm 5 from <https://eprint.iacr.org/2020/1143.pdf>
///
/// The constants are broken up into two arrays ARK1 and ARK2; ARK1 contains the constants for the
/// first half of Rescue round, and ARK2 contains constants for the second half of Rescue round.
const ARK1: [[BaseElement; STATE_WIDTH]; NUM_ROUNDS] = [
    [
        BaseElement::new(13917550007135091859),
        BaseElement::new(16002276252647722320),
        BaseElement::new(4729924423368391595),
        BaseElement::new(10059693067827680263),
        BaseElement::new(9804807372516189948),
        BaseElement::new(15666751576116384237),
        BaseElement::new(10150587679474953119),
        BaseElement::new(13627942357577414247),
        BaseElement::new(2323786301545403792),
        BaseElement::new(615170742765998613),
        BaseElement::new(8870655212817778103),
        BaseElement::new(10534167191270683080),
    ],
    [
        BaseElement::new(14572151513649018290),
        BaseElement::new(9445470642301863087),
        BaseElement::new(6565801926598404534),
        BaseElement::new(12667566692985038975),
        BaseElement::new(7193782419267459720),
        BaseElement::new(11874811971940314298),
        BaseElement::new(17906868010477466257),
        BaseElement::new(1237247437760523561),
        BaseElement::new(6829882458376718831),
        BaseElement::new(2140011966759485221),
        BaseElement::new(1624379354686052121),
        BaseElement::new(50954653459374206),
    ],
    [
        BaseElement::new(16288075653722020941),
        BaseElement::new(13294924199301620952),
        BaseElement::new(13370596140726871456),
        BaseElement::new(611533288599636281),
        BaseElement::new(12865221627554828747),
        BaseElement::new(12269498015480242943),
        BaseElement::new(8230863118714645896),
        BaseElement::new(13466591048726906480),
        BaseElement::new(10176988631229240256),
        BaseElement::new(14951460136371189405),
        BaseElement::new(5882405912332577353),
        BaseElement::new(18125144098115032453),
    ],
    [
        BaseElement::new(6076976409066920174),
        BaseElement::new(7466617867456719866),
        BaseElement::new(5509452692963105675),
        BaseElement::new(14692460717212261752),
        BaseElement::new(12980373618703329746),
        BaseElement::new(1361187191725412610),
        BaseElement::new(6093955025012408881),
        BaseElement::new(5110883082899748359),
        BaseElement::new(8578179704817414083),
        BaseElement::new(9311749071195681469),
        BaseElement::new(16965242536774914613),
        BaseElement::new(5747454353875601040),
    ],
    [
        BaseElement::new(13684212076160345083),
        BaseElement::new(19445754899749561),
        BaseElement::new(16618768069125744845),
        BaseElement::new(278225951958825090),
        BaseElement::new(4997246680116830377),
        BaseElement::new(782614868534172852),
        BaseElement::new(16423767594935000044),
        BaseElement::new(9990984633405879434),
        BaseElement::new(16757120847103156641),
        BaseElement::new(2103861168279461168),
        BaseElement::new(16018697163142305052),
        BaseElement::new(6479823382130993799),
    ],
    [
        BaseElement::new(13957683526597936825),
        BaseElement::new(9702819874074407511),
        BaseElement::new(18357323897135139931),
        BaseElement::new(3029452444431245019),
        BaseElement::new(1809322684009991117),
        BaseElement::new(12459356450895788575),
        BaseElement::new(11985094908667810946),
        BaseElement::new(12868806590346066108),
        BaseElement::new(7872185587893926881),
        BaseElement::new(10694372443883124306),
        BaseElement::new(8644995046789277522),
        BaseElement::new(1422920069067375692),
    ],
    [
        BaseElement::new(17619517835351328008),
        BaseElement::new(6173683530634627901),
        BaseElement::new(15061027706054897896),
        BaseElement::new(4503753322633415655),
        BaseElement::new(11538516425871008333),
        BaseElement::new(12777459872202073891),
        BaseElement::new(17842814708228807409),
        BaseElement::new(13441695826912633916),
        BaseElement::new(5950710620243434509),
        BaseElement::new(17040450522225825296),
        BaseElement::new(8787650312632423701),
        BaseElement::new(7431110942091427450),
    ],
];

const ARK2: [[BaseElement; STATE_WIDTH]; NUM_ROUNDS] = [
    [
        BaseElement::new(7989257206380839449),
        BaseElement::new(8639509123020237648),
        BaseElement::new(6488561830509603695),
        BaseElement::new(5519169995467998761),
        BaseElement::new(2972173318556248829),
        BaseElement::new(14899875358187389787),
        BaseElement::new(14160104549881494022),
        BaseElement::new(5969738169680657501),
        BaseElement::new(5116050734813646528),
        BaseElement::new(12120002089437618419),
        BaseElement::new(17404470791907152876),
        BaseElement::new(2718166276419445724),
    ],
    [
        BaseElement::new(2485377440770793394),
        BaseElement::new(14358936485713564605),
        BaseElement::new(3327012975585973824),
        BaseElement::new(6001912612374303716),
        BaseElement::new(17419159457659073951),
        BaseElement::new(11810720562576658327),
        BaseElement::new(14802512641816370470),
        BaseElement::new(751963320628219432),
        BaseElement::new(9410455736958787393),
        BaseElement::new(16405548341306967018),
        BaseElement::new(6867376949398252373),
        BaseElement::new(13982182448213113532),
    ],
    [
        BaseElement::new(10436926105997283389),
        BaseElement::new(13237521312283579132),
        BaseElement::new(668335841375552722),
        BaseElement::new(2385521647573044240),
        BaseElement::new(3874694023045931809),
        BaseElement::new(12952434030222726182),
        BaseElement::new(1972984540857058687),
        BaseElement::new(14000313505684510403),
        BaseElement::new(976377933822676506),
        BaseElement::new(8407002393718726702),
        BaseElement::new(338785660775650958),
        BaseElement::new(4208211193539481671),
    ],
    [
        BaseElement::new(2284392243703840734),
        BaseElement::new(4500504737691218932),
        BaseElement::new(3976085877224857941),
        BaseElement::new(2603294837319327956),
        BaseElement::new(5760259105023371034),
        BaseElement::new(2911579958858769248),
        BaseElement::new(18415938932239013434),
        BaseElement::new(7063156700464743997),
        BaseElement::new(16626114991069403630),
        BaseElement::new(163485390956217960),
        BaseElement::new(11596043559919659130),
        BaseElement::new(2976841507452846995),
    ],
    [
        BaseElement::new(15090073748392700862),
        BaseElement::new(3496786927732034743),
        BaseElement::new(8646735362535504000),
        BaseElement::new(2460088694130347125),
        BaseElement::new(3944675034557577794),
        BaseElement::new(14781700518249159275),
        BaseElement::new(2857749437648203959),
        BaseElement::new(8505429584078195973),
        BaseElement::new(18008150643764164736),
        BaseElement::new(720176627102578275),
        BaseElement::new(7038653538629322181),
        BaseElement::new(8849746187975356582),
    ],
    [
        BaseElement::new(17427790390280348710),
        BaseElement::new(1159544160012040055),
        BaseElement::new(17946663256456930598),
        BaseElement::new(6338793524502945410),
        BaseElement::new(17715539080731926288),
        BaseElement::new(4208940652334891422),
        BaseElement::new(12386490721239135719),
        BaseElement::new(10010817080957769535),
        BaseElement::new(5566101162185411405),
        BaseElement::new(12520146553271266365),
        BaseElement::new(4972547404153988943),
        BaseElement::new(5597076522138709717),
    ],
    [
        BaseElement::new(18338863478027005376),
        BaseElement::new(115128380230345639),
        BaseElement::new(4427489889653730058),
        BaseElement::new(10890727269603281956),
        BaseElement::new(7094492770210294530),
        BaseElement::new(7345573238864544283),
        BaseElement::new(6834103517673002336),
        BaseElement::new(14002814950696095900),
        BaseElement::new(15939230865809555943),
        BaseElement::new(12717309295554119359),
        BaseElement::new(4130723396860574906),
        BaseElement::new(7706153020203677238),
    ],
];
