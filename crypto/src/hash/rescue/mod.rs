// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{Digest, ElementHasher, Hasher, StarkField};

mod rp62_248;
pub use rp62_248::Rp62_248;

mod rp64_256;
pub use rp64_256::Rp64_256;

mod rp64_1;
pub use rp64_1::Rp64_256 as Rp_64_1;

mod rp64_2;
pub use rp64_2::Rp64_256 as Rp_64_2;

mod rp64_3;
pub use rp64_3::Rp64_256 as Rp_64_3;

mod rp64_4;
pub use rp64_4::Rp64_256 as Rp_64_4;

mod rp64_5;
pub use rp64_5::Rp64_256 as Rp_64_5;

mod rp64_6;
pub use rp64_6::Rp64_256 as Rp_64_6;

mod rp64mont_3;
pub use rp64mont_3::Rp64_256 as Rp_64m_3;

// HELPER FUNCTIONS
// ================================================================================================

#[inline(always)]
fn exp_acc<B: StarkField, const N: usize, const M: usize>(base: [B; N], tail: [B; N]) -> [B; N] {
    let mut result = base;
    for _ in 0..M {
        result.iter_mut().for_each(|r| *r = r.square());
    }
    result.iter_mut().zip(tail).for_each(|(r, t)| *r *= t);
    result
}

#[inline(always)]
fn exp_acc_one<B: StarkField, const M: usize>(base: B, tail: B) -> B {
    let mut result = base;
    for _ in 0..M {
        result = result.square();
    }
    result * tail
}