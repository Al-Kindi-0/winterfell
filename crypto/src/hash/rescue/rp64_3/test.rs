// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{BaseElement, Rp64_256, BATCH_SIZE, STATE_WIDTH};

#[test]
fn check_para_permutation() {
    let mut state: [BaseElement; STATE_WIDTH] = [
        BaseElement::new(0),
        BaseElement::new(1),
        BaseElement::new(2),
        BaseElement::new(3),
        BaseElement::new(4),
        BaseElement::new(5),
        BaseElement::new(6),
        BaseElement::new(7),
        BaseElement::new(8),
        BaseElement::new(9),
        BaseElement::new(10),
        BaseElement::new(11),
    ];

    let mut state_ = [[
        BaseElement::new(0),
        BaseElement::new(1),
        BaseElement::new(2),
        BaseElement::new(3),
        BaseElement::new(4),
        BaseElement::new(5),
        BaseElement::new(6),
        BaseElement::new(7),
        BaseElement::new(8),
        BaseElement::new(9),
        BaseElement::new(10),
        BaseElement::new(11),
    ]; BATCH_SIZE];

    let mut state_2 = [[
        BaseElement::new(0),
        BaseElement::new(1),
        BaseElement::new(2),
        BaseElement::new(3),
        BaseElement::new(4),
        BaseElement::new(5),
        BaseElement::new(6),
        BaseElement::new(7),
        BaseElement::new(8),
        BaseElement::new(9),
        BaseElement::new(10),
        BaseElement::new(11),
    ]; BATCH_SIZE];
    Rp64_256::apply_permutation(&mut state);
    Rp64_256::apply_permutation_batch(&mut state_);
    Rp64_256::apply_permutation_batch_freq(&mut state_2);
    //eprintln!("Classic final result {:?}",state);
    //eprintln!("Para final result {:?}",state_[1]);
    //eprintln!("Para + freq final result {:?}",state_2[1]);
    assert_eq!(state, state_[0]);
    assert_eq!(state, state_2[0]);
}

#[test]
fn check_correctness_mds_freq() {
    use rand_utils::rand_array;

    for _ in 0..1000 {
        let mut s1: [BaseElement; STATE_WIDTH] = rand_array();
        let mut s2: [BaseElement; STATE_WIDTH] = s1.clone();
        assert_eq!(
            Rp64_256::apply_mds(&mut s1),
            Rp64_256::apply_mds_freq(&mut s2)
        );
        //eprintln!("Classical method: {:?} ", s1);
        //eprintln!("FFT-based method: {:?} ", s2);
    }
}

#[test]
fn check_simd() {
    use core_simd::*;

    let a = f32x4::splat(10.0);
    let b = f32x4::from_array([1.0, 2.0, 3.0, 4.0]);
    println!("{:?}", a + b);
    assert_eq!(a + b, f32x4::from_array([11.0, 12.0, 13.0, 14.0]));
}

#[test]
fn check_delayed() {
    let mut state: [BaseElement; STATE_WIDTH] = [
        BaseElement::new(10),
        BaseElement::new(1),
        BaseElement::new(2),
        BaseElement::new(3),
        BaseElement::new(4),
        BaseElement::new(5),
        BaseElement::new(6),
        BaseElement::new(7),
        BaseElement::new(8),
        BaseElement::new(0),
        BaseElement::new(10),
        BaseElement::new(11),
    ];

    let mut state_1: [BaseElement; STATE_WIDTH] = [
        BaseElement::new(10),
        BaseElement::new(1),
        BaseElement::new(2),
        BaseElement::new(3),
        BaseElement::new(4),
        BaseElement::new(5),
        BaseElement::new(6),
        BaseElement::new(7),
        BaseElement::new(8),
        BaseElement::new(0),
        BaseElement::new(10),
        BaseElement::new(11),
    ];
    Rp64_256::apply_permutation_freq_delayed(&mut state);
    eprintln!("{:?}", state);
    Rp64_256::apply_permutation(&mut state_1);
    eprintln!("{:?}", state_1);
}
