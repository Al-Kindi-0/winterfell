// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    BaseElement, Rp64_256,
     STATE_WIDTH, BATCH_SIZE
};

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

    let mut state_= [[
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
    ];BATCH_SIZE];

    Rp64_256::apply_permutation(&mut state);
    Rp64_256::apply_permutation_batch(&mut state_);
    eprintln!("Classic final result {:?}",state);
    eprintln!("Para final result {:?}",state_);
    assert_eq!(state, state_[0]);
}