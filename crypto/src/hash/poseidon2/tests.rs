// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use math::FieldElement;

use super::{BaseElement, Poseidon2, STATE_WIDTH};

#[test]
fn permutation_test_vector() {
    // test vector from the Poseidon2 reference implementation
    let mut elements = [
        BaseElement::ZERO,
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

    Poseidon2::apply_permutation(&mut elements);
    assert_eq!(elements[0], BaseElement::new(0x01eaef96bdf1c0c1));
    assert_eq!(elements[1], BaseElement::new(0x1f0d2cc525b2540c));
    assert_eq!(elements[2], BaseElement::new(0x6282c1dfe1e0358d));
    assert_eq!(elements[3], BaseElement::new(0xe780d721f698e1e6));
    assert_eq!(elements[4], BaseElement::new(0x280c0b6f753d833b));
    assert_eq!(elements[5], BaseElement::new(0x1b942dd5023156ab));
    assert_eq!(elements[6], BaseElement::new(0x43f0df3fcccb8398));
    assert_eq!(elements[7], BaseElement::new(0xe8e8190585489025));
    assert_eq!(elements[8], BaseElement::new(0x56bdbf72f77ada22));
    assert_eq!(elements[9], BaseElement::new(0x7911c32bf9dcd705));
    assert_eq!(elements[10], BaseElement::new(0xec467926508fbe67));
    assert_eq!(elements[11], BaseElement::new(0x6a50450ddf85a6ed));
}

#[test]
fn permutation_changes_state() {
    let mut state = [BaseElement::ZERO; STATE_WIDTH];
    Poseidon2::apply_permutation(&mut state);
    assert_ne!(state, [BaseElement::ZERO; STATE_WIDTH]);
}
