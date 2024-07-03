// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use math::{fft, FieldElement};
use rand::{Rng, RngCore};
use utils::uninit_vector;

use super::{ColMatrix, StarkDomain};

// CONSTRAINT COMPOSITION POLYNOMIAL TRACE
// ================================================================================================

/// Represents merged evaluations of all constraint evaluations.
pub struct CompositionPolyTrace<E>(Vec<E>);

impl<E: FieldElement> CompositionPolyTrace<E> {
    /// Returns a new instance of [CompositionPolyTrace] instantiated from the provided evaluations.
    ///
    /// # Panics
    /// Panics if the number of evaluations is not a power of 2.
    pub fn new(evaluations: Vec<E>) -> Self {
        assert!(
            evaluations.len().is_power_of_two(),
            "length of composition polynomial trace must be a power of 2, but was {}",
            evaluations.len(),
        );

        Self(evaluations)
    }

    /// Returns the number of evaluations in this trace.
    pub fn num_rows(&self) -> usize {
        self.0.len()
    }

    /// Returns the internal vector representing this trace.
    pub fn into_inner(self) -> Vec<E> {
        self.0
    }
}

// CONSTRAINT COMPOSITION POLYNOMIAL
// ================================================================================================
/// A composition polynomial split into columns with each column being of length equal to trace_length.
///
/// For example, if the composition polynomial has degree 2N - 1, where N is the trace length,
/// it will be stored as two columns of size N (each of degree N - 1).
pub struct CompositionPoly<E: FieldElement> {
    data: ColMatrix<E>,
}

impl<E: FieldElement> CompositionPoly<E> {
    /// Returns a new composition polynomial.
    pub fn new<R: RngCore>(
        composition_trace: CompositionPolyTrace<E>,
        domain: &StarkDomain<E::BaseField>,
        num_cols: usize,
        is_zk: Option<u32>,
        original_trace_len: usize,
        prng: &mut R,
    ) -> Self {
        assert!(
            domain.trace_length() < composition_trace.num_rows(),
            "trace length must be smaller than length of composition polynomial trace"
        );

        let mut trace = composition_trace.into_inner();

        // at this point, combined_poly contains evaluations of the combined constraint polynomial;
        // we interpolate this polynomial to transform it into coefficient form.
        let inv_twiddles = fft::get_inv_twiddles::<E::BaseField>(trace.len());
        fft::interpolate_poly_with_offset(&mut trace, &inv_twiddles, domain.offset());

        let mut polys = transpose(trace, domain.trace_length(), num_cols);

        if is_zk.is_some() {
            let extended_len = (original_trace_len + is_zk.unwrap() as usize).next_power_of_two();
            let pad_len = extended_len - original_trace_len;

            //TODO: Check the degree of randomizer
            let mut zk_col = vec![E::ZERO; original_trace_len];

            for a in zk_col.iter_mut() {
                let bytes = prng.gen::<[u8; 32]>();
                *a = E::from_random_bytes(&bytes[..E::VALUE_SIZE])
                    .expect("failed to generate randomness");
            }

            let mut res_col = zk_col.to_vec();
            let added = vec![E::ZERO; pad_len];
            res_col.extend_from_slice(&added);
            polys.push(res_col)
        }

        CompositionPoly { data: ColMatrix::new(polys) }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of individual column polynomials used to describe this composition
    /// polynomial.
    pub fn num_columns(&self) -> usize {
        self.data.num_cols()
    }

    /// Returns the length of individual column polynomials; this is guaranteed to be a power of 2.
    pub fn column_len(&self) -> usize {
        self.data.num_rows()
    }

    /// Returns the degree of individual column polynomial.
    #[allow(unused)]
    pub fn column_degree(&self) -> usize {
        self.column_len() - 1
    }

    /// Returns evaluations of all composition polynomial columns at point z.
    pub fn evaluate_at(&self, z: E, is_zk: bool) -> Vec<E> {
        self.data.evaluate_columns_at(z, is_zk)
    }

    /// Returns a reference to the matrix of individual column polynomials.
    pub fn data(&self) -> &ColMatrix<E> {
        &self.data
    }

    /// Transforms this composition polynomial into a vector of individual column polynomials.
    pub fn into_columns(self) -> Vec<Vec<E>> {
        self.data.into_columns()
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Splits polynomial coefficients into the specified number of columns. The coefficients are split
/// in such a way that each resulting column has the same degree. For example, a polynomial
/// a * x^3 + b * x^2 + c * x + d, can be rewritten as: (b * x^2 + d) + x * (a * x^2 + c), and then
/// the two columns will be: (b * x^2 + d) and (a * x^2 + c).
fn transpose<E: FieldElement>(coefficients: Vec<E>, num_columns: usize) -> Vec<Vec<E>> {
    let column_len = coefficients.len() / num_columns;

    let mut result =
        unsafe { (0..num_columns).map(|_| uninit_vector(column_len)).collect::<Vec<_>>() };

    // TODO: implement multi-threaded version
    for (i, coeff) in coefficients.into_iter().enumerate() {
        let row_idx = i / num_columns;
        let col_idx = i % num_columns;
        result[col_idx][row_idx] = coeff;
    }

    result
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use alloc::vec::Vec;

    use math::fields::f128::BaseElement;

    #[test]
    fn segment() {
        let values = (0u128..16).map(BaseElement::new).collect::<Vec<_>>();
        let actual = super::segment(values, 4, 4);

        #[rustfmt::skip]
        let expected = vec![
            vec![BaseElement::new(0), BaseElement::new(1), BaseElement::new(2), BaseElement::new(3)],
            vec![BaseElement::new(4), BaseElement::new(5), BaseElement::new(6), BaseElement::new(7)],
            vec![BaseElement::new(8), BaseElement::new(9), BaseElement::new(10), BaseElement::new(11)],
            vec![BaseElement::new(12), BaseElement::new(13), BaseElement::new(14), BaseElement::new(15)],
        ];

        assert_eq!(expected, actual)
    }
}
