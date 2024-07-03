// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use air::ZkParameters;
use alloc::vec::Vec;

use math::{fft, FieldElement};
use rand::{Rng, RngCore};

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
        zk_parameters: Option<ZkParameters>,
        prng: &mut R,
    ) -> Self {
        assert!(
            domain.trace_length() < composition_trace.num_rows(),
            "trace length must be smaller than length of composition polynomial trace"
        );

        let mut trace = composition_trace.into_inner();

        let h = if let Some(ref zk_parameters) = zk_parameters {
            zk_parameters.degree_constraint_randomizer()
        } else {
            0
        };
        let l = domain.trace_length();
        let degree_chunked_quotient = l - h;

        // at this point, combined_poly contains evaluations of the combined constraint polynomial;
        // we interpolate this polynomial to transform it into coefficient form.
        let inv_twiddles = fft::get_inv_twiddles::<E::BaseField>(trace.len());
        fft::interpolate_poly_with_offset(&mut trace, &inv_twiddles, domain.offset());

        let polys = segment(trace, degree_chunked_quotient, num_cols);
        let mut polys = complement_to(polys, l, prng);

        // add randomizer polynomial for FRI
        if zk_parameters.is_some() {
            let extended_len = polys[0].len();
            let mut zk_col = vec![E::ZERO; extended_len];

            for a in zk_col.iter_mut() {
                let bytes = prng.gen::<[u8; 32]>();
                *a = E::from_random_bytes(&bytes[..E::VALUE_SIZE])
                    .expect("failed to generate randomness");
            }
            polys.push(zk_col)
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

    /// Returns evaluations of all composition polynomial columns at point z^m, where m is
    /// the number of column polynomials.
    pub fn evaluate_at(&self, z: E, is_zk: bool) -> Vec<E> {
        let z_m = z.exp((self.num_columns() as u32 - is_zk as u32).into());
        self.data.evaluate_columns_at(z_m, is_zk)
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

fn complement_to<R: RngCore, E: FieldElement>(
    polys: Vec<Vec<E>>,
    l: usize,
    prng: &mut R,
) -> Vec<Vec<E>> {
    let mut result = vec![];
    let mut current_poly = vec![E::ZERO; l - polys[0].len()];
    let mut previous_poly = vec![E::ZERO; l - polys[0].len()];

    for (_, poly) in polys.iter().enumerate().take_while(|(index, _)| *index != polys.len() - 1) {
        let diff = l - poly.len();
        for i in 0..diff {
            let bytes = prng.gen::<[u8; 32]>();
            current_poly[i] = E::from_random_bytes(&bytes[..E::VALUE_SIZE])
                .expect("failed to generate randomness");
        }

        let mut res = vec![];
        res.extend_from_slice(&poly);
        res.extend_from_slice(&current_poly);

        for i in 0..previous_poly.len() {
            res[i] -= previous_poly[i];
        }

        for i in 0..previous_poly.len() {
            previous_poly[i] = current_poly[i];
        }
        result.push(res)
    }

    let poly = polys.last().unwrap();
    let mut res = vec![E::ZERO; l];
    for (i, entry) in poly.iter().enumerate() {
        res[i] = *entry;
    }
    for i in 0..previous_poly.len() {
        res[i] -= previous_poly[i];
    }
    result.push(res);
    result
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
    fn transpose() {
        let values = (0u128..16).map(BaseElement::new).collect::<Vec<_>>();
        let actual = super::transpose(values, 4);

        #[rustfmt::skip]
        let expected = vec![
            vec![BaseElement::new(0), BaseElement::new(4), BaseElement::new(8), BaseElement::new(12)],
            vec![BaseElement::new(1), BaseElement::new(5), BaseElement::new(9), BaseElement::new(13)],
            vec![BaseElement::new(2), BaseElement::new(6), BaseElement::new(10), BaseElement::new(14)],
            vec![BaseElement::new(3), BaseElement::new(7), BaseElement::new(11), BaseElement::new(15)],
        ];

        assert_eq!(expected, actual)
    }
}
