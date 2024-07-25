use core::ops::Index;

use alloc::vec::Vec;
use utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

use crate::FieldElement;

// MULTI-LINEAR POLYNOMIAL
// ================================================================================================

/// Represents a multi-linear polynomial.
///
/// The representation stores the evaluations of the polynomial over the boolean hyper-cube
/// {0 , 1}^ν.
#[derive(Clone, Debug)]
pub struct MultiLinearPoly<E: FieldElement> {
    num_variables: usize,
    evaluations: Vec<E>,
}

impl<E: FieldElement> MultiLinearPoly<E> {
    /// Constructs a [`MultiLinearPoly`] from its evaluations over the boolean hyper-cube {0 , 1}^ν.
    pub fn from_evaluations(evaluations: Vec<E>) -> Result<Self, MultiLinearPolyError> {
        if !evaluations.len().is_power_of_two() {
            return Err(MultiLinearPolyError::EvaluationsNotPowerOfTwo);
        }
        Ok(Self {
            num_variables: (evaluations.len().ilog2()) as usize,
            evaluations,
        })
    }

    /// Returns the number of variables of the multi-linear polynomial.
    pub fn num_variables(&self) -> usize {
        self.num_variables
    }

    /// Returns the evaluations over the boolean hyper-cube.
    pub fn evaluations(&self) -> &[E] {
        &self.evaluations
    }

    /// Returns the number of evaluations. This is equal to the size of the boolean hyper-cube.
    pub fn num_evaluations(&self) -> usize {
        self.evaluations.len()
    }

    /// Evaluate the multi-linear at some query (r_0, ..., r_{ν - 1}) ∈ 𝔽^ν.
    ///
    /// It first computes the evaluations of the Lagrange basis polynomials over the interpolating
    /// set {0 , 1}^ν at (r_0, ..., r_{ν - 1}) i.e., the Lagrange kernel at (r_0, ..., r_{ν - 1}).
    /// The evaluation then is the inner product, indexed by {0 , 1}^ν, of the vector of
    /// evaluations times the Lagrange kernel.
    pub fn evaluate(&self, query: &[E]) -> E {
        let tensored_query = compute_lagrange_basis_evals_at(query);
        inner_product(self.evaluations.iter().copied(), tensored_query.iter().copied())
    }

    /// Similar to [`Self::evaluate`], except that the query was already turned into the Lagrange
    /// kernel (i.e. the [`lagrange_ker::EqFunction`] evaluated at every point in the set
    /// `{0 , 1}^ν`).
    ///
    /// This is more efficient than [`Self::evaluate`] when multiple different [`MultiLinearPoly`]
    /// need to be evaluated at the same query point.
    pub fn evaluate_with_lagrange_kernel(&self, lagrange_kernel: &[E]) -> E {
        inner_product(self.evaluations.iter().copied(), lagrange_kernel.iter().copied())
    }

    /// Computes f(r_0, y_1, ..., y_{ν - 1}) using the linear interpolation formula
    /// (1 - r_0) * f(0, y_1, ..., y_{ν - 1}) + r_0 * f(1, y_1, ..., y_{ν - 1}) and assigns
    /// the resulting multi-linear, defined over a domain of half the size, to `self`.
    pub fn bind_least_significant_variable(&mut self, round_challenge: E) {
        let mut result = vec![E::ZERO; 1 << (self.num_variables() - 1)];
        for (i, res) in result.iter_mut().enumerate() {
            *res = self.evaluations[i << 1]
                + round_challenge * (self.evaluations[(i << 1) + 1] - self.evaluations[i << 1]);
        }
        *self = Self::from_evaluations(result)
            .expect("should not fail given that it is a multi-linear");
    }

    /// Given the multilinear polynomial f(y_0, y_1, ..., y_{ν - 1}), returns two polynomials:
    /// f(0, y_1, ..., y_{ν - 1}) and f(1, y_1, ..., y_{ν - 1}).
    pub fn project_least_significant_variable(&self) -> (Self, Self) {
        let mut p0 = Vec::with_capacity(self.num_evaluations() / 2);
        let mut p1 = Vec::with_capacity(self.num_evaluations() / 2);
        for chunk in self.evaluations.chunks_exact(2) {
            p0.push(chunk[0]);
            p1.push(chunk[1]);
        }

        (
            MultiLinearPoly::from_evaluations(p0).unwrap(),
            MultiLinearPoly::from_evaluations(p1).unwrap(),
        )
    }
}

impl<E: FieldElement> Index<usize> for MultiLinearPoly<E> {
    type Output = E;

    fn index(&self, index: usize) -> &E {
        &(self.evaluations[index])
    }
}

impl<E> Serializable for MultiLinearPoly<E>
where
    E: FieldElement,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self {
            num_variables,
            evaluations,
        } = self;
        num_variables.write_into(target);
        evaluations.write_into(target);
    }
}

impl<E> Deserializable for MultiLinearPoly<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            num_variables: Deserializable::read_from(source)?,
            evaluations: Deserializable::read_from(source)?,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MultiLinearPolyError {
    #[error("A multi-linear polynomial should have a power of 2 number of evaluations over the Boolean hyper-cube")]
    EvaluationsNotPowerOfTwo,
}

// EQ FUNCTION
// ================================================================================================

/// The EQ (equality) function is the binary function defined by
///
/// ```ignore
/// EQ:    {0 , 1}^ν ⛌ {0 , 1}^ν ⇾ {0 , 1}
///   ((x_0, ..., x_{ν - 1}), (y_0, ..., y_{ν - 1})) ↦ \prod_{i = 0}^{ν - 1} (x_i * y_i + (1 - x_i)
/// * (1 - y_i))
/// ```
///
/// Taking It's multi-linear extension EQ^{~}, we can define a basis for the set of multi-linear
/// polynomials in ν variables by
///         {EQ^{~}(., (y_0, ..., y_{ν - 1})): (y_0, ..., y_{ν - 1}) ∈ {0 , 1}^ν}
/// where each basis function is a function of its first argument. This is called the Lagrange or
/// evaluation basis with evaluation set {0 , 1}^ν.
///
/// Given a function (f: {0 , 1}^ν ⇾ 𝔽), its multi-linear extension (i.e., the unique
/// mult-linear polynomial extending f to (f^{~}: 𝔽^ν ⇾ 𝔽) and agrees with it on {0 , 1}^ν) is
/// defined as the summation of the evaluations of f against the Lagrange basis.
/// More specifically, given (r_0, ..., r_{ν - 1}) ∈ 𝔽^ν, then:
///
/// ```ignore
///     f^{~}(r_0, ..., r_{ν - 1}) = \sum_{(y_0, ..., y_{ν - 1}) ∈ {0 , 1}^ν}
///                  f(y_0, ..., y_{ν - 1}) EQ^{~}((r_0, ..., r_{ν - 1}), (y_0, ..., y_{ν - 1}))
/// ```
///
/// We call the Lagrange kernel the evaluation of the EQ^{~} function at
/// ((r_0, ..., r_{ν - 1}), (y_0, ..., y_{ν - 1})) for all (y_0, ..., y_{ν - 1}) ∈ {0 , 1}^ν for
/// a fixed (r_0, ..., r_{ν - 1}) ∈ 𝔽^ν.
///
/// [`EqFunction`] represents EQ^{~} the mult-linear extension of
///
/// ((y_0, ..., y_{ν - 1}) ↦ EQ((r_0, ..., r_{ν - 1}), (y_0, ..., y_{ν - 1})))
///
/// and contains a method to generate the Lagrange kernel for defining evaluations of multi-linear
/// extensions of arbitrary functions (f: {0 , 1}^ν ⇾ 𝔽) at a given point (r_0, ..., r_{ν - 1})
/// as well as a method to evaluate EQ^{~}((r_0, ..., r_{ν - 1}), (t_0, ..., t_{ν - 1}))) for
/// (t_0, ..., t_{ν - 1}) ∈ 𝔽^ν.
pub struct EqFunction<E> {
    r: Vec<E>,
}

impl<E: FieldElement> EqFunction<E> {
    /// Creates a new [EqFunction].
    pub fn new(r: Vec<E>) -> Self {
        let tmp = r.clone();
        EqFunction { r: tmp }
    }

    /// Computes EQ((r_0, ..., r_{ν - 1}), (t_0, ..., t_{ν - 1}))).
    pub fn evaluate(&self, t: &[E]) -> E {
        assert_eq!(self.r.len(), t.len());

        (0..self.r.len())
            .map(|i| self.r[i] * t[i] + (E::ONE - self.r[i]) * (E::ONE - t[i]))
            .fold(E::ONE, |acc, term| acc * term)
    }

    /// Computes EQ((r_0, ..., r_{ν - 1}), (y_0, ..., y_{ν - 1})) for all
    /// (y_0, ..., y_{ν - 1}) ∈ {0 , 1}^ν i.e., the Lagrange kernel at r = (r_0, ..., r_{ν - 1}).
    pub fn evaluations(&self) -> Vec<E> {
        compute_lagrange_basis_evals_at(&self.r)
    }

    /// Returns the evaluations of
    /// ((y_0, ..., y_{ν - 1}) ↦ EQ^{~}((r_0, ..., r_{ν - 1}), (y_0, ..., y_{ν - 1})))
    /// over {0 , 1}^ν.
    pub fn ml_at(evaluation_point: Vec<E>) -> MultiLinearPoly<E> {
        let eq_evals = EqFunction::new(evaluation_point.clone()).evaluations();
        MultiLinearPoly::from_evaluations(eq_evals)
            .expect("should not fail because evaluations is a power of two")
    }
}

// HELPER
// ================================================================================================

/// Computes the evaluations of the Lagrange basis polynomials over the interpolating
/// set {0 , 1}^ν at (r_0, ..., r_{ν - 1}) i.e., the Lagrange kernel at (r_0, ..., r_{ν - 1}).
fn compute_lagrange_basis_evals_at<E: FieldElement>(query: &[E]) -> Vec<E> {
    let nu = query.len();
    let n = 1 << nu;

    let mut evals: Vec<E> = vec![E::ONE; n];
    let mut size = 1;
    for r_i in query.iter().rev() {
        size *= 2;
        for i in (0..size).rev().step_by(2) {
            let scalar = evals[i / 2];
            evals[i] = scalar * *r_i;
            evals[i - 1] = scalar - evals[i];
        }
    }
    evals
}

/// Computes the inner product in the extension field of two iterators that must yield the same
/// number of items.
pub fn inner_product<E: FieldElement>(
    x: impl Iterator<Item = impl Into<E>>,
    y: impl Iterator<Item = impl Into<E>>,
) -> E {
    x.zip(y).fold(E::ZERO, |acc, (x_i, y_i)| acc + x_i.into() * y_i.into())
}
