use alloc::vec::Vec;
use core::ops::Add;

use math::{
    polynom::{MultiLinearPoly, UnivariatePolyCoef},
    FieldElement,
};
use utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

mod composition_polynomials;
pub use composition_polynomials::*;

// GKR CIRCUIT PROOF
// ===============================================================================================

/// A GKR proof for the correct evaluation of the sum of fractions circuit.
#[derive(Debug, Clone)]
pub struct GkrCircuitProof<E: FieldElement> {
    pub circuit_outputs: CircuitLayerPolys<E>,
    pub before_final_layer_proofs: BeforeFinalLayerProof<E>,
    pub final_layer_proof: FinalLayerProof<E>,
}

impl<E: FieldElement> GkrCircuitProof<E> {
    pub fn get_final_opening_claim(&self) -> FinalOpeningClaim<E> {
        self.final_layer_proof.after_merge_proof.openings_claim.clone()
    }
}

impl<E> Serializable for GkrCircuitProof<E>
where
    E: FieldElement,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.circuit_outputs.write_into(target);
        self.before_final_layer_proofs.write_into(target);
        self.final_layer_proof.write_into(target);
    }
}

impl<E> Deserializable for GkrCircuitProof<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            circuit_outputs: CircuitLayerPolys::read_from(source)?,
            before_final_layer_proofs: BeforeFinalLayerProof::read_from(source)?,
            final_layer_proof: FinalLayerProof::read_from(source)?,
        })
    }
}

/// A set of sum-check proofs for all GKR layers but for the input circuit layer.
#[derive(Debug, Clone)]
pub struct BeforeFinalLayerProof<E: FieldElement> {
    pub proof: Vec<SumCheckProof<E>>,
}

impl<E> Serializable for BeforeFinalLayerProof<E>
where
    E: FieldElement,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { proof } = self;
        proof.write_into(target);
    }
}

impl<E> Deserializable for BeforeFinalLayerProof<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            proof: Deserializable::read_from(source)?,
        })
    }
}

/// A proof for the input circuit layer i.e., the final layer in the GKR protocol.
#[derive(Debug, Clone)]
pub struct FinalLayerProof<E: FieldElement> {
    pub before_merge_proof: Vec<RoundProof<E>>,
    pub after_merge_proof: SumCheckProof<E>,
}

impl<E> Serializable for FinalLayerProof<E>
where
    E: FieldElement,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { before_merge_proof, after_merge_proof } = self;
        before_merge_proof.write_into(target);
        after_merge_proof.write_into(target);
    }
}

impl<E> Deserializable for FinalLayerProof<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            before_merge_proof: Deserializable::read_from(source)?,
            after_merge_proof: Deserializable::read_from(source)?,
        })
    }
}

// CIRCUIT LAYER POLYS
// ===============================================================================================

/// Holds a layer of an [`EvaluatedCircuit`] in a representation amenable to proving circuit
/// evaluation using GKR.
#[derive(Clone, Debug)]
pub struct CircuitLayerPolys<E: FieldElement> {
    pub numerators: MultiLinearPoly<E>,
    pub denominators: MultiLinearPoly<E>,
}

impl<E> CircuitLayerPolys<E>
where
    E: FieldElement,
{
    pub fn from_circuit_layer(layer: CircuitLayer<E>) -> Self {
        Self::from_wires(layer.wires)
    }

    pub fn from_wires(wires: Vec<CircuitWire<E>>) -> Self {
        let mut numerators = Vec::new();
        let mut denominators = Vec::new();

        for wire in wires {
            numerators.push(wire.numerator);
            denominators.push(wire.denominator);
        }

        Self {
            numerators: MultiLinearPoly::from_evaluations(numerators)
                .expect("evaluations guaranteed to be a power of two"),
            denominators: MultiLinearPoly::from_evaluations(denominators)
                .expect("evaluations guaranteed to be a power of two"),
        }
    }
}

impl<E> Serializable for CircuitLayerPolys<E>
where
    E: FieldElement,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { numerators, denominators } = self;
        numerators.write_into(target);
        denominators.write_into(target);
    }
}

impl<E> Deserializable for CircuitLayerPolys<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            numerators: MultiLinearPoly::read_from(source)?,
            denominators: MultiLinearPoly::read_from(source)?,
        })
    }
}

// CIRCUIT LAYER
// ===============================================================================================

/// Represents a layer in a [`EvaluatedCircuit`].
///
/// A layer is made up of a set of `n` wires, where `n` is a power of two. This is the natural
/// circuit representation of a layer, where each consecutive pair of wires are summed to yield a
/// wire in the subsequent layer of an [`EvaluatedCircuit`].
///
/// Note that a [`Layer`] needs to be first converted to a [`LayerPolys`] before the evaluation of
/// the layer can be proved using GKR.
pub struct CircuitLayer<E: FieldElement> {
    wires: Vec<CircuitWire<E>>,
}

impl<E: FieldElement> CircuitLayer<E> {
    /// Creates a new [`Layer`] from a set of projective coordinates.
    ///
    /// Panics if the number of projective coordinates is not a power of two.
    pub fn new(wires: Vec<CircuitWire<E>>) -> Self {
        assert!(wires.len().is_power_of_two());

        Self { wires }
    }

    /// Returns the wires that make up this circuit layer.
    pub fn wires(&self) -> &[CircuitWire<E>] {
        &self.wires
    }

    /// Returns the number of wires in the layer.
    pub fn num_wires(&self) -> usize {
        self.wires.len()
    }
}

// CIRCUIT WIRE
// ===============================================================================================

/// Represents a fraction `numerator / denominator` as a pair `(numerator, denominator)`. This is
/// the type for the gates' inputs in [`prover::EvaluatedCircuit`].
///
/// Hence, addition is defined in the natural way fractions are added together: `a/b + c/d = (ad +
/// bc) / bd`.
#[derive(Debug, Clone, Copy)]
pub struct CircuitWire<E: FieldElement> {
    numerator: E,
    denominator: E,
}

impl<E> CircuitWire<E>
where
    E: FieldElement,
{
    /// Creates new projective coordinates from a numerator and a denominator.
    pub fn new(numerator: E, denominator: E) -> Self {
        assert_ne!(denominator, E::ZERO);

        Self { numerator, denominator }
    }
}

impl<E> Add for CircuitWire<E>
where
    E: FieldElement,
{
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let numerator = self.numerator * other.denominator + other.numerator * self.denominator;
        let denominator = self.denominator * other.denominator;

        Self::new(numerator, denominator)
    }
}

// SUM-CHECK
// ===============================================================================================

/// Represents an opening claim at an evaluation point against a batch of oracles.
///
/// After verifying [`Proof`], the verifier is left with a question on the validity of a final
/// claim on a number of oracles open to a given set of values at some given point.
/// This question is answered either using further interaction with the Prover or using
/// a polynomial commitment opening proof in the compiled protocol.
#[derive(Clone, Debug)]
pub struct FinalOpeningClaim<E> {
    pub eval_point: Vec<E>,
    pub openings: Vec<E>,
}

impl<E: FieldElement> Serializable for FinalOpeningClaim<E> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { eval_point, openings } = self;
        eval_point.write_into(target);
        openings.write_into(target);
    }
}

impl<E> Deserializable for FinalOpeningClaim<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            eval_point: Deserializable::read_from(source)?,
            openings: Deserializable::read_from(source)?,
        })
    }
}

/// A sum-check proof.
///
/// Composed of the round proofs i.e., the polynomials sent by the Prover at each round as well as
/// the (claimed) openings of the multi-linear oracles at the evaluation point given by the round
/// challenges.
#[derive(Debug, Clone)]
pub struct SumCheckProof<E: FieldElement> {
    pub openings_claim: FinalOpeningClaim<E>,
    pub round_proofs: Vec<RoundProof<E>>,
}

/// A sum-check round proof.
///
/// This represents the partial polynomial sent by the Prover during one of the rounds of the
/// sum-check protocol. The polynomial is in coefficient form and excludes the coefficient for
/// the linear term as the Verifier can recover it from the other coefficients and the current
/// (reduced) claim.
#[derive(Debug, Clone)]
pub struct RoundProof<E: FieldElement> {
    pub round_poly_coefs: UnivariatePolyCoef<E>,
}

impl<E: FieldElement> Serializable for RoundProof<E> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { round_poly_coefs } = self;
        round_poly_coefs.write_into(target);
    }
}

impl<E> Deserializable for RoundProof<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            round_poly_coefs: Deserializable::read_from(source)?,
        })
    }
}

impl<E> Serializable for SumCheckProof<E>
where
    E: FieldElement,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.openings_claim.write_into(target);
        self.round_proofs.write_into(target);
    }
}

impl<E> Deserializable for SumCheckProof<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            openings_claim: Deserializable::read_from(source)?,
            round_proofs: Deserializable::read_from(source)?,
        })
    }
}

/// Contains the round challenges sent by the Verifier up to some round as well as the current
/// reduced claim.
#[derive(Debug)]
pub struct SumCheckRoundClaim<E: FieldElement> {
    pub eval_point: Vec<E>,
    pub claim: E,
}
