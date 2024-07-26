use alloc::{string::ToString, vec::Vec};

use crypto::{ElementHasher, RandomCoin, RandomCoinError};
use math::FieldElement;
use utils::Deserializable;

use super::{lagrange::LagrangeKernelRandElements, LogUpGkrOracle};

/// Holds the randomly generated elements necessary to build the auxiliary trace.
///
/// Specifically, [`AuxRandElements`] currently supports 3 types of random elements:
/// - the ones needed to build the Lagrange kernel column (when using GKR to accelerate LogUp),
/// - the ones needed to build the "s" auxiliary column (when using GKR to accelerate LogUp),
/// - the ones needed to build all the other auxiliary columns
#[derive(Debug, Clone)]
pub struct AuxRandElements<E: FieldElement> {
    rand_elements: Vec<E>,
    gkr: Option<GkrRandElements<E>>,
}

impl<E> AuxRandElements<E> where E: FieldElement {
    /// Creates a new [`AuxRandElements`], where the auxiliary trace doesn't contain a Lagrange
    /// kernel column.
    pub fn new(rand_elements: Vec<E>) -> Self {
        Self { rand_elements, gkr: None}
    }

    /// Creates a new [`AuxRandElements`], where the auxiliary trace contains columns needed when
    /// using GKR to accelerate LogUp (i.e. a Lagrange kernel column and the "s" column).
    pub fn new_with_gkr(rand_elements: Vec<E>, gkr: GkrRandElements<E>) -> Self {
        Self { rand_elements, gkr: Some(gkr) }
    }

    /// Returns the random elements needed to build all columns other than the two GKR-related ones.
    pub fn rand_elements(&self) -> &[E] {
        &self.rand_elements
    }

    /// Returns the random elements needed to build the Lagrange kernel column.
    pub fn lagrange(&self) -> Option<&LagrangeKernelRandElements<E>> {
        self.gkr.as_ref().map(|gkr| &gkr.lagrange)
    }

    /// Returns the random values used to linearly combine the openings returned from the GKR proof.
    ///
    /// These correspond to the lambdas in our documentation.
    pub fn gkr_openings_combining_randomness(&self) -> Option<&[E]> {
        self.gkr.as_ref().map(|gkr| gkr.openings_combining_randomness.as_ref())
    }

    pub fn gkr_data(&self) -> Option<GkrRandElements<E>>{
        self.gkr.clone()
    }
}

/// Holds all the random elements needed when using GKR to accelerate LogUp.
///
/// This consists of two sets of random values:
/// 1. The Lagrange kernel random elements (expanded on in [`LagrangeKernelRandElements`]), and
/// 2. The "openings combining randomness".
///
/// After the verifying the LogUp-GKR circuit, the verifier is left with unproven claims provided
/// nondeterministically by the prover about the evaluations of the MLE of the main trace columns at
/// the Lagrange kernel random elements. Those claims are (linearly) combined into one using the
/// openings combining randomness.
#[derive(Clone, Debug)]
pub struct GkrRandElements<E: FieldElement> {
    pub lagrange: LagrangeKernelRandElements<E>,
    pub openings_combining_randomness: Vec<E>,
    pub openings: Vec<E>,
    pub oracles: Vec<LogUpGkrOracle<E::BaseField>>
}

impl<E: FieldElement> GkrRandElements<E> {
    /// Constructs a new [`GkrRandElements`] from [`LagrangeKernelRandElements`], and the openings
    /// combining randomness.
    ///
    /// See [`GkrRandElements`] for a more detailed description.
    pub fn new(
        lagrange: LagrangeKernelRandElements<E>,
        openings_combining_randomness: Vec<E>, openings: Vec<E>, oracles: Vec<LogUpGkrOracle<E::BaseField>>
    ) -> Self {
        Self { lagrange, openings_combining_randomness, openings: (openings), oracles: (oracles) }
    }

    /// Returns the random elements needed to build the Lagrange kernel column.
    pub fn lagrange_kernel_rand_elements(&self) -> &LagrangeKernelRandElements<E> {
        &self.lagrange
    }

    /// Returns the random values used to linearly combine the openings returned from the GKR proof.
    pub fn openings_combining_randomness(&self) -> &[E] {
        &self.openings_combining_randomness
    }

    pub fn openings(&self) -> &[E] {
        &self.openings
    }

    pub fn oracles(&self) -> &[LogUpGkrOracle<E::BaseField>]{
        &self.oracles
    }
}

/// A trait for verifying a GKR proof.
///
/// Specifically, the use case in mind is proving the constraints of a LogUp bus using GKR, as
/// described in [Improving logarithmic derivative lookups using
/// GKR](https://eprint.iacr.org/2023/1284.pdf).
pub trait GkrVerifier {
    /// The GKR proof.
    type GkrProof: Deserializable;
    /// The error that can occur during GKR proof verification.
    type Error: ToString;

    /// Verifies the GKR proof, and returns the random elements that were used in building
    /// the Lagrange kernel auxiliary column.
    fn verify<E, Hasher>(
        &self,
        gkr_proof: Self::GkrProof,
        public_coin: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> Result<GkrRandElements<E>, Self::Error>
    where
        E: FieldElement,
        Hasher: ElementHasher<BaseField = E::BaseField>;
}

impl GkrVerifier for () {
    type GkrProof = ();
    type Error = RandomCoinError;

    fn verify<E, Hasher>(
        &self,
        _gkr_proof: Self::GkrProof,
        _public_coin: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> Result<GkrRandElements<E>, Self::Error>
    where
        E: FieldElement,
        Hasher: ElementHasher<BaseField = E::BaseField>,
    {
        Ok(GkrRandElements::new(LagrangeKernelRandElements::default(), Vec::new(), Vec::new(), Vec::new()))
    }
}
