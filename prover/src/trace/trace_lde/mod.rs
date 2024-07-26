// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use air::{proof::Queries, LagrangeKernelEvaluationFrame, TraceInfo};
use crypto::{ElementHasher, Hasher, VectorCommitment};

use super::{ColMatrix, EvaluationFrame, FieldElement, TracePolyTable};
use crate::StarkDomain;

mod default;
pub use default::DefaultTraceLde;

// TRACE LOW DEGREE EXTENSION
// ================================================================================================
/// Contains all segments of the extended execution trace and their commitments.
///
/// Segments are stored in two groups:
/// - Main segment: this is the first trace segment generated by the prover. Values in this segment
///   will always be elements in the base field (even when an extension field is used).
/// - Auxiliary segments: a list of 0 or more segments for traces generated after the prover
///   commits to the first trace segment. Currently, at most 1 auxiliary segment is possible.
pub trait TraceLde<E: FieldElement>: Sync {
    /// The hash function used for hashing the rows of trace segment LDEs.
    type HashFn: ElementHasher<BaseField = E::BaseField>;

    /// The vector commitment scheme used for commiting to the trace.
    type VC: VectorCommitment<Self::HashFn>;

    /// Returns the commitment to the low-degree extension of the main trace segment.
    fn get_main_trace_commitment(&self) -> <Self::HashFn as Hasher>::Digest;

    /// Takes auxiliary trace segment columns as input, interpolates them into polynomials in
    /// coefficient form, evaluates the polynomials over the LDE domain, and commits to the
    /// polynomial evaluations.
    ///
    /// Returns a tuple containing the column polynomials in coefficient form and the commitment
    /// to the polynomial evaluations over the LDE domain.
    ///
    /// # Panics
    ///
    /// This function is expected to panic if any of the following are true:
    /// - the number of rows in the provided `aux_trace` does not match the main trace.
    /// - this segment would exceed the number of segments specified by the trace layout.
    fn set_aux_trace(
        &mut self,
        aux_trace: &ColMatrix<E>,
        domain: &StarkDomain<E::BaseField>,
    ) -> (ColMatrix<E>, <Self::HashFn as Hasher>::Digest);

    /// Reads current and next rows from the main trace segment into the specified frame.
    fn read_main_trace_frame_into(
        &self,
        lde_step: usize,
        frame: &mut EvaluationFrame<E::BaseField>,
    );

    /// Reads current and next rows from the auxiliary trace segment into the specified frame.
    fn read_aux_trace_frame_into(&self, lde_step: usize, frame: &mut EvaluationFrame<E>);

    /// Populates the provided Lagrange kernel frame starting at the current row (as defined by
    /// `lde_step`).
    ///
    /// Note that unlike [`EvaluationFrame`], the Lagrange kernel frame includes only the Lagrange
    /// kernel column (as opposed to all columns).
    fn read_lagrange_kernel_frame_into(
        &self,
        lde_step: usize,
        col_idx: usize,
        frame: &mut LagrangeKernelEvaluationFrame<E>,
    );

    fn read_s_col(
        &self,
        lde_step: usize,
        col_idx: usize,
        frame: &mut EvaluationFrame<E>,
    );

    /// Returns trace table rows at the specified positions along with an opening proof to these
    /// rows.
    fn query(&self, positions: &[usize]) -> Vec<Queries>;

    /// Returns the number of rows in the execution trace.
    fn trace_len(&self) -> usize;

    /// Returns blowup factor which was used to extend original execution trace into trace LDE.
    fn blowup(&self) -> usize;

    /// Returns the trace info of the execution trace.
    fn trace_info(&self) -> &TraceInfo;
}
