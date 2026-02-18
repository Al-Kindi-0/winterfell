// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core_utils::uninit_vector;
use winterfell::{math::StarkField, matrix::ColMatrix, EvaluationFrame, Trace, TraceInfo};

use super::{AUX_TRACE_WIDTH, MAIN_TRACE_WIDTH, NUM_AUX_RANDS};

// MOCK TRACE TABLE
// ================================================================================================

pub struct Mock72TraceTable<B: StarkField> {
    info: TraceInfo,
    trace: ColMatrix<B>,
}

impl<B: StarkField> Mock72TraceTable<B> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new execution trace of the specified length.
    pub fn new(length: usize) -> Self {
        Self::with_meta(length, vec![])
    }

    /// Creates a new execution trace of the specified length with metadata.
    pub fn with_meta(length: usize, meta: Vec<u8>) -> Self {
        let info = TraceInfo::new_multi_segment(
            MAIN_TRACE_WIDTH,
            AUX_TRACE_WIDTH,
            NUM_AUX_RANDS,
            length,
            meta,
        );
        assert!(
            length.ilog2() <= B::TWO_ADICITY,
            "execution trace length cannot exceed 2^{} steps, but was 2^{}",
            B::TWO_ADICITY,
            length.ilog2()
        );

        let columns = unsafe { (0..MAIN_TRACE_WIDTH).map(|_| uninit_vector(length)).collect() };
        Self { info, trace: ColMatrix::new(columns) }
    }

    // DATA MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Fill all rows in the execution trace.
    pub fn fill<I, U>(&mut self, init: I, update: U)
    where
        I: Fn(&mut [B]),
        U: Fn(usize, &mut [B]),
    {
        let mut state = vec![B::ZERO; self.info.main_trace_width()];
        init(&mut state);
        self.update_row(0, &state);

        for i in 0..self.info.length() - 1 {
            update(i, &mut state);
            self.update_row(i + 1, &state);
        }
    }

    /// Updates a single row in the execution trace with provided data.
    pub fn update_row(&mut self, step: usize, state: &[B]) {
        self.trace.update_row(step, state);
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns value of the cell in the specified column at the specified row of this trace.
    pub fn get(&self, column: usize, step: usize) -> B {
        self.trace.get(column, step)
    }
}

// TRACE TRAIT IMPLEMENTATION
// ================================================================================================

impl<B: StarkField> Trace for Mock72TraceTable<B> {
    type BaseField = B;

    fn info(&self) -> &TraceInfo {
        &self.info
    }

    fn read_main_frame(&self, row_idx: usize, frame: &mut EvaluationFrame<Self::BaseField>) {
        let next_row_idx = (row_idx + 1) % self.info.length();
        self.trace.read_row_into(row_idx, frame.current_mut());
        self.trace.read_row_into(next_row_idx, frame.next_mut());
    }

    fn main_segment(&self) -> &ColMatrix<B> {
        &self.trace
    }
}
