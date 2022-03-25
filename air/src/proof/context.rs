// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    air::{TraceWidthInfo, NUM_TRACE_SEGMENTS},
    ProofOptions, TraceInfo,
};
use math::StarkField;
use utils::{
    collections::Vec, string::ToString, ByteReader, ByteWriter, Deserializable,
    DeserializationError, Serializable,
};

// PROOF CONTEXT
// ================================================================================================
/// Basic metadata about a specific execution of a computation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Context {
    trace_segment_widths: TraceWidthInfo,
    trace_length: usize,
    trace_meta: Vec<u8>,
    field_modulus_bytes: Vec<u8>,
    options: ProofOptions,
}

impl Context {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates a new context for a computation described by the specified field, trace info, and
    /// proof options.
    pub fn new<B: StarkField>(trace_info: &TraceInfo, options: ProofOptions) -> Self {
        Context {
            trace_segment_widths: trace_info.segment_widths(),
            trace_length: trace_info.length(),
            trace_meta: trace_info.meta().to_vec(),
            field_modulus_bytes: B::get_modulus_le_bytes(),
            options,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns execution trace length of the computation described by this context.
    pub fn trace_length(&self) -> usize {
        self.trace_length
    }

    /// Returns the full width of the execution trace of the computation described by this
    /// context.
    ///
    /// The full width is a sum of all trace segment widths.
    pub fn trace_full_width(&self) -> usize {
        self.trace_segment_widths.iter().sum()
    }

    /// Returns widths of all execution trace segments of a computation described by this context.
    pub fn trace_segment_widths(&self) -> TraceWidthInfo {
        self.trace_segment_widths
    }

    /// Returns execution trace info for the computation described by this context.
    pub fn get_trace_info(&self) -> TraceInfo {
        TraceInfo::new_multi_segment(
            self.trace_segment_widths,
            self.trace_length(),
            self.trace_meta.clone(),
        )
    }

    /// Returns the size of the LDE domain for the computation described by this context.
    pub fn lde_domain_size(&self) -> usize {
        self.trace_length() * self.options.blowup_factor()
    }

    /// Returns modulus of the field for the computation described by this context.
    pub fn field_modulus_bytes(&self) -> &[u8] {
        &self.field_modulus_bytes
    }

    /// Returns number of bits in the base field modulus for the computation described by this
    /// context.
    ///
    /// The modulus is assumed to be encoded in little-endian byte order.
    pub fn num_modulus_bits(&self) -> u32 {
        let mut num_bits = self.field_modulus_bytes.len() as u32 * 8;
        for &byte in self.field_modulus_bytes.iter().rev() {
            if byte != 0 {
                num_bits -= byte.leading_zeros();
                return num_bits;
            }
            num_bits -= 8;
        }

        0
    }

    /// Returns proof options which were used to a proof in this context.
    pub fn options(&self) -> &ProofOptions {
        &self.options
    }
}

impl Serializable for Context {
    /// Serializes `self` and writes the resulting bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        for &w in self.trace_segment_widths.iter() {
            debug_assert!(w <= u8::MAX as usize, "width does not fit into u8 value");
            target.write_u8(w as u8);
        }
        target.write_u8(math::log2(self.trace_length) as u8); // store as power of two
        target.write_u16(self.trace_meta.len() as u16);
        target.write_u8_slice(&self.trace_meta);
        assert!(self.field_modulus_bytes.len() < u8::MAX as usize);
        target.write_u8(self.field_modulus_bytes.len() as u8);
        target.write_u8_slice(&self.field_modulus_bytes);
        self.options.write_into(target);
    }
}

impl Deserializable for Context {
    /// Reads proof context from the specified `source` and returns the result.
    ///
    /// # Errors
    /// Returns an error of a valid Context struct could not be read from the specified `source`.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // read and validate trace segment widths
        let mut trace_segment_widths = [0; NUM_TRACE_SEGMENTS];
        for width in trace_segment_widths.iter_mut() {
            *width = source.read_u8()? as usize;
        }

        if trace_segment_widths[0] == 0 {
            return Err(DeserializationError::InvalidValue(
                "main trace segment width must be greater than zero".to_string(),
            ));
        }

        let full_trace_width: usize = trace_segment_widths.iter().sum();
        if full_trace_width >= TraceInfo::MAX_TRACE_WIDTH {
            return Err(DeserializationError::InvalidValue(format!(
                "full trace width cannot be greater than {}, but was {}",
                TraceInfo::MAX_TRACE_WIDTH,
                full_trace_width
            )));
        }

        // read and validate trace length (which was stored as a power of two)
        let trace_length = source.read_u8()?;
        if trace_length < math::log2(TraceInfo::MIN_TRACE_LENGTH) as u8 {
            return Err(DeserializationError::InvalidValue(format!(
                "trace length cannot be smaller than 2^{}, but was 2^{}",
                math::log2(TraceInfo::MIN_TRACE_LENGTH),
                trace_length
            )));
        }
        let trace_length = 2_usize.pow(trace_length as u32);

        // read trace metadata
        let num_meta_bytes = source.read_u16()? as usize;
        let trace_meta = if num_meta_bytes != 0 {
            source.read_u8_vec(num_meta_bytes)?
        } else {
            vec![]
        };

        // read and validate field modulus bytes
        let num_modulus_bytes = source.read_u8()? as usize;
        if num_modulus_bytes == 0 {
            return Err(DeserializationError::InvalidValue(
                "field modulus cannot be an empty value".to_string(),
            ));
        }
        let field_modulus_bytes = source.read_u8_vec(num_modulus_bytes)?;

        // read options
        let options = ProofOptions::read_from(source)?;

        Ok(Context {
            trace_segment_widths,
            trace_length,
            trace_meta,
            field_modulus_bytes,
            options,
        })
    }
}
