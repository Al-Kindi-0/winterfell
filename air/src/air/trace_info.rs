// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::TraceWidthInfo;
use utils::collections::Vec;

// TRACE INFO
// ================================================================================================
/// Information about a specific execution trace.
///
/// Trace info consists of trace width, length, and optional custom metadata. Metadata is just a
/// vector of bytes and can store any values up to 64KB in size.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TraceInfo {
    segment_widths: TraceWidthInfo,
    length: usize,
    meta: Vec<u8>,
}

impl TraceInfo {
    /// Smallest allowed execution trace length; currently set at 8.
    pub const MIN_TRACE_LENGTH: usize = 8;
    /// Maximum number of registers in an execution trace; currently set at 255.
    pub const MAX_TRACE_WIDTH: usize = 255;
    /// Maximum number of bytes in trace metadata; currently set at 65535.
    pub const MAX_META_LENGTH: usize = 65535;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [TraceInfo] from the specified trace width and length.
    ///
    /// An execution trace described by this trace info is limited to a single segment.
    ///
    /// # Panics
    /// Panics if:
    /// * Trace width is zero or greater than 255.
    /// * Trace length is smaller than 8 or is not a power of two.
    pub fn new(width: usize, length: usize) -> Self {
        Self::with_meta(width, length, vec![])
    }

    /// Creates a new [TraceInfo] from the specified trace width, length, and metadata.
    ///
    /// An execution trace described by this trace info is limited to a single segment.
    ///
    /// # Panics
    /// Panics if:
    /// * Trace width is zero or greater than 255.
    /// * Trace length is smaller than 8 or is not a power of two.
    /// * Length of `meta` is greater than 65535;
    pub fn with_meta(width: usize, length: usize, meta: Vec<u8>) -> Self {
        assert!(width > 0, "trace width must be greater than 0");
        Self::new_multi_segment([width, 0], length, meta)
    }

    /// Creates a new [TraceInfo] from the specified trace segment widths, length, and metadata.
    ///
    /// # Panics
    /// Panics if:
    /// * The width of the first trace segment is zero.
    /// * Total width of all trace segments is greater than 255.
    /// * Trace length is smaller than 8 or is not a power of two.
    pub fn new_multi_segment(segment_widths: TraceWidthInfo, length: usize, meta: Vec<u8>) -> Self {
        assert!(
            segment_widths[0] > 0,
            "main trace segment must consist of at least one column"
        );
        let full_width: usize = segment_widths.iter().sum();
        assert!(
            full_width <= Self::MAX_TRACE_WIDTH,
            "total number of columns in the trace cannot be greater than {}, but was {}",
            Self::MAX_TRACE_WIDTH,
            full_width
        );
        assert!(
            length >= Self::MIN_TRACE_LENGTH,
            "trace length must be at least {}, but was {}",
            Self::MIN_TRACE_LENGTH,
            length
        );
        assert!(
            length.is_power_of_two(),
            "trace length must be a power of two, but was {}",
            length
        );
        assert!(
            meta.len() <= Self::MAX_META_LENGTH,
            "number of metadata bytes cannot be greater than {}, but was {}",
            Self::MAX_META_LENGTH,
            meta.len()
        );
        TraceInfo {
            segment_widths,
            length,
            meta,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the total number of columns in the execution trace.
    ///
    /// This is guaranteed to be between 1 and 255.
    pub fn full_width(&self) -> usize {
        self.segment_widths.iter().sum()
    }

    /// Returns the number of columns for all trace segments.
    ///
    /// Currently, the number of segments is limited to two. The first segment width is guaranteed
    /// to be greater than zero.
    pub fn segment_widths(&self) -> TraceWidthInfo {
        self.segment_widths
    }

    /// Returns execution trace length.
    ///
    /// The length is guaranteed to be a power of two.
    pub fn length(&self) -> usize {
        self.length
    }

    /// Returns execution trace metadata.
    pub fn meta(&self) -> &[u8] {
        &self.meta
    }
}
