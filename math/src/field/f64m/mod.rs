// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! An implementation of a 64-bit STARK-friendly prime field with modulus $2^{64} - 2^{32} + 1$.
//! This implementation is based on https://eprint.iacr.org/2022/274
//! All operations in this field are implemented using Montgomery arithmetic. It supports very
//! fast modular arithmetic including branchless multiplication and addition. Base elements are
//! stored in the Montgomery form using `u64` as the backing type.


use super::{ExtensibleField, FieldElement, StarkField};
use core::{
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display, Formatter},
    mem,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    slice,
};
use utils::{
    collections::Vec, string::ToString, AsBytes, ByteReader, ByteWriter, Deserializable,
    DeserializationError, Randomizable, Serializable,
};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Field modulus = 2^64 - 2^32 + 1
const M: u64 = 0xFFFFFFFF00000001;

/// 2^128 mod M; this is used for conversion of elements into Montgomery representation.
const R2: u64 = 0xFFFFFFFE00000001;

/// Number of bytes needed to represent field element
const ELEMENT_BYTES: usize = core::mem::size_of::<u64>();

// 2^31 root of unity
const G: u64 = 1753635133440165772;

// FIELD ELEMENT
// ================================================================================================

/// Represents base field element in the field.
///
/// Internal values are stored in Montgomery representation and can be in the range [0; 2M). The
/// backing type is `u64`.
#[derive(Copy, Clone, Debug, Default)]
pub struct BaseElement(u64);

impl BaseElement {
    /// Creates a new field element from the provided `value`; the value is converted into
    /// Montgomery representation.
    pub const fn new(value: u64) -> BaseElement {
        BaseElement(BaseElement::mont_red((value as u128) * (R2 as u128)))
    }
    /// Gets the inner value that might not be canonical

    pub const fn inner(self: &Self) -> u64 {
        return self.0;
    }

    /// Montgomery reduction
    pub const fn mont_red(x: u128) -> u64 {
        let xl = x as u64;
        let xh = (x >> 64) as u64;
        let (a, e) = xl.overflowing_add(xl << 32);

        let b = a.wrapping_sub(a >> 32).wrapping_sub(e as u64);

        let (r, c) = xh.overflowing_sub(b);
        r.wrapping_sub(0u32.wrapping_sub(c as u32) as u64)
    }

    /// Addition in BaseField
    #[inline(always)]
    const fn add(self, rhs: Self) -> Self {
        // We compute a + b = a - (p - b).
        let (x1, c1) = self.0.overflowing_sub(M - rhs.0);
        let adj = 0u32.wrapping_sub(c1 as u32);
        BaseElement(x1.wrapping_sub(adj as u64))
    }

    /// Subtraction in BaseField
    #[inline(always)]
    const fn sub(self, rhs: Self) -> Self {
        // See mont_red() for details on the subtraction.
        let (x1, c1) = self.0.overflowing_sub(rhs.0);
        let adj = 0u32.wrapping_sub(c1 as u32);
        BaseElement(x1.wrapping_sub(adj as u64))
    }

    /// Multiplication in BaseField
    #[inline(always)]
    const fn mul(self, rhs: Self) -> Self {
        // If x < p and y < p, then x*y <= (p-1)^2, and is thus in
        // range of mont_red().
        BaseElement(BaseElement::mont_red((self.0 as u128) * (rhs.0 as u128)))
    }

    /// Squaring in BaseField
    #[inline(always)]
    pub const fn square(self) -> Self {
        self.mul(self)
    }

    /// Multiple squarings in BaseField: return x^(2^n)
    pub fn msquare(self, n: u32) -> Self {
        let mut x = self;
        for _ in 0..n {
            x = x.square();
        }
        x
    }

    /// Test of equality between two BaseField elements; return value is
    /// 0xFFFFFFFFFFFFFFFF if the two values are equal, or 0 otherwise.
    #[inline(always)]
    pub const fn equals(self, rhs: Self) -> u64 {
        // Since internal representation is canonical, we can simply
        // do a xor between the two operands, and then use the same
        // expression as iszero().
        let t = self.0 ^ rhs.0;
        !((((t | t.wrapping_neg()) as i64) >> 63) as u64)
    }
}

impl FieldElement for BaseElement {
    type PositiveInteger = u64;
    type BaseField = Self;

    const ZERO: Self = BaseElement::new(0);
    const ONE: Self = BaseElement::new(1);

    const ELEMENT_BYTES: usize = ELEMENT_BYTES;
    const IS_CANONICAL: bool = false;

    fn exp(self, power: Self::PositiveInteger) -> Self {
        let mut b = self;

        if power == 0 {
            return Self::ONE;
        } else if b == Self::ZERO {
            return Self::ZERO;
        }

        let mut r = if power & 1 == 1 { b } else { Self::ONE };
        for i in 1..64 - power.leading_zeros() {
            b = b.square();
            if (power >> i) & 1 == 1 {
                r *= b;
            }
        }

        r
    }

    fn inv(self) -> Self {
        // This uses Fermat's little theorem: 1/x = x^(p-2) mod p.
        // We have p-2 = 0xFFFFFFFEFFFFFFFF. In the instructions below,
        // we call 'xj' the value x^(2^j-1).
        let x = self;
        let x2 = x * x.square();
        let x4 = x2 * x2.msquare(2);
        let x5 = x * x4.square();
        let x10 = x5 * x5.msquare(5);
        let x15 = x5 * x10.msquare(5);
        let x16 = x * x15.square();
        let x31 = x15 * x16.msquare(15);
        let x32 = x * x31.square();
        return x32 * x31.msquare(33);
    }

    fn conjugate(&self) -> Self {
        BaseElement(self.0)
    }

    fn elements_as_bytes(elements: &[Self]) -> &[u8] {
        // TODO: take endianness into account
        let p = elements.as_ptr();
        let len = elements.len() * Self::ELEMENT_BYTES;
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }

    unsafe fn bytes_as_elements(bytes: &[u8]) -> Result<&[Self], DeserializationError> {
        if bytes.len() % Self::ELEMENT_BYTES != 0 {
            return Err(DeserializationError::InvalidValue(format!(
                "number of bytes ({}) does not divide into whole number of field elements",
                bytes.len(),
            )));
        }

        let p = bytes.as_ptr();
        let len = bytes.len() / Self::ELEMENT_BYTES;

        if (p as usize) % mem::align_of::<u64>() != 0 {
            return Err(DeserializationError::InvalidValue(
                "slice memory alignment is not valid for this field element type".to_string(),
            ));
        }

        Ok(slice::from_raw_parts(p as *const Self, len))
    }

    fn zeroed_vector(n: usize) -> Vec<Self> {
        // this uses a specialized vector initialization code which requests zero-filled memory
        // from the OS; unfortunately, this works only for built-in types and we can't use
        // Self::ZERO here as much less efficient initialization procedure will be invoked.
        // We also use u64 to make sure the memory is aligned correctly for our element size.
        let result = vec![0u64; n];

        // translate a zero-filled vector of u64s into a vector of base field elements
        let mut v = core::mem::ManuallyDrop::new(result);
        let p = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();
        unsafe { Vec::from_raw_parts(p as *mut Self, len, cap) }
    }

    fn as_base_elements(elements: &[Self]) -> &[Self::BaseField] {
        elements
    }
}

impl StarkField for BaseElement {
    /// sage: MODULUS = 2^64 - 2^32 + 1 \
    /// sage: GF(MODULUS).is_prime_field() \
    /// True \
    /// sage: GF(MODULUS).order() \
    /// 18446744069414584321
    const MODULUS: Self::PositiveInteger = M;
    const MODULUS_BITS: u32 = 64;

    /// sage: GF(MODULUS).primitive_element() \
    /// 7
    const GENERATOR: Self = Self::new(7);

    /// sage: is_odd((MODULUS - 1) / 2^32) \
    /// True
    const TWO_ADICITY: u32 = 32;

    /// sage: k = (MODULUS - 1) / 2^32 \
    /// sage: GF(MODULUS).primitive_element()^k \
    /// 1753635133440165772
    const TWO_ADIC_ROOT_OF_UNITY: Self = Self::new(G);

    fn get_modulus_le_bytes() -> Vec<u8> {
        Self::MODULUS.to_le_bytes().to_vec()
    }

    #[inline]
    fn as_int(&self) -> Self::PositiveInteger {
        BaseElement::mont_red(self.0 as u128)
    }
}

impl Randomizable for BaseElement {
    const VALUE_SIZE: usize = Self::ELEMENT_BYTES;

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        Self::try_from(bytes).ok()
    }
}

impl Display for BaseElement {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{}", self.as_int())
    }
}

// EQUALITY CHECKS
// ================================================================================================

impl PartialEq for BaseElement {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        Self::equals(*self, *other) == 0xFFFFFFFFFFFFFFFF
    }
}

impl Eq for BaseElement {}

// OVERLOADED OPERATORS
// ================================================================================================

impl Add for BaseElement {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self::add(self, rhs)
    }
}

impl AddAssign for BaseElement {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl Sub for BaseElement {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self::sub(self, rhs)
    }
}

impl SubAssign for BaseElement {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for BaseElement {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self::mul(self, rhs)
    }
}

impl MulAssign for BaseElement {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs
    }
}

impl Div for BaseElement {
    type Output = Self;

    fn div(self, rhs: Self) -> Self {
        Self::mul(self, Self::inv(rhs))
    }
}

impl DivAssign for BaseElement {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs
    }
}

impl Neg for BaseElement {
    type Output = Self;

    fn neg(self) -> Self {
        Self::sub(BaseElement::ZERO, self)
    }
}

// QUADRATIC EXTENSION
// ================================================================================================

/// Defines a quadratic extension of the base field over an irreducible polynomial x<sup>2</sup> -
/// x + 2. Thus, an extension element is defined as α + β * φ, where φ is a root of this polynomial,
/// and α and β are base field elements.
impl ExtensibleField<2> for BaseElement {
    #[inline(always)]
    fn mul(a: [Self; 2], b: [Self; 2]) -> [Self; 2] {
        // performs multiplication in the extension field using 3 multiplications, 3 additions,
        // and 2 subtractions in the base field. overall, a single multiplication in the extension
        // field is slightly faster than 5 multiplications in the base field.
        let a0b0 = a[0] * b[0];
        [
            a0b0 - (a[1] * b[1]).double(),
            (a[0] + a[1]) * (b[0] + b[1]) - a0b0,
        ]
    }

    #[inline(always)]
    fn mul_base(a: [Self; 2], b: Self) -> [Self; 2] {
        // multiplying an extension field element by a base field element requires just 2
        // multiplications in the base field.
        [a[0] * b, a[1] * b]
    }

    #[inline(always)]
    fn frobenius(x: [Self; 2]) -> [Self; 2] {
        [x[0] + x[1], -x[1]]
    }
}

// CUBIC EXTENSION
// ================================================================================================

/// Defines a cubic extension of the base field over an irreducible polynomial x<sup>3</sup> -
/// x - 1. Thus, an extension element is defined as α + β * φ + γ * φ^2, where φ is a root of this
/// polynomial, and α, β and γ are base field elements.
impl ExtensibleField<3> for BaseElement {
    #[inline(always)]
    fn mul(a: [Self; 3], b: [Self; 3]) -> [Self; 3] {
        // performs multiplication in the extension field using 6 multiplications, 9 additions,
        // and 4 subtractions in the base field. overall, a single multiplication in the extension
        // field is roughly equal to 12 multiplications in the base field.
        let a0b0 = a[0] * b[0];
        let a1b1 = a[1] * b[1];
        let a2b2 = a[2] * b[2];

        let a0b0_a0b1_a1b0_a1b1 = (a[0] + a[1]) * (b[0] + b[1]);
        let a0b0_a0b2_a2b0_a2b2 = (a[0] + a[2]) * (b[0] + b[2]);
        let a1b1_a1b2_a2b1_a2b2 = (a[1] + a[2]) * (b[1] + b[2]);

        let a0b0_minus_a1b1 = a0b0 - a1b1;

        let a0b0_a1b2_a2b1 = a1b1_a1b2_a2b1_a2b2 + a0b0_minus_a1b1 - a2b2;
        let a0b1_a1b0_a1b2_a2b1_a2b2 =
            a0b0_a0b1_a1b0_a1b1 + a1b1_a1b2_a2b1_a2b2 - a1b1.double() - a0b0;
        let a0b2_a1b1_a2b0_a2b2 = a0b0_a0b2_a2b0_a2b2 - a0b0_minus_a1b1;

        [
            a0b0_a1b2_a2b1,
            a0b1_a1b0_a1b2_a2b1_a2b2,
            a0b2_a1b1_a2b0_a2b2,
        ]
    }

    #[inline(always)]
    fn mul_base(a: [Self; 3], b: Self) -> [Self; 3] {
        // multiplying an extension field element by a base field element requires just 3
        // multiplications in the base field.
        [a[0] * b, a[1] * b, a[2] * b]
    }

    #[inline(always)]
    fn frobenius(x: [Self; 3]) -> [Self; 3] {
        // coefficients were computed using SageMath
        [
            x[0] + BaseElement::new(10615703402128488253) * x[1]
                + BaseElement::new(6700183068485440220) * x[2],
            BaseElement::new(10050274602728160328) * x[1]
                + BaseElement::new(14531223735771536287) * x[2],
            BaseElement::new(11746561000929144102) * x[1]
                + BaseElement::new(8396469466686423992) * x[2],
        ]
    }
}

// TYPE CONVERSIONS
// ================================================================================================

impl From<u128> for BaseElement {
    /// Converts a 128-bit value into a field element. If the value is greater than or equal to
    /// the field modulus, modular reduction is silently performed.
    fn from(x: u128) -> Self {
        //const R3: u128 = 1 (= 2^192 mod M );// this we get that mont_reduce((mont_reduce(x) as u128) * R3) becomes
        BaseElement(mont_reduce(mont_reduce(x) as u128))
        //BaseElement(Self::mont_red(Self::mont_red(x) as u128))
    }
}

impl From<u64> for BaseElement {
    /// Converts a 64-bit value into a field element. If the value is greater than or equal to
    /// the field modulus, modular reduction is silently performed.
    fn from(value: u64) -> Self {
        BaseElement::new(value)
    }
}

impl From<u32> for BaseElement {
    /// Converts a 32-bit value into a field element.
    fn from(value: u32) -> Self {
        BaseElement::new(value as u64)
    }
}

impl From<u16> for BaseElement {
    /// Converts a 16-bit value into a field element.
    fn from(value: u16) -> Self {
        BaseElement::new(value as u64)
    }
}

impl From<u8> for BaseElement {
    /// Converts an 8-bit value into a field element.
    fn from(value: u8) -> Self {
        BaseElement::new(value as u64)
    }
}

impl From<[u8; 8]> for BaseElement {
    /// Converts the value encoded in an array of 8 bytes into a field element. The bytes are
    /// assumed to encode the element in the canonical representation in little-endian byte order.
    /// If the value is greater than or equal to the field modulus, modular reduction is silently
    /// performed.
    fn from(bytes: [u8; 8]) -> Self {
        let value = u64::from_le_bytes(bytes);
        BaseElement::new(value)
    }
}

impl<'a> TryFrom<&'a [u8]> for BaseElement {
    type Error = DeserializationError;

    /// Converts a slice of bytes into a field element; returns error if the value encoded in bytes
    /// is not a valid field element. The bytes are assumed to encode the element in the canonical
    /// representation in little-endian byte order.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < ELEMENT_BYTES {
            return Err(DeserializationError::InvalidValue(format!(
                "not enough bytes for a full field element; expected {} bytes, but was {} bytes",
                ELEMENT_BYTES,
                bytes.len(),
            )));
        }
        if bytes.len() > ELEMENT_BYTES {
            return Err(DeserializationError::InvalidValue(format!(
                "too many bytes for a field element; expected {} bytes, but was {} bytes",
                ELEMENT_BYTES,
                bytes.len(),
            )));
        }
        let value = bytes
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|error| DeserializationError::UnknownError(format!("{}", error)))?;
        if value >= M {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid field element: value {} is greater than or equal to the field modulus",
                value
            )));
        }
        Ok(BaseElement::new(value))
    }
}

impl AsBytes for BaseElement {
    fn as_bytes(&self) -> &[u8] {
        // TODO: take endianness into account
        let self_ptr: *const BaseElement = self;
        unsafe { slice::from_raw_parts(self_ptr as *const u8, ELEMENT_BYTES) }
    }
}

// SERIALIZATION / DESERIALIZATION
// ------------------------------------------------------------------------------------------------

impl Serializable for BaseElement {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // convert from Montgomery representation into canonical representation
        target.write_u8_slice(&self.as_int().to_le_bytes());
    }
}

impl Deserializable for BaseElement {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let value = source.read_u64()?;
        if value >= M {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid field element: value {} is greater than or equal to the field modulus",
                value
            )));
        }
        Ok(BaseElement::new(value))
    }
}

pub fn mont_reduce(x: u128) -> u64 {
    const NPRIME: u64 = 4294967297;
    let q = (((x as u64) as u128) * (NPRIME as u128)) as u64;
    let m = (q as u128) * (M as u128);
    let y = (((x as i128).wrapping_sub(m as i128)) >> 64) as i64;
    if x < m {
        return (y + (M as i64)) as u64;
    } else {
        return y as u64;
    };
}
