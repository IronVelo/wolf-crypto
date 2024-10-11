//! Key Derivation Functions

pub mod pbkdf2;

use crate::{can_cast_u32, const_can_cast_u32, to_u32};
use crate::sealed::AadSealed as Sealed;
use core::num::NonZeroU32;
use crate::error::InvalidIters;

non_fips! {
    mod hmac;
    pub use hmac::hkdf;
    pub use hmac::hkdf_into;
}

#[doc(inline)]
pub use crate::mac::hmac::algo::{
    InsecureKey,
    KeySlice,
    Sha224, Sha256, Sha384, Sha512,
    Sha3_224, Sha3_256, Sha3_384, Sha3_512
};

non_fips! {
    #[doc(inline)]
    pub use crate::mac::hmac::algo::{
        Sha, Md5
    };
}

/// The number of iterations for PBKDF.
///
/// The general rule is bigger is better (in terms of security), however, bigger is also more
/// computationally expensive.
///
/// `OWASP` recommends using at least 600,000 iterations with `SHA256` for passwords, a FIPS
/// requirement. [`NIST SP 800-132, Section 5.2`][1], back in 2010, recommends anywhere from 1,000
/// to 10,000,000 iterations (10,000,000 for critical secrets). **However** `SP 800-132` is under
/// [active revision][2], and the lower bound of 1,000 iterations is now considered inadequate for
/// modern security needs.
///
/// [1]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf#%5B%7B%22num%22%3A18%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C0%2C316%2Cnull%5D
/// [2]: https://csrc.nist.gov/News/2023/decision-to-revise-nist-sp-800-132
#[repr(transparent)]
pub struct Iters { count: NonZeroU32 }

impl Iters {
    /// Create a new `Iters` instance.
    ///
    /// # Arguments
    ///
    /// * `iters` - The desired number of iterations (must be non-zero).
    ///
    /// # Returns
    ///
    /// - `Some(Iters)`: The new `Iters` instance.
    /// - `None`: The provided `iters` argument was zero.
    pub const fn new(iters: u32) -> Option<Self> {
        match NonZeroU32::new(iters) {
            Some(count) => Some(Self { count }),
            None => None
        }
    }

    /// Create a new `Iters` instance without any safety checks.
    ///
    /// # Safety
    ///
    /// This will cause undefined behavior if the provided `iters` argument is `0`. Iters
    /// may only be constructed with non-zero values (as the underlying type is [`NonZeroU32`]).
    pub const unsafe fn new_unchecked(iters: u32) -> Self {
        Self { count: NonZeroU32::new_unchecked(iters) }
    }

    /// Returns the contained iteration count as a `u32`.
    #[inline]
    pub const fn get(&self) -> u32 {
        self.count.get()
    }
}

impl From<NonZeroU32> for Iters {
    #[inline]
    fn from(value: NonZeroU32) -> Self {
        Self { count: value }
    }
}

impl TryFrom<u32> for Iters {
    type Error = InvalidIters;

    /// Create a new `Iters` instance from a `u32`.
    ///
    /// # Errors
    ///
    /// If the number of iterations was zero.
    #[inline]
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(InvalidIters)
    }
}

impl TryFrom<usize> for Iters {
    type Error = InvalidIters;

    /// Create a new `Iters` instance from a `usize`.
    ///
    /// # Errors
    ///
    /// - If the number of iterations was zero.
    /// - If the number of iterations was greater than [`u32::MAX`].
    #[inline]
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        to_u32(value).and_then(Self::new).ok_or(InvalidIters)
    }
}

/// Represents a salt value used in key derivation functions (KDFs).
///
/// This trait is implemented by types that can serve as salt inputs for various KDFs, such as
/// `HKDF` (HMAC-based Key Derivation Function), `PBKDF1`, and `PBKDF2` (Password-Based Key
/// Derivation Function).
///
/// Salt is a critical component in KDFs, used to:
/// - Increase the complexity of the derived key
/// - Mitigate rainbow table attacks
/// - Ensure unique keys even when the same input is used multiple times
///
/// Of course, salts are optional, but strongly recommended. If you do not wish to use a salt
/// (which is not recommended), you may use the unit type (`()`).
pub trait Salt : Sealed {
    #[doc(hidden)]
    #[must_use]
    fn size(&self) -> u32;
    
    #[doc(hidden)]
    #[must_use]
    fn is_valid_size(&self) -> bool;
    
    #[doc(hidden)]
    #[must_use]
    fn ptr(&self) -> *const u8;
}

impl Salt for [u8] {
    #[inline]
    fn size(&self) -> u32 {
        debug_assert!(can_cast_u32(self.len()));
        self.len() as u32
    }

    #[inline]
    fn is_valid_size(&self) -> bool {
        can_cast_u32(self.len())
    }

    #[inline]
    fn ptr(&self) -> *const u8 {
        self.as_ptr()
    }
}

impl<const C: usize> Salt for [u8; C] {
    #[inline]
    fn size(&self) -> u32 {
        debug_assert!(const_can_cast_u32::<C>());
        self.len() as u32
    }

    #[inline]
    fn is_valid_size(&self) -> bool {
        const_can_cast_u32::<C>()
    }

    #[inline]
    fn ptr(&self) -> *const u8 {
        self.as_ptr()
    }
}

impl Salt for () {
    #[inline]
    fn size(&self) -> u32 {
        0
    }

    #[inline]
    fn is_valid_size(&self) -> bool {
        true
    }

    #[inline]
    fn ptr(&self) -> *const u8 {
        core::ptr::null()
    }
}

impl<T: Salt> Salt for &T {
    #[inline]
    fn size(&self) -> u32 {
        <T as Salt>::size(self)
    }

    #[inline]
    fn is_valid_size(&self) -> bool {
        <T as Salt>::is_valid_size(self)
    }

    #[inline]
    fn ptr(&self) -> *const u8 {
        <T as Salt>::ptr(self)
    }
}

impl<T: Salt> Salt for &mut T {
    #[inline]
    fn size(&self) -> u32 {
        <T as Salt>::size(self)
    }

    #[inline]
    fn is_valid_size(&self) -> bool {
        <T as Salt>::is_valid_size(self)
    }

    #[inline]
    fn ptr(&self) -> *const u8 {
        <T as Salt>::ptr(self)
    }
}

#[cfg(test)]
mod foolery {
    use core::mem;
    use super::*;

    #[test]
    fn foolery() {
        dbg!(mem::size_of::<Option<NonZeroU32>>());
        dbg!(mem::size_of::<Option<Iters>>());
        dbg!(mem::align_of::<Option<Iters>>());
        dbg!(mem::align_of::<Option<NonZeroU32>>());
    }
}