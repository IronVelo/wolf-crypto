//! Key Derivation Functions

use crate::{can_cast_u32, const_can_cast_u32};
use crate::sealed::AadSealed as Sealed;

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