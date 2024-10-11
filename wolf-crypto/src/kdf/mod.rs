//! Key Derivation Functions

pub mod pbkdf2;

use crate::{can_cast_i32, can_cast_u32, const_can_cast_i32, const_can_cast_u32, to_u32};
use crate::sealed::AadSealed as Sealed;
use core::num::NonZeroU32;
use core::marker::PhantomData;
use core::convert::Infallible;
use crate::buf::InvalidSize;
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
    /// # Note
    ///
    /// Please see the [`Iters`] type documentation for more information and sources to assist in
    /// picking the correct value. The value is context dependent, are you hashing a password?
    /// You'll need a very large value, minimum 600,000. For key derivation, again it is context
    /// dependent, how critical is this key? How powerful is the host machine? The general rule
    /// is the bigger the value, the better in terms of security.
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
        // Cool optimization rustc:
        //
        // define noundef i32 @new(i32 noundef returned %iters) unnamed_addr #0 {
        // start:
        //   ret i32 %iters
        // }
        //
        // This is practically a no-op due to NPO.
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

    /// Returns `true` if the iteration count can safely be cast to an `i32`.
    ///
    /// Certain KDFs (such as the PBKDF family) take the iteration count as an `i32`, and check
    /// at runtime if the iteration count is greater than 0. This most likely is an older design
    /// choice which they must keep for stability reasons.
    ///
    /// For ergonomic reasons, we will represent the iteration count as an unsigned int.
    pub const fn is_valid_size(&self) -> bool {
        self.get() <= i32::MAX as u32
    }

    /// Returns the contained iteration count as a `u32`.
    #[inline]
    #[must_use]
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

pub mod salt {
    //! Salt requirement marker types.
    use super::{InvalidSize, Infallible};

    /// Represents the minimum size for the [`Salt`].
    ///
    /// [`Salt`]: super::Salt
    pub trait MinSize : super::Sealed {
        /// The associated error type for creating a [`SaltSlice`] with this constraint.
        ///
        /// [`SaltSlice`]: super::SaltSlice
        type CreateError;

        /// Returns the minimum size for the [`Salt`].
        ///
        /// [`Salt`]: super::Salt
        fn min_size() -> u32;
    }

    macro_rules! def_sz {
        ($(
            $(#[$meta:meta])*
            $name:ident => $sz:literal => $err:ident
        ),* $(,)?) => {
            $(
                $(#[$meta])*
                pub struct $name;

                impl super::Sealed for $name {}
                impl MinSize for $name {
                    type CreateError = $err;

                    #[inline]
                    fn min_size() -> u32 {
                        $sz
                    }
                }
            )*
        };
    }

    def_sz! {
        /// Indicates that the [`Salt`] may be empty / optional.
        ///
        /// [`Salt`]: super::Salt
        Empty => 0 => Infallible,
        /// Indicates that the [`Salt`] **must** not be empty.
        ///
        /// [`Salt`]: super::Salt
        NonEmpty => 1 => InvalidSize,
        /// Indicates that the [`Salt`] **must** be at least 128 bits (16 bytes).
        ///
        /// [`Salt`]: super::Salt
        Min16 => 16 => InvalidSize
    }
}

/// Represents a salt value used in key derivation functions (KDFs).
///
/// This is only implemented for `HKDF`, as other KDFs require salts (such as the `PBKDF`
/// family), and for FIPS compliance, as per [NIST SP 800-132, Section 5.1, The Salt (S)][1]
/// this salt must be at least 128 bits from a valid CSPRNG.
///
/// Salt is a critical component in KDFs, used to:
/// - Increase the complexity of the derived key
/// - Mitigate rainbow table attacks
/// - Ensure unique keys even when the same input is used multiple times
///
/// Salts may be optional, this depends on the `MinSz` type.
///
/// [1]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf#%5B%7B%22num%22%3A18%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C0%2C475%2Cnull%5D
pub trait Salt<SZ: salt::MinSize>: Sealed {
    #[doc(hidden)]
    #[must_use]
    fn size(&self) -> u32;

    #[doc(hidden)]
    #[must_use]
    fn is_valid_size(&self) -> bool;

    #[doc(hidden)]
    #[must_use]
    fn i_size(&self) -> i32;

    #[doc(hidden)]
    #[must_use]
    fn i_is_valid_size(&self) -> bool;

    #[doc(hidden)]
    #[must_use]
    fn ptr(&self) -> *const u8;
}

impl Salt<salt::Empty> for [u8] {
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
    fn i_size(&self) -> i32 {
        debug_assert!(can_cast_i32(self.len()));
        self.len() as i32
    }

    #[inline]
    fn i_is_valid_size(&self) -> bool {
        can_cast_i32(self.len())
    }

    #[inline]
    fn ptr(&self) -> *const u8 {
        self.as_ptr()
    }
}

impl<const C: usize> Salt<salt::Empty> for [u8; C] {
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
    fn i_size(&self) -> i32 {
        debug_assert!(const_can_cast_i32::<C>());
        C as i32
    }

    #[inline]
    fn i_is_valid_size(&self) -> bool {
        const_can_cast_i32::<C>()
    }

    #[inline]
    fn ptr(&self) -> *const u8 {
        self.as_ptr()
    }
}

macro_rules! impl_salt_for_sizes {
    ($constraint:ty => [$($sz:literal),*]) => {
        $(
            impl Salt<$constraint> for [u8; $sz] {
                #[inline]
                fn size(&self) -> u32 { $sz }
                #[inline]
                fn is_valid_size(&self) -> bool { true }
                #[inline]
                fn i_size(&self) -> i32 { $sz }
                #[inline]
                fn i_is_valid_size(&self) -> bool { true }
                #[inline]
                fn ptr(&self) -> *const u8 { self.as_ptr() }
            }
        )*
    };
}

impl_salt_for_sizes! { salt::Min16 => [
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 48, 64
]}

impl_salt_for_sizes! { salt::NonEmpty => [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 48, 64
]}

impl Salt<salt::Empty> for () {
    #[inline]
    fn size(&self) -> u32 {
        0
    }

    #[inline]
    fn is_valid_size(&self) -> bool {
        true
    }

    #[inline]
    fn i_size(&self) -> i32 {
        0
    }

    #[inline]
    fn i_is_valid_size(&self) -> bool {
        true
    }

    #[inline]
    fn ptr(&self) -> *const u8 {
        core::ptr::null()
    }
}

impl<T: Salt<SZ>, SZ: salt::MinSize> Salt<SZ> for &T {
    #[inline]
    fn size(&self) -> u32 {
        <T as Salt<SZ>>::size(self)
    }

    #[inline]
    fn is_valid_size(&self) -> bool {
        <T as Salt<SZ>>::is_valid_size(self)
    }

    #[inline]
    fn i_size(&self) -> i32 {
        <T as Salt<SZ>>::i_size(self)
    }

    #[inline]
    fn i_is_valid_size(&self) -> bool {
        <T as Salt<SZ>>::i_is_valid_size(self)
    }

    #[inline]
    fn ptr(&self) -> *const u8 {
        <T as Salt<SZ>>::ptr(self)
    }
}

impl<T: Salt<SZ>, SZ: salt::MinSize> Salt<SZ> for &mut T {
    #[inline]
    fn size(&self) -> u32 {
        <T as Salt<SZ>>::size(self)
    }

    #[inline]
    fn is_valid_size(&self) -> bool {
        <T as Salt<SZ>>::is_valid_size(self)
    }

    #[inline]
    fn i_size(&self) -> i32 {
        <T as Salt<SZ>>::i_size(self)
    }

    #[inline]
    fn i_is_valid_size(&self) -> bool {
        <T as Salt<SZ>>::i_is_valid_size(self)
    }

    #[inline]
    fn ptr(&self) -> *const u8 {
        <T as Salt<SZ>>::ptr(self)
    }
}

/// A [`Salt`] with runtime flexibility.
///
/// The [`Salt`] trait, with its associated constraints, is implemented for most common types which
/// meet the marker constraint for pure compile-time checks. However, this can be limiting, this
/// type moves these compile-time checks to runtime.
#[repr(transparent)]
pub struct SaltSlice<'s, SZ: salt::MinSize> {
    raw: &'s [u8],
    _min_size: PhantomData<SZ>
}

macro_rules! impl_salt_for {
    ($sz:ty => { $item:item }) => {
        impl<'s> SaltSlice<'s, $sz> {
            $item
        }
    };
}

impl_salt_for! { salt::Empty => {
    /// Create a new `SaltSlice` instance.
    ///
    /// # Arguments
    ///
    /// * `slice` - The [`Salt`] (if any) to use.
    ///
    /// # Errors
    ///
    /// This is infallible, the only reason this returns a result is to keep this `new`
    /// implementation in sync with other [`Salt`] constraints (this being the weakest / most
    /// permissive constraint).
    pub const fn new(slice: &'s [u8]) -> Result<Self, Infallible> {
        Ok(Self::create(slice))
    }
}}

impl_salt_for! { salt::NonEmpty => {
    /// Create a new `SaltSlice` instance.
    ///
    /// # Arguments
    ///
    /// * `slice` - The [`Salt`], which must be non-empty.
    ///
    /// # Errors
    ///
    /// This requires the provided slice to be **non-empty**, this is the second-weakest constraint,
    /// and only leveraged with `allow-non-fips` enabled. In general, for KDFs such as PBKDF it is
    /// **strongly recommended** to use at least a 128 bit (16 byte) salt generated from a valid
    /// `CSPRNG`.
    pub const fn new(slice: &'s [u8]) -> Result<Self, InvalidSize> {
        if !slice.is_empty() {
            Ok(Self::create(slice))
        } else {
            Err(InvalidSize)
        }
    }
}}

impl_salt_for! { salt::Min16 => {
    /// Create a new `SaltSlice` instance.
    ///
    /// # Arguments
    ///
    /// * `slice` - The [`Salt`], which must be at least 128 bits (16 bytes).
    ///
    /// # Errors
    ///
    /// This requires that the provided slice is **at least** 128 bits (16 bytes), this is the
    /// strongest constraint as it enforces this best practice (as well as FIPS requirement).
    /// Regardless if the interface requires this constraint it is **strongly recommended** to use
    /// a 128 bit salt generated from a valid `CSPRNG`.
    pub const fn new(slice: &'s [u8]) -> Result<Self, InvalidSize> {
        if slice.len() >= 16 {
            Ok(Self::create(slice))
        } else {
            Err(InvalidSize)
        }
    }
}}

impl<'s, SZ: salt::MinSize> SaltSlice<'s, SZ> {
    #[inline]
    const fn create(raw: &'s [u8]) -> Self {
        Self { raw, _min_size: PhantomData }
    }
}

macro_rules! impl_salt_try_from {
    ($ty:ty) => {
        impl<'s> TryFrom<&'s [u8]> for SaltSlice<'s, $ty> {
            type Error = <$ty as salt::MinSize>::CreateError;

            #[inline]
            fn try_from(value: &'s [u8]) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

impl_salt_try_from! { salt::NonEmpty }
impl_salt_try_from! { salt::Min16 }

impl<'s> From<&'s [u8]> for SaltSlice<'s, salt::Empty> {
    #[inline]
    fn from(value: &'s [u8]) -> Self {
        Self::create(value)
    }
}

impl<'s> From<&'s [u8; 16]> for SaltSlice<'s, salt::Min16> {
    #[inline]
    fn from(value: &'s [u8; 16]) -> Self {
        Self::create(value)
    }
}

impl<'s, SZ: salt::MinSize> Sealed for SaltSlice<'s, SZ> {}

impl<'s, SZ: salt::MinSize> Salt<SZ> for SaltSlice<'s, SZ> {
    #[inline]
    fn size(&self) -> u32 {
        debug_assert!(can_cast_u32(self.raw.len()));
        self.raw.len() as u32
    }

    #[inline]
    fn is_valid_size(&self) -> bool {
        can_cast_u32(self.raw.len())
    }

    #[inline]
    fn i_size(&self) -> i32 {
        debug_assert!(can_cast_i32(self.raw.len()));
        self.raw.len() as i32
    }

    #[inline]
    fn i_is_valid_size(&self) -> bool {
        can_cast_i32(self.raw.len())
    }

    #[inline]
    fn ptr(&self) -> *const u8 {
        self.raw.as_ptr()
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