//! Collection of marker types and their associated keys which denote the hashing function.

use core::marker::PhantomData;
use wolf_crypto_sys::{
    WC_SHA224, WC_SHA256, WC_SHA384, WC_SHA512,
    WC_SHA3_224, WC_SHA3_256, WC_SHA3_384, WC_SHA3_512
};

use zeroize::Zeroize;

use crate::sealed::HmacSealed as Sealed;
use crate::buf::InvalidSize;
use crate::can_cast_u32;

non_fips! {
    use wolf_crypto_sys::{WC_MD5, WC_SHA};
}

/// Represents a valid key size for `HMAC`.
pub trait KeySz : Sealed {
    /// Returns the associated size as a `u32`.
    ///
    /// This size is equivalent to the digest size of the hash function.
    #[must_use]
    fn size() -> u32;
}

/// Represents a valid key for `HMAC`.
pub trait GenericKey : Sealed {
    /// The desired size of the key.
    type Size: KeySz;

    #[doc(hidden)]
    #[must_use]
    fn ptr(&self) -> *const u8;

    /// Returns the size of the key in bytes.
    fn size(&self) -> u32;

    /// Zeroes the memory of the key if is owned.
    fn cleanup(self);
}

/// Represent the output digest of the `HMAC` hash function.
pub trait Digest : Sealed {
    #[doc(hidden)]
    #[must_use]
    fn zeroes() -> Self;
    /// Returns the size of the digest in bytes.
    #[must_use]
    fn size() -> u32;
    #[doc(hidden)]
    #[must_use]
    fn ptr(&mut self) -> *mut u8;
}

/// The hashing algorithm to use with `HMAC`.
pub trait Hash : Sealed {
    #[doc(hidden)]
    type Digest: Digest;

    /// The associated key length for `HMAC` with this hashing function.
    ///
    /// In [`RFC2104`, section 3 `Keys`][1], it states that the key for `HMAC` can be of any length,
    /// **however** keys less than length `L` (the length of the output (SHA256 being 256 bits)) are
    /// strongly discouraged and considered insecure.
    ///
    /// This library does not support using keys which do not follow this recommendation in the
    /// safe API. The unsafe API which does expose this is not public yet, and we are decided on
    /// whether it is worth including in the first place.
    ///
    /// All modern usages of `HMAC`, for example in TLS, use the same key length as the digest
    /// length (`L`).
    ///
    /// [1]: https://www.rfc-editor.org/rfc/rfc2104#section-3
    type KeyLen: KeySz;

    #[doc(hidden)]
    #[must_use]
    fn type_id() -> core::ffi::c_int;
}

// Key sizes correspond to the digest size, this is a modern recommendation. In the original
// RFCs' this was not specified, but nowadays, it is a standard practice. For example in TLS
// the key size used always corresponds directly to the digest size of the hash function.
macro_rules! make_digest {
    ($(($name:ident, $sz:literal)),* $(,)?) => {
        $(
            impl Sealed for [u8; $sz] {}
            impl Digest for [u8; $sz] {
                #[inline]
                fn zeroes() -> Self {
                    [0u8; $sz]
                }
                #[inline]
                fn size() -> u32 {
                    $sz
                }
                #[inline]
                fn ptr(&mut self) -> *mut u8 {
                    self.as_mut_ptr()
                }
            }

            #[doc = concat!(
                "Generic representation of a ", stringify!($sz), " byte key for `HMAC`."
            )]
            #[doc = ""]
            #[doc = "It is strongly recommended that the key length in `HMAC` is equivalent "]
            #[doc = "to the hash functions digest size. (SHA256 means 256 bit (32 byte) key)."]
            pub struct $name;

            impl Sealed for $name {}
            impl KeySz for $name {
                #[inline]
                fn size() -> u32 {
                    Self::SIZE
                }
            }

            impl $name {
                /// The associated `u32` representation.
                pub const SIZE: u32 = $sz;
                pub(crate) const USIZE: usize = $sz;
            }

            impl GenericKey for [u8; $sz] {
                type Size = $name;

                #[inline]
                fn ptr(&self) -> *const u8 {
                    self.as_ptr()
                }

                #[inline]
                fn size(&self) -> u32 {
                    <$name>::SIZE
                }

                #[inline]
                fn cleanup(mut self) {
                    self.zeroize();
                }
            }

            impl Sealed for &[u8; $sz] {}

            impl GenericKey for &[u8; $sz] {
                type Size = $name;

                #[inline]
                fn ptr(&self) -> *const u8 {
                    self.as_ptr()
                }

                #[inline]
                fn size(&self) -> u32 {
                    <$name>::SIZE
                }

                #[inline(always)]
                fn cleanup(self) {}
            }
        )*
    };
}

/// Represents a key for `HMAC` which has a length greater than or equal to the length of the
/// hash functions digest.
#[repr(transparent)]
pub struct KeySlice<'k, SZ: KeySz> {
    inner: &'k [u8],
    _min_size: PhantomData<SZ>
}

impl<'k, SZ: KeySz> Sealed for KeySlice<'k, SZ> {}

impl<'k, SZ: KeySz> GenericKey for KeySlice<'k, SZ> {
    type Size = SZ;

    #[inline]
    fn ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }

    #[inline]
    fn size(&self) -> u32 {
        // KeySlice cannot be constructed with a slice which has a length greater than u32::MAX.
        self.inner.len() as u32
    }

    #[inline(always)]
    fn cleanup(self) {}
}

impl<'k, SZ: KeySz> KeySlice<'k, SZ> {
    /// Try creating a new `KeySlice` instance.
    ///
    /// # Errors
    ///
    /// - If the length of the `slice` is less than the [`SZ::size`][1].
    /// - If the length of the `slice` is greater than [`u32::MAX`].
    ///
    /// [1]: KeySz::size
    #[inline]
    pub fn new(slice: &'k [u8]) -> Result<Self, InvalidSize> {
        if slice.len() < SZ::size() as usize || !can_cast_u32(slice.len()) {
            Err(InvalidSize)
        } else {
            Ok(Self { inner: slice, _min_size: PhantomData })
        }
    }
}

impl<'k, SZ: KeySz> TryFrom<&'k [u8]> for KeySlice<'k, SZ> {
    type Error = InvalidSize;

    /// Try creating a new `KeySlice` instance.
    ///
    /// # Errors
    ///
    /// - If the length of the `slice` is less than the [`SZ::size`][1].
    /// - If the length of the `slice` is greater than [`u32::MAX`].
    /// 
    /// [1]: KeySz::size
    #[inline]
    fn try_from(value: &'k [u8]) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

macro_rules! make_algo_type {
    ($((
        $(#[$meta:meta])*
        $name:ident,
        $sz:ident,
        $wc_ty:ident
    )),* $(,)?) => {
        $(
            $(#[$meta])*
            pub struct $name;
            impl Sealed for $name {}

            impl Hash for $name {
                type Digest = [u8; $sz::USIZE];
                type KeyLen = $sz;

                #[inline]
                fn type_id() -> ::core::ffi::c_int {
                    // This is a silly assertion as the maximum constant for wc_ty is 13.
                    debug_assert!($wc_ty <= i32::MAX as ::core::ffi::c_uint);
                    $wc_ty as ::core::ffi::c_int
                }
            }
        )*
    };
}

#[cfg_attr(docsrs, doc(cfg(feature = "allow-non-fips")))]
#[cfg(feature = "allow-non-fips")]
make_digest! { (U16, 16), (U20, 20) }

make_digest! { (U28, 28), (U32, 32), (U48, 48), (U64, 64) }

#[cfg_attr(docsrs, doc(cfg(feature = "allow-non-fips")))]
#[cfg(feature = "allow-non-fips")]
make_algo_type! {
    (
        /// The `MD5` HMAC Hash Function.
        ///
        /// `MD5` should be [considered cryptographically broken and unsuitable for further use][1].
        /// Collision attacks against `MD5` are both practical and trivial, theoretical attacks
        /// against `MD5` have been found.
        ///
        /// `MD5` is included in this library for legacy reasons only.
        ///
        /// [1]: https://www.kb.cert.org/vuls/id/836068
        Md5, U16, WC_MD5
    ),
    (
        /// The `SHA-1` HMAC Hash Function.
        ///
        /// The SHA-1 algorithm is included in this library for legacy reasons only. It is
        /// cryptographically broken and should not be used for any security-critical or modern
        /// applications, especially digital signatures or certificate validation.
        ///
        /// The U.S. National Institute of Standards and Technology (NIST) has officially deprecated
        /// SHA-1 for all digital signature use cases as of 2011. As of 2022, NIST recommends
        /// transitioning all applications from SHA-1 to SHA-2 or SHA-3 family of hash functions.
        Sha, U20, WC_SHA
    )
}

make_algo_type! {
    (
        /// The `SHA224` HMAC Hash Function.
        Sha224, U28, WC_SHA224
    ),
    (
        /// The `SHA256` HMAC Hash Function.
        Sha256, U32, WC_SHA256
    ),
    (
        /// The `SHA384` HMAC Hash Function.
        Sha384, U48, WC_SHA384
    ),
    (
        /// The `SHA512` HMAC Hash Function.
        Sha512, U64, WC_SHA512
    ),
    (
        /// The `SHA3-224` HMAC Hash Function.
        Sha3_224, U28, WC_SHA3_224
    ),
    (
        /// The `SHA3-256` HMAC Hash Function.
        Sha3_256, U32, WC_SHA3_256
    ),
    (
        /// The `SHA3-384` HMAC Hash Function.
        Sha3_384, U48, WC_SHA3_384
    ),
    (
        /// The `SHA3-512` HMAC Hash Function.
        Sha3_512, U64, WC_SHA3_512
    )
}