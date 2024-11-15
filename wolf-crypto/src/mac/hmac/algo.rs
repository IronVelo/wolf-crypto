//! Collection of marker types and their associated keys which denote the hashing function.

use core::marker::PhantomData;
use wolf_crypto_sys::{
    WC_SHA224, WC_SHA256, WC_SHA384, WC_SHA512,
    WC_SHA3_224, WC_SHA3_256, WC_SHA3_384, WC_SHA3_512
};

use zeroize::Zeroize;

use crate::sealed::HmacSealed as Sealed;
use crate::sealed::HmacDigestSealed as SealedDigest;

use crate::buf::InvalidSize;
use crate::can_cast_u32;
use crate::Fips;
use core::fmt;

non_fips! {
    use wolf_crypto_sys::{WC_MD5, WC_SHA};
}

/// Represents a valid key size for the associated hashing algorithm.
pub trait KeySz : Sealed {
    /// Returns the associated size as a `u32`.
    ///
    /// This size is equivalent to the digest size of the hash function.
    #[must_use]
    fn size() -> u32;
}

/// Represents a valid key for the associated hashing algorithm..
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

/// Represents the hex-encoded output digest of the `HMAC` hash functions.
pub trait HexDigest : SealedDigest + AsRef<[u8]> + AsMut<[u8]> + Copy {
    /// The associated hex-decoded digest type.
    type Digest: Digest;

    #[doc(hidden)]
    #[must_use]
    fn zeroes() -> Self;
}

/// Represents the output digest of the `HMAC` hash function.
pub trait Digest : Sealed + AsRef<[u8]> + AsMut<[u8]> + Copy {
    /// The associated hex-encoded digest type.
    type Hex: HexDigest;

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

/// Indicates the hashing algorithm to use with message authentication codes and key derivation
/// functions.
pub trait Hash : Sealed {
    /// Represents the output digest of the hash function.
    type Digest: Digest;

    /// The associated key length for this hashing function.
    ///
    /// In [`RFC2104`, Section 3 `Keys`][1], it states that the key for `HMAC` can be of any length,
    /// **however** keys less than length `L` (the length of the output (SHA256 being 256 bits)) are
    /// strongly discouraged and considered insecure.
    ///
    /// This library does not support using keys which do not follow this recommendation in the
    /// secure API. If you are not able to follow these best practices, see [`InsecureKey`],
    /// though this is strongly discouraged.
    ///
    /// All modern usages of `HMAC`, for example in TLS, use the same key length as the digest
    /// length (`L`).
    ///
    /// These recommendations remain unaltered for key derivation functions.
    /// 
    /// ## Larger Keys
    /// 
    /// As pointed out in [`RFC2104`, section 3 `Keys`][1] the provided key material may be larger
    /// than the length of the output. This can be done via the [`KeySlice`] type. In general there
    /// won't be any real advantage to this, however this is with an exception, as stated: 
    /// 
    /// ```txt
    ///    A longer key may be advisable if the randomness of the key is
    ///    considered weak.
    /// ```
    /// 
    /// Keys larger than the digest / hash output size will be hashed.
    /// 
    /// [1]: https://www.rfc-editor.org/rfc/rfc2104#section-3
    type KeyLen: KeySz;

    /// Writes the algorithm name into `f`.
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result;

    #[doc(hidden)]
    #[must_use]
    fn type_id() -> core::ffi::c_int;
}

// Key sizes correspond to the digest size pursuant to RFC2104, and all relevant
// NIST SP recommendations.
macro_rules! make_digest {
    ($(($name:ident, $sz:literal)),* $(,)?) => {
        $(
            impl SealedDigest for [u8; crate::ct::hex_encode_len($sz)] {}
            
            impl HexDigest for [u8; crate::ct::hex_encode_len($sz)] {
                type Digest = [u8; $sz];

                #[inline]
                fn zeroes() -> Self {
                    [0u8; crate::ct::hex_encode_len($sz)]
                }
            }
        
            impl Sealed for [u8; $sz] {}
            impl Digest for [u8; $sz] {
                type Hex = [u8; crate::ct::hex_encode_len($sz)];
                
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
                "Generic representation of a ", stringify!($sz), " byte key for `HMAC` or KDFs."
            )]
            #[doc = ""]
            #[doc = "It is strongly recommended that the key length is equivalent "]
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

/// Represents a key for the associated hashing algorithm which has a length greater than or
/// equal to the length of the hash function's digest.
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

/// Represents a key associated with the desired hashing function which can be **insecure**.
///
/// # Security
///
/// It is **not recommended** to use this unless you have a very good reason. This reason in general
/// should be legacy system compatibility, modern systems without this constant
/// **should not leverage this**, instead, use the [`KeySlice`], or provide the exact key
/// corresponding to the digest size of the underlying hashing function.
///
/// # FIPS Compliance
///
/// Using this plays into `FIPS` compliance, **without** this crate's `allow-non-fips` feature
/// enabled, this **cannot be constructed with a key smaller than the acceptable FIPS standard**
/// of 14 bytes.
///
/// For more information, See [FIPS 198-1, Section 3 Cryptographic Keys][1] reference to
/// [NIST SP 800-107][2]. Which discusses this minimum security strength of 112 bits (14 bytes) in
/// [SP 800-107, Section 5.2 Digital Signatures][3] and [SP 800-107 Section 5.3.2 The HMAC Key][4].
///
/// [1]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf#%5B%7B%22num%22%3A20%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C0%2C792%2Cnull%5D
/// [2]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf
/// [3]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf#%5B%7B%22num%22%3A28%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C88%2C463%2C0%5D
/// [4]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf#%5B%7B%22num%22%3A35%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C88%2C139%2C0%5D
#[repr(transparent)]
pub struct InsecureKey<'k, SZ: KeySz> {
    inner: &'k [u8],
    _min_size: PhantomData<SZ>
}

impl<'k, SZ: KeySz> InsecureKey<'k, SZ> {
    /// Minimum Size without FIPS requirement (1)
    #[cfg(feature = "allow-non-fips")]
    const MIN_SIZE: usize = 1;
    /// Minimum Size with FIPS requirement (14)
    #[cfg(not(feature = "allow-non-fips"))]
    const MIN_SIZE: usize = 14;

    #[inline]
    #[must_use]
    const fn new_predicate(len: usize) -> bool {
        (len >= Self::MIN_SIZE) && can_cast_u32(len)
    }

    /// Create a new [`InsecureKey`] instance.
    ///
    /// # Security
    ///
    /// Please read the [`InsecureKey`]'s type documentation regarding security, and why it is
    /// strongly recommended to use safer, more secure alternatives like [`KeySlice`] or passing
    /// a key of the underlying hash functions digest length for compile-time checks.
    ///
    /// # Errors
    ///
    /// This will return `InvalidSize` on conditions dependent on the `allow-non-fips` feature
    /// flag.
    ///
    /// - `allow-non-fips` enabled:
    ///   This will return `InvalidSize` if the provided key is empty.
    /// - `allow-non-fips` disabled:
    ///   Pursuant to the FIPS requirements for HMAC and KDFs (for more information again read the
    ///   [`InsecureKey`]'s type documentation), this will return `InvalidSize` if the provided
    ///   key is shorter than the minimum acceptable FIPS standard of 14 bytes.
    /// - any configuration:
    ///   Regardless of the enabled feature flags, if the length of the key is greater than
    ///   [`u32::MAX`] this will return `InvalidSize`.
    pub const fn new(slice: &'k [u8]) -> Result<Self, InvalidSize> {
        if Self::new_predicate(slice.len()) {
            Ok(Self { inner: slice, _min_size: PhantomData })
        } else {
            Err(InvalidSize)
        }
    }
}

impl<'k, SZ: KeySz> Sealed for InsecureKey<'k, SZ> {}

impl<'k, SZ: KeySz> GenericKey for InsecureKey<'k, SZ> {
    type Size = SZ;

    #[inline]
    fn ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }

    #[inline]
    fn size(&self) -> u32 {
        // InsecureKey cannot be constructed with a slice which has a length greater than u32::MAX.
        self.inner.len() as u32
    }

    #[inline(always)]
    fn cleanup(self) {}
}

impl<'k, SZ: KeySz> TryFrom<&'k [u8]> for InsecureKey<'k, SZ> {
    type Error = InvalidSize;

    /// Create a new [`InsecureKey`] instance.
    ///
    /// # Security
    ///
    /// Please read the [`InsecureKey`]'s type documentation regarding security, and why it is
    /// strongly recommended to use safer, more secure alternatives like [`KeySlice`] or passing
    /// a key of the underlying hash functions digest length for compile-time checks.
    ///
    /// # Errors
    ///
    /// This will return `InvalidSize` on conditions dependent on the `allow-non-fips` feature
    /// flag.
    ///
    /// - `allow-non-fips` enabled:
    ///   This will return `InvalidSize` if the provided key is empty.
    /// - `allow-non-fips` disabled:
    ///   Pursuant to the FIPS requirements for HMAC and KDFs (for more information again read the
    ///   [`InsecureKey`]'s type documentation), this will return `InvalidSize` if the provided
    ///   key is shorter than the minimum acceptable FIPS standard of 14 bytes.
    /// - any configuration:
    ///   Regardless of the enabled feature flags, if the length of the key is greater than
    ///   [`u32::MAX`] this will return `InvalidSize`.
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
        $(, $fips_trait:ident)?
    )),* $(,)?) => {
        $(
            $(#[$meta])*
            pub struct $name;
            impl Sealed for $name {}
            impl $crate::sealed::Sealed for $name {}
            $(
                impl $crate::sealed::FipsSealed for $name {}
                impl $fips_trait for $name {}
            )?

            impl Hash for $name {
                type Digest = [u8; $sz::USIZE];
                type KeyLen = $sz;

                #[doc = concat!("Writes \"", stringify!($name), "\" to `f`.")]
                #[inline]
                fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str(stringify!($name))
                }

                #[inline]
                fn type_id() -> ::core::ffi::c_int {
                    // This is a silly assertion as the maximum constant for wc_ty is 13.
                    debug_assert!($wc_ty <= i32::MAX as ::core::ffi::c_uint);
                    $wc_ty as ::core::ffi::c_int
                }
            }

            impl Sealed for $crate::hash::$name {}

            impl Hash for $crate::hash::$name {
                type Digest = [u8; $sz::USIZE];
                type KeyLen = $sz;

                #[doc = concat!("Writes \"", stringify!($name), "\" to `f`.")]
                #[inline]
                fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str(stringify!($name))
                }

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
        /// The `MD5` Hash Function Marker Type.
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
        /// The `SHA-1` Hash Function Marker Type.
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
        /// The `SHA224` Hash Function Marker Type.
        Sha224, U28, WC_SHA224, Fips
    ),
    (
        /// The `SHA256` Hash Function Marker Type.
        Sha256, U32, WC_SHA256, Fips
    ),
    (
        /// The `SHA384` Hash Function Marker Type.
        Sha384, U48, WC_SHA384, Fips
    ),
    (
        /// The `SHA512` Hash Function Marker Type.
        Sha512, U64, WC_SHA512, Fips
    ),
    (
        /// The `SHA3-224` Hash Function Marker Type.
        Sha3_224, U28, WC_SHA3_224, Fips
    ),
    (
        /// The `SHA3-256` Hash Function Marker Type.
        Sha3_256, U32, WC_SHA3_256, Fips
    ),
    (
        /// The `SHA3-384` Hash Function Marker Type.
        Sha3_384, U48, WC_SHA3_384, Fips
    ),
    (
        /// The `SHA3-512` Hash Function Marker Type.
        Sha3_512, U64, WC_SHA3_512, Fips
    )
}