use core::fmt;
use crate::mac::hmac::algo::{self, Digest as _, HexDigest as _};
use crate::ct;
use crate::hex;

/// Utility wrapper around the final `HMAC` hash.
#[must_use]
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct Digest<D: algo::Digest> {
    raw: D
}

impl<D: algo::Digest> fmt::Debug for Digest<D> {
    /// Writes "Digest { ... }" to the provided formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Digest { ... }")
    }
}

impl<D: algo::Digest + Copy> Digest<D> {
    /// Create a new `Digest` instance.
    pub const fn new(digest: D) -> Self {
        Self { raw: digest }
    }

    /// Unwraps this `Digest` returning the raw byte array.
    ///
    /// # Note
    ///
    /// Comparing `Digest`s should always be in constant-time, do not use `into_inner` prior to
    /// checking equivalence between `Digest`s. The `Digest` type's `PartialEq` implementations
    /// are all in constant-time. Either leverage these, or use this crate's [`ct_eq`] function.
    ///
    /// [`ct_eq`]: crate::ct_eq
    #[must_use]
    pub const fn into_inner(self) -> D {
        self.raw
    }

    /// Hex-encodes the underlying digest in constant-time, returning the [`HexDigest`] type.
    pub fn hex_encode(&self) -> HexDigest<D::Hex> {
        let mut out = D::Hex::zeroes();
        hex::encode_into(self.as_ref(), out.as_mut()).unwrap(/* infallible */);
        HexDigest::new(out)
    }
}

impl<D: algo::Digest> AsRef<[u8]> for Digest<D> {
    #[inline]
    fn as_ref(&self) -> &[u8] { self.raw.as_ref() }
}

impl<D: algo::Digest> AsRef<D> for Digest<D> {
    #[inline]
    fn as_ref(&self) -> &D { &self.raw }
}

impl<D: algo::Digest> PartialEq for Digest<D> {
    /// Constant-Time Equivalence.
    fn eq(&self, other: &Self) -> bool {
        ct::ct_eq(self.raw, other.raw)
    }
}

impl<D: algo::Digest> Eq for Digest<D> {}

impl<D: algo::Digest> PartialEq<[u8]> for Digest<D> {
    /// Constant-Time Equivalence.
    fn eq(&self, other: &[u8]) -> bool {
        ct::ct_eq(self.raw, other)
    }
}

impl<D: algo::Digest, T> PartialEq<&T> for Digest<D> where Self: PartialEq<T> {
    /// Constant-Time Equivalence.
    #[inline]
    fn eq(&self, other: &&T) -> bool {
        self.eq(other)
    }
}

impl<D: algo::Digest, T> PartialEq<&mut T> for Digest<D> where Self: PartialEq<T> {
    /// Constant-Time Equivalence.
    #[inline]
    fn eq(&self, other: &&mut T) -> bool {
        self.eq(other)
    }
}

/// Utility wrapper around the hex-encoded final `HMAC` hash.
#[repr(transparent)]
#[must_use]
#[derive(Copy, Clone)]
pub struct HexDigest<D: algo::HexDigest> {
    raw: D
}

impl<D: algo::HexDigest> HexDigest<D> {
    /// Create a new `HexDigest` instance
    ///
    /// # Arguments
    ///
    /// * `digest` - The hex-encoded digest.
    // new is not public as we cannot guarantee the provided data is properly hex-encoded.
    const fn new(digest: D) -> Self {
        Self { raw: digest }
    }

    /// Decodes the `HexDigest` into a raw [`Digest`] in constant-time.
    pub fn decode(&self) -> Digest<D::Digest> {
        let mut output = D::Digest::zeroes();
        hex::decode_into(self.raw.as_ref(), output.as_mut())
            .unwrap(/* This is infallible as this type may not be constructed without correct hex
                       encoding */);
        Digest::new(output)
    }

    /// Returns the underlying hex-encoded digest as a `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        // SAFETY: See `ct` module's hex encode documentation.
        unsafe { core::str::from_utf8_unchecked(self.raw.as_ref()) }
    }

    /// Unwraps this `HexDigest` returning the hex-encoded byte array.
    ///
    /// # Note
    ///
    /// Comparing `HexDigest`s should always be in constant-time, do not use `into_inner` prior to
    /// checking equivalence between `HexDigest`s. The `HexDigest` type's `PartialEq`
    /// implementations are all in constant-time. Either leverage these, or use this crate's
    /// [`ct_eq`] function.
    ///
    /// [`ct_eq`]: crate::ct_eq
    #[must_use]
    pub const fn into_inner(self) -> D {
        self.raw
    }
}

impl<D: algo::HexDigest> AsRef<[u8]> for HexDigest<D> {
    #[inline]
    fn as_ref(&self) -> &[u8] { self.raw.as_ref() }
}

impl<D: algo::HexDigest> AsRef<D> for HexDigest<D> {
    #[inline]
    fn as_ref(&self) -> &D { &self.raw }
}

impl<D: algo::HexDigest> PartialEq for HexDigest<D> {
    /// Constant-Time Equivalence.
    fn eq(&self, other: &Self) -> bool {
        ct::ct_eq(self.raw, other.raw)
    }
}

impl<D: algo::HexDigest> Eq for HexDigest<D> {}

impl<D: algo::HexDigest> PartialEq<[u8]> for HexDigest<D> {
    /// Constant-Time Equivalence.
    fn eq(&self, other: &[u8]) -> bool {
        ct::ct_eq(self.raw, other)
    }
}

impl<D: algo::HexDigest, T> PartialEq<&T> for HexDigest<D> where Self: PartialEq<T> {
    /// Constant-Time Equivalence.
    #[inline]
    fn eq(&self, other: &&T) -> bool {
        self.eq(other)
    }
}

impl<D: algo::HexDigest, T> PartialEq<&mut T> for HexDigest<D> where Self: PartialEq<T> {
    /// Constant-Time Equivalence.
    #[inline]
    fn eq(&self, other: &&mut T) -> bool {
        self.eq(other)
    }
}

impl<D: algo::HexDigest> From<HexDigest<D>> for Digest<D::Digest> {
    fn from(value: HexDigest<D>) -> Self {
        value.decode()
    }
}

impl<D: algo::Digest> From<Digest<D>> for HexDigest<D::Hex> {
    fn from(value: Digest<D>) -> Self {
        value.hex_encode()
    }
}