//! AES Key Wrap (KW, NIST SP 800-38F section 6.2, RFC 3394)
//!
//! Key wrapping protects the confidentiality and integrity of key material under a
//! key-encryption key ([`Kek`]). Wrapping a `P` byte key yields a [`Wrapped<P>`] of `P + 8`
//! bytes; unwrapping checks the integrity check value and only then releases an
//! [`Unwrapped<P>`], which zeroes itself on drop.
//!
//! Only the forward-cipher KW with the default integrity check value (`ICV1`, `0xA6A6...A6`)
//! is exposed, which is the approved mode of SP 800-38F. All three key-encryption key sizes are
//! marked [`Fips`](crate::Fips).
//!
//! # Sizes
//!
//! The wrapped key length `P` is a type parameter. KW requires `P` to be a multiple of the
//! 8 byte semiblock and at least two semiblocks (16 bytes); other lengths do not compile:
//!
//! ```compile_fail
//! use wolf_crypto::aes::kw::Kek256;
//!
//! let kek = Kek256::new([7u8; 32]);
//! let _ = kek.wrap(&[1u8; 20]); // 20 is not a multiple of 8
//! ```
//!
//! ```compile_fail
//! use wolf_crypto::aes::kw::Kek256;
//!
//! let kek = Kek256::new([7u8; 32]);
//! let _ = kek.wrap(&[1u8; 8]); // a single semiblock needs KWP, not KW
//! ```
//!
//! Key-encryption keys only exist for AES-128, AES-192 and AES-256:
//!
//! ```compile_fail
//! use wolf_crypto::aes::kw::Kek;
//!
//! let kek = Kek::<20>::new([7u8; 20]);
//! ```
//!
//! # Example
//!
//! ```
//! use wolf_crypto::aes::kw::{Kek256, Wrapped};
//!
//! let kek = Kek256::new([7u8; 32]);
//! let data_key = [42u8; 32];
//!
//! let wrapped: Wrapped<32> = kek.wrap(&data_key).unwrap();
//! assert_eq!(wrapped.as_slice().len(), 40);
//!
//! let unwrapped = kek.unwrap(&wrapped).unwrap();
//! assert_eq!(unwrapped.as_array(), &data_key);
//!
//! // any modification is detected
//! let mut tampered = wrapped.as_slice().to_vec();
//! tampered[9] ^= 1;
//! let tampered = Wrapped::<32>::try_from(tampered.as_slice()).unwrap();
//! assert!(kek.unwrap(&tampered).is_err());
//! ```

use core::ffi::{c_int, c_uint};
use core::fmt;
use core::mem::{size_of, MaybeUninit};
use core::ptr;
use wolf_crypto_sys::{
    Aes as AesLL,
    wc_AesInit, wc_AesSetKey,
    wc_AesKeyWrap_ex, wc_AesKeyUnWrap_ex,
    INVALID_DEVID, AES_ENCRYPTION, AES_DECRYPTION
};
use zeroize::Zeroize;
use crate::buf::InvalidSize;
use crate::error::Unspecified;
use crate::opaque_res::Res;
use crate::sealed::FipsSealed;
use crate::Fips;

/// The size of a KW semiblock in bytes.
pub const SEMIBLOCK: usize = 8;

/// The smallest plaintext KW accepts (two semiblocks).
pub const MIN_PLAINTEXT: usize = 2 * SEMIBLOCK;

/// The largest plaintext this binding accepts.
///
/// SP 800-38F allows up to `2^54 - 1` semiblocks, `wolfcrypt` reports the output length as a
/// C `int`, so the wrapped output (`P + 8`) must fit in an `i32`.
pub const MAX_PLAINTEXT: usize = (i32::MAX as usize - SEMIBLOCK) & !(SEMIBLOCK - 1);

/// Compile-time validation of the plaintext length `P`.
struct Len<const P: usize>;

impl<const P: usize> Len<P> {
    const VALID: () = assert!(
        P >= MIN_PLAINTEXT && P.is_multiple_of(SEMIBLOCK) && P <= MAX_PLAINTEXT,
        "AES-KW requires the plaintext to be a multiple of 8 bytes, and at least 16 bytes"
    );
}

/// An AES key-encryption key (KEK) for AES Key Wrap.
///
/// `N` is the AES key size in bytes, only [`Kek128`], [`Kek192`] and [`Kek256`] can be
/// constructed. The key is zeroed on drop.
pub struct Kek<const N: usize> {
    key: [u8; N]
}

/// An AES-128 key-encryption key.
pub type Kek128 = Kek<16>;
/// An AES-192 key-encryption key.
pub type Kek192 = Kek<24>;
/// An AES-256 key-encryption key.
pub type Kek256 = Kek<32>;

macro_rules! impl_kek {
    ($($sz:literal => $alias:ident),* $(,)?) => {$(
        impl Kek<$sz> {
            #[doc = concat!("Create a new [`", stringify!($alias), "`] from its key material.")]
            #[inline]
            pub const fn new(key: [u8; $sz]) -> Self {
                Self { key }
            }
        }

        impl From<[u8; $sz]> for Kek<$sz> {
            #[inline]
            fn from(value: [u8; $sz]) -> Self {
                Self::new(value)
            }
        }

        impl<'a> TryFrom<&'a [u8]> for Kek<$sz> {
            type Error = InvalidSize;

            /// Create a key-encryption key from a slice of exactly the key size.
            #[inline]
            fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
                <[u8; $sz]>::try_from(value).map(Self::new).map_err(|_| InvalidSize)
            }
        }

        impl FipsSealed for Kek<$sz> {}
        impl Fips for Kek<$sz> {}
    )*};
}

impl_kek! { 16 => Kek128, 24 => Kek192, 32 => Kek256 }

impl<const N: usize> Kek<N> {
    /// Wrap `key` under this key-encryption key (KW-AE).
    ///
    /// # Errors
    ///
    /// If `wolfcrypt` fails to set up the key schedule or to wrap the key. With valid inputs,
    /// which the types ensure, this does not happen with the current `wolfcrypt` configuration.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::aes::kw::Kek128;
    ///
    /// // RFC 3394 section 4.1
    /// let kek = Kek128::new(hex_literal::hex!("000102030405060708090A0B0C0D0E0F"));
    /// let wrapped = kek.wrap(&hex_literal::hex!("00112233445566778899AABBCCDDEEFF")).unwrap();
    ///
    /// assert_eq!(
    ///     wrapped.as_slice(),
    ///     hex_literal::hex!("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
    /// );
    /// ```
    pub fn wrap<const P: usize>(&self, key: &[u8; P]) -> Result<Wrapped<P>, Unspecified> {
        let () = Len::<P>::VALID;

        let mut out = Wrapped::<P> { icv: [0u8; SEMIBLOCK], body: [0u8; P] };

        // SAFETY: `out` is `repr(C)` with only byte arrays, so it is `P + 8` contiguous bytes,
        // which `Len::<P>::VALID` bounds to fit in an `i32` (and therefore a `word32`).
        let res = unsafe {
            with_schedule(&self.key, AES_ENCRYPTION, |aes| {
                // SAFETY: `wc_AesKeyWrap_ex` (aes.c) reads `inSz` bytes of `in` and writes
                // `inSz + 8` bytes of `out`, it requires `inSz >= 16`, `inSz % 8 == 0` and
                // `outSz >= inSz + 8`, all ensured by `Len::<P>::VALID` and the size of `out`.
                // A null `iv` selects the default ICV (`0xA6` * 8). On success it returns
                // `inSz + 8`.
                wc_AesKeyWrap_ex(
                    aes,
                    key.as_ptr(), P as u32,
                    out.as_mut_ptr(), Wrapped::<P>::LEN as u32,
                    ptr::null()
                ) == Wrapped::<P>::LEN as c_int
            })
        };

        if res.is_ok() {
            Ok(out)
        } else {
            // a failure part way leaves (partially wrapped) plaintext in the output
            out.zeroize();
            Err(Unspecified)
        }
    }

    /// Unwrap `wrapped` under this key-encryption key (KW-AD).
    ///
    /// The integrity check value is verified before the key is released.
    ///
    /// # Errors
    ///
    /// - The integrity check failed: `wrapped` was not produced by this key-encryption key, or
    ///   it has been modified.
    /// - `wolfcrypt` failed to set up the key schedule.
    ///
    /// On error no part of the unwrapped key is returned, the output buffer is zeroed.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::aes::kw::{Kek256, Wrapped};
    ///
    /// // RFC 3394 section 4.6
    /// let kek = Kek256::new(hex_literal::hex!(
    ///     "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    /// ));
    /// let wrapped = Wrapped::<32>::try_from(hex_literal::hex!(
    ///     "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
    /// ).as_slice()).unwrap();
    ///
    /// let key = kek.unwrap(&wrapped).unwrap();
    /// assert_eq!(
    ///     key.as_array(),
    ///     &hex_literal::hex!("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
    /// );
    /// ```
    pub fn unwrap<const P: usize>(&self, wrapped: &Wrapped<P>) -> Result<Unwrapped<P>, Unspecified> {
        let () = Len::<P>::VALID;

        let mut out = Unwrapped::<P> { key: [0u8; P] };

        // SAFETY: see `unwrap_raw`, `out.key` is exactly `P` bytes.
        unsafe { unwrap_raw(&self.key, wrapped, &mut out.key) }
            // on error `out` is dropped, which zeroes it (`unwrap_raw` already did)
            .unit_err(out)
    }
}

/// Unwrap `wrapped` into `out`, zeroing `out` on failure.
///
/// # Safety
///
/// `P` must satisfy `Len::<P>::VALID`, and `kek` must be a valid AES key length.
unsafe fn unwrap_raw<const P: usize>(kek: &[u8], wrapped: &Wrapped<P>, out: &mut [u8; P]) -> Res {
    let res = with_schedule(kek, AES_DECRYPTION, |aes| {
        // SAFETY: `wc_AesKeyUnWrap_ex` (aes.c) reads `inSz` bytes of `in` and writes
        // `inSz - 8` bytes of `out`, it requires `inSz >= 24`, `inSz % 8 == 0` and
        // `outSz >= inSz - 8`; with `inSz = P + 8` this follows from `Len::<P>::VALID` and the
        // size of `out`. With a null `iv` it compares the recovered ICV against the default
        // (`0xA6` * 8) and returns `BAD_KEYWRAP_IV_E` on mismatch, `inSz - 8` on success.
        wc_AesKeyUnWrap_ex(
            aes,
            wrapped.as_ptr(), Wrapped::<P>::LEN as u32,
            out.as_mut_ptr(), P as u32,
            ptr::null()
        ) == P as c_int
    });

    if res.is_err() {
        // On an integrity failure `wc_AesKeyUnWrap_ex` has already written the unauthenticated
        // plaintext into `out`, SP 800-38F requires that none of it is released.
        out.zeroize();
    }

    res
}

/// Run `op` with an AES key schedule for `key` in direction `dir`, then free and zero it.
///
/// `wc_AesFree` does not clear the key schedule in our configuration, so the `Aes` is kept on
/// this frame (never moved) and zeroed here (by `free_aes`).
///
/// # Safety
///
/// `key` must be 16, 24 or 32 bytes, `op` must uphold the safety requirements of the
/// `wolfcrypt` functions it calls with the provided pointer.
unsafe fn with_schedule<F>(key: &[u8], dir: c_uint, op: F) -> Res
    where F: FnOnce(*mut AesLL) -> bool
{
    let mut aes = MaybeUninit::<AesLL>::uninit();
    let mut res = Res::new();

    // SAFETY: `wc_AesInit` initializes the `Aes` structure behind a non-null pointer, with no
    // heap and no device (`INVALID_DEVID`).
    res.ensure_0(wc_AesInit(aes.as_mut_ptr(), ptr::null_mut(), INVALID_DEVID));

    if res.is_ok() {
        // SAFETY: the `Aes` is initialized, `key` is a valid AES key length and `wc_AesSetKey`
        // only reads `keySz` bytes of it. A null IV leaves the (unused) IV zeroed.
        res.ensure_0(wc_AesSetKey(
            aes.as_mut_ptr(),
            key.as_ptr(), key.len() as u32,
            ptr::null(),
            dir as c_int
        ));

        if res.is_ok() {
            res.check(op(aes.as_mut_ptr()));
        }

        // SAFETY: the `Aes` was initialized by `wc_AesInit`, it is not used afterwards.
        // `free_aes` frees it and zeroes the key schedule.
        super::free_aes(aes.as_mut_ptr());
    } else {
        // SAFETY: `Aes` is plain C data (integers, byte arrays and nullable raw pointers), for
        // which all-zero bytes are valid; this clears any partial initialization, and it is not
        // used after this.
        zeroize::zeroize_flat_type(aes.as_mut_ptr());
    }

    res
}

/// A wrapped key: the KW ciphertext of a `P` byte key, `P + 8` bytes long.
///
/// This is not secret, it can be stored or transmitted, and parsed back with
/// [`TryFrom<&[u8]>`](#impl-TryFrom<%26%5Bu8%5D>-for-Wrapped<P>).
#[repr(C)]
#[derive(Clone, PartialEq, Eq)]
pub struct Wrapped<const P: usize> {
    // `repr(C)` with only `u8` arrays: `icv` and `body` are contiguous, without padding.
    icv: [u8; SEMIBLOCK],
    body: [u8; P]
}

impl<const P: usize> Wrapped<P> {
    /// The length of the wrapped key in bytes (`P + 8`).
    pub const LEN: usize = P + SEMIBLOCK;

    const LAYOUT: () = assert!(size_of::<Self>() == Self::LEN);

    /// The wrapped key as a byte slice of length [`Self::LEN`].
    #[inline]
    pub const fn as_slice(&self) -> &[u8] {
        let () = Self::LAYOUT;
        // SAFETY: `Self` is `repr(C)` with two `u8` arrays, `LAYOUT` asserts that it is exactly
        // `LEN` bytes without padding, all of them initialized.
        unsafe { core::slice::from_raw_parts(self.as_ptr(), Self::LEN) }
    }

    #[inline]
    const fn as_ptr(&self) -> *const u8 {
        ptr::from_ref(self).cast()
    }

    #[inline]
    const fn as_mut_ptr(&mut self) -> *mut u8 {
        let () = Self::LAYOUT;
        ptr::from_mut(self).cast()
    }
}

impl<const P: usize> AsRef<[u8]> for Wrapped<P> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'a, const P: usize> TryFrom<&'a [u8]> for Wrapped<P> {
    type Error = InvalidSize;

    /// Parse a wrapped key, `value` must be exactly `P + 8` bytes long.
    ///
    /// Whether it is authentic is only known once it is unwrapped.
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let () = Len::<P>::VALID;
        if value.len() != Self::LEN { return Err(InvalidSize) }

        let (icv, body) = value.split_at(SEMIBLOCK);
        Ok(Self {
            icv: icv.try_into().map_err(|_| InvalidSize)?,
            body: body.try_into().map_err(|_| InvalidSize)?
        })
    }
}

impl<const P: usize> Zeroize for Wrapped<P> {
    #[inline]
    fn zeroize(&mut self) {
        self.icv.zeroize();
        self.body.zeroize();
    }
}

impl<const P: usize> fmt::Debug for Wrapped<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Wrapped<{P}>(")?;
        for byte in self.as_slice() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// An unwrapped key of `P` bytes, zeroed on drop.
///
/// It can only be obtained from a successful [`Kek::unwrap`], so its contents are always
/// authenticated.
pub struct Unwrapped<const P: usize> {
    key: [u8; P]
}

impl<const P: usize> Unwrapped<P> {
    /// The unwrapped key material.
    #[inline]
    pub const fn as_array(&self) -> &[u8; P] {
        &self.key
    }

    /// The unwrapped key material as a slice.
    #[inline]
    pub const fn as_slice(&self) -> &[u8] {
        self.key.as_slice()
    }
}

impl<const P: usize> Zeroize for Unwrapped<P> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<const P: usize> Drop for Unwrapped<P> {
    #[inline]
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const P: usize> zeroize::ZeroizeOnDrop for Unwrapped<P> {}

impl<const P: usize> fmt::Debug for Unwrapped<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unwrapped<{P}> {{ ... }}")
    }
}

impl<const N: usize> Zeroize for Kek<N> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<const N: usize> Drop for Kek<N> {
    #[inline]
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const N: usize> zeroize::ZeroizeOnDrop for Kek<N> {}

impl<const N: usize> fmt::Debug for Kek<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Kek<{N}> {{ ... }}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use aes_kw::{KekAes128, KekAes192, KekAes256};

    /// RFC 3394 section 4 test vectors (KEK, key data, ciphertext).
    #[test]
    fn rfc3394() {
        use hex_literal::hex;

        let kek = Kek128::new(hex!("000102030405060708090A0B0C0D0E0F"));
        let w = kek.wrap(&hex!("00112233445566778899AABBCCDDEEFF")).unwrap();
        assert_eq!(w.as_slice(), hex!("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"));

        let kek = Kek192::new(hex!("000102030405060708090A0B0C0D0E0F1011121314151617"));
        let w = kek.wrap(&hex!("00112233445566778899AABBCCDDEEFF0001020304050607")).unwrap();
        assert_eq!(
            w.as_slice(),
            hex!("031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2")
        );

        let kek = Kek256::new(hex!(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
        ));
        let w = kek.wrap(&hex!(
            "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"
        )).unwrap();
        assert_eq!(
            w.as_slice(),
            hex!("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
        );
        assert_eq!(
            kek.unwrap(&w).unwrap().as_array(),
            &hex!("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
        );
    }

    #[test]
    fn layout() {
        assert_eq!(size_of::<Wrapped<16>>(), 24);
        assert_eq!(size_of::<Wrapped<512>>(), 520);
        assert_eq!(Wrapped::<16>::LEN, 24);
    }

    #[test]
    fn try_from_rejects_wrong_lengths() {
        assert!(Wrapped::<16>::try_from([0u8; 23].as_slice()).is_err());
        assert!(Wrapped::<16>::try_from([0u8; 25].as_slice()).is_err());
        assert!(Wrapped::<16>::try_from([0u8; 24].as_slice()).is_ok());
        assert!(Kek128::try_from([0u8; 15].as_slice()).is_err());
        assert!(Kek128::try_from([0u8; 16].as_slice()).is_ok());
    }

    #[test]
    fn integrity_failure_zeroes_output() {
        let kek = Kek256::new([3u8; 32]);
        let mut wrapped = kek.wrap(&[9u8; 32]).unwrap();
        wrapped.body[31] ^= 0x80;

        let mut out = [0x55u8; 32];
        // SAFETY: 32 is a valid KW length, the KEK is an AES-256 key.
        let res = unsafe { unwrap_raw(&kek.key, &wrapped, &mut out) };
        assert!(res.is_err());
        assert_eq!(out, [0u8; 32]);
    }

    #[test]
    fn wrong_kek_fails() {
        let wrapped = Kek128::new([1u8; 16]).wrap(&[2u8; 24]).unwrap();
        assert!(Kek128::new([4u8; 16]).unwrap(&wrapped).is_err());
    }

    macro_rules! cross_check {
        ($name:ident, $kek:ident, $rc:ident, $ksz:literal, $($p:literal),*) => {
            proptest! {
                #![proptest_config(ProptestConfig::with_cases(256))]

                #[test]
                fn $name(kek in any::<[u8; $ksz]>(), seed in any::<[u8; 64]>()) {
                    let ours = $kek::new(kek);
                    let theirs = $rc::from(kek);
                    $({
                        let mut plain = [0u8; $p];
                        for (i, b) in plain.iter_mut().enumerate() {
                            *b = seed[i % seed.len()] ^ (i as u8);
                        }

                        let wrapped = ours.wrap(&plain).unwrap();
                        let mut expected = [0u8; $p + 8];
                        theirs.wrap(&plain, &mut expected).unwrap();
                        prop_assert_eq!(wrapped.as_slice(), expected.as_slice());

                        let unwrapped = ours.unwrap(&wrapped).unwrap();
                        prop_assert_eq!(unwrapped.as_array(), &plain);

                        let mut back = [0u8; $p];
                        theirs.unwrap(wrapped.as_slice(), &mut back).unwrap();
                        prop_assert_eq!(back, plain);
                    })*
                }
            }
        };
    }

    cross_check! { cross_check_128, Kek128, KekAes128, 16, 16, 24, 32, 40, 64, 72 }
    cross_check! { cross_check_192, Kek192, KekAes192, 24, 16, 24, 32, 40, 64, 72 }
    cross_check! { cross_check_256, Kek256, KekAes256, 32, 16, 24, 32, 40, 64, 72 }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn roundtrip(kek in any::<[u8; 32]>(), plain in any::<[u8; 48]>()) {
            let kek = Kek256::new(kek);
            let wrapped = kek.wrap(&plain).unwrap();
            let unwrapped = kek.unwrap(&wrapped).unwrap();
            prop_assert_eq!(unwrapped.as_array(), &plain);
        }

        #[test]
        fn tamper_is_detected(
            kek in any::<[u8; 16]>(),
            plain in any::<[u8; 32]>(),
            bit in 0usize..(40 * 8)
        ) {
            let kek = Kek128::new(kek);
            let wrapped = kek.wrap(&plain).unwrap();

            let mut raw = wrapped.as_slice().to_vec();
            raw[bit / 8] ^= 1 << (bit % 8);
            let tampered = Wrapped::<32>::try_from(raw.as_slice()).unwrap();

            prop_assert!(kek.unwrap(&tampered).is_err());
        }
    }
}
