//! Private and public keys for the NIST prime curves.
use core::fmt;
use core::marker::PhantomData;
use core::ptr::{self, addr_of, addr_of_mut};
use core::mem::MaybeUninit;
use wolf_crypto_sys::{
    ecc_key, INVALID_DEVID,
    wc_ecc_init_ex, wc_ecc_free,
    wc_ecc_make_key_ex, wc_ecc_check_key, wc_ecc_make_pub_ex,
    wc_ecc_import_x963_ex, wc_ecc_export_x963,
    wc_ecc_import_private_key_ex, wc_ecc_export_private_only,
    wc_EccPublicKeyToDer, wc_EccPublicKeyDecode,
    wc_ecc_get_curve_id,
};
use zeroize::Zeroize;
use crate::ecc::{ByteArray, Curve};
use crate::error::Unspecified;
use crate::opaque_res::Res;
use crate::random::Rng;
use crate::{ct, can_cast_u32, Fips};
use crate::sealed::FipsSealed;

/// Owned, initialized `ecc_key`.
///
/// # Invariants
///
/// `raw` has been initialized with `wc_ecc_init_ex` and has not been freed.
///
/// # Moving and Copying
///
/// Under this crate's `wolfcrypt` configuration (`WOLFSSL_NO_MALLOC`, `USE_FAST_MATH`, no
/// `ALT_ECC_SIZE`, no `WOLFSSL_SMALL_STACK_CACHE`, no async or hardware back-ends) `ecc_key` is
/// address independent and owns no allocations: its big integers are inline arrays, `dp` points
/// to the static curve table, `heap` is null, and `rng` is only set by this module for the
/// duration of a single call. Moving the key and making bitwise copies of it are therefore
/// sound. This is an assumption on `wolfcrypt`'s internals and is recorded in
/// `wolfcrypt-update-checklist.org`.
#[repr(transparent)]
pub(crate) struct Key {
    raw: ecc_key
}

impl Key {
    /// Initialize a new, empty, `ecc_key`.
    pub(crate) fn new() -> Result<Self, Unspecified> {
        let mut key = MaybeUninit::<ecc_key>::uninit();
        let mut res = Res::new();

        unsafe {
            // SAFETY: `wc_ecc_init_ex` only writes to the provided key (zeroing it and
            // initializing its big integers). We do not use a heap hint nor a device id.
            res.ensure_0(wc_ecc_init_ex(key.as_mut_ptr(), ptr::null_mut(), INVALID_DEVID));

            // SAFETY: the key is only assumed initialized iff `wc_ecc_init_ex` succeeded.
            res.unit_err_with(|| Self { raw: key.assume_init() })
        }
    }

    #[inline]
    pub(crate) const fn as_mut_ptr(&mut self) -> *mut ecc_key {
        addr_of_mut!(self.raw)
    }

    /// Bitwise copy of the key, used to call `wolfcrypt` functions which take a mutable key
    /// (they may write bookkeeping such as `key->state`) from a shared reference.
    ///
    /// The copy zeroes itself on drop, like the original.
    #[inline]
    pub(crate) const fn copy(&self) -> Self {
        // SAFETY: `ecc_key` is plain data under our configuration (see the type docs), so a
        // bitwise copy is an independent, valid, initialized key.
        Self { raw: unsafe { ptr::read(addr_of!(self.raw)) } }
    }

    /// The `wolfcrypt` curve id of this key, or a negative value if the key has no curve.
    #[inline]
    fn curve_id(&self) -> core::ffi::c_int {
        unsafe {
            // SAFETY: `idx` is the public index into wolfcrypt's curve table, set by every
            // import / generation routine, `wc_ecc_get_curve_id` handles invalid indices.
            wc_ecc_get_curve_id(self.raw.idx)
        }
    }
}

// SAFETY: `Key` exclusively owns its `ecc_key`: the only pointers it holds are `dp` (to
// wolfcrypt's immutable, static, curve table), `heap` (always null), and `rng` (only set for the
// duration of a call made through `&mut Key`). Nothing is shared with other `Key`s or threads.
unsafe impl Send for Key {}
// SAFETY: wolfcrypt is only given `&mut Key` (through `as_mut_ptr`), a shared `&Key` is only
// ever read (`copy`, `curve_id`), so concurrent access through shared references is read-only.
unsafe impl Sync for Key {}

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: `raw` is initialized (type invariant), `wc_ecc_free` zeroes the private
            // scalar (`mp_forcezero`) and clears the public point. Under `WOLFSSL_NO_MALLOC`
            // there is nothing to deallocate, so this cannot fail in a way that matters.
            let _res = wc_ecc_free(self.as_mut_ptr());
            debug_assert_eq!(_res, 0);

            // SAFETY: `ecc_key` is a flat C struct for which all zeroes is a valid value
            // (null pointers, zero integers). This additionally clears any bookkeeping.
            zeroize::zeroize_flat_type(self.as_mut_ptr());
        }
    }
}

/// Generate a key pair on the curve `C` into `key`.
fn generate_into<C: Curve>(key: &mut Key, rng: &mut Rng) -> Res {
    let mut res = Res::new();

    unsafe {
        // SAFETY: `key` is initialized, and `rng` is a valid, anchored, `WC_RNG` for the duration
        // of the call (we hold a mutable borrow). `C::SIZE` and `C::ID` describe the same
        // curve, which is in the compiled curve table (`HAVE_ECC384`, `NO_ECC256` not defined).
        res.ensure_0(wc_ecc_make_key_ex(
            rng.as_mut_ptr(), C::SIZE as core::ffi::c_int, key.as_mut_ptr(), C::ID
        ));

        // Full validation of the generated key pair: the public key is on the curve and of
        // order n, and the private key is in [1, n - 1]. `WOLFSSL_VALIDATE_ECC_KEYGEN` (which
        // also performs a pairwise consistency test) cannot be used with `WOLFSSL_NO_MALLOC`,
        // see `wolfcrypt-update-checklist.org`.
        if res.is_ok() {
            res.ensure_0(wc_ecc_check_key(key.as_mut_ptr()));
        }
    }

    res
}

/// Import an uncompressed SEC1 public point for `C` into `key`, without validation.
///
/// # Safety
///
/// The point is not validated, the caller must validate it (`wc_ecc_check_key`) unless it was
/// derived from an already validated key.
unsafe fn import_sec1_unchecked<C: Curve>(key: &mut Key, point: &C::Sec1Point) -> Res {
    let mut res = Res::new();
    // SAFETY: The point's length is `1 + 2 * C::SIZE` (type invariant of `C::Sec1Point`), which
    // `wc_ecc_import_x963_ex` reads at most. The length is far below `u32::MAX`.
    res.ensure_0(wc_ecc_import_x963_ex(
        point.as_ref().as_ptr(),
        C::Sec1Point::LEN as u32,
        key.as_mut_ptr(),
        C::ID
    ));
    res.check(key.curve_id() == C::ID);
    res
}

/// Export the public point of `key` in uncompressed SEC1 form.
fn export_sec1<C: Curve>(key: &Key) -> Result<C::Sec1Point, Unspecified> {
    let mut out = C::Sec1Point::zeroes();
    let mut len = C::Sec1Point::LEN as u32;
    let mut res = Res::new();
    let mut tmp = key.copy();

    unsafe {
        // SAFETY: `out` is writable for `len` bytes, `wc_ecc_export_x963` checks that `len` is
        // large enough for the point (`1 + 2 * size`), writes at most that and updates `len`.
        res.ensure_0(wc_ecc_export_x963(tmp.as_mut_ptr(), out.as_mut().as_mut_ptr(), addr_of_mut!(len)));
    }
    res.check(len as usize == C::Sec1Point::LEN);

    res.unit_err(out)
}

/// An ECC private key on the curve `C`, holding its public key.
///
/// The private key is validated on construction (the scalar is in `[1, n - 1]` and the public
/// key is a valid point of order `n`), it is neither `Copy` nor `Clone`, and its memory is
/// zeroed on drop.
///
/// # Note on Moves
///
/// As with any Rust value, moving a `PrivateKey` may leave copies of its bytes in the previous
/// location (for example on the stack), which are not zeroed. Avoid moving long-lived keys
/// (for example, keep them behind a reference or in a `Box`).
pub struct PrivateKey<C: Curve> {
    pub(crate) key: Key,
    _curve: PhantomData<C>
}

impl<C: Curve> PrivateKey<C> {
    /// Generate a new key pair from the provided [`Rng`].
    ///
    /// The key pair is generated per FIPS 186-5 (Appendix A.2.1, extra random bits), and fully
    /// validated afterwards.
    ///
    /// # Errors
    ///
    /// - The `Rng` failed to produce random bytes.
    /// - Key generation or validation failed.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{ecc::{PrivateKey, P384}, random::Rng};
    ///
    /// let mut rng = Rng::new().unwrap();
    /// let key = PrivateKey::<P384>::generate(&mut rng).unwrap();
    /// # drop(key);
    /// ```
    pub fn generate(rng: &mut Rng) -> Result<Self, Unspecified> {
        let mut key = Key::new()?;
        generate_into::<C>(&mut key, rng).unit_err(Self { key, _curve: PhantomData })
    }

    /// Import a private key from its big-endian scalar, deriving the public key.
    ///
    /// The `rng` is used to randomize the projective coordinates of the scalar multiplication
    /// which derives the public key (timing / side-channel resistance).
    ///
    /// # Errors
    ///
    /// - The scalar is zero, or not less than the order of the curve.
    /// - Deriving the public key failed.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{ecc::{PrivateKey, P256}, random::Rng};
    ///
    /// let mut rng = Rng::new().unwrap();
    /// let key = PrivateKey::<P256>::generate(&mut rng).unwrap();
    ///
    /// let bytes = key.to_bytes().unwrap();
    /// let imported = PrivateKey::<P256>::from_bytes(bytes.as_bytes(), &mut rng).unwrap();
    ///
    /// assert_eq!(imported.public_key().unwrap(), key.public_key().unwrap());
    ///
    /// // zero is not a valid private key
    /// assert!(PrivateKey::<P256>::from_bytes(&[0u8; 32], &mut rng).is_err());
    /// ```
    pub fn from_bytes(scalar: &C::Scalar, rng: &mut Rng) -> Result<Self, Unspecified> {
        let mut key = Key::new()?;
        let mut res = Res::new();

        unsafe {
            // SAFETY: `scalar` is `C::SIZE` bytes (type invariant of `C::Scalar`), which is the
            // length provided. No public key is provided (null, 0), wolfcrypt then only sets the
            // curve and reads the scalar.
            res.ensure_0(wc_ecc_import_private_key_ex(
                scalar.as_ref().as_ptr(), C::SIZE as u32,
                ptr::null(), 0,
                key.as_mut_ptr(), C::ID
            ));

            // SAFETY: the key holds a private scalar for curve `C`, a null `pubOut` stores the
            // public key in the key itself. `rng` is valid and anchored for the call.
            if res.is_ok() {
                res.ensure_0(wc_ecc_make_pub_ex(key.as_mut_ptr(), ptr::null_mut(), rng.as_mut_ptr()));
            }

            // SAFETY: the key is initialized. Checks Q is valid and d in [1, n - 1].
            if res.is_ok() {
                res.ensure_0(wc_ecc_check_key(key.as_mut_ptr()));
            }
        }
        res.check(key.curve_id() == C::ID);

        res.unit_err(Self { key, _curve: PhantomData })
    }

    /// Export the private scalar (big-endian, `C::SIZE` bytes).
    ///
    /// The returned [`PrivateKeyBytes`] zeroes its memory on drop.
    ///
    /// # Errors
    ///
    /// If `wolfcrypt` failed to export the scalar.
    pub fn to_bytes(&self) -> Result<PrivateKeyBytes<C>, Unspecified> {
        let mut out = PrivateKeyBytes::<C> { inner: C::Scalar::zeroes(), _curve: PhantomData };
        let mut len = C::SIZE as u32;
        let mut res = Res::new();
        let mut tmp = self.key.copy();

        unsafe {
            // SAFETY: `out` is writable for `len` (`C::SIZE`) bytes, `wc_ecc_export_private_only`
            // checks `len` against the curve size and writes the left-padded scalar. `tmp` is
            // zeroed on drop.
            res.ensure_0(wc_ecc_export_private_only(
                tmp.as_mut_ptr(), out.inner.as_mut().as_mut_ptr(), addr_of_mut!(len)
            ));
        }
        res.check(len as usize == C::SIZE);

        res.unit_err(out)
    }

    /// Returns the public key of this key pair.
    ///
    /// # Errors
    ///
    /// If `wolfcrypt` failed to export or import the public point.
    pub fn public_key(&self) -> Result<PublicKey<C>, Unspecified> {
        let point = export_sec1::<C>(&self.key)?;
        let mut key = Key::new()?;

        unsafe {
            // SAFETY: the point was derived from this private key, which was fully validated on
            // construction, so it is a valid public key for `C`.
            import_sec1_unchecked::<C>(&mut key, &point)
                .unit_err(PublicKey { key, _curve: PhantomData })
        }
    }
}

impl<C: Curve> fmt::Debug for PrivateKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey<")?;
        f.write_str(C::NAME)?;
        f.write_str("> { ... }")
    }
}

impl<C: Curve + Fips> FipsSealed for PrivateKey<C> {}
impl<C: Curve + Fips> Fips for PrivateKey<C> {}

/// The exported scalar of a [`PrivateKey`].
///
/// This type is neither `Copy` nor `Clone`, and zeroes its memory on drop.
pub struct PrivateKeyBytes<C: Curve> {
    inner: C::Scalar,
    _curve: PhantomData<C>
}

impl<C: Curve> PrivateKeyBytes<C> {
    /// The big-endian private scalar.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &C::Scalar {
        &self.inner
    }
}

impl<C: Curve> Drop for PrivateKeyBytes<C> {
    #[inline]
    fn drop(&mut self) {
        self.inner.as_mut().zeroize();
    }
}

impl<C: Curve> fmt::Debug for PrivateKeyBytes<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKeyBytes { ... }")
    }
}

/// A validated ECC public key on the curve `C`.
///
/// A `PublicKey` can only be obtained from a [`PrivateKey`] or through full public-key
/// validation (SP 800-56A rev. 3, section 5.6.2.3.3: not the point at infinity, coordinates in
/// range, on the curve, and of order `n`).
pub struct PublicKey<C: Curve> {
    pub(crate) key: Key,
    _curve: PhantomData<C>
}

impl<C: Curve> PublicKey<C> {
    /// Import and validate an uncompressed SEC1 point (`0x04 || X || Y`).
    ///
    /// # Errors
    ///
    /// - The encoding is not an uncompressed point.
    /// - The point fails full public-key validation.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{ecc::{PrivateKey, PublicKey, P256}, random::Rng};
    ///
    /// let mut rng = Rng::new().unwrap();
    /// let public = PrivateKey::<P256>::generate(&mut rng).unwrap().public_key().unwrap();
    ///
    /// let point = public.to_sec1().unwrap();
    /// assert_eq!(PublicKey::<P256>::from_sec1(&point).unwrap(), public);
    ///
    /// // a point which is not on the curve is rejected
    /// let mut bad = point;
    /// bad[64] ^= 1;
    /// assert!(PublicKey::<P256>::from_sec1(&bad).is_err());
    /// ```
    pub fn from_sec1(point: &C::Sec1Point) -> Result<Self, Unspecified> {
        let mut key = Key::new()?;
        let mut res = Res::new();

        // explicit, so that wolfcrypt's handling of other point types is irrelevant.
        res.check(point.as_ref()[0] == 0x04);

        unsafe {
            if res.is_ok() {
                // SAFETY: the point is validated immediately below.
                res.ensure(import_sec1_unchecked::<C>(&mut key, point));
            }

            // SAFETY: the key is initialized. Performs full public key validation.
            if res.is_ok() {
                res.ensure_0(wc_ecc_check_key(key.as_mut_ptr()));
            }
        }

        res.unit_err(Self { key, _curve: PhantomData })
    }

    /// Import and validate an uncompressed SEC1 point from a slice.
    ///
    /// # Errors
    ///
    /// - The slice's length is not `1 + 2 * C::SIZE`.
    /// - See [`from_sec1`](Self::from_sec1).
    pub fn from_sec1_slice(point: &[u8]) -> Result<Self, Unspecified> {
        if point.len() != C::Sec1Point::LEN { return Err(Unspecified) }
        let mut buf = C::Sec1Point::zeroes();
        buf.as_mut().copy_from_slice(point);
        Self::from_sec1(&buf)
    }

    /// Export the public key as an uncompressed SEC1 point (`0x04 || X || Y`).
    ///
    /// # Errors
    ///
    /// If `wolfcrypt` failed to export the point.
    pub fn to_sec1(&self) -> Result<C::Sec1Point, Unspecified> {
        export_sec1::<C>(&self.key)
    }

    /// Import and validate a DER-encoded `SubjectPublicKeyInfo` (RFC 5480), for example a
    /// pinned raw public key.
    ///
    /// The algorithm must be `id-ecPublicKey` with the named curve `C` (explicit curve
    /// parameters are rejected), the point must be uncompressed, and the input must contain
    /// nothing but the `SubjectPublicKeyInfo`.
    ///
    /// # Errors
    ///
    /// - The DER is malformed, has trailing data, or names a different curve.
    /// - The point fails full public-key validation.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{ecc::{PrivateKey, PublicKey, P256, P384}, random::Rng};
    ///
    /// let mut rng = Rng::new().unwrap();
    /// let public = PrivateKey::<P384>::generate(&mut rng).unwrap().public_key().unwrap();
    ///
    /// let spki = public.to_spki_der().unwrap();
    /// assert_eq!(PublicKey::<P384>::from_spki_der(&spki).unwrap(), public);
    ///
    /// // the curve is part of the encoding
    /// assert!(PublicKey::<P256>::from_spki_der(&spki).is_err());
    /// ```
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Unspecified> {
        if !can_cast_u32(der.len()) { return Err(Unspecified) }

        let mut key = Key::new()?;
        let mut res = Res::new();
        let mut idx = 0u32;

        unsafe {
            // SAFETY: `der` is readable for `der.len()` bytes, which fits in a u32 (checked
            // above), `wc_EccPublicKeyDecode` never reads past `inSz` and advances `idx` by the
            // amount consumed.
            res.ensure_0(wc_EccPublicKeyDecode(
                der.as_ptr(), addr_of_mut!(idx), key.as_mut_ptr(), der.len() as u32
            ));
        }

        // no trailing data, and the named curve must be `C`.
        res.check(idx as usize == der.len());
        res.check(key.curve_id() == C::ID);

        unsafe {
            // SAFETY: the key is initialized. Performs full public key validation.
            if res.is_ok() {
                res.ensure_0(wc_ecc_check_key(key.as_mut_ptr()));
            }
        }

        res.unit_err(Self { key, _curve: PhantomData })
    }

    /// Export the public key as a DER-encoded `SubjectPublicKeyInfo` (RFC 5480), with the named
    /// curve and an uncompressed point.
    ///
    /// # Errors
    ///
    /// If `wolfcrypt` failed to encode the key.
    pub fn to_spki_der(&self) -> Result<C::Spki, Unspecified> {
        let mut out = C::Spki::zeroes();
        let mut tmp = self.key.copy();
        let mut res = Res::new();

        let written = unsafe {
            // SAFETY: `out` is writable for `C::Spki::LEN` bytes, the length provided.
            // `wc_EccPublicKeyToDer` checks the output length and returns the number of bytes
            // written, or a negative error.
            wc_EccPublicKeyToDer(tmp.as_mut_ptr(), out.as_mut().as_mut_ptr(), C::Spki::LEN as u32, 1)
        };
        res.check(written as usize == C::Spki::LEN);

        res.unit_err(out)
    }
}

impl<C: Curve> Clone for PublicKey<C> {
    #[inline]
    fn clone(&self) -> Self {
        Self { key: self.key.copy(), _curve: PhantomData }
    }
}

impl<C: Curve> PartialEq for PublicKey<C> {
    /// Compares the encoded points (in constant time, though public keys are not secret).
    fn eq(&self, other: &Self) -> bool {
        match (self.to_sec1(), other.to_sec1()) {
            (Ok(a), Ok(b)) => ct::ct_eq(a, b),
            _ => false
        }
    }
}

impl<C: Curve> Eq for PublicKey<C> {}

impl<C: Curve> fmt::Debug for PublicKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey<")?;
        f.write_str(C::NAME)?;
        f.write_str("> { ... }")
    }
}

impl<C: Curve + Fips> FipsSealed for PublicKey<C> {}
impl<C: Curve + Fips> Fips for PublicKey<C> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc::{P256, P384};

    fn keygen_roundtrip<C: Curve>() {
        let mut rng = Rng::new().unwrap();
        let key = PrivateKey::<C>::generate(&mut rng).unwrap();
        let public = key.public_key().unwrap();

        let bytes = key.to_bytes().unwrap();
        let imported = PrivateKey::<C>::from_bytes(bytes.as_bytes(), &mut rng).unwrap();
        assert_eq!(imported.public_key().unwrap(), public);

        let sec1 = public.to_sec1().unwrap();
        assert_eq!(sec1.as_ref()[0], 0x04);
        assert_eq!(PublicKey::<C>::from_sec1(&sec1).unwrap(), public);
        assert_eq!(PublicKey::<C>::from_sec1_slice(sec1.as_ref()).unwrap(), public);

        let spki = public.to_spki_der().unwrap();
        assert_eq!(PublicKey::<C>::from_spki_der(spki.as_ref()).unwrap(), public);
    }

    #[test]
    fn keygen_roundtrip_p256() { keygen_roundtrip::<P256>(); }

    #[test]
    fn keygen_roundtrip_p384() { keygen_roundtrip::<P384>(); }

    #[test]
    fn keys_survive_moves() {
        // `Key` must be address independent, move keys and the rng around between uses.
        let mut rng = Rng::new().unwrap();
        let key = PrivateKey::<P256>::generate(&mut rng).unwrap();
        let mut keys = [None, None];
        keys[1] = Some(key);
        let key = keys[1].take().unwrap();
        let mut rngs = [Rng::new().unwrap(), rng];
        let public = key.public_key().unwrap();
        let bytes = key.to_bytes().unwrap();
        let again = PrivateKey::<P256>::from_bytes(bytes.as_bytes(), &mut rngs[1]).unwrap();
        assert_eq!(again.public_key().unwrap(), public);
    }

    #[test]
    fn rejects_invalid_scalars() {
        let mut rng = Rng::new().unwrap();
        assert!(PrivateKey::<P256>::from_bytes(&[0u8; 32], &mut rng).is_err());
        assert!(PrivateKey::<P256>::from_bytes(&[0xffu8; 32], &mut rng).is_err());
        assert!(PrivateKey::<P384>::from_bytes(&[0u8; 48], &mut rng).is_err());
        assert!(PrivateKey::<P384>::from_bytes(&[0xffu8; 48], &mut rng).is_err());

        // n itself is out of range, n - 1 is the largest valid scalar.
        let mut n = hex_literal::hex!(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
        );
        assert!(PrivateKey::<P256>::from_bytes(&n, &mut rng).is_err());
        n[31] -= 1;
        assert!(PrivateKey::<P256>::from_bytes(&n, &mut rng).is_ok());

        let one = {
            let mut one = [0u8; 32];
            one[31] = 1;
            one
        };
        let key = PrivateKey::<P256>::from_bytes(&one, &mut rng).unwrap();
        // 1 * G = G
        let g = hex_literal::hex!(
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        );
        assert_eq!(key.public_key().unwrap().to_sec1().unwrap(), g);
    }

    #[test]
    fn rejects_invalid_points() {
        // the identity / point at infinity cannot be encoded as uncompressed, all zero is not on
        // the curve.
        let mut zero = [0u8; 65];
        assert!(PublicKey::<P256>::from_sec1(&zero).is_err());
        zero[0] = 0x04;
        assert!(PublicKey::<P256>::from_sec1(&zero).is_err());

        let mut rng = Rng::new().unwrap();
        let point = PrivateKey::<P256>::generate(&mut rng).unwrap()
            .public_key().unwrap()
            .to_sec1().unwrap();

        // compressed / hybrid / unknown prefixes
        for prefix in [0x00, 0x02, 0x03, 0x05, 0x06, 0x07] {
            let mut p = point;
            p[0] = prefix;
            assert!(PublicKey::<P256>::from_sec1(&p).is_err());
        }

        // off curve
        let mut p = point;
        p[1] ^= 0x80;
        assert!(PublicKey::<P256>::from_sec1(&p).is_err());

        // wrong length
        assert!(PublicKey::<P256>::from_sec1_slice(&point[..64]).is_err());
        assert!(PublicKey::<P384>::from_sec1_slice(&point).is_err());
    }

    #[test]
    fn coordinate_out_of_range() {
        // x = p, which is congruent to 0 and out of the range [0, p - 1].
        let mut p = [0u8; 65];
        p[0] = 0x04;
        p[1..33].copy_from_slice(&hex_literal::hex!(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
        ));
        // any y, this must fail the range check (and, after reduction, the curve check).
        p[33..].copy_from_slice(&hex_literal::hex!(
            "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4"
        ));
        assert!(PublicKey::<P256>::from_sec1(&p).is_err());
    }

    #[test]
    fn spki_rejects_trailing_and_truncated() {
        let mut rng = Rng::new().unwrap();
        let public = PrivateKey::<P256>::generate(&mut rng).unwrap().public_key().unwrap();
        let spki = public.to_spki_der().unwrap();

        let mut long = [0u8; 92];
        long[..91].copy_from_slice(&spki);
        assert!(PublicKey::<P256>::from_spki_der(&long).is_err());
        assert!(PublicKey::<P256>::from_spki_der(&spki[..90]).is_err());
        assert!(PublicKey::<P256>::from_spki_der(&[]).is_err());
        assert!(PublicKey::<P384>::from_spki_der(&spki).is_err());
    }

    #[test]
    fn spki_matches_rust_crypto() {
        use p256::pkcs8::{EncodePublicKey, DecodePublicKey};

        let mut rng = Rng::new().unwrap();
        let public = PrivateKey::<P256>::generate(&mut rng).unwrap().public_key().unwrap();
        let spki = public.to_spki_der().unwrap();

        let rc = p256::PublicKey::from_public_key_der(&spki).unwrap();
        assert_eq!(
            rc.to_public_key_der().unwrap().as_bytes(),
            spki.as_slice()
        );

        let public = PrivateKey::<P384>::generate(&mut rng).unwrap().public_key().unwrap();
        let spki = public.to_spki_der().unwrap();
        let rc = p384::PublicKey::from_public_key_der(&spki).unwrap();
        assert_eq!(rc.to_public_key_der().unwrap().as_bytes(), spki.as_slice());
    }
}

#[cfg(all(test, not(miri)))]
mod property_tests {
    use super::*;
    use crate::ecc::{P256, P384};
    use proptest::prelude::*;
    use crate::random::Rng;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn import_export_roundtrip_p256(seed in any::<[u8; 32]>()) {
            let mut rng = Rng::new().unwrap();
            // most 256-bit strings are valid scalars, invalid ones must be rejected cleanly.
            if let Ok(key) = PrivateKey::<P256>::from_bytes(&seed, &mut rng) {
                let exported = key.to_bytes().unwrap();
                prop_assert_eq!(exported.as_bytes(), &seed);

                let public = key.public_key().unwrap();
                let sec1 = public.to_sec1().unwrap();
                prop_assert_eq!(&PublicKey::<P256>::from_sec1(&sec1).unwrap(), &public);
                let spki = public.to_spki_der().unwrap();
                prop_assert_eq!(&PublicKey::<P256>::from_spki_der(&spki).unwrap(), &public);

                // same public key as RustCrypto
                let rc = p256::SecretKey::from_slice(&seed).unwrap();
                let rc_point = p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(
                    &rc.public_key(), false
                );
                prop_assert_eq!(rc_point.as_bytes(), sec1.as_slice());
            } else {
                prop_assert!(p256::SecretKey::from_slice(&seed).is_err());
            }
        }

        #[test]
        fn import_export_roundtrip_p384(seed in any::<[u8; 48]>()) {
            let mut rng = Rng::new().unwrap();
            if let Ok(key) = PrivateKey::<P384>::from_bytes(&seed, &mut rng) {
                let exported = key.to_bytes().unwrap();
                prop_assert_eq!(exported.as_bytes(), &seed);

                let public = key.public_key().unwrap();
                let sec1 = public.to_sec1().unwrap();
                prop_assert_eq!(&PublicKey::<P384>::from_sec1(&sec1).unwrap(), &public);
                let spki = public.to_spki_der().unwrap();
                prop_assert_eq!(&PublicKey::<P384>::from_spki_der(&spki).unwrap(), &public);

                let rc = p384::SecretKey::from_slice(&seed).unwrap();
                let rc_point = p384::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(
                    &rc.public_key(), false
                );
                prop_assert_eq!(rc_point.as_bytes(), sec1.as_slice());
            } else {
                prop_assert!(p384::SecretKey::from_slice(&seed).is_err());
            }
        }

        #[test]
        fn random_points_rejected_p256(point in any::<[u8; 64]>()) {
            // random coordinates are on the curve with negligible probability.
            let mut sec1 = [0u8; 65];
            sec1[0] = 0x04;
            sec1[1..].copy_from_slice(&point);
            prop_assert!(PublicKey::<P256>::from_sec1(&sec1).is_err());
        }
    }
}
