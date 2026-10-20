//! ECDSA (FIPS 186-5) signature generation and verification.
use core::fmt;
use core::marker::PhantomData;
use core::convert::TryFrom;
use core::ptr::addr_of_mut;
use wolf_crypto_sys::{
    wc_ecc_sign_hash, wc_ecc_verify_hash,
    wc_ecc_rs_raw_to_sig, wc_ecc_sig_to_rs,
};
use crate::ecc::{ByteArray, Curve, PrivateKey, PublicKey};
use crate::error::Unspecified;
use crate::opaque_res::Res;
use crate::random::Rng;
use crate::buf::InvalidSize;
use crate::{can_cast_u32, Fips};
use crate::sealed::FipsSealed;

/// A raw ECDSA signature for the curve `C`: the big-endian integers `r || s`, each `C::SIZE`
/// bytes.
///
/// A `Signature` is not checked on construction, `r` and `s` out of the range `[1, n - 1]`
/// simply fail verification.
pub struct Signature<C: Curve> {
    raw: C::RawSignature,
    _curve: PhantomData<C>
}

impl<C: Curve> Signature<C> {
    /// Create a `Signature` from raw `r || s`.
    #[inline]
    pub const fn new(raw: C::RawSignature) -> Self {
        Self { raw, _curve: PhantomData }
    }

    /// The raw signature, `r || s`.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &C::RawSignature {
        &self.raw
    }

    /// Unwrap the raw signature, `r || s`.
    #[inline]
    #[must_use]
    pub const fn into_inner(self) -> C::RawSignature {
        self.raw
    }

    /// The big-endian `r` component (`C::SIZE` bytes).
    #[inline]
    #[must_use]
    pub fn r(&self) -> &[u8] {
        &self.raw.as_ref()[..C::SIZE]
    }

    /// The big-endian `s` component (`C::SIZE` bytes).
    #[inline]
    #[must_use]
    pub fn s(&self) -> &[u8] {
        &self.raw.as_ref()[C::SIZE..]
    }

    /// Decode an ASN.1 DER `ECDSA-Sig-Value` (`SEQUENCE { r INTEGER, s INTEGER }`).
    ///
    /// # Errors
    ///
    /// - The input is not a valid DER encoding of the signature.
    /// - `r` or `s` does not fit in `C::SIZE` bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{ecc::{PrivateKey, Signature, P256}, random::Rng};
    ///
    /// let mut rng = Rng::new().unwrap();
    /// let mut key = PrivateKey::<P256>::generate(&mut rng).unwrap();
    ///
    /// let sig = key.sign(b"hello world", &mut rng).unwrap();
    /// let der = sig.to_der().unwrap();
    ///
    /// assert_eq!(Signature::<P256>::from_der(der.as_ref()).unwrap(), sig);
    /// ```
    pub fn from_der(der: &[u8]) -> Result<Self, Unspecified> {
        if !can_cast_u32(der.len()) { return Err(Unspecified) }

        let mut r = C::Scalar::zeroes();
        let mut s = C::Scalar::zeroes();
        let mut r_len = C::SIZE as u32;
        let mut s_len = C::SIZE as u32;
        let mut res = Res::new();

        unsafe {
            // SAFETY: `der` is readable for `der.len()` bytes (fits in a u32, checked above). `r`
            // and `s` are writable for `C::SIZE` bytes each, the lengths provided, wolfcrypt
            // fails if either integer does not fit and sets the lengths to the bytes written.
            res.ensure_0(wc_ecc_sig_to_rs(
                der.as_ptr(), der.len() as u32,
                r.as_mut().as_mut_ptr(), addr_of_mut!(r_len),
                s.as_mut().as_mut_ptr(), addr_of_mut!(s_len)
            ));
        }
        res.check(r_len as usize <= C::SIZE && s_len as usize <= C::SIZE);

        // re-encode and compare, so that only the canonical (DER, not BER) encoding is accepted
        // and trailing data is rejected.
        res.unit_err_with(|| {
            let mut raw = C::RawSignature::zeroes();
            let (raw_r, raw_s) = raw.as_mut().split_at_mut(C::SIZE);
            // left-pad, wolfcrypt writes the minimal big-endian encoding.
            raw_r[C::SIZE - r_len as usize..].copy_from_slice(&r.as_ref()[..r_len as usize]);
            raw_s[C::SIZE - s_len as usize..].copy_from_slice(&s.as_ref()[..s_len as usize]);
            Self::new(raw)
        }).and_then(|sig| {
            let canonical = sig.to_der()?;
            if canonical.as_ref() == der { Ok(sig) } else { Err(Unspecified) }
        })
    }

    /// Encode as an ASN.1 DER `ECDSA-Sig-Value` (`SEQUENCE { r INTEGER, s INTEGER }`).
    ///
    /// # Errors
    ///
    /// If `wolfcrypt` failed to encode the signature.
    pub fn to_der(&self) -> Result<DerSignature<C>, Unspecified> {
        let mut out = DerSignature::<C> { buf: C::DerBuf::zeroes(), len: 0, _curve: PhantomData };
        let mut len = C::DerBuf::LEN as u32;
        let mut res = Res::new();

        unsafe {
            // SAFETY: `r` and `s` are `C::SIZE` bytes each, the lengths provided. The output is
            // writable for `len` bytes, the largest possible encoding for `C`, wolfcrypt checks
            // this bound and sets `len` to the bytes written.
            res.ensure_0(wc_ecc_rs_raw_to_sig(
                self.r().as_ptr(), C::SIZE as u32,
                self.s().as_ptr(), C::SIZE as u32,
                out.buf.as_mut().as_mut_ptr(), addr_of_mut!(len)
            ));
        }
        res.check(len as usize <= C::DerBuf::LEN);
        out.len = len as usize;

        res.unit_err(out)
    }
}

impl<C: Curve> Clone for Signature<C> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: Curve> Copy for Signature<C> {}

impl<C: Curve> PartialEq for Signature<C> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.raw.as_ref() == other.raw.as_ref()
    }
}

impl<C: Curve> Eq for Signature<C> {}

impl<C: Curve> fmt::Debug for Signature<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signature<")?;
        f.write_str(C::NAME)?;
        f.write_str("> { r: ")?;
        for b in self.r() { write!(f, "{b:02x}")?; }
        f.write_str(", s: ")?;
        for b in self.s() { write!(f, "{b:02x}")?; }
        f.write_str(" }")
    }
}

impl<C: Curve> AsRef<[u8]> for Signature<C> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.raw.as_ref()
    }
}

impl<C: Curve> TryFrom<&[u8]> for Signature<C> {
    type Error = InvalidSize;

    /// Create a `Signature` from a raw `r || s` slice of `2 * C::SIZE` bytes.
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != C::RawSignature::LEN { return Err(InvalidSize) }
        let mut raw = C::RawSignature::zeroes();
        raw.as_mut().copy_from_slice(value);
        Ok(Self::new(raw))
    }
}

impl<C: Curve + Fips> FipsSealed for Signature<C> {}
impl<C: Curve + Fips> Fips for Signature<C> {}

/// A DER-encoded ECDSA signature (`ECDSA-Sig-Value`), see [`Signature::to_der`].
pub struct DerSignature<C: Curve> {
    buf: C::DerBuf,
    len: usize,
    _curve: PhantomData<C>
}

impl<C: Curve> DerSignature<C> {
    /// The DER encoding.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf.as_ref()[..self.len]
    }
}

impl<C: Curve> AsRef<[u8]> for DerSignature<C> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<C: Curve> Clone for DerSignature<C> {
    #[inline]
    fn clone(&self) -> Self {
        Self { buf: self.buf, len: self.len, _curve: PhantomData }
    }
}

impl<C: Curve> fmt::Debug for DerSignature<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DerSignature(")?;
        for b in self.as_slice() { write!(f, "{b:02x}")?; }
        f.write_str(")")
    }
}

impl<C: Curve + Fips> FipsSealed for DerSignature<C> {}
impl<C: Curve + Fips> Fips for DerSignature<C> {}

impl<C: Curve> PrivateKey<C> {
    /// Sign a digest computed by the caller.
    ///
    /// The digest must be the output of the hash function matching the curve, SHA-256 for
    /// [`P256`](crate::ecc::P256) and SHA-384 for [`P384`](crate::ecc::P384), its size is
    /// enforced by the type system. The per-message secret `k` is generated with the `rng`.
    ///
    /// # Errors
    ///
    /// - The `rng` failed.
    /// - `wolfcrypt` failed to produce the signature.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{ecc::{PrivateKey, P256}, hash::Sha256, random::Rng};
    ///
    /// let mut rng = Rng::new().unwrap();
    /// let mut key = PrivateKey::<P256>::generate(&mut rng).unwrap();
    ///
    /// let mut hasher = Sha256::new().unwrap();
    /// assert!(hasher.try_update(b"hello world").is_ok());
    /// let digest = hasher.try_finalize().unwrap();
    ///
    /// let sig = key.sign_digest(&digest, &mut rng).unwrap();
    /// assert!(key.public_key().unwrap().verify_digest(&digest, &sig).is_ok());
    /// ```
    pub fn sign_digest(
        &mut self, digest: &C::Digest, rng: &mut Rng
    ) -> Result<Signature<C>, Unspecified> {
        let mut der = C::DerBuf::zeroes();
        let mut der_len = C::DerBuf::LEN as u32;
        let mut res = Res::new();

        unsafe {
            // SAFETY: the digest is `C::SIZE` bytes, the length provided. `der` is writable for
            // `der_len` bytes, the largest encoding for `C` (`wc_ecc_sig_size`), wolfcrypt
            // checks the bound and sets `der_len` to the bytes written. `rng` is valid and
            // anchored for the duration of the call, the key is initialized and on curve `C`.
            res.ensure_0(wc_ecc_sign_hash(
                digest.as_ref().as_ptr(), C::SIZE as u32,
                der.as_mut().as_mut_ptr(), addr_of_mut!(der_len),
                rng.as_mut_ptr(),
                self.key.as_mut_ptr()
            ));
        }
        res.check(der_len as usize <= C::DerBuf::LEN);

        if res.is_err() { return Err(Unspecified) }
        Signature::from_der(&der.as_ref()[..der_len as usize])
    }

    /// Hash the message with the hash function matching the curve (SHA-256 for
    /// [`P256`](crate::ecc::P256), SHA-384 for [`P384`](crate::ecc::P384)) and sign the digest.
    ///
    /// # Errors
    ///
    /// - The message is longer than `u32::MAX` bytes.
    /// - See [`sign_digest`](Self::sign_digest).
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{ecc::{PrivateKey, P384}, random::Rng};
    ///
    /// let mut rng = Rng::new().unwrap();
    /// let mut key = PrivateKey::<P384>::generate(&mut rng).unwrap();
    ///
    /// let sig = key.sign(b"hello world", &mut rng).unwrap();
    /// assert!(key.public_key().unwrap().verify(b"hello world", &sig).is_ok());
    /// ```
    #[inline]
    pub fn sign(&mut self, msg: &[u8], rng: &mut Rng) -> Result<Signature<C>, Unspecified> {
        let digest = C::digest(msg)?;
        self.sign_digest(&digest, rng)
    }
}

impl<C: Curve> PublicKey<C> {
    /// Verify a signature over a digest computed by the caller.
    ///
    /// The digest must be the output of the hash function matching the curve, SHA-256 for
    /// [`P256`](crate::ecc::P256) and SHA-384 for [`P384`](crate::ecc::P384).
    ///
    /// # Returns
    ///
    /// An OK [`Res`] if and only if the signature is valid.
    pub fn verify_digest(&self, digest: &C::Digest, sig: &Signature<C>) -> Res {
        let Ok(der) = sig.to_der() else { return Res::ERR };
        let mut tmp = self.key.copy();
        let mut stat: core::ffi::c_int = 0;
        let mut res = Res::new();

        unsafe {
            // SAFETY: `der` is readable for its length (at most `C::DerBuf::LEN`), the digest is
            // `C::SIZE` bytes, the length provided. `stat` is written with 1 iff the signature
            // is valid. wolfcrypt writes bookkeeping (`state`) to the key, so a private copy is
            // used.
            res.ensure_0(wc_ecc_verify_hash(
                der.as_slice().as_ptr(), der.len as u32,
                digest.as_ref().as_ptr(), C::SIZE as u32,
                addr_of_mut!(stat),
                tmp.as_mut_ptr()
            ));
        }
        res.check(stat == 1);

        res
    }

    /// Hash the message with the hash function matching the curve (SHA-256 for
    /// [`P256`](crate::ecc::P256), SHA-384 for [`P384`](crate::ecc::P384)) and verify the
    /// signature over the digest.
    ///
    /// # Returns
    ///
    /// An OK [`Res`] if and only if the message could be hashed and the signature is valid.
    pub fn verify(&self, msg: &[u8], sig: &Signature<C>) -> Res {
        C::digest(msg).map_or(Res::ERR, |digest| self.verify_digest(&digest, sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc::{P256, P384};

    fn sign_verify<C: Curve>() {
        let mut rng = Rng::new().unwrap();
        let mut key = PrivateKey::<C>::generate(&mut rng).unwrap();
        let public = key.public_key().unwrap();

        let sig = key.sign(b"hello world", &mut rng).unwrap();
        assert!(public.verify(b"hello world", &sig).is_ok());
        assert!(public.verify(b"hello world!", &sig).is_err());

        // signatures are randomized
        let other = key.sign(b"hello world", &mut rng).unwrap();
        assert_ne!(sig, other);
        assert!(public.verify(b"hello world", &other).is_ok());

        // another key
        let public2 = PrivateKey::<C>::generate(&mut rng).unwrap().public_key().unwrap();
        assert!(public2.verify(b"hello world", &sig).is_err());

        // der roundtrip
        let der = sig.to_der().unwrap();
        assert_eq!(Signature::<C>::from_der(der.as_ref()).unwrap(), sig);

        // zero signature
        let zero = Signature::<C>::new(C::RawSignature::zeroes());
        assert!(public.verify(b"hello world", &zero).is_err());

        // raw slice
        assert_eq!(Signature::<C>::try_from(sig.as_ref()).unwrap(), sig);
        assert!(Signature::<C>::try_from(&sig.as_ref()[1..]).is_err());
    }

    #[test]
    fn sign_verify_p256() { sign_verify::<P256>(); }

    #[test]
    fn sign_verify_p384() { sign_verify::<P384>(); }

    #[test]
    fn der_rejects_malformed() {
        let mut rng = Rng::new().unwrap();
        let mut key = PrivateKey::<P256>::generate(&mut rng).unwrap();
        let sig = key.sign(b"hello", &mut rng).unwrap();
        let der = sig.to_der().unwrap();
        let der = der.as_slice();

        assert!(Signature::<P256>::from_der(&[]).is_err());
        assert!(Signature::<P256>::from_der(&der[..der.len() - 1]).is_err());

        let mut trailing = [0u8; 80];
        trailing[..der.len()].copy_from_slice(der);
        assert!(Signature::<P256>::from_der(&trailing[..=der.len()]).is_err());

        // a P-384 sized integer does not fit P-256
        let mut key384 = PrivateKey::<P384>::generate(&mut rng).unwrap();
        let big = key384.sign(b"hello", &mut rng).unwrap().to_der().unwrap();
        assert!(Signature::<P256>::from_der(big.as_ref()).is_err());

        // non-minimal integer encoding (BER, not DER): r = 0x00 0x01
        let ber = [0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01];
        assert!(Signature::<P256>::from_der(&ber).is_err());
        let ok = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        let parsed = Signature::<P256>::from_der(&ok).unwrap();
        assert_eq!(parsed.r()[31], 1);
        assert_eq!(parsed.s()[31], 1);
    }
}

#[cfg(all(test, not(miri)))]
mod property_tests {
    use super::*;
    use crate::ecc::{P256, P384};
    use proptest::prelude::*;
    use crate::random::Rng;

    macro_rules! ecdsa_props {
        ($mod:ident, $curve:ident, $rc:ident, $sz:literal) => {
            mod $mod {
                use super::*;
                use $rc::ecdsa::signature::hazmat::PrehashVerifier;
                use $rc::ecdsa::signature::Verifier;

                proptest! {
                    #![proptest_config(ProptestConfig::with_cases(32))]

                    #[test]
                    fn sign_verify_roundtrip(
                        msg in proptest::collection::vec(any::<u8>(), 0..512)
                    ) {
                        let mut rng = Rng::new().unwrap();
                        let mut key = PrivateKey::<$curve>::generate(&mut rng).unwrap();
                        let public = key.public_key().unwrap();
                        let sig = key.sign(&msg, &mut rng).unwrap();

                        prop_assert!(public.verify(&msg, &sig).is_ok());
                        let der = sig.to_der().unwrap();
                        prop_assert_eq!(Signature::<$curve>::from_der(der.as_ref()).unwrap(), sig);
                    }

                    #[test]
                    fn rejects_tampered_message(
                        msg in proptest::collection::vec(any::<u8>(), 1..512),
                        idx in any::<usize>(),
                        flip in 1u8..=255
                    ) {
                        let mut rng = Rng::new().unwrap();
                        let mut key = PrivateKey::<$curve>::generate(&mut rng).unwrap();
                        let public = key.public_key().unwrap();
                        let sig = key.sign(&msg, &mut rng).unwrap();

                        let mut tampered = msg.clone();
                        let idx = idx % tampered.len();
                        tampered[idx] ^= flip;
                        prop_assert!(public.verify(&tampered, &sig).is_err());

                        // extending the message also breaks the signature
                        let mut longer = msg.clone();
                        longer.push(0);
                        prop_assert!(public.verify(&longer, &sig).is_err());
                    }

                    #[test]
                    fn rejects_tampered_signature(
                        msg in proptest::collection::vec(any::<u8>(), 0..512),
                        idx in 0usize..(2 * $sz),
                        flip in 1u8..=255
                    ) {
                        let mut rng = Rng::new().unwrap();
                        let mut key = PrivateKey::<$curve>::generate(&mut rng).unwrap();
                        let public = key.public_key().unwrap();
                        let sig = key.sign(&msg, &mut rng).unwrap();

                        let mut raw = sig.into_inner();
                        raw[idx] ^= flip;
                        prop_assert!(public.verify(&msg, &Signature::new(raw)).is_err());
                    }

                    #[test]
                    fn rust_crypto_verifies_ours(
                        msg in proptest::collection::vec(any::<u8>(), 0..512)
                    ) {
                        let mut rng = Rng::new().unwrap();
                        let mut key = PrivateKey::<$curve>::generate(&mut rng).unwrap();
                        let point = key.public_key().unwrap().to_sec1().unwrap();
                        let sig = key.sign(&msg, &mut rng).unwrap();

                        let vk = $rc::ecdsa::VerifyingKey::from_sec1_bytes(&point).unwrap();
                        let rc_sig = $rc::ecdsa::Signature::from_slice(sig.as_ref()).unwrap();
                        prop_assert!(vk.verify(&msg, &rc_sig).is_ok());

                        let rc_der = $rc::ecdsa::DerSignature::try_from(
                            sig.to_der().unwrap().as_ref()
                        ).unwrap();
                        prop_assert!(vk.verify(&msg, &rc_der).is_ok());

                        let digest = <$curve as Curve>::digest(&msg).unwrap();
                        prop_assert!(vk.verify_prehash(&digest, &rc_sig).is_ok());
                    }

                    #[test]
                    fn we_verify_rust_crypto(
                        msg in proptest::collection::vec(any::<u8>(), 0..512),
                        secret in any::<[u8; $sz]>()
                    ) {
                        use $rc::ecdsa::signature::Signer;

                        let Ok(sk) = $rc::ecdsa::SigningKey::from_slice(&secret) else {
                            return Ok(())
                        };
                        let rc_sig: $rc::ecdsa::Signature = sk.sign(&msg);
                        let point = sk.verifying_key().to_encoded_point(false);

                        let public = PublicKey::<$curve>::from_sec1_slice(point.as_bytes())
                            .unwrap();
                        let sig = Signature::<$curve>::try_from(rc_sig.to_bytes().as_slice())
                            .unwrap();
                        prop_assert!(public.verify(&msg, &sig).is_ok());

                        let der = rc_sig.to_der();
                        let from_der = Signature::<$curve>::from_der(der.as_bytes()).unwrap();
                        prop_assert_eq!(from_der, sig);

                        let mut tampered = msg.clone();
                        tampered.push(1);
                        prop_assert!(public.verify(&tampered, &sig).is_err());
                    }
                }
            }
        };
    }

    ecdsa_props! { p256_props, P256, p256, 32 }
    ecdsa_props! { p384_props, P384, p384, 48 }
}
