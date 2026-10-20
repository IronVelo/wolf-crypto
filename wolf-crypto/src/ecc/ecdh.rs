//! Elliptic-Curve Diffie-Hellman (the SP 800-56A rev. 3 ECC CDH primitive).
use core::fmt;
use core::marker::PhantomData;
use core::ptr::{self, addr_of_mut};
use wolf_crypto_sys::{wc_ecc_set_rng, wc_ecc_shared_secret};
use zeroize::Zeroize;
use crate::ecc::{ByteArray, Curve, PrivateKey, PublicKey};
use crate::error::Unspecified;
use crate::opaque_res::Res;
use crate::random::Rng;
use crate::{ct, Fips};
use crate::sealed::FipsSealed;

/// The shared secret `Z` of an ECDH key agreement: the big-endian x-coordinate of `d * Q`
/// (`C::SIZE` bytes).
///
/// `Z` must not be used as a key directly, derive keys from it with a KDF (for example
/// HKDF, `kdf::hkdf`) as SP 800-56C describes.
///
/// This type is neither `Copy` nor `Clone`, its equality is constant-time, and it zeroes its
/// memory on drop.
pub struct SharedSecret<C: Curve> {
    inner: C::Scalar,
    _curve: PhantomData<C>
}

impl<C: Curve> SharedSecret<C> {
    /// The shared secret bytes.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &C::Scalar {
        &self.inner
    }
}

impl<C: Curve> Drop for SharedSecret<C> {
    #[inline]
    fn drop(&mut self) {
        self.inner.as_mut().zeroize();
    }
}

impl<C: Curve> PartialEq for SharedSecret<C> {
    /// Constant-Time Equivalence.
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        ct::ct_eq(self.inner, other.inner)
    }
}

impl<C: Curve> Eq for SharedSecret<C> {}

impl<C: Curve> PartialEq<[u8]> for SharedSecret<C> {
    /// Constant-Time Equivalence.
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        ct::ct_eq(self.inner, other)
    }
}

impl<C: Curve> fmt::Debug for SharedSecret<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret { ... }")
    }
}

impl<C: Curve + Fips> FipsSealed for SharedSecret<C> {}
impl<C: Curve + Fips> Fips for SharedSecret<C> {}

impl<C: Curve> PrivateKey<C> {
    /// Compute the ECC CDH shared secret `Z` with the peer's public key.
    ///
    /// This is the primitive of SP 800-56A rev. 3, section 5.7.1.2 (for the NIST prime curves
    /// the cofactor is 1). The peer's public key was fully validated when the [`PublicKey`]
    /// was constructed. The curve of the peer's key must be the curve of this key, which is
    /// enforced by the type system.
    ///
    /// The `rng` randomizes the scalar multiplication (`ECC_TIMING_RESISTANT`).
    ///
    /// For the ephemeral-unified scheme (`C(2e, 0s)`) prefer [`EphemeralSecret`], which can
    /// only be used once.
    ///
    /// # Errors
    ///
    /// If `wolfcrypt` failed to compute the shared secret.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{ecc::{PrivateKey, P384}, random::Rng};
    ///
    /// let mut rng = Rng::new().unwrap();
    /// let mut alice = PrivateKey::<P384>::generate(&mut rng).unwrap();
    /// let mut bob = PrivateKey::<P384>::generate(&mut rng).unwrap();
    ///
    /// let alice_pub = alice.public_key().unwrap();
    /// let bob_pub = bob.public_key().unwrap();
    ///
    /// assert_eq!(
    ///     alice.diffie_hellman(&bob_pub, &mut rng).unwrap(),
    ///     bob.diffie_hellman(&alice_pub, &mut rng).unwrap()
    /// );
    /// ```
    pub fn diffie_hellman(
        &mut self, peer: &PublicKey<C>, rng: &mut Rng
    ) -> Result<SharedSecret<C>, Unspecified> {
        let mut out = SharedSecret::<C> { inner: C::Scalar::zeroes(), _curve: PhantomData };
        let mut len = C::SIZE as u32;
        let mut res = Res::new();
        // wolfcrypt takes the public key as mutable, work on a private copy.
        let mut peer = peer.key.copy();

        unsafe {
            // SAFETY: Both keys are initialized. The rng pointer is stored in the private key
            // only for the duration of this call: `rng` is mutably borrowed (so neither moved nor
            // used elsewhere) until we clear the pointer again below.
            res.ensure_0(wc_ecc_set_rng(self.key.as_mut_ptr(), rng.as_mut_ptr()));

            // SAFETY: `out` is writable for `len` (`C::SIZE`) bytes, wolfcrypt checks `len`
            // against the field size before writing and updates it to the bytes written. Both
            // keys are on curve `C` (type invariant, wolfcrypt checks the curve ids again).
            if res.is_ok() {
                res.ensure_0(wc_ecc_shared_secret(
                    self.key.as_mut_ptr(),
                    peer.as_mut_ptr(),
                    out.inner.as_mut().as_mut_ptr(),
                    addr_of_mut!(len)
                ));
            }

            // SAFETY: clearing the stored rng pointer, see above.
            let _res = wc_ecc_set_rng(self.key.as_mut_ptr(), ptr::null_mut());
            debug_assert_eq!(_res, 0);
        }
        res.check(len as usize == C::SIZE);

        res.unit_err(out)
    }
}

/// An ephemeral ECDH private key, for the SP 800-56A ephemeral-unified scheme (`C(2e, 0s)`).
///
/// The key agreement consumes the `EphemeralSecret`, so it can be used at most once. It is
/// neither `Copy` nor `Clone`, and it zeroes its memory on drop.
///
/// # Example
///
/// ```
/// use wolf_crypto::{ecc::{EphemeralSecret, PublicKey, P256}, random::Rng};
///
/// let mut rng = Rng::new().unwrap();
///
/// let alice = EphemeralSecret::<P256>::generate(&mut rng).unwrap();
/// let bob = EphemeralSecret::<P256>::generate(&mut rng).unwrap();
///
/// // exchange public keys (validated on import)
/// let alice_pub = PublicKey::<P256>::from_sec1(&alice.public_key().unwrap().to_sec1().unwrap())
///     .unwrap();
/// let bob_pub = PublicKey::<P256>::from_sec1(&bob.public_key().unwrap().to_sec1().unwrap())
///     .unwrap();
///
/// let z_alice = alice.diffie_hellman(&bob_pub, &mut rng).unwrap();
/// let z_bob = bob.diffie_hellman(&alice_pub, &mut rng).unwrap();
///
/// assert_eq!(z_alice, z_bob);
/// ```
///
/// An `EphemeralSecret` cannot be reused:
///
/// ```compile_fail
/// use wolf_crypto::{ecc::{EphemeralSecret, P256}, random::Rng};
///
/// let mut rng = Rng::new().unwrap();
/// let ours = EphemeralSecret::<P256>::generate(&mut rng).unwrap();
/// let theirs = EphemeralSecret::<P256>::generate(&mut rng).unwrap().public_key().unwrap();
///
/// let _first = ours.diffie_hellman(&theirs, &mut rng);
/// let _second = ours.diffie_hellman(&theirs, &mut rng); // does not compile!
/// ```
pub struct EphemeralSecret<C: Curve> {
    inner: PrivateKey<C>
}

impl<C: Curve> EphemeralSecret<C> {
    /// Generate a new ephemeral key pair.
    ///
    /// # Errors
    ///
    /// See [`PrivateKey::generate`].
    #[inline]
    pub fn generate(rng: &mut Rng) -> Result<Self, Unspecified> {
        PrivateKey::generate(rng).map(|inner| Self { inner })
    }

    /// The public key to send to the peer.
    ///
    /// # Errors
    ///
    /// See [`PrivateKey::public_key`].
    #[inline]
    pub fn public_key(&self) -> Result<PublicKey<C>, Unspecified> {
        self.inner.public_key()
    }

    /// Compute the shared secret with the peer's public key, consuming this ephemeral key.
    ///
    /// # Errors
    ///
    /// See [`PrivateKey::diffie_hellman`].
    #[inline]
    pub fn diffie_hellman(
        mut self, peer: &PublicKey<C>, rng: &mut Rng
    ) -> Result<SharedSecret<C>, Unspecified> {
        self.inner.diffie_hellman(peer, rng)
    }
}

impl<C: Curve> fmt::Debug for EphemeralSecret<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EphemeralSecret { ... }")
    }
}

impl<C: Curve + Fips> FipsSealed for EphemeralSecret<C> {}
impl<C: Curve + Fips> Fips for EphemeralSecret<C> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc::{P256, P384};

    fn agreement<C: Curve>() {
        let mut rng = Rng::new().unwrap();
        let mut a = PrivateKey::<C>::generate(&mut rng).unwrap();
        let mut b = PrivateKey::<C>::generate(&mut rng).unwrap();
        let a_pub = a.public_key().unwrap();
        let b_pub = b.public_key().unwrap();

        let z_ab = a.diffie_hellman(&b_pub, &mut rng).unwrap();
        let z_ba = b.diffie_hellman(&a_pub, &mut rng).unwrap();
        assert_eq!(z_ab, z_ba);

        // repeated agreement is deterministic (the rng only blinds)
        assert_eq!(a.diffie_hellman(&b_pub, &mut rng).unwrap(), z_ab);

        let mut c = PrivateKey::<C>::generate(&mut rng).unwrap();
        assert_ne!(c.diffie_hellman(&b_pub, &mut rng).unwrap(), z_ab);
    }

    #[test]
    fn agreement_p256() { agreement::<P256>(); }

    #[test]
    fn agreement_p384() { agreement::<P384>(); }

    #[test]
    fn ephemeral() {
        let mut rng = Rng::new().unwrap();
        let a = EphemeralSecret::<P384>::generate(&mut rng).unwrap();
        let b = EphemeralSecret::<P384>::generate(&mut rng).unwrap();
        let a_pub = a.public_key().unwrap();
        let b_pub = b.public_key().unwrap();
        assert_eq!(
            a.diffie_hellman(&b_pub, &mut rng).unwrap(),
            b.diffie_hellman(&a_pub, &mut rng).unwrap()
        );
    }
}

#[cfg(all(test, not(miri)))]
mod property_tests {
    use super::*;
    use crate::ecc::{P256, P384};
    use proptest::prelude::*;
    use crate::random::Rng;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn symmetry_p256(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
            let mut rng = Rng::new().unwrap();
            let (Ok(mut a), Ok(mut b)) = (
                PrivateKey::<P256>::from_bytes(&a, &mut rng),
                PrivateKey::<P256>::from_bytes(&b, &mut rng)
            ) else { return Ok(()) };

            let a_pub = a.public_key().unwrap();
            let b_pub = b.public_key().unwrap();
            prop_assert_eq!(
                a.diffie_hellman(&b_pub, &mut rng).unwrap(),
                b.diffie_hellman(&a_pub, &mut rng).unwrap()
            );
        }

        #[test]
        fn symmetry_p384(a in any::<[u8; 48]>(), b in any::<[u8; 48]>()) {
            let mut rng = Rng::new().unwrap();
            let (Ok(mut a), Ok(mut b)) = (
                PrivateKey::<P384>::from_bytes(&a, &mut rng),
                PrivateKey::<P384>::from_bytes(&b, &mut rng)
            ) else { return Ok(()) };

            let a_pub = a.public_key().unwrap();
            let b_pub = b.public_key().unwrap();
            prop_assert_eq!(
                a.diffie_hellman(&b_pub, &mut rng).unwrap(),
                b.diffie_hellman(&a_pub, &mut rng).unwrap()
            );
        }

        #[test]
        fn rust_crypto_interop_p256(ours in any::<[u8; 32]>(), theirs in any::<[u8; 32]>()) {
            let mut rng = Rng::new().unwrap();
            let Ok(mut ours) = PrivateKey::<P256>::from_bytes(&ours, &mut rng) else {
                return Ok(())
            };
            let Ok(theirs) = p256::SecretKey::from_slice(&theirs) else { return Ok(()) };

            // RustCrypto's public key, imported and validated by us.
            let their_point = theirs.public_key().to_encoded_point(false);
            let their_pub = PublicKey::<P256>::from_sec1_slice(their_point.as_bytes()).unwrap();

            // our public key, imported by RustCrypto.
            let our_pub = p256::PublicKey::from_sec1_bytes(
                &ours.public_key().unwrap().to_sec1().unwrap()
            ).unwrap();

            let z = ours.diffie_hellman(&their_pub, &mut rng).unwrap();
            let rc_z = p256::ecdh::diffie_hellman(theirs.to_nonzero_scalar(), our_pub.as_affine());
            prop_assert!(z == *rc_z.raw_secret_bytes().as_slice());
        }

        #[test]
        fn rust_crypto_interop_p384(ours in any::<[u8; 48]>(), theirs in any::<[u8; 48]>()) {
            let mut rng = Rng::new().unwrap();
            let Ok(mut ours) = PrivateKey::<P384>::from_bytes(&ours, &mut rng) else {
                return Ok(())
            };
            let Ok(theirs) = p384::SecretKey::from_slice(&theirs) else { return Ok(()) };

            let their_point = p384::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(
                &theirs.public_key(), false
            );
            let their_pub = PublicKey::<P384>::from_sec1_slice(their_point.as_bytes()).unwrap();

            let our_pub = p384::PublicKey::from_sec1_bytes(
                &ours.public_key().unwrap().to_sec1().unwrap()
            ).unwrap();

            let z = ours.diffie_hellman(&their_pub, &mut rng).unwrap();
            let rc_z = p384::ecdh::diffie_hellman(theirs.to_nonzero_scalar(), our_pub.as_affine());
            prop_assert!(z == *rc_z.raw_secret_bytes().as_slice());
        }
    }
}
