//! Elliptic-Curve Cryptography over the NIST Prime Curves
//!
//! This module provides key generation, key import and export, ECDH (the SP 800-56A ECC CDH
//! primitive), and ECDSA (FIPS 186-5) over the curves [`P256`] and [`P384`].
//!
//! # Type Safety
//!
//! - The curve is a type parameter of every key, signature, and shared secret, so keys of
//!   different curves cannot be combined: a [`PrivateKey<P256>`] only agrees with a
//!   [`PublicKey<P256>`], and only verifies / produces a [`Signature<P256>`].
//! - All sizes are fixed by the curve: scalars, points, digests and signatures are byte arrays
//!   whose length is determined by the [`Curve`], so a digest of the wrong length (for example a
//!   SHA-384 digest with [`P256`]) does not compile.
//! - A [`PublicKey`] can only be constructed through full public-key validation
//!   (SP 800-56A rev. 3, section 5.6.2.3.3), so every public key used for ECDH or verification
//!   is known to be a valid point of prime order on its curve.
//! - Private keys, [`EphemeralSecret`]s and [`SharedSecret`]s are neither `Copy` nor `Clone`,
//!   and zero their memory on drop. An [`EphemeralSecret`] is consumed by the key agreement,
//!   so it is used at most once.
//!
//! # Example
//!
//! ```
//! use wolf_crypto::{ecc::{PrivateKey, PublicKey, P256}, random::Rng};
//!
//! let mut rng = Rng::new().unwrap();
//!
//! // ECDSA
//! let mut signer = PrivateKey::<P256>::generate(&mut rng).unwrap();
//! let verifier = signer.public_key().unwrap();
//!
//! let sig = signer.sign(b"hello world", &mut rng).unwrap();
//! assert!(verifier.verify(b"hello world", &sig).is_ok());
//! assert!(verifier.verify(b"goodbye world", &sig).is_err());
//!
//! // ECDH
//! let mut alice = PrivateKey::<P256>::generate(&mut rng).unwrap();
//! let mut bob = PrivateKey::<P256>::generate(&mut rng).unwrap();
//!
//! // public keys are sent as uncompressed SEC1 points, and validated on import.
//! let alice_pub = PublicKey::<P256>::from_sec1(&alice.public_key().unwrap().to_sec1().unwrap())
//!     .unwrap();
//! let bob_pub = bob.public_key().unwrap();
//!
//! let z_alice = alice.diffie_hellman(&bob_pub, &mut rng).unwrap();
//! let z_bob = bob.diffie_hellman(&alice_pub, &mut rng).unwrap();
//! assert_eq!(z_alice, z_bob);
//! ```
//!
//! Keys of different curves cannot be used together:
//!
//! ```compile_fail
//! use wolf_crypto::{ecc::{PrivateKey, P256, P384}, random::Rng};
//!
//! let mut rng = Rng::new().unwrap();
//! let mut ours = PrivateKey::<P256>::generate(&mut rng).unwrap();
//! let theirs = PrivateKey::<P384>::generate(&mut rng).unwrap().public_key().unwrap();
//!
//! let _ = ours.diffie_hellman(&theirs, &mut rng); // does not compile!
//! ```
//!
//! Nor can a digest of the wrong size be signed:
//!
//! ```compile_fail
//! use wolf_crypto::{ecc::{PrivateKey, P256}, hash::Sha384, random::Rng};
//!
//! let mut rng = Rng::new().unwrap();
//! let mut key = PrivateKey::<P256>::generate(&mut rng).unwrap();
//! let digest = Sha384::new().unwrap().try_finalize().unwrap(); // 48 bytes
//!
//! let _ = key.sign_digest(&digest, &mut rng); // does not compile!
//! ```

use core::ffi::c_int;
use core::fmt;
use crate::sealed::EccSealed;
use crate::error::Unspecified;

mod key;
mod ecdh;
mod ecdsa;

pub use key::{PrivateKey, PublicKey, PrivateKeyBytes};
pub use ecdh::{SharedSecret, EphemeralSecret};
pub use ecdsa::{Signature, DerSignature};

/// A fixed-size byte array used for the encodings of a [`Curve`].
///
/// This trait is sealed, it is implemented only for the array sizes the supported curves use.
pub trait ByteArray : EccSealed + AsRef<[u8]> + AsMut<[u8]> + Copy {
    /// The length of the array in bytes.
    const LEN: usize;

    #[doc(hidden)]
    #[must_use]
    fn zeroes() -> Self;
}

macro_rules! byte_array {
    ($($sz:literal),* $(,)?) => {
        $(
            impl EccSealed for [u8; $sz] {}
            impl ByteArray for [u8; $sz] {
                const LEN: usize = $sz;

                #[inline]
                fn zeroes() -> Self {
                    [0u8; $sz]
                }
            }
        )*
    };
}

byte_array! { 32, 48, 64, 65, 72, 91, 96, 97, 104, 120 }

/// A NIST prime curve supported by this module.
///
/// This trait is sealed, the only implementations are [`P256`] and [`P384`].
pub trait Curve : EccSealed {
    /// The byte length of a field element and of a scalar.
    const SIZE: usize;

    /// The name of the curve, as in FIPS 186-5 (for example `P-256`).
    const NAME: &'static str;

    #[doc(hidden)]
    const ID: c_int;

    /// A big-endian scalar (`SIZE` bytes), for example a private key.
    type Scalar: ByteArray;

    /// An uncompressed SEC1 point, `0x04 || X || Y` (`1 + 2 * SIZE` bytes).
    type Sec1Point: ByteArray;

    /// The DER `SubjectPublicKeyInfo` (RFC 5480) of a public key with an uncompressed point.
    type Spki: ByteArray;

    /// The digest which is signed with this curve: SHA-256 for [`P256`] and SHA-384 for
    /// [`P384`] (`SIZE` bytes).
    type Digest: ByteArray;

    /// A raw ECDSA signature, `r || s` (`2 * SIZE` bytes).
    type RawSignature: ByteArray;

    /// A buffer large enough to hold the largest DER-encoded ECDSA signature for this curve.
    type DerBuf: ByteArray;

    #[doc(hidden)]
    fn digest(msg: &[u8]) -> Result<Self::Digest, Unspecified>;
}

macro_rules! define_curve {
    (
        $(#[$meta:meta])*
        $name:ident {
            name: $c_name:literal,
            id: $id:ident,
            size: $sz:literal,
            sec1: $sec1:literal,
            spki: $spki:literal,
            sig: $sig:literal,
            der: $der:literal,
            hash: $hash:ident
        }
    ) => {
        $(#[$meta])*
        pub struct $name;

        impl EccSealed for $name {}

        impl Curve for $name {
            const SIZE: usize = $sz;
            const NAME: &'static str = $c_name;
            const ID: c_int = wolf_crypto_sys::$id;

            type Scalar = [u8; $sz];
            type Sec1Point = [u8; $sec1];
            type Spki = [u8; $spki];
            type Digest = [u8; $sz];
            type RawSignature = [u8; $sig];
            type DerBuf = [u8; $der];

            #[inline]
            fn digest(msg: &[u8]) -> Result<Self::Digest, Unspecified> {
                let mut hasher = crate::hash::$hash::new()?;
                hasher.try_update(msg).unit_err(())?;
                hasher.try_finalize()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($c_name)
            }
        }

        mark_fips! { $name, Sealed }
    };
}

define_curve! {
    /// The NIST P-256 curve (`secp256r1`), signing SHA-256 digests.
    P256 {
        name: "P-256",
        id: ecc_curve_id_ECC_SECP256R1,
        size: 32,
        sec1: 65,
        spki: 91,
        sig: 64,
        der: 72,
        hash: Sha256
    }
}

define_curve! {
    /// The NIST P-384 curve (`secp384r1`), signing SHA-384 digests.
    P384 {
        name: "P-384",
        id: ecc_curve_id_ECC_SECP384R1,
        size: 48,
        sec1: 97,
        spki: 120,
        sig: 96,
        der: 104,
        hash: Sha384
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_are_consistent() {
        fn check<C: Curve>() {
            assert_eq!(C::Scalar::LEN, C::SIZE);
            assert_eq!(C::Digest::LEN, C::SIZE);
            assert_eq!(C::Sec1Point::LEN, 1 + 2 * C::SIZE);
            assert_eq!(C::RawSignature::LEN, 2 * C::SIZE);
            // SEQUENCE { INTEGER r, INTEGER s }, each INTEGER at most SIZE + 1 content bytes.
            assert_eq!(C::DerBuf::LEN, 2 + 2 * (2 + C::SIZE + 1));
            assert_eq!(
                unsafe { wolf_crypto_sys::wc_ecc_get_curve_size_from_id(C::ID) },
                C::SIZE as c_int
            );
        }

        check::<P256>();
        check::<P384>();
    }
}
