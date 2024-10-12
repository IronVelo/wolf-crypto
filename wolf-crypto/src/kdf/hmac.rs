//! The `HMAC` Key Derivation Function (`HKDF`).
//!
//! This module provides an implementation of HKDF as specified in [`RFC 5869`][1]. `HKDF` is a key
//! derivation function based on HMAC, designed to derive one or more secret keys from a master
//! secret key.
//!
//! [1]: https://www.rfc-editor.org/rfc/rfc5869
use wolf_crypto_sys::{wc_HKDF};
use crate::aead::Aad as Additional;
use crate::{can_cast_u32, const_can_cast_u32, Unspecified};
use crate::kdf::{Salt, salt::Empty};

use crate::mac::hmac::algo::{GenericKey, Hash};

/// Performs the `HKDF` operation without input validation.
///
/// # Safety
///
/// This does not perform any input validation.
/// The caller must ensure that all input sizes are valid and can be cast to u32.
#[inline]
unsafe fn hkdf_unchecked<H: Hash>(
    key: impl GenericKey<Size = H::KeyLen>,
    salt: impl Salt<Empty>,
    additional: impl Additional,
    into: &mut [u8]
) {
    debug_assert!(salt.is_valid_size());
    debug_assert!(additional.is_valid_size());
    debug_assert!(can_cast_u32(into.len()));

    // Infallible via types.
    let _res = wc_HKDF(
        H::type_id(),
        key.ptr(),
        key.size(),
        salt.ptr(),
        salt.size(),
        additional.ptr(),
        additional.size(),
        into.as_mut_ptr(),
        into.len() as u32
    );

    debug_assert_eq!(_res, 0);
}

/// Checks if the salt and additional data have valid sizes.
#[inline]
#[must_use]
fn hkdf_predicate<S: Salt<Empty>, A: Additional>(s: &S, a: &A) -> bool {
    s.is_valid_size() && a.is_valid_size()
}

/// Performs HKDF and returns the result as a fixed-size array.
///
/// # Arguments
///
/// * `key` - The input keying material.
/// * `salt` - The salt value (a non-secret random value).
/// * `additional` - Additional input (optional context and application specific information).
///
/// # Returns
///
/// The derived key material with length `KL`.
///
/// # Errors
///
/// - The length of the `salt` was greater than [`u32::MAX`].
/// - The length of the `additional` data was greater than [`u32::MAX`].
/// - The length of the desired key material (`KL`) was greater than [`u32::MAX`].
///
/// # Examples
///
/// ```
/// use wolf_crypto::kdf::{hkdf, Sha256};
///
/// let key = [42u8; 32];
/// let salt = b"salt";
/// let info = b"context information";
///
/// let derived_key = hkdf::<Sha256, 32>(key, salt, info).unwrap();
/// assert_eq!(derived_key.len(), 32);
/// ```
#[inline]
pub fn hkdf<H: Hash, const KL: usize>(
    key: impl GenericKey<Size = H::KeyLen>,
    salt: impl Salt<Empty>,
    additional: impl Additional,
) -> Result<[u8; KL], Unspecified> {
    if hkdf_predicate(&salt, &additional) && const_can_cast_u32::<KL>() {
        let mut out = [0u8; KL];
        unsafe { hkdf_unchecked::<H>(key, salt, additional, out.as_mut_slice()) };
        Ok(out)
    } else {
        Err(Unspecified)
    }
}

/// Performs HKDF and writes the result into the provided output buffer.
///
/// # Arguments
///
/// * `key` - The input keying material.
/// * `salt` - The salt value (a non-secret random value).
/// * `additional` - Additional input (optional context and application specific information).
/// * `output` - The buffer to write the derived key material into.
///
/// # Errors
///
/// - The length of the `salt` was greater than [`u32::MAX`].
/// - The length of the `additional` data was greater than [`u32::MAX`].
/// - The length of the `output` was greater than [`u32::MAX`].
///
/// # Examples
///
/// ```
/// use wolf_crypto::kdf::{hkdf_into, Sha256};
///
/// let key = [42u8; 32];
/// let salt = b"salt";
/// let info = b"context information";
/// let mut output = [0u8; 64];
///
/// hkdf_into::<Sha256>(key, salt, info, &mut output).unwrap();
/// ```
#[inline]
pub fn hkdf_into<H: Hash>(
    key: impl GenericKey<Size = H::KeyLen>,
    salt: impl Salt<Empty>,
    additional: impl Additional,
    output: &mut [u8]
) -> Result<(), Unspecified> {
    if hkdf_predicate(&salt, &additional) && can_cast_u32(output.len()) {
        unsafe { hkdf_unchecked::<H>(key, salt, additional, output) };
        Ok(())
    } else {
        Err(Unspecified)
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use crate::aes::test_utils::BoundList;
    use proptest::prelude::*;
    use hkdf::Hkdf;

    macro_rules! against_rc {
        (
            name: $name:ident,
            cases: $cases:literal,
            algo: $rc_crate:ident :: $algo:ident,
            ds: $ds:literal
        ) => {proptest! {
        #![proptest_config(ProptestConfig::with_cases(5_000))]

        #[test]
        fn $name(
            key in any::<[u8; $ds]>(),
            salt in any::<Option<BoundList<128>>>()
        ) {
            let salt = salt.as_ref().map(BoundList::as_slice);

            let mut rc_out = [0u8; $ds];
            Hkdf::<$rc_crate::$algo>::new(salt, key.as_slice()).expand(b"", rc_out.as_mut_slice()).unwrap();

            let out = hkdf::<$crate::kdf::$algo, { $ds }>(key, salt, ()).unwrap();

            prop_assert_eq!(out, rc_out);
        }
        }};
    }

    against_rc! {
        name: rust_crypto_equivalence_sha224,
        cases: 5000,
        algo: sha2::Sha224,
        ds: 28
    }

    against_rc! {
        name: rust_crypto_equivalence_sha256,
        cases: 5000,
        algo: sha2::Sha256,
        ds: 32
    }

    against_rc! {
        name: rust_crypto_equivalence_sha384,
        cases: 5000,
        algo: sha2::Sha384,
        ds: 48
    }

    against_rc! {
        name: rust_crypto_equivalence_sha512,
        cases: 2500,
        algo: sha2::Sha512,
        ds: 64
    }

    against_rc! {
        name: rust_crypto_equivalence_sha3_224,
        cases: 5000,
        algo: sha3::Sha3_224,
        ds: 28
    }

    against_rc! {
        name: rust_crypto_equivalence_sha3_256,
        cases: 5000,
        algo: sha3::Sha3_256,
        ds: 32
    }

    against_rc! {
        name: rust_crypto_equivalence_sha3_384,
        cases: 5000,
        algo: sha3::Sha3_384,
        ds: 48
    }

    against_rc! {
        name: rust_crypto_equivalence_sha3_512,
        cases: 2500,
        algo: sha3::Sha3_512,
        ds: 64
    }
    
    mod sha1 {
        pub use sha1::Sha1 as Sha;
    }
    
    non_fips! {
        against_rc! {
            name: rust_crypto_equivalence_sha1,
            cases: 10000,
            algo: sha1::Sha,
            ds: 20
        }
        
        against_rc! {
            name: rust_crypto_equivalence_md5,
            cases: 10000,
            algo: md5::Md5,
            ds: 16
        }
    }
}