//! Known-answer testing of `wolfcrypt`'s `Hash_DRBG` mechanism (SHA-256)
//!
//! [`hash_drbg_sha256`] runs the NIST DRBGVS procedure on a fresh, caller-seeded `Hash_DRBG`
//! instance (`wc_RNG_HealthTest_ex`): instantiate with the given entropy and nonce, optionally
//! reseed, generate twice, and return the second output. This is how [`Rng`](super::Rng)'s
//! mechanism is checked against the NIST CAVP vectors; `wolfcrypt` runs the same procedure on
//! its own vectors before every instantiation and automatic reseed.
//!
//! **This is not a random bit generator.** The output is fully determined by the inputs, it is
//! only meant for conformance testing. Use [`Rng`](super::Rng) to generate random data.
//!
//! # Example
//!
//! ```
//! use wolf_crypto::random::kat::hash_drbg_sha256;
//! use hex_literal::hex;
//!
//! // NIST CAVP Hash_DRBG, [SHA-256], no reseed, COUNT = 0
//! let out = hash_drbg_sha256(
//!     &hex!("a65ad0f345db4e0effe875c3a2e71f42c7129d620ff5c119a9ef55f05185e0fb"),
//!     &hex!("8581f9317517276e06e9607ddbcbcc2e"),
//!     None
//! ).unwrap();
//!
//! assert_eq!(out[..16], hex!("d3e160c35b99f340b2628264d1751060"));
//! ```

use core::ptr;
use wolf_crypto_sys::{wc_RNG_HealthTest_ex, INVALID_DEVID};
use crate::error::Unspecified;
use crate::opaque_res::Res;
use super::hash_drbg::{MIN_ENTROPY_SIZE, MIN_NONCE_SIZE};

/// The output length of [`hash_drbg_sha256`] in bytes (`ReturnedBitsLen = 1024`), the only
/// length `wolfcrypt`'s health test supports.
pub const OUTPUT_SIZE: usize = 128;

#[inline]
const fn valid_len(len: usize, min: usize) -> bool {
    len >= min && crate::can_cast_u32(len)
}

/// Run the DRBGVS known-answer procedure on `Hash_DRBG` with SHA-256.
///
/// Instantiates with `entropy` and `nonce` (no personalization string), reseeds with
/// `reseed_entropy` if given (no additional input), generates [`OUTPUT_SIZE`] bytes twice and
/// returns the second block. This corresponds to the CAVP `Hash_DRBG.rsp` sections
/// `[SHA-256]`, `[PredictionResistance = False]`, `[PersonalizationStringLen = 0]` and
/// `[AdditionalInputLen = 0]`, of the `no_reseed` (without `reseed_entropy`) and `pr_false`
/// (with it) sets.
///
/// # Errors
///
/// - `entropy` or `reseed_entropy` is shorter than the security strength (32 bytes).
/// - `nonce` is shorter than half the security strength (16 bytes).
/// - An input does not fit in a `u32`, or `wolfcrypt` failed.
pub fn hash_drbg_sha256(
    entropy: &[u8],
    nonce: &[u8],
    reseed_entropy: Option<&[u8]>
) -> Result<[u8; OUTPUT_SIZE], Unspecified> {
    let reseed_ok = reseed_entropy.is_none_or(|seed| valid_len(seed.len(), MIN_ENTROPY_SIZE));
    if !(valid_len(entropy.len(), MIN_ENTROPY_SIZE) && valid_len(nonce.len(), MIN_NONCE_SIZE)
        && reseed_ok)
    {
        return Err(Unspecified);
    }

    let (reseed, seed_b, seed_b_len) = reseed_entropy
        .map_or((0, ptr::null(), 0), |seed| (1, seed.as_ptr(), seed.len() as u32));

    let mut out = [0u8; OUTPUT_SIZE];
    let mut res = Res::new();

    unsafe {
        // SAFETY: `wc_RNG_HealthTest_ex` instantiates a Hash_DRBG on its own stack, reading
        // `nonceSz` bytes of `nonce`, `seedASz` of `seedA` and (when `reseed != 0`) `seedBSz`
        // of `seedB`, all checked to fit in a `word32` above. It writes exactly `outputSz`
        // bytes, and requires `outputSz == RNG_HEALTH_TEST_CHECK_SIZE` (128, `OUTPUT_SIZE`).
        // The heap is unused (null) and no device is used (`INVALID_DEVID`). It returns 0 on
        // success and uninstantiates (zeroes) its DRBG in every case.
        res.ensure_0(wc_RNG_HealthTest_ex(
            reseed,
            nonce.as_ptr(), nonce.len() as u32,
            entropy.as_ptr(), entropy.len() as u32,
            seed_b, seed_b_len,
            out.as_mut_ptr(), OUTPUT_SIZE as u32,
            ptr::null_mut(), INVALID_DEVID
        ));
    }

    res.unit_err(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // `wolfcrypt`'s own health test vectors (random.c, `seedA_data`, `reseedSeedA_data` and
    // `outputA_data`), which are CAVP `pr_false` COUNT = 0 with entropy and nonce concatenated.
    #[test]
    fn wolfcrypt_reseed_vector() {
        let out = hash_drbg_sha256(
            &hex!("63363377e41e86468deb0ab4a8ed683f6a134e47e014c700454e81e95358a569"),
            &hex!("808aa38f2a72a62359915a9f8a04ca68"),
            Some(&hex!("e62b8a8ee8f141b6980566e3bfe3c04903dad4ac2cdf9f2280010a6739bc83d3"))
        ).unwrap();

        assert_eq!(out, hex!(
            "04eec63bb231df2c630a1afbe724949d005a587851e1aa795e477347c8b05662"
            "1c18bddcdd8d99fc5fc2b92053d8cfacfb0bb8831205fad1ddd6c071318a6018"
            "f03b73f5ede4d4d071f9de03fd7aea105d9299b8af99aa075bdb4db9aa28c18d"
            "174b56ee2a014d098896ff2282c955a81969e069fa8ce007a180183a07dfae17"
        ));
    }

    #[test]
    fn rejects_short_inputs() {
        assert!(hash_drbg_sha256(&[1u8; 31], &[2u8; 16], None).is_err());
        assert!(hash_drbg_sha256(&[1u8; 32], &[2u8; 15], None).is_err());
        assert!(hash_drbg_sha256(&[1u8; 32], &[2u8; 16], Some(&[3u8; 31])).is_err());
        assert!(hash_drbg_sha256(&[1u8; 32], &[2u8; 16], Some(&[3u8; 32])).is_ok());
    }

    #[test]
    fn deterministic_and_input_sensitive() {
        let a = hash_drbg_sha256(&[1u8; 32], &[2u8; 16], None).unwrap();
        assert_eq!(a, hash_drbg_sha256(&[1u8; 32], &[2u8; 16], None).unwrap());
        assert_ne!(a, hash_drbg_sha256(&[1u8; 32], &[3u8; 16], None).unwrap());
        assert_ne!(a, hash_drbg_sha256(&[1u8; 32], &[2u8; 16], Some(&[4u8; 32])).unwrap());
    }
}
