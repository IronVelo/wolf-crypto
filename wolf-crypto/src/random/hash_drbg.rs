//! The SP 800-90A `Hash_DRBG` behind [`Rng`]: nonce on instantiation, explicit reseeding and the
//! FIPS marker.
//!
//! In our configuration (`HAVE_HASHDRBG`, no `CUSTOM_RAND_GENERATE_BLOCK`, no RDRAND bypass)
//! every `WC_RNG` is a `Hash_DRBG` with SHA-256 at a 256 bit security strength, seeded from the
//! operating system (`wc_GenerateSeed`) and reseeded by `wolfcrypt` after `WC_RESEED_INTERVAL`
//! requests. Before instantiating, and before every automatic reseed, `wolfcrypt` runs its
//! known-answer health test of the mechanism.

use core::mem;
use core::ptr::addr_of_mut;
use wolf_crypto_sys::{wc_InitRngNonce, wc_RNG_DRBG_Reseed, wc_RNG_TestSeed, WC_RNG};
use crate::error::Unspecified;
use crate::opaque_res::Res;
use super::Rng;

/// The security strength of [`Rng`] in bits (`Hash_DRBG` with SHA-256).
pub const SECURITY_STRENGTH: usize = 256;

/// The minimum entropy input for [`Rng::reseed`] in bytes, the security strength.
pub const MIN_ENTROPY_SIZE: usize = SECURITY_STRENGTH / 8;

/// The minimum nonce for [`Rng::with_nonce`] in bytes, half the security strength
/// (SP 800-90A section 8.6.7).
pub const MIN_NONCE_SIZE: usize = SECURITY_STRENGTH / 16;

/// Inputs are passed to `wolfcrypt` as a `word32` length.
const MAX_INPUT_SIZE: usize = u32::MAX as usize;

struct Nonce<const N: usize>;

impl<const N: usize> Nonce<N> {
    const VALID: () = assert!(
        N >= MIN_NONCE_SIZE && N <= MAX_INPUT_SIZE,
        "the Hash_DRBG nonce must be at least 16 bytes (half the security strength)"
    );
}

struct Entropy<const N: usize>;

impl<const N: usize> Entropy<N> {
    const VALID: () = assert!(
        N >= MIN_ENTROPY_SIZE && N <= MAX_INPUT_SIZE,
        "the Hash_DRBG entropy input must be at least 32 bytes (the security strength)"
    );
}

mark_fips! { Rng, Sealed }

impl Rng {
    /// Create a new random bit generator, instantiated with a caller-provided nonce.
    ///
    /// The entropy input still comes from the operating system. `nonce` takes the place of the
    /// nonce `wolfcrypt` would otherwise draw from the entropy source (SP 800-90A section 8.6.7):
    /// it must not repeat across instantiations, e.g. a counter or a timestamp. Anything after
    /// the first 16 bytes acts as a personalization string, as `Hash_DRBG` concatenates both.
    ///
    /// # Errors
    ///
    /// If the underlying random bit generator could not be initialized (failed health test or
    /// entropy source).
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::random::Rng;
    ///
    /// let mut nonce = [0u8; 24];
    /// nonce[..8].copy_from_slice(&42u64.to_be_bytes()); // e.g. a persisted counter
    /// nonce[8..].copy_from_slice(b"my-service-v1\0\0\0");
    ///
    /// let mut rng = Rng::with_nonce(&nonce).unwrap();
    /// assert!(rng.random_array::<32>().is_ok());
    /// ```
    ///
    /// A nonce shorter than 16 bytes does not compile:
    ///
    /// ```compile_fail
    /// use wolf_crypto::random::Rng;
    ///
    /// let rng = Rng::with_nonce(&[0u8; 8]);
    /// ```
    pub fn with_nonce<const N: usize>(nonce: &[u8; N]) -> Result<Self, Unspecified> {
        let () = Nonce::<N>::VALID;

        unsafe {
            let mut res = Res::new();
            let mut wc_rng: WC_RNG = mem::zeroed();

            // SAFETY: `wc_InitRngNonce` initializes the `WC_RNG` behind a non-null pointer. It
            // only reads `nonceSz` bytes of `nonce` (passed on to `Hash_df` as `const byte*`,
            // the parameter is not const in the signature), `N` fits in a `word32` by
            // `Nonce::<N>::VALID`.
            res.ensure_0(wc_InitRngNonce(
                addr_of_mut!(wc_rng),
                nonce.as_ptr().cast_mut(),
                N as u32
            ));

            // SAFETY: as in `Rng::new`, `wc_rng` is initialized if `res` is OK, and its `drbg`
            // pointer is re-anchored by `as_mut_ptr` before every use.
            res.unit_err_with(|| Self { inner: wc_rng })
        }
    }

    /// Reseed the generator with caller-provided entropy (SP 800-90A `Hash_DRBG` reseed).
    ///
    /// `wolfcrypt` already reseeds from the operating system automatically, this is for mixing
    /// in entropy from another source, e.g. a hardware entropy source. For the generator to stay
    /// within FIPS 140-3 requirements the entropy must come from a validated entropy source and
    /// hold at least [`SECURITY_STRENGTH`] bits of entropy.
    ///
    /// The entropy is first checked with `wolfcrypt`'s continuous test for its own seeds
    /// (`wc_RNG_TestSeed`, which rejects adjacent repeated 4 byte words), so a stuck source such
    /// as all-zero input is refused.
    ///
    /// # Errors
    ///
    /// - The entropy failed the continuous test.
    /// - `wolfcrypt` failed to reseed (the DRBG state is then unchanged or the generator is in an
    ///   error state, and further requests fail).
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::random::Rng;
    ///
    /// let mut rng = Rng::new().unwrap();
    /// let entropy: [u8; 48] = Rng::new().unwrap().random_array().unwrap(); // your source here
    ///
    /// assert!(rng.reseed(&entropy).is_ok());
    /// assert!(rng.random_array::<32>().is_ok());
    ///
    /// // a stuck entropy source is rejected
    /// assert!(rng.reseed(&[0u8; 32]).is_err());
    /// ```
    ///
    /// Less than [`MIN_ENTROPY_SIZE`] bytes does not compile:
    ///
    /// ```compile_fail
    /// use wolf_crypto::random::Rng;
    ///
    /// let mut rng = Rng::new().unwrap();
    /// let _ = rng.reseed(&[7u8; 16]);
    /// ```
    pub fn reseed<const N: usize>(&mut self, entropy: &[u8; N]) -> Res {
        let () = Entropy::<N>::VALID;
        let mut res = Res::new();

        unsafe {
            // SAFETY: `wc_RNG_TestSeed` reads `seedSz` bytes of `seed`, and requires
            // `seedSz > SEED_BLOCK_SZ` (4) for its loop bound not to wrap, ensured by
            // `Entropy::<N>::VALID` (`N >= 32`, and `N` fits in a `word32`).
            res.ensure_0(wc_RNG_TestSeed(entropy.as_ptr(), N as u32));

            if res.is_ok() {
                // SAFETY: `as_mut_ptr` anchors the DRBG pointer to this `Rng`'s inline state, which
                // `Rng`'s invariant guarantees to be instantiated. `wc_RNG_DRBG_Reseed` reads
                // `entropySz` bytes of `entropy` and returns 0 (`DRBG_SUCCESS`) on success.
                res.ensure_0(wc_RNG_DRBG_Reseed(self.as_mut_ptr(), entropy.as_ptr(), N as u32));
            }
        }

        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ensure_fips;

    #[test]
    fn rng_is_fips() {
        ensure_fips::<Rng>();
    }

    #[test]
    fn with_nonce_generates() {
        let mut a = Rng::with_nonce(&[1u8; 16]).unwrap();
        let mut b = Rng::with_nonce(&[1u8; 16]).unwrap();
        // same nonce, independent entropy
        assert_ne!(a.random_array::<64>().unwrap(), b.random_array::<64>().unwrap());
    }

    #[test]
    fn reseed_then_generate() {
        let mut rng = Rng::new().unwrap();
        let entropy: [u8; 32] = Rng::new().unwrap().random_array().unwrap();
        let before = rng.random_array::<32>().unwrap();
        assert!(rng.reseed(&entropy).is_ok());
        assert_ne!(before, rng.random_array::<32>().unwrap());
    }

    #[test]
    fn reseed_rejects_stuck_entropy() {
        let mut rng = Rng::new().unwrap();
        assert!(rng.reseed(&[0u8; 32]).is_err());
        assert!(rng.reseed(&[0xAAu8; 64]).is_err());
        // the generator is still usable
        assert!(rng.random_array::<32>().is_ok());
    }

    #[test]
    fn reseed_after_move() {
        fn moved(rng: Rng) -> Rng { rng }

        let mut rng = moved(Rng::with_nonce(&[9u8; 32]).unwrap());
        let entropy: [u8; 32] = Rng::new().unwrap().random_array().unwrap();
        assert!(rng.reseed(&entropy).is_ok());

        let mut rng = moved(rng);
        assert!(rng.random_array::<128>().is_ok());
        assert_eq!(
            rng.inner.drbg.cast::<u8>(),
            addr_of_mut!(rng.inner.drbg_data).cast::<u8>()
        );
    }
}
