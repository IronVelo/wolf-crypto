//! Safe Abstractions for using WolfCrypt's Random Number Generator C API
// Why a module dedicated to `random`?
//
// 1. Convenience
//
// Originally, I was considering adding a `Random` type, which acts as a singleton stored in thread
// local storage to alleviate the need for synchronization and add a great deal of convenience for
// applications where the overhead of re-initializing the RNG and cleaning up the RNG once complete
// is not favorable. These applications in general would have to pass around the underlying instance
// themselves, or implement what I am talking about by hand.
//
// I may still make this addition, which is why the `random` module still exists, and if I do make
// this addition, it would be gated behind the `std` feature, as again this existing in the codebase
// could be quite undesirable for embedded applications.
//
// 2. Performance (Needs further review of wolfcrypt)
//
// I have not read too much into the source of wolfcrypt's random bit generator, though I am aware
// of the relevant features.
//
// Wolfcrypt supports using RDRAND on x86_64 processors with this supported, which is great, RDRAND
// and RDSEED are very well-designed and I prefer over ARMs approach and most operating systems
// entropy pools. TLDR it seeds a hardware AES CTR DRBG with the TRNG (which is from thermal noise)
// to spread the TRNG entropy, reseeding at 2^16. Quite good, quite secure.
//
// ARM I am less a fan of, while these issues are purely theoretical, the TRNG is simply not as
// robust. TLDR again, collects entropy from the jitter in a free-running ring oscillator, this
// is less "random" than what physicists consider to be truly random (thermal noise). Quite
// performant though, this would be challenging to exhaust.
//
// Operating system entropy pools are of course worse than both of these from a standpoint of
// security, I very much rather avoid them if the hardware supports random bit generation.
//
// Wolfcrypt (though I have not read the source yet) most likely uses an AES CTR DRBG implementation
// reseeding at the minimum of NIST recommendations given their FIPS 140-3 certificate, and is
// probably quite effective. Sometimes, it can be advantageous to have an RBG in userspace, like
// what wolfcrypt is doing, this is really just balancing security with performance depending on
// the hardware you're running. If with the intel RDRAND feature enabled the userspace DRBG is not
// included I would implement one in Rust using the `aes::ctr` module mixed with this module. Which
// would only be applicable to applications with less stringent compliance requirements or for
// less critical components where performance is more important than security, but a CSPRNG is still
// a requirement.

use wolf_crypto_sys::{
    WC_RNG, wc_InitRng, wc_FreeRng,
    wc_RNG_GenerateBlock,
};
use core::mem;
use core::ptr::addr_of_mut;
use crate::opaque_res::Res;

/// # SAFETY
///
/// The returned `WC_RNG` (position 0 of the returned tuple) is **only initialized if** Res is OK.
/// Using it without guarding against the Res being OK will cause undefined behavior.
#[must_use]
#[inline]
pub(crate) unsafe fn init_rng() -> (WC_RNG, Res) {
    let mut res = Res::new();

    let mut wc_rng: WC_RNG = mem::zeroed();
    res.ensure_0(wc_InitRng(addr_of_mut!(wc_rng)));

    (wc_rng, res)
}

// Exact definition of `MAX_REQUEST_LEN` in wolfcrypt/src/random.c
// See: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/random.c#L217
// See: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf (section 10
// Table 2)
pub const MAX_REQUEST_SIZE: usize = 0x10000usize;

#[inline]
#[must_use]
const fn fill_predicate(byte_len: usize) -> bool {
    byte_len <= MAX_REQUEST_SIZE
}

#[must_use]
const fn fill_predicate_sized<const C: usize>() -> bool {
    C <= MAX_REQUEST_SIZE
}

/// Random Bit Generator
///
/// `Rng` is a safe zero-cost abstraction over wolfcrypt's `WC_RNG`, with a convenient interface
/// for generating key material, initialization vectors, or simply filling some slice with random
/// bytes.
///
/// # Example
///
/// ```
/// use wolf_crypto::{random::Rng, buf::Iv, aes::Key};
///
/// let mut rng = Rng::new().unwrap();
/// let my_iv: Iv = rng.random_array().unwrap().into();
///
/// // or generate a key for AES
/// let my_aes_256_key: Key = rng.random_array::<32>()
///     .unwrap()
///     .into();
/// let my_aes_192_key: Key = rng.random_array::<24>()
///     .unwrap()
///     .into();
/// let my_aes_128_key: Key = rng.random_array::<16>()
///     .unwrap()
///     .into();
///
/// // or simply fill some slice with random bytes
/// let mut buf = [0u8; 64];
/// assert!(rng.try_fill_bytes(buf.as_mut_slice()).is_ok());
/// assert_ne!(buf, [0u8; 64]);
/// #
/// # drop(my_iv); drop(my_aes_256_key); drop(my_aes_192_key); drop(my_aes_128_key);
/// ```
#[repr(transparent)]
pub struct Rng {
    inner: WC_RNG
}

impl Rng {
    /// Create a new random bit generator
    ///
    /// # Errors
    ///
    /// If there was an issue in initializing the underling random bit generator.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{random::Rng, buf::Iv, aes::Key};
    ///
    /// let mut rng = Rng::new().unwrap();
    ///
    /// // generate a key for Aes256
    /// let key: Key = rng.random_array::<32>().unwrap().into();
    /// // and a random initialization vector
    /// let iv: Iv = rng.random_array().unwrap().into();
    ///
    /// // use the key and iv ...
    /// # drop(key);
    /// # drop(iv);
    /// ```
    pub fn new() -> Result<Self, ()> {
        unsafe {
            let (maybe_rng, res) = init_rng();

            // SAFETY:
            //
            // `maybe_rng` is only confirmed to be initialized iff res is OK. It may not be a
            // perfect biconditional, though it is certainly an implication
            // res -> is-init maybe_rng.
            res.unit_err(Self { inner: maybe_rng })
        }
    }

    /// Fill `bytes` with random values
    ///
    /// # Arguments
    ///
    /// * `bytes` - The slice to fill with random values
    ///
    /// # Panics
    ///
    /// - The length of the `bytes` was greater than the NIST DRBG max request length (0x10000)
    /// - The underlying Hash_gen returned `DRBG_CONT_FAILURE`
    /// - Default error. rng’s status originally not ok, or set to `DRBG_FAILED`
    ///
    /// If panicking is unacceptable for your use case, which in general is true, please see the
    /// [`try_fill_bytes`] and [`fill_bytes_sized`] methods.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::random::Rng;
    ///
    /// let mut rng = Rng::new().unwrap();
    /// let mut bytes = [0u8; 64];
    ///
    /// rng.fill_bytes(&mut bytes);
    /// assert_ne!(bytes, [0u8; 64]);
    /// ```
    ///
    /// [`try_fill_bytes`]: Self::try_fill_bytes
    /// [`fill_bytes_sized`]: Self::fill_bytes_sized
    #[cfg(feature = "panic-api")]
    #[track_caller]
    pub fn fill_bytes(&mut self, bytes: &mut [u8]) {
        if self.try_fill_bytes(bytes).is_err() {
            panic!("Failed to invoke `fill_bytes` on input of length: {}", bytes.len());
        }
    }

    /// Fill `bytes` with random values
    ///
    /// # Arguments
    ///
    /// * `bytes` - The slice to fill with random values
    ///
    /// # Errors
    ///
    /// - The length of the `bytes` was greater than the NIST DRBG max request length (0x10000)
    /// - The underlying Hash_gen returned `DRBG_CONT_FAILURE`
    /// - Default error. rng’s status originally not ok, or set to `DRBG_FAILED`
    ///
    /// ```
    /// use wolf_crypto::random::Rng;
    ///
    /// let mut rng = Rng::new().unwrap();
    /// let mut bytes = [0u8; 64];
    ///
    /// assert!(rng.try_fill_bytes(bytes.as_mut_slice()).is_ok());
    /// assert_ne!(bytes, [0u8; 64]);
    /// ```
    #[inline]
    pub fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Res {
        if !fill_predicate(bytes.len()) {
            return Res::ERR
        }

        unsafe {
            // SAFETY: `fill_predicate` ensures that the byte length is less than the
            // NIST DRBG maximum request length. Which is well below where the cast would cause
            // issues.
            self.fill_bytes_unchecked(bytes)
        }
    }

    /// Fill `bytes` with random values
    ///
    /// The advantage of `fill_bytes_sized` over other methods such as [`try_fill_bytes`] is that
    /// the precondition for [`fill_bytes_unchecked`] is checked at compilation time, rather than
    /// runtime.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The array to fill with random values
    ///
    /// # Errors
    ///
    /// - The length of the `bytes` was greater than the NIST DRBG max request length (0x10000)
    /// - The underlying Hash_gen returned `DRBG_CONT_FAILURE`
    /// - Default error. rng’s status originally not ok, or set to `DRBG_FAILED`
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::random::Rng;
    ///
    /// let mut rng = Rng::new().unwrap();
    /// let mut bytes = [0u8; 64];
    ///
    /// assert!(rng.fill_bytes_sized(&mut bytes).is_ok());
    /// assert_ne!(bytes, [0u8; 64]);
    /// ```
    ///
    /// [`try_fill_bytes`]: Self::try_fill_bytes
    /// [`fill_bytes_unchecked`]: Self::fill_bytes_unchecked
    #[inline]
    pub fn fill_bytes_sized<const C: usize>(&mut self, bytes: &mut [u8; C]) -> Res {
        if !fill_predicate_sized::<C>() {
            return Res::ERR
        }

        unsafe {
            // SAFETY: `fill_predicate_sized` ensures that the byte length is less than the
            // NIST DRBG maximum request length. Which is well below where the cast would cause
            // issues.
            self.fill_bytes_unchecked(bytes)
        }
    }

    /// Generate an array of size `C` filled with random bytes.
    ///
    /// # Const Generic
    ///
    /// The constant generic `C` denotes the size of the output array which will be filled with
    /// random bytes.
    ///
    /// # Errors
    ///
    /// - The length of the `bytes` was greater than the NIST DRBG max request length (0x10000)
    /// - The underlying Hash_gen returned `DRBG_CONT_FAILURE`
    /// - Default error. rng’s status originally not ok, or set to `DRBG_FAILED`
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{random::Rng, buf::Iv, aes::Key};
    ///
    /// let mut rng = Rng::new().unwrap();
    ///
    /// // we can create a random array
    /// let array: [u8; 32] = rng.random_array().unwrap();
    /// assert_ne!(array, [0u8; 32]);
    ///
    /// // a random initialization vector
    /// let iv: Iv = rng.random_array().unwrap().into();
    ///
    /// // or a random key (in this case for AES-256)
    /// let key: Key = rng.random_array::<32>().unwrap().into();
    /// #
    /// # drop(key); drop(iv); // no warnings for unused.
    /// ```
    #[inline]
    pub fn random_array<const C: usize>(&mut self) -> Result<[u8; C], ()> {
        if !fill_predicate_sized::<C>() {
            return Err(())
        }

        let mut buf = [0u8; C];
        let res = unsafe {
            // SAFETY: `fill_predicate_sized` ensures that the byte length is less than the
            // NIST DRBG maximum request length. Which is well below where the cast would cause
            // issues.
            self.fill_bytes_unchecked(buf.as_mut_slice())
        };

        res.unit_err(buf)
    }

    /// Fill `bytes` with random values
    ///
    /// # Arguments
    ///
    /// * `bytes` - The slice to fill with random values
    ///
    /// # Safety
    ///
    /// While generally will never be an issue in practice, the length of bytes must not ever
    /// be greater than what can be stored in a `word32`, or in rust terms, a `u32`.
    ///
    /// This is since the length is cast to a `word32` without any checks, in the case that this
    /// overflows, while unlikely, could be problematic.
    #[no_mangle]
    pub unsafe fn fill_bytes_unchecked(&mut self, bytes: &mut [u8]) -> Res {
        let mut res = Res::new();
        let len = bytes.len() as u32;

        res.ensure_0(wc_RNG_GenerateBlock(
            addr_of_mut!(self.inner),
            bytes.as_mut_ptr(),
            len
        ));

        res
    }
}

impl Drop for Rng {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            // SAFETY:
            //
            // We are in the drop implementation, therefore the lifetime of the `Rng` is over.
            // At this point, the `Rng` can no longer be used, which guarantees that it will never
            // be accessed in an uninitialized or partially initialized state.
            //
            // FAILURE SAFETY:
            //
            // We are using the `WOLFSSL_NO_MALLOC` configuration, meaning that the RNG is backed
            // by statically allocated memory, so there should be no heap allocation or deallocation
            // concerns. Therefore, the failure to deallocate the RNG should be highly unlikely or
            // non-existent. This eliminates concerns about dynamic memory failures.
            //
            // Finally, the pointer to `self.inner` is guaranteed not to be null due to the
            // invariant of `Rng`'s structure: it must remain valid for the entire lifetime of the
            // `Rng`. If this pointer were null, it would already indicate undefined behavior
            // earlier in the program. Additionally, in the case of a null pointer, no cleanup would
            // be necessary.

            // We will debug assert this to increase our confidence in these claims post long-term
            // fuzzing.
            debug_assert_eq!(wc_FreeRng(addr_of_mut!(self.inner)), 0);
        }
    }
}

// SAFETY:
// All methods which mutate the underlying `WC_RNG` instance require a mutable reference,
// the only way to obtain a mutable reference across thread boundaries is via synchronization or
// unsafe in Rust (which then would be the user's responsibility).
unsafe impl Send for Rng {}

// SAFETY:
// There is no providing of interior mutability in the `Rng`, all methods which mutate the
// underlying `WC_RNG` instance require a mutable reference, thus making this safe to mark `Sync`.
unsafe impl Sync for Rng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_small() {
        let mut rng = Rng::new().unwrap();
        assert!(rng.random_array::<510>().is_ok());
    }

    #[test]
    fn fill_odd_sizes() {
        // we can use the random array method for convenience.
        let mut rng = Rng::new().unwrap();

        macro_rules! create_many {
            ($rng:ident; $($size:literal),* $(,)?) => {
                $(
                println!("Attempting: {}", $size);
                assert!(
                    $rng.random_array::<$size>().is_ok(),
                    "Creating rand array of size {} failed", $size
                );
                )*
            };
        }

        create_many![
            rng;
            1, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 127, 129, 230, 231, 253, 254, 255, 256,
            511, 512, 513, 530, 639, 721, 1027, 1123
        ];
    }
}