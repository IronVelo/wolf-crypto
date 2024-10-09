//! Hashed-Based Message Authentication Codes `HMAC`.

pub mod algo;

#[doc(inline)]
pub use algo::{
    Sha224, Sha256, Sha384, Sha512, 
    Sha3_224, Sha3_256, Sha3_384, Sha3_512,
    Sha, Md5,

    KeySlice
};

use algo::GenericKey;
use crate::ct;

use wolf_crypto_sys::{
    Hmac as wc_Hmac,
    wc_HmacSetKey, wc_HmacUpdate, wc_HmacFree, wc_HmacFinal,
};

use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;
use crate::{can_cast_u32, const_can_cast_u32, Unspecified};
use crate::buf::InvalidSize;
use crate::mac::hmac::algo::Digest as DigestT;

/// Utility wrapper around the final `HMAC` hash.
#[must_use]
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct Digest<D: algo::Digest> {
    raw: D
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
        ct::cmp_slice(self.raw.as_ref(), other.raw.as_ref()) != 0
    }
}

impl<D: algo::Digest> Eq for Digest<D> {}

impl<D: algo::Digest> PartialEq<[u8]> for Digest<D> {
    /// Constant-Time Equivalence.
    fn eq(&self, other: &[u8]) -> bool {
        ct::cmp_slice(self.raw.as_ref(), other) != 0
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

/// Hashed-Based Message Authentication Codes `HMAC`.
///
/// # Generic `H`
///
/// This denotes which hashing function you wish to use under the hood. Options are:
///
/// - `Sha224`
/// - `Sha256`
/// - `Sha384`
/// - `Sha512`
/// - `Sha3_224`
/// - `Sha3_256`
/// - `Sha3_384`
/// - `Sha3_512`
///
/// ### Non-FIPS / Legacy
///
/// - `Md5`
/// - `Sha` (`SHA-1`)
/// 
/// # Example
/// 
/// ```
/// use wolf_crypto::mac::hmac::{Hmac, Sha256};
/// 
/// # fn main() -> Result<(), wolf_crypto::Unspecified> {
/// let mut hmac = Hmac::<Sha256>::new([42u8; 32]);
/// 
/// hmac.update(b"hello world, ")?;
/// hmac.update(b"beautiful weather.")?;
/// 
/// let parts = hmac.finalize();
/// 
/// let mut hmac = Hmac::<Sha256>::new([42u8; 32]);
/// 
/// hmac.update(b"hello world, beautiful weather.")?;
/// 
/// let all = hmac.finalize();
/// 
/// assert_eq!(parts, all);
/// # Ok(()) }
#[repr(transparent)]
pub struct Hmac<H: algo::Hash> {
    inner: wc_Hmac,
    _algo: PhantomData<H>
}

impl<H: algo::Hash> Hmac<H> {
    /// Create a new `Hmac` instance.
    ///
    /// # Arguments
    ///
    /// * `key` - The key material to initialize the `Hmac` instance with. This can be the size of
    ///   the digest or greater (for example, `Sha256` means a 256-bit (32 byte) or larger key).
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::hmac::{Hmac, Sha3_512, KeySlice}, MakeOpaque};
    ///
    /// // we can provide the exact size of our digest:
    /// let hmac = Hmac::<Sha3_512>::new([42u8; 64]);
    ///
    /// // or we can provide a larger key, however this does not
    /// // come with much benefit.
    /// let hmac = KeySlice::new(&[42u8; 128])
    ///     .opaque_map(Hmac::<Sha3_512>::new)
    ///     .unwrap();
    /// ```
    pub fn new<K>(key: K) -> Self
        where K: GenericKey<Size = H::KeyLen>
    {
        let mut inner = MaybeUninit::<wc_Hmac>::uninit();

        unsafe {
            // INFALLIBLE
            //
            // With our current configuration, even with FIPS 140-3 enabled, this is completely
            // infallible. The possible failures are OOM, invalid type ID, and for FIPS 140-3 the
            // key not being at least the FIPS standard of 14 bytes.
            //
            // We use the no malloc configuration, so OOM is not of concern, all the type IDs
            // are from the wolfcrypt constants, and the generic H only includes enabled hashing
            // functions so all type IDs are valid. Our minimum key size for invoking new is
            // the hash functions digest length, pursuant to the RFC2104 section 3 recommendations.
            //
            // So, this function is infallible under all possible paths.
            let _res = wc_HmacSetKey(
                inner.as_mut_ptr(),
                H::type_id(),
                key.ptr(),
                key.size()
            );

            debug_assert_eq!(_res, 0);

            // If the provided key was owned zero the memory.
            key.cleanup();

            Self { inner: inner.assume_init(), _algo: PhantomData }
        }
    }

    /// Updates the message to authenticate using `HMAC`, without performing any safety checks.
    ///
    /// # Arguments
    ///
    /// * `data` - The buffer containing the message to append.
    ///
    /// # Safety
    ///
    /// The length of `data` must not be greater than [`u32::MAX`].
    #[inline]
    unsafe fn update_unchecked(&mut self, data: &[u8]) -> &mut Self {
        debug_assert!(can_cast_u32(data.len()));

        // Infallible
        //
        // The infallibility of wc_HmacUpdate depends on the underlying hash functions
        // infallibility for updates. Which as outlined in the hash module infallibility commentary,
        // these all are to be considered infallible.
        //
        // Then, there's the basic preconditions which the type system and borrow checker ensure
        // are satisfied.
        let _res = wc_HmacUpdate(
            addr_of_mut!(self.inner),
            data.as_ptr(),
            data.len() as u32
        );

        debug_assert_eq!(_res, 0);

        self
    }

    /// Updates the message to authenticate using `HMAC`.
    ///
    /// # Arguments
    ///
    /// * `data` - The buffer containing the message to append.
    ///
    /// # Errors
    ///
    /// If the length of `data` is greater than [`u32::MAX`].
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::hmac::{Hmac, Sha3_256}, ct_eq};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let mut hmac = Hmac::<Sha3_256>::new([42; 32]);
    /// hmac.update("hello world".as_bytes())?;
    ///
    /// let out = hmac.finalize();
    ///
    /// let mut hmac = Hmac::<Sha3_256>::new([42; 32]);
    /// hmac.update("hello world".as_bytes())?;
    ///
    /// let other = hmac.finalize();
    ///
    /// // Always check in constant-time!! (Digest does this for us)
    /// assert_eq!(out, other);
    /// # Ok(()) }
    /// ```
    pub fn update(&mut self, data: &[u8]) -> Result<&mut Self, Unspecified> {
        if can_cast_u32(data.len()) {
            Ok(unsafe { self.update_unchecked(data) })
        } else {
            Err(Unspecified)
        }
    }

    /// Updates the message to authenticate using `HMAC`.
    ///
    /// The distinction between this and [`update`] is that the safety checks are performed over
    /// the constant `C`, thus during compilation time.
    ///
    /// # Arguments
    ///
    /// * `data` - The fixed-size buffer containing the message to append.
    ///
    /// # Errors
    ///
    /// If the length of `data` is greater than [`u32::MAX`].
    ///
    /// [`update`]: Self::update
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::mac::hmac::{Hmac, Sha3_256};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let mut hmac = Hmac::<Sha3_256>::new([42; 32]);
    /// hmac.update_sized(b"hello world")?;
    ///
    /// // It is generally recommended to use `finalize` instead.
    /// let mut out = [0u8; 32];
    /// hmac.finalize_into(&mut out);
    ///
    /// let mut hmac = Hmac::<Sha3_256>::new([42; 32]);
    /// hmac.update_sized(b"hello world")?;
    ///
    /// // Always check in constant-time!!
    /// assert!(hmac.compare_digest(&out));
    /// # Ok(()) }
    /// ```
    pub fn update_sized<const C: usize>(&mut self, data: &[u8; C]) -> Result<&mut Self, Unspecified> {
        if const_can_cast_u32::<C>() {
            Ok(unsafe { self.update_unchecked(data) })
        } else {
            Err(Unspecified)
        }
    }

    /// Compute the final hash of the `HMAC` instance's message into the `output` pointer.
    /// 
    /// # Arguments
    /// 
    /// * `output` - The pointer to write the underlying hash function's digest to.
    /// 
    /// # Safety
    /// 
    /// The output pointer must be valid for writes and non-null for the length of the underlying
    /// hash functions digest.
    #[inline(always)]
    unsafe fn finalize_imp(mut self, output: *mut u8) {
        debug_assert!(!output.is_null());
        unsafe {
            // INFALLIBLE
            //
            // See hash module commentary on all the associated hashing algorithms' final functions.
            let _res = wc_HmacFinal(
                addr_of_mut!(self.inner),
                output
            );

            debug_assert_eq!(_res, 0);
        }
    }

    /// Compute the final hash of the `HMAC` instance's message into the `output` buffer.
    /// 
    /// # Arguments
    /// 
    /// * `output` - The buffer to write the digest to.
    ///
    /// # Note
    ///
    /// It is generally recommended to use [`finalize`] in favor of this, as mistakes happen,
    /// [`finalize`]'s returned [`Digest`] type can help prevent these mistakes.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::mac::hmac::{Hmac, Sha3_256};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let mut hmac = Hmac::<Sha3_256>::new([42; 32]);
    /// hmac.update(b"hello world")?;
    ///
    /// let mut out = [0u8; 32];
    /// hmac.finalize_into(&mut out);
    ///
    /// let mut hmac = Hmac::<Sha3_256>::new([42; 32]);
    /// hmac.update(b"hello world")?;
    ///
    /// // Always check in constant-time!!
    /// assert!(hmac.compare_digest(&out));
    /// # Ok(()) }
    /// ```
    ///
    /// [`finalize`]: Self::finalize
    #[inline]
    pub fn finalize_into(self, output: &mut H::Digest) {
        unsafe { self.finalize_imp(output.ptr()); }
    }
    
    /// Compute the final hash of the `HMAC` instance's message into the `output` buffer.
    ///
    /// # Arguments
    /// 
    /// * `output` - The buffer to write the digest to.
    /// 
    /// # Errors
    /// 
    /// If the length of `output` is less than the result of [`size`] (the digest size) for the
    /// underlying hashing function.
    ///
    /// # Note
    ///
    /// It is generally recommended to use [`finalize`] in favor of this, as mistakes happen,
    /// [`finalize`]'s returned [`Digest`] type can help prevent these mistakes.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::hmac::{Hmac, Sha3_256}, ct_eq};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let mut hmac = Hmac::<Sha3_256>::new([42; 32]);
    /// hmac.update(b"hello world")?;
    ///
    /// let mut out = [0u8; 32];
    /// hmac.finalize_into_slice(out.as_mut_slice())?;
    ///
    /// let mut hmac = Hmac::<Sha3_256>::new([42; 32]);
    /// hmac.update(b"hello world")?;
    ///
    /// let mut other = [0u8; 32];
    /// hmac.finalize_into_slice(other.as_mut_slice())?;
    ///
    /// // Always check in constant-time!!
    /// // (either using the Digest type or ct_eq directly)
    /// assert_eq!(ct_eq(&out, &other), 1);
    /// # Ok(()) }
    /// ```
    ///
    /// [`finalize`]: Self::finalize
    /// [`size`]: algo::Digest::size
    pub fn finalize_into_slice(self, output: &mut [u8]) -> Result<(), InvalidSize> {
        if output.len() >= <H::Digest as algo::Digest>::size() as usize {
            unsafe { self.finalize_imp(output.as_mut_ptr()); }
            Ok(())
        } else {
            Err(InvalidSize)
        }
    }
    
    /// Compute the final hash of the `HMAC` instance's message.
    /// 
    /// # Returns
    /// 
    /// The resulting final digest for the underlying hash function. The type returned ([`Digest`])
    /// has `PartialEq` utilities which all are in constant-time.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::hmac::{Hmac, Sha3_256}, ct_eq};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let mut hmac = Hmac::<Sha3_256>::new([42; 32]);
    /// hmac.update(b"hello world")?;
    ///
    /// let out = hmac.finalize();
    ///
    /// let mut hmac = Hmac::<Sha3_256>::new([42; 32]);
    /// hmac.update(b"hello world")?;
    ///
    /// let other = hmac.finalize();
    ///
    /// // Always check in constant-time!! (Digest does this for us)
    /// assert_eq!(out, other);
    /// # Ok(()) }
    /// ```
    #[inline]
    pub fn finalize(self) -> Digest<H::Digest> {
        let mut out = <H::Digest as algo::Digest>::zeroes();
        unsafe { self.finalize_imp(out.ptr()) };
        Digest::new(out)
    }

    /// Ensure that `other` is equivalent to the current message in constant-time.
    ///
    /// # Arguments
    ///
    /// * `other` - The digest to compare with.
    ///
    /// # Returns
    ///
    /// `true` if the digests were equivalent, `false` otherwise.
    ///
    /// # Note
    ///
    /// If you do not have a fixed size buffer of the digest size, see [`compare_digest_slice`]. Or,
    /// you can use the [`finalize`] method which returns a type who's `PartialEq` implementations
    /// are all in constant-time.
    ///
    /// [`compare_digest_slice`]: Self::compare_digest_slice
    /// [`finalize`]: Self::finalize
    #[must_use]
    pub fn compare_digest(self, other: &H::Digest) -> bool {
        let finalized = self.finalize();
        ct::cmp_slice(finalized.as_ref(), other.as_ref()) != 0
    }

    /// Ensure that `other` is equivalent to the current message in constant-time.
    ///
    /// # Arguments
    ///
    /// * `other` - The digest to compare with.
    ///
    /// # Returns
    ///
    /// `true` if the digests were equivalent, `false` otherwise.
    pub fn compare_digest_slice(self, other: &[u8]) -> bool {
        let finalized = self.finalize();
        ct::cmp_slice(finalized.as_ref(), other) != 0
    }
}

impl<H: algo::Hash> Drop for Hmac<H> {
    #[inline]
    fn drop(&mut self) {
        unsafe { wc_HmacFree(addr_of_mut!(self.inner)); }
    }
}