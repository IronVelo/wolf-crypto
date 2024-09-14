use wolf_crypto_sys::{
    Blake2b as wc_Blake2b,
    wc_InitBlake2b_WithKey,
    wc_InitBlake2b, wc_Blake2bUpdate,
    wc_Blake2bFinal
};
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;
use crate::opaque_res::Res;
use crate::{const_lte, const_can_cast_u32, can_cast_u32, gte, const_gte, lte};

/// The `Blake2b` hasher.
///
/// # Soundness Note
///
/// In the underlying `wolfcrypt` source, the `blake2b_final` function includes a comment
/// [`/* Is this correct? */`][1], which may raise concern about its implementation.
/// However, we have subjected this Rust API to extensive testing, including property tests
/// against other trusted BLAKE2b implementations, and no failures have been observed.
///
/// Furthermore, this comment is not present in the public WolfSSL API, suggesting that they may
/// have confidence in their own implementation despite the internal comment.
///
/// # Const Generic
///
/// * `C` - The length of the BLAKE2b digest to implement, with a maximum length of `64`.
///
/// # Example
///
/// ```
/// use wolf_crypto::hash::Blake2b;
///
/// let mut hasher = Blake2b::<64>::new().unwrap();
///
/// let input = b"hello world";
/// assert!(hasher.try_update(input.as_slice()).is_ok());
///
/// let finalized = hasher.try_finalize().unwrap();
/// assert_ne!(finalized, input);
/// assert_eq!(finalized.len(), 64);
/// ```
///
/// [1]: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/blake2b.c#L337
#[repr(transparent)]
pub struct Blake2b<const C: usize> {
    inner: wc_Blake2b
}

impl<const C: usize> Blake2b<C> {
    /// Create a new `Blake2b` instance.
    ///
    /// # Errors
    ///
    /// - If the digest length is greater than `64` (const generic `C`)
    /// - If the underling initialization function fails (`wc_InitBlake2b`)
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::hash::Blake2b;
    ///
    /// let mut hasher = Blake2b::<64>::new().unwrap();
    ///
    /// let input = b"hello world";
    /// assert!(hasher.try_update(input.as_slice()).is_ok());
    ///
    /// let finalized = hasher.try_finalize().unwrap();
    /// assert_ne!(finalized.as_slice(), input.as_slice());
    /// assert_eq!(finalized.len(), 64);
    ///
    /// // Maximum `C` is 64
    /// assert!(Blake2b::<128>::new().is_err());
    /// ```
    pub fn new() -> Result<Self, ()> {
        if !const_lte::<C, 64>() { return Err(()); }
        let mut res = Res::new();

        unsafe {
            let mut inner = MaybeUninit::<wc_Blake2b>::uninit();
            res.ensure_0(wc_InitBlake2b(inner.as_mut_ptr(), C as u32));
            res.unit_err_with(|| Self { inner: inner.assume_init() })
        }
    }

    #[inline]
    #[must_use]
    unsafe fn new_with_key_unchecked(key: &[u8]) -> (MaybeUninit<wc_Blake2b>, Res) {
        let mut res = Res::new();
        let mut inner = MaybeUninit::<wc_Blake2b>::uninit();

        res.ensure_0(wc_InitBlake2b_WithKey(
            inner.as_mut_ptr(),
            C as u32,
            key.as_ptr(),
            key.len() as u32
        ));

        (inner, res)
    }

    /// Create a new `Blake2b` instance using a key.
    ///
    /// The key is used to create a keyed BLAKE2b instance, which is suitable for
    /// message authentication (MAC) purposes. The output digest length is determined
    /// by the constant generic parameter `C`.
    ///
    /// # Errors
    ///
    /// - If the digest length `C` is greater than `64`.
    /// - If the key length exceeds `64` bytes.
    /// - If the underlying initialization function (`wc_InitBlake2b_WithKey`) fails.
    ///
    /// # Arguments
    ///
    /// * `key` - A secret key used to initialize the BLAKE2b instance. The length of the key must
    ///           be less than or equal to 64 bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::hash::Blake2b;
    ///
    /// let key = b"my-secret-key";
    /// let mut hasher = Blake2b::<64>::new_with_key(key).unwrap();
    ///
    /// let input = b"hello world";
    /// assert!(hasher.try_update(input.as_slice()).is_ok());
    ///
    /// let finalized = hasher.try_finalize().unwrap();
    /// assert_ne!(finalized.as_slice(), input.as_slice());
    /// assert_eq!(finalized.len(), 64);
    ///
    /// // Key length must be less than or equal to 64 bytes.
    /// let long_key = [0u8; 128];
    /// assert!(Blake2b::<64>::new_with_key(&long_key).is_err());
    /// ```
    pub fn new_with_key(key: &[u8]) -> Result<Self, ()> {
        if !(const_lte::<C, 64>() && lte::<64>(key.len())) { return Err(()); }

        unsafe {
            let (inner, res) = Self::new_with_key_unchecked(key);
            res.unit_err_with(|| Self { inner: inner.assume_init() })
        }
    }

    /// Create a new `Blake2b` instance using a fixed-size key.
    ///
    /// This function allows you to specify the key as a fixed-size array. It is similar to
    /// `new_with_key` but works with keys that have a compile-time constant size.
    ///
    /// # Errors
    ///
    /// - If the digest length `C` is greater than `64`.
    /// - If the key length exceeds `64` bytes (compile-time check).
    /// - If the underlying initialization function (`wc_InitBlake2b_WithKey`) fails.
    ///
    /// # Parameters
    ///
    /// - `key`: A fixed-size secret key (length `K`) used to initialize the BLAKE2b instance. The
    ///   length of the key must be less than or equal to 64 bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::hash::Blake2b;
    ///
    /// let key: [u8; 32] = [0x00; 32];
    /// let mut hasher = Blake2b::<64>::new_with_sized_key(&key).unwrap();
    ///
    /// let input = b"some data";
    /// assert!(hasher.try_update(input.as_slice()).is_ok());
    ///
    /// let finalized = hasher.try_finalize().unwrap();
    /// assert_eq!(finalized.len(), 64);
    ///
    /// // Key length must be less than or equal to 64 bytes.
    /// let oversized_key = [0u8; 128];
    /// assert!(Blake2b::<64>::new_with_sized_key(&oversized_key).is_err());
    /// ```
    pub fn new_with_sized_key<const K: usize>(key: &[u8; K]) -> Result<Self, ()> {
        if !(const_lte::<C, 64>() && const_lte::<K, 64>()) { return Err(()); }

        unsafe {
            let (inner, res) = Self::new_with_key_unchecked(key);
            res.unit_err_with(|| Self { inner: inner.assume_init() })
        }
    }

    /// Update the `Blake2b` instance with the provided data, without performing any safety checks.
    ///
    /// # Safety
    ///
    /// The length of the data is cast to a 32-bit unsigned integer without checking for
    /// overflow. While this is unlikely to occur in most practical scenarios, it is not impossible,
    /// especially with very large slices. Therefore, this function is marked `unsafe`.
    ///
    /// # Arguments
    ///
    /// * `data` - The slice to update the underlying hasher state with.
    ///
    /// # Returns
    ///
    /// This function returns the result of the operation.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::hash::Blake2b;
    ///
    /// let mut hasher = Blake2b::<64>::new().unwrap();
    ///
    /// let input = b"hello world";
    /// // SAFETY: The length of `hello world` is 11, which cannot overflow even an 8-bit integer.
    /// let res = unsafe { hasher.update_unchecked(input.as_slice()) };
    /// assert!(res.is_ok());
    ///
    /// let finalized = hasher.try_finalize().unwrap();
    /// assert_ne!(finalized.as_slice(), input.as_slice());
    /// assert_eq!(finalized.len(), 64);
    /// ```
    #[inline]
    pub unsafe fn update_unchecked(&mut self, data: &[u8]) -> Res {
        let mut res = Res::new();

        res.ensure_0(wc_Blake2bUpdate(
            addr_of_mut!(self.inner),
            data.as_ptr(),
            data.len() as u32
        ));

        res
    }

    /// Update the `Blake2b` instance with the provided data.
    ///
    /// # Arguments
    ///
    /// * `data` - The slice to update the underlying hasher state with.
    ///
    /// # Returns
    ///
    /// This function returns the result of the operation.
    ///
    /// # Errors
    ///
    /// - If the length of `data` cannot be safely cast to a `u32`.
    /// - If the underlying `wc_Blake2bUpdate` function fails.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::hash::Blake2b;
    ///
    /// let mut hasher = Blake2b::<64>::new().unwrap();
    ///
    /// let input = b"hello world";
    /// assert!(hasher.try_update(input.as_slice()).is_ok());
    ///
    /// let finalized = hasher.try_finalize().unwrap();
    /// assert_ne!(finalized.as_slice(), input.as_slice());
    /// assert_eq!(finalized.len(), 64);
    /// ```
    #[inline]
    pub fn try_update(&mut self, data: &[u8]) -> Res {
        if !can_cast_u32(data.len()) { return Res::ERR }
        unsafe { self.update_unchecked(data) }
    }

    /// Update the `Blake2b` instance with the provided data, using compile-time safety checks.
    ///
    /// # Arguments
    ///
    /// * `data` - The slice to update the underlying hasher state with, where the size of the slice
    ///   is known at compile time.
    ///
    /// # Returns
    ///
    /// This function returns the result of the operation.
    ///
    /// # Errors
    ///
    /// - If the length of `data` cannot be safely cast to a `u32`.
    /// - If the underlying `wc_Blake2bUpdate` function fails.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::hash::Blake2b;
    ///
    /// let mut hasher = Blake2b::<64>::new().unwrap();
    ///
    /// let input = [b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd'];
    /// assert!(hasher.update_sized(&input).is_ok());
    ///
    /// let finalized = hasher.try_finalize().unwrap();
    /// assert_ne!(finalized.as_slice(), input.as_slice());
    /// assert_eq!(finalized.len(), 64);
    /// ```
    #[inline]
    pub fn update_sized<const OC: usize>(&mut self, data: &[u8; OC]) -> Res {
        if !const_can_cast_u32::<{ OC }>() { return Res::ERR }
        unsafe { self.update_unchecked(data) }
    }

    /// Update the `Blake2b` instance with the provided data, panicking on failure.
    ///
    /// # Arguments
    ///
    /// * `data` - The slice to update the underlying hasher state with.
    ///
    /// # Panics
    ///
    /// - If the length of `data` cannot be safely cast to a `u32`.
    /// - If the underlying `wc_Blake2bUpdate` function fails.
    ///
    /// If a panic is not acceptable for your use case, consider using [`try_update`] instead.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::hash::Blake2b;
    ///
    /// let mut hasher = Blake2b::<64>::new().unwrap();
    ///
    /// let input = b"hello world";
    /// hasher.update(input.as_slice());
    ///
    /// let finalized = hasher.try_finalize().unwrap();
    /// assert_ne!(finalized.as_slice(), input.as_slice());
    /// assert_eq!(finalized.len(), 64);
    /// ```
    ///
    /// [`try_update`]: Self::try_update
    #[cfg(feature = "panic-api")]
    #[track_caller]
    pub fn update(&mut self, data: &[u8]) {
        self.try_update(data).unit_err(()).expect("Failed to update hash in `Blake2b`")
    }

    /// Finalize the `Blake2b` hashing process, writing the output to the provided buffer, without
    /// performing safety checks.
    ///
    /// # Safety
    ///
    /// The size of the `output` argument must be at least `C` (the size of the digest).
    ///
    /// # Arguments
    ///
    /// * `output` - The buffer to store the output digest in.
    ///
    /// # Returns
    ///
    /// This function returns the result of the operation.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::hash::Blake2b;
    /// let mut hasher = Blake2b::<64>::new().unwrap();
    ///
    /// let mut output = [0u8; 64];
    /// // SAFETY: The size of the output buffer is exactly 64 bytes (the size of the digest).
    /// let res = unsafe { hasher.finalize_unchecked(&mut output) };
    /// assert!(res.is_ok());
    /// ```
    #[inline]
    pub unsafe fn finalize_unchecked(mut self, output: &mut [u8]) -> Res {
        let mut res = Res::new();

        res.ensure_0(wc_Blake2bFinal(
            addr_of_mut!(self.inner),
            output.as_mut_ptr(),
            C as u32
        ));

        res
    }

    /// Finalize the `Blake2b` hashing process, writing the output to the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `output` - The buffer to store the output digest in.
    ///
    /// # Errors
    ///
    /// - If the size of `output` is less than `C` (the size of the digest).
    /// - If the underlying finalize function fails.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::hash::Blake2b;
    /// let mut hasher = Blake2b::<64>::new().unwrap();
    ///
    /// // use the hasher ...
    ///
    /// let mut output = [0u8; 64];
    /// assert!(hasher.finalize_into(&mut output).is_ok());
    /// ```
    #[inline]
    pub fn finalize_into(self, output: &mut [u8]) -> Res {
        if !gte::<C>(output.len()) { return Res::ERR }
        unsafe { self.finalize_unchecked(output) }
    }

    /// Finalize the `Blake2b` hashing process, writing the output to a fixed-size buffer, and
    /// performing safety checks at compilation time.
    ///
    /// # Arguments
    ///
    /// * `output` - The fixed-size buffer to store the output digest in.
    ///
    /// # Errors
    ///
    /// - If the length of `output` is less than `C` (the size of the digest).
    /// - If the underlying finalize function fails.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::hash::Blake2b;
    /// let mut hasher = Blake2b::<64>::new().unwrap();
    ///
    /// // use the hasher ...
    ///
    /// let mut output = [0u8; 64];
    /// assert!(hasher.finalize_into_sized(&mut output).is_ok());
    /// ```
    #[inline]
    pub fn finalize_into_sized<const OC: usize>(self, output: &mut [u8; OC]) -> Res {
        if !const_gte::<OC, C>() { return Res::ERR }
        unsafe { self.finalize_unchecked(output) }
    }

    /// Finalize the `Blake2b` hashing process, writing the output to a buffer with an exact size.
    ///
    /// This method is for cases where the size of the output buffer is exactly the same as the
    /// digest size (`C`). The buffer size is checked at compile time, so no runtime size checks
    /// are necessary, making this a highly optimized version of finalization.
    ///
    /// # Arguments
    ///
    /// * `output` - The buffer to store the output digest in, with a size exactly equal to the
    ///              digest size (`C`).
    ///
    /// # Returns
    ///
    /// This function returns the result of the operation.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::hash::Blake2b;
    /// let mut hasher = Blake2b::<64>::new().unwrap();
    ///
    /// // use the hasher ...
    ///
    /// let mut output = [0u8; 64];
    /// assert!(hasher.finalize_into_exact(&mut output).is_ok());
    /// ```
    ///
    /// **Note**: If the size of the output buffer is not exactly `C`, see [`finalize_into`] for
    /// greater flexibility, or [`finalize_into_sized`] if the size is known at compile time but is
    /// not exactly `C`.
    ///
    /// [`finalize_into`]: Self::finalize_into
    /// [`finalize_into_sized`]: Self::finalize_into_sized
    #[inline]
    pub fn finalize_into_exact(self, output: &mut [u8; C]) -> Res {
        unsafe { self.finalize_unchecked(output) }
    }

    /// Finalize the `Blake2b` hashing process, returning the result as an array.
    ///
    /// # Returns
    ///
    /// On success, this returns the output digest as an array.
    ///
    /// # Errors
    ///
    /// If the underlying finalize function fails.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::hash::Blake2b;
    /// let mut hasher = Blake2b::<64>::new().unwrap();
    ///
    /// // use the hasher ...
    ///
    /// let res = hasher.try_finalize().unwrap();
    /// assert_eq!(res.len(), 64);
    /// ```
    #[inline]
    pub fn try_finalize(self) -> Result<[u8; C], ()> {
        let mut buf = [0u8; C];
        self.finalize_into_exact(&mut buf).unit_err(buf)
    }

    /// Finalize the `Blake2b` hashing process, returning the result as an array, panicking on
    /// failure.
    ///
    /// # Returns
    ///
    /// On success, this returns the output digest as an array.
    ///
    /// # Panics
    ///
    /// If the underlying finalize function fails.
    ///
    /// If panicking is not acceptable for your use case, consider using [`try_finalize`] instead.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::hash::Blake2b;
    /// let mut hasher = Blake2b::<64>::new().unwrap();
    ///
    /// // use the hasher ...
    ///
    /// let res = hasher.finalize();
    /// assert_eq!(res.len(), 64);
    /// ```
    ///
    /// [`try_finalize`]: Self::try_finalize
    #[cfg(feature = "panic-api")]
    #[track_caller]
    pub fn finalize(self) -> [u8; C] {
        self.try_finalize().expect("Failed to finalize in `Blake2b`")
    }
}

