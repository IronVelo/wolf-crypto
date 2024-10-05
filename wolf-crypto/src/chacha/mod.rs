//! The `ChaCha20` Stream Cipher

mod key;
pub mod state;

pub use key::{Key, KeyRef, GenericKey};
use core::fmt;

use wolf_crypto_sys::{
    ChaCha,
    wc_Chacha_SetKey, wc_Chacha_SetIV,
    wc_Chacha_Process
};

use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;
use crate::buf::{GenericIv, U12};
use crate::{can_cast_u32, const_can_cast_u32, lte, Unspecified};
use state::{State, CanProcess, Init, NeedsIv, Ready, Streaming};

macro_rules! impl_fmt {
    ($(#[$meta:meta])* $trait:ident for $state:ident) => {
        impl fmt::$trait for ChaCha20<$state> {
            $(#[$meta])*
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(concat!("ChaCha20<", stringify!($state), "> { ... }"))
            }
        }
    };
    ($state:ident) => {
        impl_fmt! { Debug for $state }
        impl_fmt! {
            #[inline]
            Display for $state
        }
    };
}

/// The `ChaCha20` Stream Cipher
///
/// # Warning
///
/// `ChaCha20` alone does not ensure that the ciphertext is authentic, unless you have a reason
/// for using this directly, it is generally recommended to use `ChaCha20-Poly1305`.
///
/// # Generic `S`
///
/// This `ChaCha20` implementation is implemented as a state machine, this is to better enforce
/// best practices such as avoiding initialization vector reuse. The generic `S` represents the
/// current state.
///
/// The state machine takes the following form:
///
/// ```text
///      +----------+
///      |   Init   |
///      +----------+
///        |
///        |
///        v
///      +----------+      `finalize()`
///   +> | Needs IV | <----------------------+
///   |  +----------+                        |
///   |    |                                 |
///   |    |                                 |
///   |    v                                 |
///   |  +--------------------------+      +-----------+
///   |  |                          |      |           | ---+
///   |  |          Ready           |      | Streaming |    |
///   |  |                          | ---> |           | <--+
///   |  +--------------------------+      +-----------+
///   |    |           ^    |
///   |    |           |    |
///   |    v           |    v
///   |  +----------+  |  +---------+
///   +- | Encrypt  |  +- | Decrypt |
///      +----------+     +---------+
/// ```
///
/// # Example
///
/// ```
/// use wolf_crypto::chacha::ChaCha20;
///
/// let (output, mut chacha) = ChaCha20::new(&[7u8; 32])
///     .set_iv(&[3u8; 12])
///     .encrypt_exact(b"hello world")
///     .unwrap();
///
/// let plaintext = chacha.set_iv(&[3u8; 12])
///     .decrypt_exact(&output)
///     .unwrap();
///
/// assert_eq!(b"hello world", &plaintext);
/// ```
#[repr(transparent)]
pub struct ChaCha20<S: State = Init> {
    inner: ChaCha,
    _state: PhantomData<S>
}

impl ChaCha20<Init> {
    /// Create a new `ChaCha20` instance.
    ///
    /// # Arguments
    ///
    /// * `key` - The 128-bit or 256-bit key material.
    ///
    /// # Returns
    ///
    /// A new `ChaCha20` instance in the [`NeedsIv`] state.
    pub fn new<K: GenericKey>(key: K) -> ChaCha20<NeedsIv> {
        let mut inner = MaybeUninit::<ChaCha>::uninit();

        unsafe {
            // Infallible, the GenericKey is sealed and only supports 128 or 256-bit keys, which
            // are valid sizes. According to the docs this is the only way that this function
            // can fail. Debug assert to build further confidence. This has been confirmed post
            // reviewing the source code.
            //
            // See for yourself:
            // https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/chacha.c#L154
            let _res = wc_Chacha_SetKey(
                inner.as_mut_ptr(),
                key.slice().as_ptr(),
                key.size()
            );
            debug_assert_eq!(_res, 0);

            Self::new_with(inner.assume_init())
        }
    }
}

impl<S: State> ChaCha20<S> {
    #[inline]
    #[must_use]
    const fn new_with<NS: State>(inner: ChaCha) -> ChaCha20<NS> {
        ChaCha20::<NS> {
            inner,
            _state: PhantomData
        }
    }
}

impl ChaCha20<NeedsIv> {
    /// Set the initialization vector to use for the next [`Ready`] state.
    ///
    /// # Arguments
    ///
    /// * `iv` - The 96-bit initialization vector.
    /// * `counter` - The value at which the block counter should start, generally zero.
    ///
    /// # Returns
    ///
    /// The `ChaCha20` instance in the [`Ready`] state.
    pub fn set_iv_with_ctr<IV>(mut self, iv: IV, counter: u32) -> ChaCha20<Ready>
        where IV: GenericIv<Size = U12>
    {
        // Infallible, see source:
        // /**
        //   * Set up iv(nonce). Earlier versions used 64 bits instead of 96, this version
        //   * uses the typical AEAD 96 bit nonce and can do record sizes of 256 GB.
        //   */
        // int wc_Chacha_SetIV(ChaCha* ctx, const byte* inIv, word32 counter)
        // {
        //     word32 temp[CHACHA_IV_WORDS];/* used for alignment of memory */
        //
        //
        //     if (ctx == NULL || inIv == NULL)
        //         return BAD_FUNC_ARG;
        //
        //     XMEMCPY(temp, inIv, CHACHA_IV_BYTES);
        //
        //     ctx->left = 0; /* resets state */
        //     ctx->X[CHACHA_MATRIX_CNT_IV+0] = counter;           /* block counter */
        //     ctx->X[CHACHA_MATRIX_CNT_IV+1] = LITTLE32(temp[0]); /* fixed variable from nonce */
        //     ctx->X[CHACHA_MATRIX_CNT_IV+2] = LITTLE32(temp[1]); /* counter from nonce */
        //     ctx->X[CHACHA_MATRIX_CNT_IV+3] = LITTLE32(temp[2]); /* counter from nonce */
        //
        //     return 0;
        // }
        //
        // https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/chacha.c#L127
        unsafe {
            let _res = wc_Chacha_SetIV(
                addr_of_mut!(self.inner),
                iv.as_slice().as_ptr(),
                counter
            );
            debug_assert_eq!(_res, 0);
        }

        Self::new_with(self.inner)
    }

    /// Set the initialization vector to use for the next [`Ready`] state.
    ///
    /// # Arguments
    ///
    /// * `iv` - The 96-bit initialization vector.
    ///
    /// # Returns
    ///
    /// The `ChaCha20` instance in the [`Ready`] state.
    #[inline]
    pub fn set_iv<IV: GenericIv<Size = U12>>(self, iv: IV) -> ChaCha20<Ready> {
        self.set_iv_with_ctr(iv, 0)
    }
}

impl_fmt! { NeedsIv }

impl<S: CanProcess> ChaCha20<S> {
    #[inline]
    #[must_use]
    const fn predicate(input_len: usize, output_len: usize) -> bool {
        input_len <= output_len && can_cast_u32(input_len)
    }

    #[inline]
    #[must_use]
    const fn const_predicate<const I: usize, const O: usize>() -> bool {
        I <= O && const_can_cast_u32::<I>()
    }

    /// Processes the input into the output buffer without checking lengths.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it does not check if the input and output
    /// lengths are valid. The caller must ensure that:
    /// - The input length is less than or equal to the output length.
    /// - The input length can be cast to a `u32` without overflow.
    ///
    /// # Arguments
    ///
    /// * `input` - The input slice to process.
    /// * `output` - The output buffer to write the processed data into.
    #[inline]
    unsafe fn process_unchecked(&mut self, input: &[u8], output: &mut [u8]) {
        debug_assert!(
            Self::predicate(input.len(), output.len()),
            "Process unchecked precondition violated (debug assertion). The size of the input must \
            be less than or equal to the size of the output. The size of the input must also be \
            representable as a `u32` without overflowing."
        );

        // INFALLIBLE (with preconditions respected, but this function is unsafe so caller's
        // responsibility)
        //
        // -- ACTUAL PROCESSING:
        // https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/chacha.c#L267
        //
        // Returns void, so of course, no fallibility here (which makes sense).
        //
        // -- PROCESS FUNCTION
        // https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/chacha.c#L317
        //
        // The null checks at the start of wc_ChaCha_Process are the only fallible aspects, with
        // the length corresponding to the input size and the output size being greater or eq to
        // this length implied.
        let _res = wc_Chacha_Process(
            addr_of_mut!(self.inner),
            output.as_mut_ptr(),
            input.as_ptr(),
            input.len() as u32
        );

        debug_assert_eq!(_res, 0);
    }

    /// Processes the input into the output buffer without checking lengths.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it does not check if the input and output
    /// lengths are valid. The caller must ensure that the input length can be cast to a `u32`
    /// without overflow.
    ///
    /// # Arguments
    ///
    /// * `in_out` - The buffer to process in-place.
    #[inline]
    unsafe fn process_in_place_unchecked<'io>(&mut self, in_out: &'io mut [u8]) -> &'io [u8] {
        debug_assert!(
            can_cast_u32(in_out.len()),
            "Process unchecked precondition violated (debug assertion). The size of the input must \
            be less than or equal to the size of the output. The size of the input must also be \
            representable as a `u32` without overflowing."
        );

        // The soundness of passing the input ptr as the output ptr is implied by this being sound
        // in ChaCha20Poly1305.
        //
        // The infallibility explanation can be seen in the process_unchecked implementation.
        let _res = wc_Chacha_Process(
            addr_of_mut!(self.inner),
            in_out.as_ptr().cast_mut(),
            in_out.as_ptr(),
            in_out.len() as u32
        );

        debug_assert_eq!(_res, 0);

        in_out
    }

    /// Processes the input into the output buffer, checking lengths.
    ///
    /// # Arguments
    ///
    /// * `input` - The input slice to process.
    /// * `output` - The output buffer to write the processed data into.
    ///
    /// # Errors
    ///
    /// `!(input_len <= output_len && can_cast_u32(input_len))`
    #[inline]
    fn process(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), Unspecified> {
        if !Self::predicate(input.len(), output.len()) { return Err(Unspecified) }
        unsafe { self.process_unchecked(input, output) };
        Ok(())
    }

    /// Encrypt / Decrypt the data in-place
    ///
    /// # Arguments
    ///
    /// * `in_out` - The buffer to encrypt / decrypt in-place
    ///
    /// # Errors
    ///
    /// `!can_cast_u32(in_out.len())`
    #[inline]
    fn process_in_place<'io>(&mut self, in_out: &'io mut [u8]) -> Result<&'io [u8], Unspecified> {
        if can_cast_u32(in_out.len()) {
            Ok(unsafe { self.process_in_place_unchecked(in_out) })
        } else {
            Err(Unspecified)
        }
    }

    /// Processes the input into the output buffer with exact sizes.
    ///
    /// # Arguments
    ///
    /// * `input` - The input array to process.
    /// * `output` - The output array to write the processed data into.
    ///
    /// # Errors
    ///
    /// `!const_can_cast_u32::<C>()`
    #[inline]
    fn process_exact<const C: usize>(
        &mut self,
        input: &[u8; C],
        output: &mut [u8; C]
    ) -> Result<(), Unspecified> {
        if !const_can_cast_u32::<C>() { return Err(Unspecified); }
        unsafe { self.process_unchecked(input, output) };
        Ok(())
    }

    /// Processes the input into the output buffer with compile-time size checking.
    ///
    /// # Type Parameters
    ///
    /// * `I` - The size of the input array.
    /// * `O` - The size of the output array.
    ///
    /// # Arguments
    ///
    /// * `input` - The input array to process.
    /// * `output` - The output array to write the processed data into.
    ///
    /// # Errors
    ///
    /// `!(I <= O && const_can_cast_u32::<I>())`
    #[inline]
    fn process_sized<const I: usize, const O: usize>(
        &mut self,
        input: &[u8; I],
        output: &mut [u8; O]
    ) -> Result<(), Unspecified> {
        if !Self::const_predicate::<I, O>() { return Err(Unspecified) }
        unsafe { self.process_unchecked(input, output) };
        Ok(())
    }

    /// Encrypt / Decrypt the `in_out` buffer in-place, with safety checks performed at compilation
    /// time.
    ///
    /// # Arguments
    ///
    /// * `in_out` - The buffer to encrypt/decrypt in-place
    ///
    /// # Errors
    ///
    /// `!const_can_cast_u32::<C>()`
    #[inline]
    fn process_in_place_sized<'io, const C: usize>(&mut self, in_out: &'io mut [u8; C]) -> Result<&'io [u8; C], Unspecified> {
        if const_can_cast_u32::<C>() {
            unsafe { self.process_in_place_unchecked(in_out) };
            Ok(in_out)
        } else {
            Err(Unspecified)
        }
    }

    /// Processes the input into the output buffer with a fixed-size output.
    ///
    /// # Type Parameters
    ///
    /// * `O` - The size of the output array.
    ///
    /// # Arguments
    ///
    /// * `input` - The input slice to process.
    /// * `output` - The output array to write the processed data into.
    ///
    /// # Errors
    ///
    /// `!(lte::<O>(input.len()) && can_cast_u32(input.len()))`
    #[inline]
    fn process_sized_out<const O: usize>(
        &mut self,
        input: &[u8],
        output: &mut [u8; O]
    ) -> Result<(), Unspecified> {
        if !(lte::<O>(input.len()) && can_cast_u32(input.len())) { return Err(Unspecified) }
        unsafe { self.process_unchecked(input, output) };
        Ok(())
    }
}

impl ChaCha20<Ready> {
    /// Encrypts the plaintext into the ciphertext buffer.
    ///
    /// # Arguments
    ///
    /// * `plain` - The plaintext to encrypt.
    /// * `cipher` - The buffer to store the encrypted data.
    ///
    /// # Errors
    ///
    /// - The length of `plain` was greater than [`u32::MAX`]
    /// - The length of `cipher` was less than the length of `plain`
    #[inline]
    pub fn encrypt_into(
        mut self,
        plain: &[u8],
        cipher: &mut [u8]
    ) -> Result<ChaCha20<NeedsIv>, Self> {
        if self.process(plain, cipher).is_ok() {
            Ok(Self::new_with(self.inner))
        } else {
            Err(self)
        }
    }

    /// Encrypts the plaintext in-place.
    ///
    /// # Arguments
    ///
    /// * `in_out` - The buffer to encrypt in-place.
    ///
    /// # Errors
    ///
    /// The length of `in_out` was greater than [`u32::MAX`].
    #[inline]
    pub fn encrypt_in_place(mut self, in_out: &mut [u8]) -> Result<ChaCha20<NeedsIv>, Self> {
        if self.process_in_place(in_out).is_ok() {
            Ok(Self::new_with(self.inner))
        } else {
            Err(self)
        }
    }

    /// Encrypts the plaintext into the ciphertext buffer with compile-time safety checks.
    ///
    /// # Arguments
    ///
    /// * `plain` - The plaintext array to encrypt.
    /// * `cipher` - The array to store the encrypted data.
    ///
    /// # Returns
    ///
    /// `ChaCha20` instance in the `NeedsIv` state.
    ///
    /// # Errors
    ///
    /// - The length of `plain` was greater than [`u32::MAX`].
    /// - The length of `cipher` was less than the length of `plain`.
    #[inline]
    pub fn encrypt_into_sized<const P: usize, const C: usize>(
        mut self,
        plain: &[u8; P],
        cipher: &mut [u8; C]
    ) -> Result<ChaCha20<NeedsIv>, Self> {
        if self.process_sized(plain, cipher).is_ok() {
            Ok(Self::new_with(self.inner))
        } else {
            Err(self)
        }
    }

    /// Encrypts the plaintext in-place with compile-time safety checks.
    ///
    /// # Arguments
    ///
    /// * `in_out` - The plaintext to encrypt in-place.
    ///
    /// # Returns
    ///
    /// `ChaCha20` instance in the `NeedsIv` state.
    ///
    /// # Errors
    ///
    /// The length of `in_out` was greater than [`u32::MAX`].
    #[inline]
    pub fn encrypt_in_place_sized<const C: usize>(mut self, in_out: &mut [u8; C]) -> Result<ChaCha20<NeedsIv>, Self> {
        if self.process_in_place_sized(in_out).is_ok() {
            Ok(Self::new_with(self.inner))
        } else {
            Err(self)
        }
    }

    /// Encrypts the plaintext into a fixed-size ciphertext buffer.
    ///
    /// # Arguments
    ///
    /// * `plain` - The plaintext to encrypt.
    /// * `cipher` - The array to store the encrypted data.
    ///
    /// # Returns
    ///
    /// `ChaCha20` instance in the `NeedsIv` state.
    ///
    /// # Errors
    ///
    /// - The length of `plain` was greater than [`u32::MAX`].
    /// - The length of `cipher` was less than the length of `plain`.
    #[inline]
    pub fn encrypt_into_sized_out<const C: usize>(
        mut self,
        plain: &[u8],
        cipher: &mut [u8; C]
    ) -> Result<ChaCha20<NeedsIv>, Self> {
        if self.process_sized_out(plain, cipher).is_ok() {
            Ok(Self::new_with(self.inner))
        } else {
            Err(self)
        }
    }

    /// Encrypts the plaintext into the ciphertext buffer with exact sizes.
    ///
    /// # Arguments
    ///
    /// * `plain` - The plaintext array to encrypt.
    /// * `cipher` - The array to store the encrypted data.
    ///
    /// # Returns
    ///
    /// `ChaCha20` instance in the `NeedsIv` state.
    ///
    /// # Errors
    ///
    /// If `C` (the length of `plain` and `cipher`) was greater than [`u32::MAX`].
    #[inline]
    pub fn encrypt_into_exact<const C: usize>(
        mut self,
        plain: &[u8; C],
        cipher: &mut [u8; C]
    ) -> Result<ChaCha20<NeedsIv>, Self> {
        if self.process_exact(plain, cipher).is_ok() {
            Ok(Self::new_with(self.inner))
        } else {
            Err(self)
        }
    }

    alloc! {
        /// Encrypts the plaintext and returns the ciphertext as a vector.
        ///
        /// # Arguments
        ///
        /// * `plain` - The plaintext to encrypt.
        ///
        /// # Returns
        ///
        /// `ChaCha20` instance in the `NeedsIv` state.
        ///
        /// # Errors
        ///
        /// The length of `plain` was greater than [`u32::MAX`].
        pub fn encrypt(
            self,
            plain: &[u8]
        ) -> Result<(alloc::vec::Vec<u8>, ChaCha20<NeedsIv>), Self> {
            let mut output = alloc::vec![0u8; plain.len()];
            self.encrypt_into(plain, output.as_mut_slice()).map(move |ni| (output, ni))
        }
    }

    /// Encrypts the plaintext array and returns the ciphertext array.
    ///
    /// # Type Parameters
    ///
    /// * `I` - The size of the plaintext and ciphertext arrays.
    ///
    /// # Arguments
    ///
    /// * `plain` - The plaintext array to encrypt.
    ///
    /// # Returns
    ///
    /// `ChaCha20` instance in the `NeedsIv` state.
    ///
    /// # Errors
    ///
    /// The length of `plain` was greater than [`u32::MAX`].
    #[inline]
    pub fn encrypt_exact<const I: usize>(
        self,
        plain: &[u8; I]
    ) -> Result<([u8; I], ChaCha20<NeedsIv>), Self> {
        let mut output = [0u8; I];
        self.encrypt_into_exact(plain, &mut output).map(move |ni| (output, ni))
    }

    pub const fn stream(self) -> ChaCha20<Streaming> {
        Self::new_with(self.inner)
    }
}

impl_fmt! { Ready }

impl<S: CanProcess> ChaCha20<S> {
    /// Decrypts the ciphertext into the output buffer.
    ///
    /// # Arguments
    ///
    /// * `cipher` - The ciphertext to decrypt.
    /// * `plain` - The buffer to store the decrypted data.
    ///
    /// # Errors
    ///
    /// - If the length of `cipher` is greater than [`u32::MAX`].
    /// - If the length of `cipher` is greater than the length of `plain`.
    #[inline]
    pub fn decrypt_into(&mut self, cipher: &[u8], plain: &mut [u8]) -> Result<(), Unspecified> {
        self.process(cipher, plain)
    }

    /// Decrypts the ciphertext in-place.
    ///
    /// # Arguments
    ///
    /// * `in_out` - The plaintext to decrypt in place.
    ///
    /// # Errors
    ///
    /// If the length of `in_out` is greater than [`u32::MAX`].
    ///
    /// # Returns
    ///
    /// The `in_out` argument, decrypted, for convenience. This can be ignored.
    #[inline]
    pub fn decrypt_in_place<'io>(&mut self, in_out: &'io mut [u8]) -> Result<&'io [u8], Unspecified> {
        self.process_in_place(in_out)
    }

    /// Decrypts the ciphertext into the output buffer with compile-time safety checks.
    ///
    /// # Arguments
    ///
    /// * `cipher` - The ciphertext array to decrypt.
    /// * `plain` - The array to store the decrypted data.
    ///
    /// # Errors
    ///
    /// - If the length of `cipher` is greater than [`u32::MAX`].
    /// - If the length of `cipher` is greater than the length of `plain`.
    #[inline]
    pub fn decrypt_into_sized<const I: usize, const O: usize>(
        &mut self,
        cipher: &[u8; I],
        plain: &mut [u8; O]
    ) -> Result<(), Unspecified> {
        self.process_sized(cipher, plain)
    }

    /// Decrypts the ciphertext in-place with compile-time safety checks.
    ///
    /// # Arguments
    ///
    /// * `in_out` - The ciphertext to decrypt in-place.
    ///
    /// # Returns
    ///
    /// `ChaCha20` instance in the `NeedsIv` state.
    ///
    /// # Errors
    ///
    /// - The length of `in_out` was greater than [`u32::MAX`].
    #[inline]
    pub fn decrypt_in_place_sized<'io, const C: usize>(
        &mut self,
        in_out: &'io mut [u8; C]
    ) -> Result<&'io [u8; C], Unspecified> {
        self.process_in_place_sized(in_out)
    }

    /// Decrypts the ciphertext into the output buffer with exact sizes.
    ///
    /// # Arguments
    ///
    /// * `cipher` - The ciphertext array to decrypt.
    /// * `plain` - The array to store the decrypted data.
    ///
    /// # Errors
    ///
    /// If `C` (the length of `cipher` and `plain`) is greater than [`u32::MAX`].
    #[inline]
    pub fn decrypt_into_exact<const C: usize>(&mut self, cipher: &[u8; C], plain: &mut [u8; C]) -> Result<(), Unspecified> {
        self.process_exact(cipher, plain)
    }

    alloc! {
        /// Decrypts the ciphertext and returns the plaintext as a vector.
        ///
        /// # Arguments
        ///
        /// * `cipher` - The ciphertext to decrypt.
        ///
        /// # Errors
        ///
        /// If the length of `cipher` is greater than [`u32::MAX`].
        ///
        /// # Returns
        ///
        /// A newly allocated buffer, the same length as `cipher`, containing the decrypted
        /// plaintext.
        #[inline]
        pub fn decrypt(&mut self, cipher: &[u8]) -> Result<alloc::vec::Vec<u8>, Unspecified> {
            let mut output = alloc::vec![0u8; cipher.len()];
            self.decrypt_into(cipher, output.as_mut_slice()).map(move |()| output)
        }
    }

    /// Decrypts the ciphertext array and returns the plaintext array.
    ///
    /// # Arguments
    ///
    /// * `cipher` - The ciphertext array to decrypt.
    ///
    /// # Errors
    ///
    /// If `O` (the length of `cipher`) is greater than [`u32::MAX`].
    #[inline]
    pub fn decrypt_exact<const O: usize>(&mut self, cipher: &[u8; O]) -> Result<[u8; O], Unspecified> {
        let mut output = [0u8; O];
        self.decrypt_into_exact(cipher, &mut output).map(move |()| output)
    }
}

impl ChaCha20<Streaming> {
    /// Encrypts the input into the output buffer in streaming mode.
    ///
    /// # Arguments
    ///
    /// * `plain` - The input to encrypt.
    /// * `cipher` - The buffer to store the encrypted data.
    ///
    /// # Returns
    ///
    /// A `Res` indicating the success or failure of the operation.
    #[inline]
    pub fn encrypt_into(&mut self, plain: &[u8], cipher: &mut [u8]) -> Result<(), Unspecified> {
        self.process(plain, cipher)
    }

    /// Encrypts the input into the output buffer in streaming mode with compile-time size checking.
    ///
    /// # Arguments
    ///
    /// * `plain` - The input array to encrypt.
    /// * `cipher` - The array to store the encrypted data.
    ///
    /// # Errors
    ///
    /// - The length of `plain` was greater than [`u32::MAX`].
    /// - The length of `cipher` was less than the length of `plain`.
    #[inline]
    pub fn encrypt_into_sized<const I: usize, const O: usize>(
        &mut self,
        plain: &[u8; I],
        cipher: &mut [u8; O]
    ) -> Result<(), Unspecified> {
        self.process_sized(plain, cipher)
    }

    /// Encrypts the input into the output buffer in streaming mode with exact sizes.
    ///
    /// # Type Parameters
    ///
    /// * `C` - The size of both the input and output arrays.
    ///
    /// # Arguments
    ///
    /// * `input` - The input array to encrypt.
    /// * `output` - The array to store the encrypted data.
    ///
    /// # Errors
    ///
    /// `C` (the length of `input` and `output`) was greater than [`u32::MAX`].
    #[inline]
    pub fn encrypt_into_exact<const C: usize>(
        &mut self,
        input: &[u8; C],
        output: &mut [u8; C]
    ) -> Result<(), Unspecified> {
        self.process_exact(input, output)
    }

    /// Finishes the streaming encryption and returns to the `NeedsIv` state.
    ///
    /// # Returns
    ///
    /// A `ChaCha20` instance in the `NeedsIv` state.
    #[inline]
    pub const fn finish(self) -> ChaCha20<NeedsIv> {
        Self::new_with(self.inner)
    }

    std! {
        /// Creates a new `Writer` for streaming encryption with a custom chunk size.
        ///
        /// # Type Parameters
        ///
        /// * `CHUNK` - The chunk size for processing. This is the size of the intermediary buffer
        ///             stored on the stack in bytes for the `write_all` and `write`
        ///             implementations.
        ///
        /// # Arguments
        ///
        /// * `writer` - The underlying writer to use.
        ///
        /// # Returns
        ///
        /// A new `Writer` instance.
        ///
        /// # Errors
        ///
        /// If the provided `CHUNK` constant is greater than U32 max this will return the provided
        /// `writer`.
        pub const fn writer<W: io::Write, const CHUNK: usize>(self, writer: W) -> Result<Writer<W, CHUNK>, W> {
            Writer::new(self, writer)
        }

        /// Creates a new `Writer` for streaming encryption with a default chunk size of 128 bytes.
        ///
        /// # Arguments
        ///
        /// * `writer` - The underlying writer to use.
        ///
        /// # Returns
        ///
        /// A new `Writer` instance with a chunk size of 128 bytes.
        pub const fn default_writer<W: io::Write>(self, writer: W) -> Writer<W, 128> {
            // SAFETY: 128 is significantly less than u32::MAX
            unsafe { Writer::<W, 128>::new_unchecked(self, writer) }
        }
    }
}

impl_fmt! { Streaming }

std! {
    use std::io;
    use core::ops;

    /// A wrapper for any implementor of `std::io::Write`.
    ///
    /// `Writer` implements `std::io::Write` and takes a child which also implements this trait.
    /// This type can wrap any writer, and ensure all data passed to said writer is encrypted.
    pub struct Writer<W, const CHUNK: usize> {
        chacha: ChaCha20<Streaming>,
        writer: W
    }

    impl<W, const CHUNK: usize> Writer<W, CHUNK> {
        /// Creates a new `Writer` instance.
        ///
        /// # Arguments
        ///
        /// * `chacha` - The `ChaCha20` instance in streaming mode.
        /// * `writer` - The underlying writer.
        ///
        /// # Returns
        ///
        /// A new `Writer` instance.
        ///
        /// # Errors
        ///
        /// If the size of `CHUNK` is greater than [`u32::MAX`]
        pub const fn new(chacha: ChaCha20<Streaming>, writer: W) -> Result<Self, W> {
            if const_can_cast_u32::<CHUNK>() {
                Ok(Self {
                    chacha,
                    writer
                })
            } else {
                Err(writer)
            }
        }

        /// # Safety
        ///
        /// The size of `CHUNK` must not be greater than [`u32::MAX`]
        const unsafe fn new_unchecked(chacha: ChaCha20<Streaming>, writer: W) -> Self {
            Self {
                chacha,
                writer
            }
        }

        /// Finishes the streaming encryption and returns to the `NeedsIv` state.
        ///
        /// # Returns
        ///
        /// A `ChaCha20` instance in the `NeedsIv` state.
        #[inline]
        pub fn finish(self) -> ChaCha20<NeedsIv> {
            self.chacha.finish()
        }
    }

    impl<W, const CHUNK: usize> ops::Deref for Writer<W, CHUNK> {
        type Target = ChaCha20<Streaming>;

        #[inline]
        fn deref(&self) -> &Self::Target {
            &self.chacha
        }
    }

    impl<W, const CHUNK: usize> ops::DerefMut for Writer<W, CHUNK> {
        #[inline]
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.chacha
        }
    }

    impl<W: io::Write, const CHUNK: usize> io::Write for Writer<W, CHUNK> {
        /// Encrypts and writes the given buffer.
        ///
        /// # Arguments
        ///
        /// * `buf` - The buffer to encrypt and write.
        ///
        /// # Returns
        ///
        /// The number of bytes written on success, or an `io::Error` on failure.
        ///
        /// # Note
        ///
        /// The maximum number of bytes this can write in a single invocation is capped by the
        /// `CHUNK` size. If this is not desirable, please consider using the `write_all`
        /// implementation.
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut out = [0u8; CHUNK];
            let to_write = core::cmp::min(CHUNK, buf.len());

            // SAFETY: we cannot be constructed with a chunk size larger than u32::MAX
            unsafe { self.process_unchecked(&buf[..to_write], &mut out[..to_write]) };
            self.writer.write(&out[..to_write])
        }

        /// Encrypts and writes the entire buffer.
        ///
        /// # Arguments
        ///
        /// * `buf` - The buffer to encrypt and write.
        ///
        /// # Returns
        ///
        /// `Ok(())` on success, or an `io::Error` on failure.
        fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            let mut out = [0u8; CHUNK];
            let mut pos = 0usize;
            let len = buf.len();

            while pos + CHUNK <= len {
                unsafe {
                    // SAFETY: we cannot be constructed with a chunk size larger than u32::MAX
                    self.process_unchecked(&buf[pos..pos + CHUNK], &mut out);
                    pos += CHUNK;
                    self.writer.write_all(&out)?;
                }
            }

            let last = &buf[pos..];
            debug_assert!(last.len() <= CHUNK);

            // SAFETY: We are handling less than the CHUNK size.
            unsafe { self.process_unchecked(last, &mut out) }
            self.writer.write_all(&out[..last.len()])
        }

        /// Flushes the underlying writer.
        ///
        /// # Returns
        ///
        /// Propagates the result of invoking flush for the underlying writer
        #[inline]
        fn flush(&mut self) -> io::Result<()> {
            self.writer.flush()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        let (encrypted, chacha) = ChaCha20::new(&[0u8; 16])
            .set_iv([3u8; 12])
            .encrypt_exact(b"hello world!")
            .unwrap();

        let plain = chacha
            .set_iv([3u8; 12])
            .decrypt_exact(&encrypted)
            .unwrap();

        assert_eq!(plain, *b"hello world!");
    }
}

#[cfg(test)]
mod property_tests {
    use crate::aes::test_utils::{BoundList, AnyList};
    use proptest::prelude::*;
    use crate::chacha::{ChaCha20, Key};
    use crate::buf::Nonce;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10_000))]

        #[test]
        fn in_place_bijectivity(
            input in any::<BoundList<1024>>(),
            key in any::<Key>(),
            iv in any::<Nonce>()
        ) {
            let mut in_out = input;

            ChaCha20::new(key.as_ref())
                .set_iv(iv.copy())
                .encrypt_in_place(in_out.as_mut_slice())
                .unwrap();

            if in_out.len() >= 3 {
                prop_assert_ne!(in_out, input);
            }

            ChaCha20::new(key)
                .set_iv(iv)
                .decrypt_in_place(in_out.as_mut_slice())
                .unwrap();

            prop_assert_eq!(in_out, input);
        }

        #[test]
        fn enc_into_dec_in_place(
            input in any::<BoundList<1024>>(),
            key in any::<Key>(),
            iv in any::<Nonce>()
        ) {
            let mut enc = input.create_self();

            ChaCha20::new(key.as_ref()).set_iv(iv.copy())
                .encrypt_into(input.as_slice(), enc.as_mut_slice())
                .unwrap();

            if enc.len() >= 3 {
                prop_assert_ne!(enc.as_slice(), input.as_slice());
            }

            ChaCha20::new(key.as_ref()).set_iv(iv)
                .decrypt_in_place(enc.as_mut_slice())
                .unwrap();

            prop_assert_eq!(enc, input);
        }

        #[test]
        fn enc_in_place_dec_into(
            input in any::<BoundList<1024>>(),
            key in any::<Key>(),
            iv in any::<Nonce>()
        ) {
            let mut enc = input;

            ChaCha20::new(key.as_ref()).set_iv(iv.copy())
                .encrypt_in_place(enc.as_mut_slice())
                .unwrap();

            if enc.len() >= 3 {
                prop_assert_ne!(enc.as_slice(), input.as_slice());
            }

            let mut dec = input.create_self();

            ChaCha20::new(key.as_ref()).set_iv(iv)
                .decrypt_into(enc.as_slice(), dec.as_mut_slice())
                .unwrap();

            prop_assert_eq!(dec, input);
        }

        #[test]
        fn bijective_arb_updates(
            inputs in any::<AnyList<32, BoundList<512>>>(),
            key in any::<Key>(),
            iv in any::<[u8; 12]>()
        ) {
            let mut outputs = inputs.create_self();

            let io_iter = inputs.as_slice().iter().zip(outputs.as_mut_slice());
            let mut chacha = ChaCha20::new(key.as_ref()).set_iv(&iv).stream();

            for (i, o) in io_iter {
                chacha.encrypt_into(i, o).unwrap();
                if i.len() >= 3 { prop_assert_ne!(i.as_slice(), o.as_slice()); }
            }

            let mut in_out = outputs.join();
            let expected = inputs.join();

            ChaCha20::new(key).set_iv(iv)
                .decrypt_in_place(in_out.as_mut_slice())
                .unwrap();

            prop_assert_eq!(in_out, expected);
        }
    }
}