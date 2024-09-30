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
use crate::opaque_res::Res;
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
    ///
    /// # Returns
    ///
    /// A `Res` indicating the success or failure of the operation.
    #[inline]
    unsafe fn process_unchecked(&mut self, input: &[u8], output: &mut [u8]) -> Res {
        debug_assert!(
            Self::predicate(input.len(), output.len()),
            "Process unchecked precondition violated (debug assertion). The size of the input must \
            be less than or equal to the size of the output. The size of the input must also be \
            representable as a `u32` without overflowing."
        );
        let mut res = Res::new();

        res.ensure_0(wc_Chacha_Process(
            addr_of_mut!(self.inner),
            output.as_mut_ptr(),
            input.as_ptr(),
            input.len() as u32
        ));

        res
    }

    /// Processes the input into the output buffer, checking lengths.
    ///
    /// # Arguments
    ///
    /// * `input` - The input slice to process.
    /// * `output` - The output buffer to write the processed data into.
    ///
    /// # Returns
    ///
    /// A `Res` indicating the success or failure of the operation.
    #[inline]
    fn process(&mut self, input: &[u8], output: &mut [u8]) -> Res {
        if !Self::predicate(input.len(), output.len()) { return Res::ERR }
        unsafe { self.process_unchecked(input, output) }
    }

    /// Processes the input into the output buffer with exact sizes.
    ///
    /// # Arguments
    ///
    /// * `input` - The input array to process.
    /// * `output` - The output array to write the processed data into.
    ///
    /// # Returns
    ///
    /// A `Res` indicating the success or failure of the operation.
    #[inline]
    fn process_exact<const C: usize>(
        &mut self,
        input: &[u8; C],
        output: &mut [u8; C]
    ) -> Res {
        if !const_can_cast_u32::<C>() { return Res::ERR; }
        unsafe { self.process_unchecked(input, output) }
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
    /// # Returns
    ///
    /// A `Res` indicating the success or failure of the operation.
    #[inline]
    fn process_sized<const I: usize, const O: usize>(
        &mut self,
        input: &[u8; I],
        output: &mut [u8; O]
    ) -> Res {
        if !Self::const_predicate::<I, O>() { return Res::ERR }
        unsafe { self.process_unchecked(input, output) }
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
    /// # Returns
    ///
    /// A `Res` indicating the success or failure of the operation.
    #[inline]
    fn process_sized_out<const O: usize>(
        &mut self,
        input: &[u8],
        output: &mut [u8; O]
    ) -> Res {
        if !(lte::<O>(input.len()) && can_cast_u32(input.len())) { return Res::ERR }
        unsafe { self.process_unchecked(input, output) }
    }
}

impl ChaCha20<Ready> {
    /// Encrypts the plaintext into the ciphertext buffer.
    ///
    /// # Arguments
    ///
    /// * `plain` - The plaintext to encrypt.
    /// * `ciphertext` - The buffer to store the encrypted data.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the `ChaCha20` instance in the `NeedsIv` state
    /// on success, or the original instance on failure.
    #[inline]
    pub fn encrypt_into(
        mut self,
        plain: &[u8],
        ciphertext: &mut [u8]
    ) -> Result<ChaCha20<NeedsIv>, Self> {
        if self.process(plain, ciphertext).is_ok() {
            Ok(Self::new_with(self.inner))
        } else {
            Err(self)
        }
    }

    /// Encrypts the plaintext into the ciphertext buffer with compile-time size checking.
    ///
    /// # Type Parameters
    ///
    /// * `P` - The size of the plaintext array.
    /// * `C` - The size of the ciphertext array.
    ///
    /// # Arguments
    ///
    /// * `plain` - The plaintext array to encrypt.
    /// * `ciphertext` - The array to store the encrypted data.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the `ChaCha20` instance in the `NeedsIv` state
    /// on success, or the original instance on failure.
    #[inline]
    pub fn encrypt_into_sized<const P: usize, const C: usize>(
        mut self,
        plain: &[u8; P],
        ciphertext: &mut [u8; C]
    ) -> Result<ChaCha20<NeedsIv>, Self> {
        if self.process_sized(plain, ciphertext).is_ok() {
            Ok(Self::new_with(self.inner))
        } else {
            Err(self)
        }
    }

    /// Encrypts the plaintext into a fixed-size ciphertext buffer.
    ///
    /// # Type Parameters
    ///
    /// * `C` - The size of the ciphertext array.
    ///
    /// # Arguments
    ///
    /// * `plain` - The plaintext to encrypt.
    /// * `ciphertext` - The array to store the encrypted data.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the `ChaCha20` instance in the `NeedsIv` state
    /// on success, or the original instance on failure.
    #[inline]
    pub fn encrypt_into_sized_out<const C: usize>(
        mut self,
        plain: &[u8],
        ciphertext: &mut [u8; C]
    ) -> Result<ChaCha20<NeedsIv>, Self> {
        if self.process_sized_out(plain, ciphertext).is_ok() {
            Ok(Self::new_with(self.inner))
        } else {
            Err(self)
        }
    }

    /// Encrypts the plaintext into the ciphertext buffer with exact sizes.
    ///
    /// # Type Parameters
    ///
    /// * `C` - The size of both the plaintext and ciphertext arrays.
    ///
    /// # Arguments
    ///
    /// * `plain` - The plaintext array to encrypt.
    /// * `ciphertext` - The array to store the encrypted data.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the `ChaCha20` instance in the `NeedsIv` state
    /// on success, or the original instance on failure.
    #[inline]
    pub fn encrypt_into_exact<const C: usize>(
        mut self,
        plain: &[u8; C],
        ciphertext: &mut [u8; C]
    ) -> Result<ChaCha20<NeedsIv>, Self> {
        if self.process_exact(plain, ciphertext).is_ok() {
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
    /// A `Result` containing either a tuple of the ciphertext vector and the `ChaCha20`
    /// instance in the `NeedsIv` state on success, or the original instance on failure.
    pub fn encrypt(
        mut self,
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
    /// A `Result` containing either a tuple of the ciphertext array and the `ChaCha20`
    /// instance in the `NeedsIv` state on success, or the original instance on failure.
    #[inline]
    pub fn encrypt_exact<const I: usize>(
        self,
        plain: &[u8; I]
    ) -> Result<([u8; I], ChaCha20<NeedsIv>), Self> {
        let mut output = [0u8; I];
        self.encrypt_into_exact(plain, &mut output).map(move |ni| (output, ni))
    }
}

impl_fmt! { Ready }

impl<S: CanProcess> ChaCha20<S> {
    /// Decrypts the ciphertext into the output buffer.
    ///
    /// # Arguments
    ///
    /// * `cipher` - The ciphertext to decrypt.
    /// * `output` - The buffer to store the decrypted data.
    ///
    /// # Returns
    ///
    /// A `Res` indicating the success or failure of the operation.
    #[inline]
    pub fn decrypt_into(&mut self, cipher: &[u8], output: &mut [u8]) -> Res {
        self.process(cipher, output)
    }

    /// Decrypts the ciphertext into the output buffer with compile-time size checking.
    ///
    /// # Type Parameters
    ///
    /// * `I` - The size of the ciphertext array.
    /// * `O` - The size of the output array.
    ///
    /// # Arguments
    ///
    /// * `cipher` - The ciphertext array to decrypt.
    /// * `output` - The array to store the decrypted data.
    ///
    /// # Returns
    ///
    /// A `Res` indicating the success or failure of the operation.
    #[inline]
    pub fn decrypt_into_sized<const I: usize, const O: usize>(
        &mut self,
        cipher: &[u8; I],
        output: &mut [u8; O]
    ) -> Res {
        self.process_sized(cipher, output)
    }

    /// Decrypts the ciphertext into the output buffer with exact sizes.
    ///
    /// # Type Parameters
    ///
    /// * `C` - The size of both the ciphertext and output arrays.
    ///
    /// # Arguments
    ///
    /// * `cipher` - The ciphertext array to decrypt.
    /// * `output` - The array to store the decrypted data.
    ///
    /// # Returns
    ///
    /// A `Res` indicating the success or failure of the operation.
    #[inline]
    pub fn decrypt_into_exact<const C: usize>(&mut self, cipher: &[u8; C], output: &mut [u8; C]) -> Res {
        self.process_exact(cipher, output)
    }

    alloc! {
    /// Decrypts the ciphertext and returns the plaintext as a vector.
    ///
    /// # Arguments
    ///
    /// * `cipher` - The ciphertext to decrypt.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the decrypted plaintext as a vector on success,
    /// or an `Unspecified` error on failure.
    #[inline]
    pub fn decrypt(&mut self, cipher: &[u8]) -> Result<alloc::vec::Vec<u8>, Unspecified> {
        let mut output = alloc::vec![0u8; cipher.len()];
        self.decrypt_into(cipher, output.as_mut_slice()).unit_err(output)
    }
    }

    /// Decrypts the ciphertext array and returns the plaintext array.
    ///
    /// # Type Parameters
    ///
    /// * `O` - The size of the ciphertext and plaintext arrays.
    ///
    /// # Arguments
    ///
    /// * `cipher` - The ciphertext array to decrypt.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the decrypted plaintext array on success,
    /// or an `Unspecified` error on failure.
    #[inline]
    pub fn decrypt_exact<const O: usize>(&mut self, cipher: &[u8; O]) -> Result<[u8; O], Unspecified> {
        let mut output = [0u8; O];
        self.decrypt_into_exact(cipher, &mut output).unit_err(output)
    }
}

impl ChaCha20<Streaming> {
    /// Encrypts the input into the output buffer in streaming mode.
    ///
    /// # Arguments
    ///
    /// * `input` - The input to encrypt.
    /// * `output` - The buffer to store the encrypted data.
    ///
    /// # Returns
    ///
    /// A `Res` indicating the success or failure of the operation.
    #[inline]
    pub fn encrypt_into(&mut self, input: &[u8], output: &mut [u8]) -> Res {
        self.process(input, output)
    }

    /// Encrypts the input into the output buffer in streaming mode with compile-time size checking.
    ///
    /// # Type Parameters
    ///
    /// * `I` - The size of the input array.
    /// * `O` - The size of the output array.
    ///
    /// # Arguments
    ///
    /// * `input` - The input array to encrypt.
    /// * `output` - The array to store the encrypted data.
    ///
    /// # Returns
    ///
    /// A `Res` indicating the success or failure of the operation.
    #[inline]
    pub fn encrypt_into_sized<const I: usize, const O: usize>(
        &mut self,
        input: &[u8; I],
        output: &mut [u8; O]
    ) -> Res {
        self.process_sized(input, output)
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
    /// # Returns
    ///
    /// A `Res` indicating the success or failure of the operation.
    #[inline]
    pub fn encrypt_into_exact<const C: usize>(
        &mut self,
        input: &[u8; C],
        output: &mut [u8; C]
    ) -> Res {
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
        /// * `W` - The type of the writer.
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
        pub const fn writer<W: io::Write, const CHUNK: usize>(self, writer: W) -> Writer<W, CHUNK> {
            Writer::new(self, writer)
        }

        /// Creates a new `Writer` for streaming encryption with a default chunk size of 128 bytes.
        ///
        /// # Type Parameters
        ///
        /// * `W` - The type of the writer.
        ///
        /// # Arguments
        ///
        /// * `writer` - The underlying writer to use.
        ///
        /// # Returns
        ///
        /// A new `Writer` instance with a chunk size of 128 bytes.
        pub const fn default_writer<W: io::Write>(self, writer: W) -> Writer<W, 128> {
            Writer::new(self, writer)
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
        pub const fn new(chacha: ChaCha20<Streaming>, writer: W) -> Self {
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

            if unsafe { self.process_unchecked(&buf[..to_write], &mut out[..to_write]).is_err() } {
                return Err(io::Error::other(Unspecified))
            }

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
                    if self.process_unchecked(&buf[pos..pos + CHUNK], &mut out).is_err() {
                        return Err(io::Error::other(Unspecified));
                    }
                    pos += CHUNK;
                    self.writer.write_all(&out)?;
                }
            }

            let last = &buf[pos..];

            if unsafe { self.process_unchecked(last, &mut out).is_err() } {
                return Err(io::Error::other(Unspecified));
            }

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