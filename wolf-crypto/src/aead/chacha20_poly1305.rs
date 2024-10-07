//! The `ChaCha20Poly1305` Authenticated Encryption with Associated Data (AEAD).
//!
//! This module offers both one-shot encryption/decryption functions and a stateful API that can be
//! used to perform streaming encryption/decryption with optional associated data (AAD). The
//! stateful API ensures correct usage through a compile-time state machine.
//!
//! # Examples
//!
//! Using the one-shot encryption function:
//!
//! ```
//! use wolf_crypto::aead::chacha20_poly1305::{encrypt, decrypt_in_place, Key};
//!
//! # fn main() -> Result<(), wolf_crypto::Unspecified> {
//! let key = Key::new([0u8; 32]);
//! let iv = [0u8; 12];
//! let plaintext = b"Secret message";
//! let mut ciphertext = [0u8; 14];
//!
//! let tag = encrypt(key.as_ref(), &iv, plaintext, &mut ciphertext, ())?;
//! decrypt_in_place(key, iv, &mut ciphertext, (), tag)?;
//!
//! assert_eq!(ciphertext, *plaintext);
//! # Ok(()) }
//! ```
//!
//! Using the stateful API:
//!
//! ```
//! use wolf_crypto::{aead::ChaCha20Poly1305, MakeOpaque};
//! use wolf_crypto::mac::poly1305::Key;
//!
//! # fn main() -> Result<(), wolf_crypto::Unspecified> {
//! let plaintext = b"Secret message";
//! let aad = "Additional data";
//! let mut ciphertext = [0u8; 14];
//!
//! let tag = ChaCha20Poly1305::new_encrypt(Key::new([7u8; 32]), [7u8; 12])
//!     .set_aad(aad).opaque()?
//!     .update(plaintext, &mut ciphertext).opaque()?
//!     .finalize();
//!
//! let d_tag = ChaCha20Poly1305::new_decrypt(Key::new([7u8; 32]), [7u8; 12])
//!     .update_aad("Additional ")
//!     .opaque_bind(|aead| aead.update_aad("data"))
//!     .opaque_bind(|aead| aead.update_in_place(&mut ciphertext))
//!     .opaque_map(|aead| aead.finalize())?;
//!
//! assert_eq!(tag, d_tag);
//! assert_eq!(ciphertext, *plaintext);
//! # Ok(())}
//! ```

pub mod states;

io_impls! {
    #[doc(hidden)]
    pub mod io;

    #[doc(inline)]
    pub use io::Aad as IoAad;

    #[doc(inline)]
    pub use io::Data as IoData;
}

use wolf_crypto_sys::{
    ChaChaPoly_Aead,
    wc_ChaCha20Poly1305_UpdateData, wc_ChaCha20Poly1305_UpdateAad,
    wc_ChaCha20Poly1305_Init, wc_ChaCha20Poly1305_Final,
    wc_ChaCha20Poly1305_Decrypt, wc_ChaCha20Poly1305_Encrypt,
    CHACHA20_POLY1305_AEAD_DECRYPT, CHACHA20_POLY1305_AEAD_ENCRYPT,
};

#[cfg(feature = "llvm-assume")]
use wolf_crypto_sys::{
    CHACHA20_POLY1305_STATE_READY, CHACHA20_POLY1305_STATE_AAD, CHACHA20_POLY1305_STATE_DATA,
    byte
};

use states::{
    State, Init, CanUpdate, CanSetAad, CanUpdateAad,
    Updating, UpdatingAad,

    EncryptMaybeAad, DecryptMaybeAad,
    EncryptAad, DecryptAad,
};

#[doc(inline)]
pub use states::{Decrypt, Encrypt};

use core::mem::MaybeUninit;
use core::marker::PhantomData;
use core::ptr::addr_of_mut;
use crate::aead::{Aad, Tag};
use crate::buf::{GenericIv, U12};
use crate::mac::poly1305::GenericKey;
use crate::opaque_res::Res;
use crate::{can_cast_u32, const_can_cast_u32, Unspecified};

#[doc(inline)]
pub use crate::mac::poly1305::{Key, KeyRef};

opaque_dbg! { ChaCha20Poly1305<Init> }
opaque_dbg! { ChaCha20Poly1305<EncryptMaybeAad> }
opaque_dbg! { ChaCha20Poly1305<DecryptMaybeAad> }
opaque_dbg! { ChaCha20Poly1305<EncryptAad> }
opaque_dbg! { ChaCha20Poly1305<DecryptAad> }
opaque_dbg! { ChaCha20Poly1305<Encrypt> }
opaque_dbg! { ChaCha20Poly1305<Decrypt> }

#[inline(always)]
#[must_use]
fn oneshot_predicate<A: Aad>(plain: &[u8], out: &[u8], aad: &A) -> bool {
    can_cast_u32(plain.len()) && out.len() >= plain.len() && aad.is_valid_size()
}

/// Encrypts data using the `ChaCha20Poly1305` AEAD.
///
/// # Arguments
///
/// * `key` - The 32-byte key material.
/// * `iv` - The 12-byte initialization vector.
/// * `plain` - The plaintext data to encrypt.
/// * `out` - The buffer to store the resulting ciphertext. The buffer must be at least as large
///   as `plain`.
/// * `aad` - The associated data, which is authenticated but not encrypted.
///
/// # Returns
///
/// The authentication [`Tag`] for the ciphertext, used to verify the integrity and authenticity
/// of the data during decryption.
///
/// # Errors
///
/// - The length of the plaintext is greater than [`u32::MAX`].
/// - The length of the output buffer is less than the plaintext length.
/// - The length of the associated data is greater than [`u32::MAX`].
///
/// # Example
///
/// ```
/// use wolf_crypto::{aead::chacha20_poly1305::encrypt, mac::poly1305::Key};
///
/// let mut out = [0u8; 12];
///
/// let tag = encrypt(
///     Key::new([7u8; 32]), [42u8; 12],
///     b"hello world!", &mut out,
///     "Some additional data"
/// ).unwrap();
///
/// assert_ne!(&out, b"hello world!");
/// # let _ = tag;
/// ```
pub fn encrypt<K, IV, A>(
    key: K, iv: IV,
    plain: &[u8], out: &mut [u8],
    aad: A
) -> Result<Tag, Unspecified>
    where
        K: GenericKey,
        IV: GenericIv<Size = U12>,
        A: Aad
{
    if !oneshot_predicate(plain, out, &aad) { return Err(Unspecified) }
    let mut res = Res::new();
    let mut tag = Tag::new_zeroed();

    unsafe {
        res.ensure_0(wc_ChaCha20Poly1305_Encrypt(
            key.ptr(),
            iv.as_slice().as_ptr(),
            aad.ptr(),
            aad.size(),
            plain.as_ptr(),
            plain.len() as u32,
            out.as_mut_ptr(),
            tag.as_mut_ptr()
        ));
    }

    res.unit_err(tag)
}

/// Encrypts data in-place using the `ChaCha20Poly1305` AEAD.
///
/// # Arguments
///
/// * `key` - The 32-byte key material.
/// * `iv` - The 12-byte initialization vector.
/// * `in_out` - A mutable buffer containing the plaintext, which is overwritten with the ciphertext.
/// * `aad` - The associated data, which is authenticated but not encrypted.
///
/// # Returns
///
/// The authentication [`Tag`] for the ciphertext, used to verify the integrity and authenticity
/// of the data during decryption.
///
/// # Errors
///
/// - The length of the plaintext is greater than [`u32::MAX`].
/// - The length of the associated data is greater than [`u32::MAX`].
///
/// # Example
///
/// ```
/// use wolf_crypto::aead::chacha20_poly1305::{encrypt_in_place, Key};
///
/// let mut in_out = *b"Hello, world!";
/// let tag = encrypt_in_place(Key::new([7u8; 32]), [42u8; 12], &mut in_out, "additional").unwrap();
///
/// assert_ne!(&in_out, b"Hello, world!");
/// # let _ = tag;
/// ```
pub fn encrypt_in_place<K, IV, A>(key: K, iv: IV, in_out: &mut [u8], aad: A) -> Result<Tag, Unspecified>
    where
        K: GenericKey,
        IV: GenericIv<Size = U12>,
        A: Aad
{
    if !(can_cast_u32(in_out.len()) && aad.is_valid_size()) { return Err(Unspecified) }
    let mut res = Res::new();
    let mut tag = Tag::new_zeroed();

    unsafe {
        res.ensure_0(wc_ChaCha20Poly1305_Encrypt(
            key.ptr(),
            iv.as_slice().as_ptr(),
            aad.ptr(),
            aad.size(),
            in_out.as_ptr(),
            in_out.len() as u32,
            in_out.as_ptr().cast_mut(),
            tag.as_mut_ptr()
        ));
    }

    res.unit_err(tag)
}

/// Decrypts data using the `ChaCha20Poly1305` AEAD.
///
/// # Arguments
///
/// * `key` - The 32-byte key material.
/// * `iv` - The 12-byte initialization vector.
/// * `cipher` - The ciphertext to decrypt.
/// * `out` - The buffer to store the resulting plaintext. The buffer must be at least as large as
///   `cipher`.
/// * `aad` - The associated data, which is authenticated but not encrypted.
/// * `tag` - The authentication tag to verify.
///
/// # Errors
///
/// - The length of the ciphertext is greater than [`u32::MAX`].
/// - The length of the output buffer is less than the plaintext length.
/// - The length of the associated data is greater than [`u32::MAX`].
/// - The verification of the authentication tag failed, indicating tampering.
///
/// # Example
///
/// ```
/// use wolf_crypto::aead::chacha20_poly1305::{encrypt_in_place, decrypt, Key};
///
/// let (key, iv, mut cipher) = (Key::new([7u8; 32]), [42u8; 12], *b"plaintext");
/// let tag = encrypt_in_place(key.as_ref(), &iv, &mut cipher, "additional data").unwrap();
///
/// let mut plain = [0u8; 9];
/// decrypt(key, iv, &cipher, &mut plain, "additional data", tag).unwrap();
///
/// assert_eq!(plain, *b"plaintext");
/// ```
pub fn decrypt<K, IV, A>(
    key: K, iv: IV,
    cipher: &[u8], out: &mut [u8],
    aad: A, tag: Tag
) -> Result<(), Unspecified>
    where
        K: GenericKey,
        IV: GenericIv<Size = U12>,
        A: Aad
{
    if !oneshot_predicate(cipher, out, &aad) { return Err(Unspecified) }
    let mut res = Res::new();

    unsafe {
        res.ensure_0(wc_ChaCha20Poly1305_Decrypt(
            key.ptr(),
            iv.as_slice().as_ptr(),
            aad.ptr(),
            aad.size(),
            cipher.as_ptr(),
            cipher.len() as u32,
            tag.as_ptr(),
            out.as_mut_ptr()
        ));
    }

    res.unit_err(())
}

/// Decrypts data in-place using the `ChaCha20Poly1305` AEAD.
///
/// # Arguments
///
/// * `key` - The 32-byte key material.
/// * `iv` - The 12-byte initialization vector.
/// * `in_out` - A mutable buffer containing the ciphertext, which is overwritten with the plaintext.
/// * `aad` - The associated data, which is authenticated but not encrypted.
/// * `tag` - The authentication tag to verify.
///
/// # Errors
///
/// - The length of the ciphertext is greater than [`u32::MAX`].
/// - The length of the associated data is greater than [`u32::MAX`].
/// - The verification of the authentication tag failed, indicating tampering.
///
/// # Example
///
/// ```
/// use wolf_crypto::aead::chacha20_poly1305::{encrypt_in_place, decrypt_in_place, Key};
///
/// let (key, iv, mut in_out) = (Key::new([7u8; 32]), [42u8; 12], *b"plaintext");
/// let tag = encrypt_in_place(key.as_ref(), &iv, &mut in_out, "additional data").unwrap();
///
/// decrypt_in_place(key, iv, &mut in_out, "additional data", tag).unwrap();
///
/// assert_eq!(in_out, *b"plaintext");
/// ```
pub fn decrypt_in_place<K, IV, A>(
    key: K, iv: IV,
    in_out: &mut [u8],
    aad: A, tag: Tag
) -> Result<(), Unspecified>
where
    K: GenericKey,
    IV: GenericIv<Size = U12>,
    A: Aad
{
    if !(can_cast_u32(in_out.len()) && aad.is_valid_size()) { return Err(Unspecified) }
    let mut res = Res::new();

    unsafe {
        res.ensure_0(wc_ChaCha20Poly1305_Decrypt(
            key.ptr(),
            iv.as_slice().as_ptr(),
            aad.ptr(),
            aad.size(),
            in_out.as_ptr(),
            in_out.len() as u32,
            tag.as_ptr(),
            in_out.as_ptr().cast_mut()
        ));
    }

    res.unit_err(())
}

/// The `ChaCha20Poly1305` ([`RFC8439`][1]) [AEAD][2].
///
/// `ChaCha20Poly1305` combines the [`ChaCha20`][3] stream cipher with the [`Poly1305`][4] message
/// authentication code. `ChaCha20Poly1305` is well-regarded for efficiency and performance, with
/// or without hardware acceleration, making it amenable to resource constrained environments.
///
/// # Interface
///
/// This crate's interface for `ChaCha20Poly1305` is designed as a compile-time state machine,
/// ensuring errors / misuse is caught early, and without any runtime overhead.
///
/// The state machine for both encryption and decryption follows the following flow
///
/// ```txt
///                       set_aad(...)
///   +--------------------------------------+
///   |           +---+                      |
///   |           |   v                      v           finalize()
/// +------+     +-----+   finish()        +----------+        +-----+
/// | Init | --> | AAD | ----------------> |          | -----> | Tag |
/// +------+     +-----+                   | Updating |        +-----+
///   |                   update(...)      |          |
///   +----------------------------------> |          |
///                                        +----------+
///                                          ^      |
///                                          +------+
/// ```
///
/// The state machine is initialized in either decryption or encryption mode, this initial state
/// has the following three possible transitions:
///
/// ```txt
///                 +------------------+
///   +------------ |       Init       | --------+
///   |             +------------------+         |
///   |               |                          |
///   |               | update_aad(...)          |
///   |               v                          |
///   |             +------------------+         |
///   |             |                  |--+      |
///   |             |       AAD        |  |      |
///   |             |                  |<-+      |
///   |             +------------------+         |
///   |               |                          |
///   | update(...)   | finish()                 | set_aad(...)
///   |               v                          |
///   |             +------------------+         |
///   +-----------> |     Updating     | <-------+
///                 +------------------+
///                          |
///                          v
///                         ...
/// ```
///
/// - [`update(...)`][5] path:
///     The user encrypts or decrypts data without providing any AAD. This method is used
///     to process the main body of the message. After processing the plaintext or ciphertext,
///     the user can either continue updating with more data, or invoke [`finalize()`][6]
///     to return the authentication tag.
/// - [`set_aad`][6] path:
///     Similar to the [`update(...)`][5] path, but this method sets the associated data (AAD),
///     which is data that is authenticated but not encrypted. The AAD is processed first
///     before transitioning to the `Updating` state, where data is encrypted or decrypted.
///     AAD helps verify the integrity of the message.
/// - [`update_aad(...)`][7] path:
///     This method transitions to the `AAD` state, allowing the user to process associated
///     data in chunks. It is useful in cases where the complete AAD is not available at once,
///     and the user needs to progressively update it. Once all AAD is processed, the state
///     transitions to `Updating` by invoking [`finish()`][8].
///
/// # Examples
///
/// ```
/// use wolf_crypto::{aead::ChaCha20Poly1305, mac::poly1305::Key, MakeOpaque};
///
/// # fn main() -> Result<(), wolf_crypto::Unspecified> {
/// let mut in_out = [7u8; 42];
/// let key = Key::new([3u8; 32]);
///
/// let tag = ChaCha20Poly1305::new_encrypt(key.as_ref(), [7u8; 12])
///     .update_in_place(&mut in_out).opaque()?
///     .finalize();
///
/// assert_ne!(in_out, [7u8; 42]);
///
/// let d_tag = ChaCha20Poly1305::new_decrypt(key.as_ref(), [7u8; 12])
///     .update_in_place(&mut in_out).opaque()?
///     .finalize();
///
/// // PartialEq for tags is constant time
/// assert_eq!(tag, d_tag);
/// assert_eq!(in_out, [7u8; 42]);
/// #
/// # Ok(()) }
/// ```
///
/// **With AAD**
///
/// ```
/// use wolf_crypto::{aead::ChaCha20Poly1305, mac::poly1305::Key, MakeOpaque};
///
/// # fn main() -> Result<(), wolf_crypto::Unspecified> {
/// let mut in_out = [7u8; 42];
/// let key = Key::new([3u8; 32]);
///
/// let tag = ChaCha20Poly1305::new_encrypt(key.as_ref(), [7u8; 12])
///     .set_aad("hello world").opaque()?
///     .update_in_place(&mut in_out).opaque()?
///     .finalize();
///
/// assert_ne!(in_out, [7u8; 42]);
///
/// let d_tag = ChaCha20Poly1305::new_decrypt(key.as_ref(), [7u8; 12])
///     .set_aad("hello world")
///     .opaque_bind(|aead| aead.update_in_place(&mut in_out))
///     .opaque_map(|aead| aead.finalize())?;
///
/// // PartialEq for tags is constant time
/// assert_eq!(tag, d_tag);
/// assert_eq!(in_out, [7u8; 42]);
/// #
/// # Ok(()) }
/// ```
///
/// # Errors
///
/// To guarantee that the state machine is correctly used, all methods take ownership over the
/// `ChaCha20Poly1305` instance. The `ChaCha20Poly1305` instance is always returned whether the
/// operation failed or not, allowing for retries.
///
/// For example, with the [`set_aad(...)`][6] method:
///
/// ```txt
///     Error!
///   +----------+
///   v          |
/// +--------------+  Success!   +----------------+
/// | set_aad(...) | ----------> | Updating State |
/// +--------------+             +----------------+
/// ```
///
/// While this serves its purpose in allowing retries, it can be annoying for error propagation. To
/// remedy this, there is the [`MakeOpaque`] trait, which will convert the error type into the
/// [`Unspecified`] type via the [`opaque`] method, as well as provide common combinatorics such as
/// [`opaque_bind`] and [`opaque_map`].
///
/// [1]: https://datatracker.ietf.org/doc/html/rfc8439
/// [2]: https://en.wikipedia.org/wiki/Authenticated_encryption
/// [3]: crate::chacha::ChaCha20
/// [4]: crate::mac::Poly1305
/// [5]: ChaCha20Poly1305::update
/// [6]: ChaCha20Poly1305::set_aad
/// [7]: ChaCha20Poly1305::update_aad
/// [8]: ChaCha20Poly1305::finish
///
/// [`MakeOpaque`]: crate::MakeOpaque
/// [`opaque`]: crate::MakeOpaque::opaque
/// [`opaque_bind`]: crate::MakeOpaque::opaque_bind
/// [`opaque_map`]: crate::MakeOpaque::opaque_map
#[must_use]
#[repr(transparent)]
pub struct ChaCha20Poly1305<S: State = Init> {
    inner: ChaChaPoly_Aead,
    _state: PhantomData<S>
}

impl ChaCha20Poly1305<Init> {
    /// Creates a new `ChaCha20Poly1305` instance with the specified direction.
    ///
    /// # Arguments
    ///
    /// * `key` - The 32-byte key material.
    /// * `iv` - The 12-byte initialization vector.
    /// * `dir` - The direction of the operation (`CHACHA20_POLY1305_AEAD_ENCRYPT` or
    ///   `CHACHA20_POLY1305_AEAD_DECRYPT`).
    ///
    /// # Safety
    ///
    /// This function is unsafe as it assumes that the provided `dir` is valid.
    fn new_with_dir<K, IV, S>(key: K, iv: IV, dir: core::ffi::c_int) -> ChaCha20Poly1305<S>
        where
            K: GenericKey,
            IV: GenericIv<Size = U12>,
            S: State
    {
        debug_assert!(matches!(
            dir as core::ffi::c_uint,
            CHACHA20_POLY1305_AEAD_ENCRYPT | CHACHA20_POLY1305_AEAD_DECRYPT
        ));

        let mut inner = MaybeUninit::<ChaChaPoly_Aead>::uninit();

        unsafe {
            let _res = wc_ChaCha20Poly1305_Init(
                inner.as_mut_ptr(),
                key.ptr(),
                iv.as_slice().as_ptr(),
                dir
            );

            debug_assert_eq!(_res, 0);

            ChaCha20Poly1305::<S> {
                inner: inner.assume_init(),
                _state: PhantomData
            }
        }
    }

    /// Create a new [`ChaCha20Poly1305`] instance for either encryption or decryption.
    ///
    /// # Generic
    ///
    /// The provided `Mode` generic denotes whether this instance will be used for encryption or
    /// decryption. The possible types are:
    ///
    /// * [`Decrypt`] - Initialize the instance for decryption, there is also the [`new_decrypt`][1]
    ///   convenience associated function.
    /// * [`Encrypt`] - Initialize the instance for encryption, there is also the [`new_encrypt`][2]
    ///   convenience associated function.
    ///
    /// # Arguments
    ///
    /// * `key` - The 32 byte key material to use.
    /// * `iv`  - The 12 byte initialization vector to use.
    ///
    /// # Examples
    ///
    /// **Decryption**
    /// ```
    /// use wolf_crypto::{aead::chacha20_poly1305::{ChaCha20Poly1305, Decrypt}, mac::poly1305::Key};
    ///
    /// # let _ = {
    /// ChaCha20Poly1305::new::<Decrypt>(Key::new([7u8; 32]), [42u8; 12])
    /// # };
    /// ```
    ///
    /// **Encryption**
    /// ```
    /// use wolf_crypto::{aead::chacha20_poly1305::{ChaCha20Poly1305, Encrypt}, mac::poly1305::Key};
    ///
    /// # let _ = {
    /// ChaCha20Poly1305::new::<Encrypt>(Key::new([7u8; 32]), [42u8; 12])
    /// # };
    /// ```
    ///
    /// [1]: Self::new_decrypt
    /// [2]: Self::new_encrypt
    #[inline]
    pub fn new<Mode: Updating>(key: impl GenericKey, iv: impl GenericIv<Size = U12>) -> ChaCha20Poly1305<Mode::InitState> {
        Self::new_with_dir(key, iv, Mode::direction())
    }

    /// Create a new [`ChaCha20Poly1305`] instance for encryption.
    ///
    /// # Arguments
    ///
    /// * `key` - The 32 byte key material to use.
    /// * `iv`  - The 12 byte initialization vector to use.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{aead::ChaCha20Poly1305, mac::poly1305::Key};
    ///
    /// # let _ = {
    /// ChaCha20Poly1305::new_encrypt(Key::new([7u8; 32]), [42u8; 12])
    /// # };
    /// ```
    ///
    /// # Note
    ///
    /// This is a convenience associated function for calling [`ChaCha20Poly1305::new::<Encrypt>(...)`][1],
    /// circumventing the need for importing the [`Encrypt`] marker type.
    ///
    /// [1]: Self::new
    #[inline]
    pub fn new_encrypt<K, IV>(key: K, iv: IV) -> ChaCha20Poly1305<<Encrypt as Updating>::InitState>
        where
            K: GenericKey,
            IV: GenericIv<Size = U12>
    {
        ChaCha20Poly1305::new::<Encrypt>(key, iv)
    }

    /// Create a new [`ChaCha20Poly1305`] instance for decryption.
    ///
    /// # Arguments
    ///
    /// * `key` - The 32 byte key material to use.
    /// * `iv`  - The 12 byte initialization vector to use.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{aead::ChaCha20Poly1305, mac::poly1305::Key};
    ///
    /// # let _ = {
    /// ChaCha20Poly1305::new_decrypt(Key::new([7u8; 32]), [42u8; 12])
    /// # };
    /// ```
    ///
    /// # Note
    ///
    /// This is a convenience associated function for calling [`ChaCha20Poly1305::new::<Decrypt>(...)`][1],
    /// circumventing the need for importing the [`Decrypt`] marker type.
    ///
    /// [1]: Self::new
    #[inline]
    pub fn new_decrypt<K, IV>(key: K, iv: IV) -> ChaCha20Poly1305<<Decrypt as Updating>::InitState>
        where
            K: GenericKey,
            IV: GenericIv<Size = U12>
    {
        ChaCha20Poly1305::new::<Decrypt>(key, iv)
    }
}

impl<S: State> ChaCha20Poly1305<S> {
    /// Transitions the state of the `ChaCha20Poly1305` instance to a new state.
    ///
    /// # Type Parameters
    ///
    /// * `N` - The new state type.
    ///
    /// # Returns
    ///
    /// A new `ChaCha20Poly1305` instance with the updated state.
    #[inline]
    pub(crate) const fn with_state<N: State>(self) -> ChaCha20Poly1305<N> {
        // SAFETY: we're just updating the phantom data state, same everything
        unsafe { core::mem::transmute(self) }
    }
}

impl<S: CanUpdateAad> ChaCha20Poly1305<S> {
    /// Updates the AAD (Additional Authenticated Data) without performing any safety checks in
    /// release builds.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the AAD length is safely representable as a `u32`.
    ///
    /// # Arguments
    ///
    /// * `aad` - The additional authenticated data to include in the authentication tag.
    ///
    /// # Panics
    ///
    /// Panics in debug mode if the AAD size is invalid or if the internal state is incorrect.
    #[cfg_attr(debug_assertions, track_caller)]
    #[inline]
    unsafe fn update_aad_unchecked<A: Aad>(&mut self, aad: A) {
        debug_assert!(aad.is_valid_size());

        #[cfg(feature = "llvm-assume")] {
            // Guaranteed via trait based state machine
            core::hint::assert_unchecked(
                self.inner.state == CHACHA20_POLY1305_STATE_READY as byte ||
                    self.inner.state == CHACHA20_POLY1305_STATE_AAD as byte
            );

            core::hint::assert_unchecked(
                self.inner.state != CHACHA20_POLY1305_STATE_DATA as byte
            );
        }

        let _res = wc_ChaCha20Poly1305_UpdateAad(
            addr_of_mut!(self.inner),
            aad.ptr(),
            aad.size()
        );

        debug_assert_eq!(_res, 0);
    }

    io_impls! {
        /// Returns an `Aad<S::Updating, IO>` struct which implements the `Read` and `Write` traits
        /// for processing Additional Authenticated Data (AAD).
        ///
        /// This method allows for streaming AAD processing, which is useful when the entire AAD
        /// is not available at once or when working with I/O streams.
        ///
        /// # Arguments
        ///
        /// * `io`: An implementor of the `Read` or `Write` traits. The data passed to and from
        ///   this `io` implementor will be authenticated as AAD.
        ///
        /// # Returns
        ///
        /// An `Aad<S::Updating, IO>` struct that wraps the ChaCha20Poly1305 instance and the
        /// provided IO type.
        ///
        /// # Example
        ///
        /// ```
        /// use wolf_crypto::aead::chacha20_poly1305::{ChaCha20Poly1305, Key};
        /// use wolf_crypto::MakeOpaque;
        #[cfg_attr(all(feature = "embedded-io", not(feature = "std")), doc = "use embedded_io::Write;")]
        #[cfg_attr(feature = "std", doc = "use std::io::Write;")]
        ///
        #[cfg_attr(
            all(feature = "embedded-io", not(feature = "std")),
            doc = "# fn main() -> Result<(), wolf_crypto::Unspecified> {"
        )]
        #[cfg_attr(feature = "std", doc = "# fn main() -> Result<(), Box<dyn std::error::Error>> {")]
        /// let (key, iv) = (Key::new([7u8; 32]), [42; 12]);
        /// let mut some_io_write_implementor = [7u8; 64];
        ///
        /// let mut io = ChaCha20Poly1305::new_encrypt(key, iv)
        ///     .aad_io(some_io_write_implementor.as_mut_slice());
        ///
        /// let read = io.write(b"hello world")?;
        /// let (aead, _my_writer) = io.finish();
        ///
        /// assert_eq!(&some_io_write_implementor[..read], b"hello world");
        ///
        /// let tag = aead.finalize();
        /// # assert_ne!(tag, wolf_crypto::aead::Tag::new_zeroed()); // no warnings
        /// # Ok(()) }
        /// ```
        #[inline]
        pub const fn aad_io<IO>(self, io: IO) -> IoAad<S::Updating, IO> {
            io::Aad::new(self.with_state(), io)
        }
    }

    /// Update the underlying message authentication code without encrypting the data.
    ///
    /// This transitions to the streaming state for updating the AAD, allowing for partial updates.
    /// If you already have the entire AAD, consider using [`set_aad`] instead.
    ///
    /// # Arguments
    ///
    /// * `aad` - The additional authenticated data to include in the authentication [`Tag`].
    ///
    /// # Errors
    ///
    /// If the length of the AAD is greater than [`u32::MAX`].
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{aead::chacha20_poly1305::{ChaCha20Poly1305, Key}, MakeOpaque};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let tag = ChaCha20Poly1305::new_encrypt(Key::new([7u8; 32]), [42u8; 12])
    ///     .update_aad("hello world").opaque()?
    ///     .update_aad("!").opaque()?
    ///     .finish()
    ///     .finalize();
    ///
    /// let d_tag = ChaCha20Poly1305::new_decrypt(Key::new([7u8; 32]), [42u8; 12])
    ///     .update_aad("hello world!").opaque()? // equivalent to processing in parts
    ///     .finish()
    ///     .finalize();
    ///
    /// assert_eq!(tag, d_tag);
    /// # Ok(()) }
    /// ```
    ///
    /// [`set_aad`]: ChaCha20Poly1305::set_aad
    #[inline]
    pub fn update_aad<A: Aad>(mut self, aad: A) -> Result<ChaCha20Poly1305<S::Updating>, Self> {
        if !aad.is_valid_size() { return Err(self) }
        unsafe { self.update_aad_unchecked(aad); }
        Ok(self.with_state())
    }
}

impl<S: CanUpdate> ChaCha20Poly1305<S> {
    /// Performs an unchecked in-place update of the `data` buffer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the length of `data` can be safely cast to `u32`.
    #[inline]
    unsafe fn update_in_place_unchecked(&mut self, data: &mut [u8]) {
        debug_assert!(can_cast_u32(data.len()));

        #[cfg(feature = "llvm-assume")]
            // Guaranteed via trait based state machine
            core::hint::assert_unchecked(!( // written like this to be an exact negation of
                                            // the failure condition
                   self.inner.state != CHACHA20_POLY1305_STATE_READY as byte
                && self.inner.state != CHACHA20_POLY1305_STATE_AAD as byte
                && self.inner.state != CHACHA20_POLY1305_STATE_DATA as byte
            ));

        // INFALLIBLE
        //
        // https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/chacha20_poly1305.c#L247
        //
        // The functions preconditions are as follows:
        //
        // - aead != NULL /\ inData != NULL /\ outData != NULL
        // - state == CHACHA20_POLY1305_STATE_READY
        //   /\ state == CHACHA20_POLY1305_STATE_AAD
        //   /\ state == CHACHA20_POLY1305_STATE_DATA
        //
        // Which we satisfy via the type system.
        //
        // The internal function calls we have also already shown to be infallible. These being:
        //
        // - wc_Poly1305_Pad (see this crates poly1305 implementations infallibility commentary)
        // - wc_Poly1305_Update (see this crates poly1305 implementations infallibility commentary)
        // - wc_ChaCha_Process (see this crates chacha implementation's process_unchecked commentary)
        //
        // Which means both update_in_place_unchecked and update_unchecked are infallible.

        let _res = wc_ChaCha20Poly1305_UpdateData(
            addr_of_mut!(self.inner),
            // See comment at:
            // https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/chacha20_poly1305.c#L246
            // if you were wondering if it is safe to have the in and out ptr be the same.
            data.as_ptr(),
            data.as_ptr().cast_mut(),
            data.len() as u32
        );

        debug_assert_eq!(_res, 0);
    }

    /// Performs an unchecked update of the `data`, writing the `output` to a separate buffer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `data.len() <= output.len()`
    /// - The length of `data` can be safely cast to `u32`.
    #[inline]
    unsafe fn update_unchecked(&mut self, data: &[u8], output: &mut [u8]) {
        debug_assert!(data.len() <= output.len());
        debug_assert!(can_cast_u32(data.len()));

        #[cfg(feature = "llvm-assume")] {
            // Guaranteed via trait based state machine
            core::hint::assert_unchecked(
                self.inner.state == CHACHA20_POLY1305_STATE_READY as byte
                    || self.inner.state == CHACHA20_POLY1305_STATE_AAD as byte
                    || self.inner.state == CHACHA20_POLY1305_STATE_DATA as byte
            );
        }

        // See the update_in_place_unchecked commentary regarding the infallibility of this.

        let _res = wc_ChaCha20Poly1305_UpdateData(
            addr_of_mut!(self.inner),
            data.as_ptr(),
            output.as_mut_ptr(),
            data.len() as u32
        );

        debug_assert_eq!(_res, 0);
    }

    /// Predicate to check if the update operation can proceed.
    ///
    /// Ensures that the `input` length can be cast to `u32` and that the `output` buffer is large
    /// enough.
    #[inline]
    #[must_use]
    const fn update_predicate(input: &[u8], output: &[u8]) -> bool {
        can_cast_u32(input.len()) && output.len() >= input.len()
    }

    /// Encrypt / Decrypt the provided `in_out` data in-place.
    ///
    /// # Arguments
    ///
    /// * `in_out` - A mutable slice of data to be encrypted / decrypted in place.
    ///
    /// # Errors
    ///
    /// If the length of `in_out` is greater than `u32::MAX`.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{aead::ChaCha20Poly1305, mac::poly1305::Key, MakeOpaque};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let mut in_out = [7u8; 42];
    /// let key = Key::new([3u8; 32]);
    ///
    /// let tag = ChaCha20Poly1305::new_encrypt(key.as_ref(), [7u8; 12])
    ///     .set_aad("hello world").opaque()?
    ///     .update_in_place(&mut in_out).opaque()?
    ///     .finalize();
    ///
    /// assert_ne!(in_out, [7u8; 42]);
    ///
    /// let d_tag = ChaCha20Poly1305::new_decrypt(key.as_ref(), [7u8; 12])
    ///     .set_aad("hello world")
    ///     .opaque_bind(|aead| aead.update_in_place(&mut in_out))
    ///     .opaque_map(|aead| aead.finalize())?;
    ///
    /// assert_eq!(tag, d_tag);
    /// assert_eq!(in_out, [7u8; 42]);
    /// # Ok(()) }
    /// ```
    #[inline]
    pub fn update_in_place(mut self, in_out: &mut [u8]) -> Result<ChaCha20Poly1305<S::Mode>, Self> {
        if can_cast_u32(in_out.len()) {
            unsafe { self.update_in_place_unchecked(in_out) };
            Ok(self.with_state())
        } else {
            Err(self)
        }
    }

    /// Encrypt / Decrypt the provided `in_out` data in-place.
    ///
    /// This method is similar to [`update_in_place`], but accepts a fixed-size array, allowing for
    /// potential optimizations and compile-time checks.
    ///
    /// # Arguments
    ///
    /// * `in_out` - A mutable fixed-size array of data to be encrypted or decrypted in place.
    ///
    /// # Errors
    ///
    /// If the length of `in_out` is greater than `u32::MAX`.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::aead::{ChaCha20Poly1305};
    /// use wolf_crypto::mac::poly1305::Key;
    /// use wolf_crypto::MakeOpaque;
    ///
    /// let mut data = [42u8; 64];
    /// let key = Key::new([0u8; 32]);
    /// let iv = [0u8; 12];
    ///
    /// let tag = ChaCha20Poly1305::new_encrypt(key.as_ref(), iv)
    ///     .update_in_place_sized(&mut data).unwrap()
    ///     .finalize();
    ///
    /// assert_ne!(data, [42u8; 64]);
    ///
    /// let d_tag = ChaCha20Poly1305::new_decrypt(key, iv)
    ///     .update_in_place_sized(&mut data).unwrap()
    ///     .finalize();
    ///
    /// assert_eq!(data, [42u8; 64]);
    /// assert_eq!(tag, d_tag);
    /// ```
    ///
    /// [`update_in_place`]: Self::update_in_place
    #[inline]
    pub fn update_in_place_sized<const C: usize>(mut self, in_out: &mut [u8; C]) -> Result<ChaCha20Poly1305<S::Mode>, Self> {
        if const_can_cast_u32::<C>() {
            unsafe { self.update_in_place_unchecked(in_out) };
            Ok(self.with_state())
        } else {
            Err(self)
        }
    }

    /// Encrypt / Decrypt the provided `data` into the `output` buffer.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of data to be encrypted or decrypted.
    /// * `output` - A mutable slice where the result will be written. It must be at least as large
    ///   as `data`.
    ///
    /// # Errors
    ///
    /// - The length of `data` is greater than `u32::MAX`.
    /// - The `output` buffer is smaller than the `data` buffer.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::aead::{ChaCha20Poly1305};
    /// use wolf_crypto::mac::poly1305::Key;
    /// use wolf_crypto::MakeOpaque;
    ///
    /// let data = [42u8; 64];
    /// let mut out = [0u8; 64];
    /// let key = Key::new([0u8; 32]);
    /// let iv = [0u8; 12];
    ///
    /// let tag = ChaCha20Poly1305::new_encrypt(key.as_ref(), iv)
    ///     .update(&data, &mut out).unwrap()
    ///     .finalize();
    ///
    /// assert_ne!(out, data);
    ///
    /// let d_tag = ChaCha20Poly1305::new_decrypt(key, iv)
    ///     .update_in_place(&mut out).unwrap()
    ///     .finalize();
    ///
    /// assert_eq!(out, data);
    /// assert_eq!(tag, d_tag);
    /// ```
    pub fn update(mut self, data: &[u8], output: &mut [u8]) -> Result<ChaCha20Poly1305<S::Mode>, Self> {
        if Self::update_predicate(data, output) {
            unsafe { self.update_unchecked(data, output) };
            Ok(self.with_state())
        } else {
            Err(self)
        }
    }

    io_impls! {
        /// Returns a `Data<S::Mode, IO>` struct which implements the `Read` trait for
        /// encrypting / decrypting data.
        ///
        /// This method allows for streaming data processing, which is useful when working
        /// with large amounts of data or I/O streams.
        ///
        /// # Arguments
        ///
        /// * `io`: An implementor of the `Read` trait. The data read from this `io` implementor
        ///   will be encrypted or decrypted depending on the mode of the ChaCha20Poly1305 instance.
        ///
        /// # Returns
        ///
        /// A `Data<S::Mode, IO>` struct that wraps the ChaCha20Poly1305 instance and the
        /// provided IO type.
        ///
        /// # Example
        ///
        /// ```
        /// use wolf_crypto::aead::chacha20_poly1305::{ChaCha20Poly1305, Key};
        /// use wolf_crypto::MakeOpaque;
        #[cfg_attr(all(feature = "embedded-io", not(feature = "std")), doc = "use embedded_io::Read;")]
        #[cfg_attr(feature = "std", doc = "use std::io::Read;")]
        ///
        #[cfg_attr(
            all(feature = "embedded-io", not(feature = "std")),
            doc = "# fn main() -> Result<(), wolf_crypto::Unspecified> {"
        )]
        #[cfg_attr(feature = "std", doc = "# fn main() -> Result<(), Box<dyn std::error::Error>> {")]
        /// let (key, iv) = (Key::new([7u8; 32]), [42; 12]);
        /// let plaintext = b"hello world";
        ///
        /// // Encrypt
        /// let mut encrypted = [0u8; 32];
        /// let mut encrypt_io = ChaCha20Poly1305::new_encrypt(key.as_ref(), iv)
        ///     .data_io(&plaintext[..]);
        /// let encrypted_len = encrypt_io.read(&mut encrypted)?;
        /// let (aead, _) = encrypt_io.finish();
        /// let tag = aead.finalize();
        ///
        /// // Decrypt
        /// let mut decrypted = [0u8; 32];
        /// let mut decrypt_io = ChaCha20Poly1305::new_decrypt(key, iv)
        ///     .data_io(&encrypted[..encrypted_len]);
        /// let decrypted_len = decrypt_io.read(&mut decrypted)?;
        /// let (aead, _) = decrypt_io.finish();
        /// let decrypted_tag = aead.finalize();
        ///
        /// assert_eq!(&decrypted[..decrypted_len], plaintext);
        /// assert_eq!(tag, decrypted_tag);
        /// # Ok(()) }
        /// ```
        pub const fn data_io<IO>(self, io: IO) -> IoData<S::Mode, IO> {
            io::Data::new(self.with_state(), io)
        }
    }
}

impl<S: CanSetAad> ChaCha20Poly1305<S> {
    /// Sets the Additional Authenticated Data (AAD) for the AEAD operation.
    ///
    /// # Arguments
    ///
    /// * `aad` - The additional authenticated data to include in the authentication tag.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::aead::chacha20_poly1305::{ChaCha20Poly1305, Key};
    ///
    /// let key = Key::new([7u8; 32]);
    /// let iv = [42u8; 12];
    ///
    /// let aead = ChaCha20Poly1305::new_encrypt(key, iv)
    ///     .set_aad("additional data").unwrap();
    /// # drop(aead);
    /// ```
    ///
    /// # Errors
    ///
    /// If the length of the AAD is greater than `u32::MAX`.
    ///
    /// # Notes
    ///
    /// - The AAD contributes to the authentication tag but is not part of the encrypted output.
    /// - If you need to provide the AAD in multiple parts, consider using [`update_aad`] instead.
    ///
    /// [`update_aad`]: ChaCha20Poly1305::update_aad
    #[inline]
    pub fn set_aad<A: Aad>(
        mut self,
        aad: A
    ) -> Result<ChaCha20Poly1305<<S as CanSetAad>::Mode>, Self>
    {
        if aad.is_valid_size() {
            unsafe { self.update_aad_unchecked(aad); }
            Ok(self.with_state())
        } else {
            Err(self)
        }
    }
}

impl<S: UpdatingAad> ChaCha20Poly1305<S> {
    /// Signals that no more Additional Authenticated Data (AAD) will be provided, transitioning the
    /// cipher to the data processing state.
    ///
    /// This method finalizes the AAD input phase. After calling `finish`, you may [`finalize`] the
    /// state machine, or begin updating the cipher with data to be encrypted / decrypted.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::aead::chacha20_poly1305::{ChaCha20Poly1305, Key};
    /// use wolf_crypto::MakeOpaque;
    ///
    /// let (key, iv) = (Key::new([7u8; 32]), [42; 12]);
    ///
    /// let tag = ChaCha20Poly1305::new_encrypt(key, iv)
    ///     .update_aad("additional ")
    ///     .opaque_bind(|aead| aead.update_aad("data"))
    ///     .opaque_bind(|aead| aead.update_aad("..."))
    ///     .opaque_map(|aead| aead.finish())
    ///      // (just use Poly1305 directly if you're doing this)
    ///     .opaque_map(|aead| aead.finalize()).unwrap();
    /// # assert_ne!(tag, wolf_crypto::aead::Tag::new_zeroed()); // no warnings
    /// ```
    ///
    /// [`finalize`]: ChaCha20Poly1305::finalize
    pub const fn finish(self) -> ChaCha20Poly1305<S::Mode> {
        self.with_state()
    }

    /// Update the underlying message authentication code without encrypting the data or taking
    /// ownership of the [`ChaCha20Poly1305`] instance.
    ///
    /// This method is only available in the streaming state, making partial updates less of a
    /// hassle.
    ///
    /// # Arguments
    ///
    /// * `aad` - The additional authenticated data to include in the authentication [`Tag`].
    ///
    /// # Errors
    ///
    /// If the length of the AAD is greater than [`u32::MAX`].
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{aead::chacha20_poly1305::{ChaCha20Poly1305, Key}, MakeOpaque};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let tag = ChaCha20Poly1305::new_encrypt(Key::new([7u8; 32]), [42u8; 12])
    ///     .set_aad("hello world! Beautiful weather.")
    ///     .opaque_map(|aead| aead.finalize())?;
    ///
    /// let mut d_cipher = ChaCha20Poly1305::new_decrypt(Key::new([7u8; 32]), [42u8; 12])
    ///     .update_aad("hello world").opaque()?;
    ///
    /// // does not take ownership
    /// d_cipher.update_aad_streaming("! ")?;
    /// d_cipher.update_aad_streaming("Beautiful weather.")?;
    ///
    /// let d_tag = d_cipher.finish().finalize();
    ///
    /// assert_eq!(tag, d_tag);
    /// # Ok(()) }
    /// ```
    pub fn update_aad_streaming<A: Aad>(&mut self, aad: A) -> Result<(), Unspecified> {
        if aad.is_valid_size() {
            unsafe { self.update_aad_unchecked(aad); }
            Ok(())
        } else {
            Err(Unspecified)
        }
    }
}

impl<S: Updating> ChaCha20Poly1305<S> {
    /// Finalizes the AEAD operation computing and returning the authentication [`Tag`].
    ///
    /// # Returns
    ///
    /// The authentication [`Tag`], resulting from the processed AAD and encryption / decryption
    /// operations.
    ///
    /// # Security
    ///
    /// On decryption, the returned [`Tag`] should be ensured to be equivalent to the [`Tag`]
    /// associated with the ciphertext. The decrypted ciphertext **should not be trusted** if
    /// the tags do not match.
    ///
    /// Also, the comparison should not be done outside the [`Tag`] type, you **must not** call
    /// `as_slice()` or anything for the comparison. **ALWAYS** leverage the [`Tag`]'s `PartialEq`
    /// implementation.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::aead::chacha20_poly1305::{ChaCha20Poly1305, Key};
    ///
    /// let key = Key::new([7u8; 32]);
    /// let iv = [42u8; 12];
    /// let mut data = [0u8; 64];
    ///
    /// let tag = ChaCha20Poly1305::new_encrypt(key.as_ref(), iv)
    ///     .set_aad("additional data").unwrap()
    ///     .update_in_place(&mut data).unwrap()
    ///     .finalize();
    ///
    /// // be sure to keep the tag around! important!
    ///
    /// // On decryption, we **must** ensure that the resulting tag matches
    /// // the provided tag.
    ///
    /// let d_tag = ChaCha20Poly1305::new_decrypt(key, iv)
    ///     .set_aad("additional data").unwrap()
    ///     .update_in_place(&mut data).unwrap()
    ///     .finalize();
    ///
    /// assert_eq!(data, [0u8; 64]);
    ///
    /// // most importantly!
    /// assert_eq!(tag, d_tag);
    /// ```
    #[inline]
    pub fn finalize(mut self) -> Tag {
        let mut tag = Tag::new_zeroed();

        // INFALLIBLE
        //
        // The only way this function can fail is via the preconditions or an internal function
        // failing. All internal functions are infallible, as described in this crate's poly1305
        // commentary.
        //
        // The preconditions are as follows:
        //
        // - state == CHACHA20_POLY1305_STATE_AAD \/ state == CHACHA20_POLY1305_STATE_DATA
        // - aead != null /\ outAuthTag != null
        //
        // The inherited preconditions from the internal function calls are respected in the same
        // way that we respect them in the Poly1305 module, using the same types, et cetera.

        unsafe {
            let _res = wc_ChaCha20Poly1305_Final(
                addr_of_mut!(self.inner),
                tag.as_mut_ptr()
            );

            debug_assert_eq!(_res, 0);
        }

        tag
    }

    /// Encrypt / Decrypt the provided `in_out` data in-place without taking ownership of the AEAD
    /// instance.
    ///
    /// # Arguments
    ///
    /// * `in_out` - A mutable slice of data to be encrypted / decrypted in place.
    ///
    /// # Returns
    ///
    /// A reference to the updated `in_out` slice on success.
    ///
    /// # Errors
    ///
    /// Returns `Unspecified` if the length of `in_out` is greater than `u32::MAX`.
    ///
    /// # Example
    ///
    /// ```
    /// # use wolf_crypto::{aead::ChaCha20Poly1305, mac::poly1305::Key, MakeOpaque};
    /// #
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// # let mut in_out1 = [7u8; 42];
    /// # let mut in_out2 = [8u8; 42];
    /// # let key = Key::new([3u8; 32]);
    /// #
    /// let mut aead = ChaCha20Poly1305::new_encrypt(key.as_ref(), [7u8; 12])
    ///     .set_aad("hello world").opaque()?;
    ///
    /// aead.update_in_place_streaming(&mut in_out1)?;
    /// aead.update_in_place_streaming(&mut in_out2)?;
    ///
    /// let tag = aead.finalize();
    ///
    /// assert_ne!(in_out1, [7u8; 42]);
    /// assert_ne!(in_out2, [8u8; 42]);
    /// # Ok(()) }
    /// ```
    pub fn update_in_place_streaming<'io>(&mut self, in_out: &'io mut [u8]) -> Result<&'io mut [u8], Unspecified> {
        if can_cast_u32(in_out.len()) {
            unsafe { self.update_in_place_unchecked(in_out) };
            Ok(in_out)
        } else {
            Err(Unspecified)
        }
    }

    /// Encrypt / Decrypt the provided `input` data into the `output` buffer without taking
    /// ownership of the AEAD instance.
    ///
    /// # Arguments
    ///
    /// * `input` - A slice of data to be encrypted / decrypted.
    /// * `output` - A mutable slice where the result will be written. It must be at least as large
    ///   as `input`.
    ///
    /// # Errors
    ///
    /// - The length of `input` is greater than `u32::MAX`.
    /// - The `output` buffer is smaller than the `input` buffer.
    ///
    /// # Example
    ///
    /// ```
    /// # use wolf_crypto::aead::{ChaCha20Poly1305};
    /// # use wolf_crypto::mac::poly1305::Key;
    /// # use wolf_crypto::MakeOpaque;
    /// #
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// # let data1 = [42u8; 32];
    /// # let data2 = [43u8; 32];
    /// # let mut out1 = [0u8; 32];
    /// # let mut out2 = [0u8; 32];
    /// # let key = Key::new([0u8; 32]);
    /// # let iv = [0u8; 12];
    /// #
    /// let mut aead = ChaCha20Poly1305::new_encrypt(key.as_ref(), iv)
    ///     .set_aad("additional data").opaque()?;
    ///
    /// aead.update_streaming(&data1, &mut out1)?;
    /// aead.update_streaming(&data2, &mut out2)?;
    ///
    /// let tag = aead.finalize();
    ///
    /// assert_ne!(out1, data1);
    /// assert_ne!(out2, data2);
    /// # Ok(()) }
    /// ```
    pub fn update_streaming(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), Unspecified> {
        if Self::update_predicate(input, output) {
            unsafe { self.update_unchecked(input, output) };
            Ok(())
        } else {
            Err(Unspecified)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::mac::poly1305::Key;
    use core::{
        slice,
    };
    use super::*;

    #[test]
    fn type_state_machine() {
        let key = Key::new([0u8; 32]);

        let mut cipher = [69, 69, 69, 69];

        let tag = ChaCha20Poly1305::new::<Encrypt>(key.as_ref(), [0u8; 12])
            .set_aad(Some(Some(Some(())))).unwrap()
            .update_in_place(cipher.as_mut_slice()).unwrap()
            .finalize();

        let new_tag = ChaCha20Poly1305::new::<Decrypt>(key.as_ref(), [0u8; 12])
            .set_aad(()).unwrap()
            .update_in_place(cipher.as_mut_slice()).unwrap()
            .finalize();

        assert_eq!(tag, new_tag);
        assert_eq!(cipher, [69, 69, 69, 69]);
    }

    macro_rules! bogus_slice {
        ($size:expr) => {{
            let src = b"hello world";
            unsafe { slice::from_raw_parts(src.as_ptr(), $size) }
        }};
    }

    #[test]
    fn oneshot_size_predicate_fail() {
        // I am not allocating the maximum number for u32
        let slice = bogus_slice!(u32::MAX as usize + 1);
        let out = slice;
        assert!(!oneshot_predicate(slice, out, &()))
    }

    #[test]
    fn oneshot_size_predicate() {
        let slice = bogus_slice!(u32::MAX as usize - 1);
        let out = slice;
        assert!(oneshot_predicate(slice, out, &()))
    }

    #[test]
    fn oneshot_size_predicate_too_small_out() {
        let slice = bogus_slice!(u32::MAX as usize - 1);
        let out = bogus_slice!(u32::MAX as usize - 2);
        assert!(!oneshot_predicate(slice, out, &()));
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use crate::aes::test_utils::{BoundList};
    use crate::buf::Nonce;
    use crate::mac::poly1305::Key;
    use proptest::{prelude::*, proptest};

    proptest! {
        // these take some time. I ran with 50k cases once, but I cannot wait for these to pass
        // each time I run the tests.
        #![proptest_config(ProptestConfig::with_cases(5_000))]

        #[test]
        fn bijectivity(
            input in any::<BoundList<1024>>(),
            key in any::<Key>(),
            iv in any::<Nonce>()
        ) {
            let mut output = input.create_self();
            let tag = ChaCha20Poly1305::new::<Encrypt>(key.as_ref(), iv.copy())
                .update(input.as_slice(), output.as_mut_slice()).unwrap()
                .finalize();

            if output.len() >= 6 {
                prop_assert_ne!(output.as_slice(), input.as_slice());
            }

            let mut decrypted = output.create_self();
            let d_tag = ChaCha20Poly1305::new::<Decrypt>(key.as_ref(), iv)
                .update(output.as_slice(), decrypted.as_mut_slice()).unwrap()
                .finalize();

            prop_assert_eq!(tag, d_tag);
            prop_assert_eq!(decrypted.as_slice(), input.as_slice());
        }

        #[test]
        fn bijectivity_with_aad(
            input in any::<BoundList<1024>>(),
            key in any::<Key>(),
            iv in any::<Nonce>(),
            aad in any::<Option<String>>()
        ) {
            let mut output = input.create_self();
            let tag = ChaCha20Poly1305::new::<Encrypt>(key.as_ref(), iv.copy())
                .set_aad(aad.as_ref()).unwrap()
                .update(input.as_slice(), output.as_mut_slice()).unwrap()
                .finalize();

            if output.len() >= 6 {
                prop_assert_ne!(output.as_slice(), input.as_slice());
            }

            let mut decrypted = output.create_self();
            let d_tag = ChaCha20Poly1305::new::<Decrypt>(key.as_ref(), iv)
                .set_aad(aad.as_ref()).unwrap()
                .update(output.as_slice(), decrypted.as_mut_slice()).unwrap()
                .finalize();

            prop_assert_eq!(tag, d_tag);
            prop_assert_eq!(decrypted.as_slice(), input.as_slice());
        }

        #[test]
        fn oneshot_bijectivity(
            input in any::<BoundList<1024>>(),
            key in any::<Key>(),
            iv in any::<Nonce>()
        ) {
            let mut output = input.create_self();

            let tag = encrypt(
                key.as_ref(), iv.copy(),
                input.as_slice(), output.as_mut_slice(),
                ()
            ).unwrap();

            if output.len() >= 6 {
                prop_assert_ne!(output.as_slice(), input.as_slice());
            }

            let mut decrypted = output.create_self();
            prop_assert!(decrypt(
                key.as_ref(), iv,
                output.as_slice(), decrypted.as_mut_slice(),
                (), tag
            ).is_ok());

            prop_assert_eq!(input.as_slice(), decrypted.as_slice());
        }

        #[test]
        fn oneshot_bijectivity_with_aad(
            input in any::<BoundList<1024>>(),
            key in any::<Key>(),
            iv in any::<Nonce>(),
            aad in any::<Option<String>>()
        ) {
            let mut output = input.create_self();

            let tag = encrypt(
                key.as_ref(), iv.copy(),
                input.as_slice(), output.as_mut_slice(),
                aad.as_ref()
            ).unwrap();

            if output.len() >= 6 {
                prop_assert_ne!(output.as_slice(), input.as_slice());
            }

            let mut decrypted = output.create_self();
            prop_assert!(decrypt(
                key.as_ref(), iv,
                output.as_slice(), decrypted.as_mut_slice(),
                aad.as_ref(), tag
            ).is_ok());

            prop_assert_eq!(input.as_slice(), decrypted.as_slice());
        }
    }
}