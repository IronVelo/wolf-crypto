//! The `Poly1305` Message Authentication Code
//!
//! ```
//! use wolf_crypto::mac::{Poly1305, poly1305::Key};
//!
//! # fn main() -> Result<(), wolf_crypto::Unspecified> {
//! let key = Key::new([0u8; 32]);
//!
//! let tag = Poly1305::new(key.as_ref())
//!     .aead_padding()
//!     .update(b"hello world")?
//!     .finalize();
//!
//! let o_tag = Poly1305::new(key)
//!     .mac(b"Different message", ()).unwrap();
//!
//! assert_eq!(
//!     tag, o_tag,
//!     "All of our coefficients are zero!"
//! );
//!
//! let key = Key::new([42u8; 32]);
//!
//! let tag = Poly1305::new(key.as_ref())
//!     .aead_padding_ct()
//!     .update_ct(b"thankfully this ")
//!     .update_ct(b"is only the case ")
//!     .update_ct(b"with a key of all zeroes.")
//!     .finalize(/* errors are accumulated in constant-time, so we handle them here */)?;
//!
//! let o_tag = Poly1305::new(key.as_ref())
//!     .mac(b"thankfully this is only the case with a key of all zeroes.", ())?;
//!
//! assert_eq!(tag, o_tag);
//!
//! let bad_tag = Poly1305::new(key)
//!     .update(b"This tag will not be the same.")?
//!     .finalize();
//!
//! assert_ne!(bad_tag, tag);
//! # Ok(()) }
//! ```
//!
//! ## Note
//!
//! The first test may be concerning, it is not. `Poly1305` was originally designed to be
//! [paired with `AES`][1], this example only would take place if the cipher it is paired with
//! is fundamentally broken. More explicitly, the cipher would need to be an identity function for
//! the first 32 bytes, meaning not encrypt the first 32 bytes in any way shape or form.
//!
//! The author of `Poly1305` ([Daniel J. Bernstein][2]) also created [`Salsa20` (`Snuffle 2005`)][3],
//! and then [`ChaCha`][4], which `Poly1305` generally complements for authentication.
//!
//! ## Security
//!
//! `Poly1305` is meant to be used with a **one-time key**, key reuse in `Poly1305` can be
//! devastating. When pairing with something like [`ChaCha20Poly1305`] this requirement is handled
//! via the discreteness of the initialization vector (more reason to never reuse initialization
//! vectors).
//!
//! If you are using `Poly1305` directly, each discrete message you authenticate must leverage
//! fresh key material.
//!
//! [1]: https://cr.yp.to/mac/poly1305-20050329.pdf
//! [2]: https://cr.yp.to/djb.html
//! [3]: https://cr.yp.to/snuffle.html
//! [4]: https://cr.yp.to/chacha/chacha-20080128.pdf
//! [`ChaCha20Poly1305`]: crate::aead::ChaCha20Poly1305

use wolf_crypto_sys::{
    Poly1305 as wc_Poly1305,
    wc_Poly1305SetKey, wc_Poly1305Update, wc_Poly1305Final,
    wc_Poly1305_Pad, wc_Poly1305_EncodeSizes,
    wc_Poly1305_MAC
};

mod key;
pub mod state;

pub use key::{GenericKey, Key, KeyRef, KEY_SIZE};
use key::KEY_SIZE_U32;

use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;
use state::{Poly1305State, Init, Ready, Streaming};
use crate::opaque_res::Res;
use crate::{can_cast_u32, to_u32, Unspecified};
use core::marker::PhantomData;
use crate::aead::{Aad, Tag};
use crate::ct;

// INFALLIBILITY COMMENTARY
//
// — poly1305_blocks
//
// SRC: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/poly1305.c#L277
//
// Only can fail under SMALL_STACK /\ W64WRAPPER via OOM. We do not enable either of these
// features, and both must be enabled for this to be fallible.
//
// — poly1305_block
//
// SRC: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/poly1305.c#L483
//
// Returns 0 OR returns the result of poly1305_blocks. Which again is infallible unless the
// aforementioned features are both enabled.
//
// — wc_Poly1305SetKey
//
// SRC: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/poly1305.c#L496
//
// Only can fail if these preconditions are not met:
//
//   key != null /\ KeySz == 32 /\ ctx != null
//
// Which our types guarantee this is satisfied.
//
// — wc_Poly1305Final
//
// SRC: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/poly1305.c#L584
//
// Only can fail if these preconditions are not met:
//
//   ctx != null /\ mac != null
//
// With an implicit, unchecked precondition (observed in the wc_Poly1305_MAC function)
//
//   macSz == 16
//
// Which, again, our types guarantee this precondition is satisfied.
//
// — wc_Poly1305Update
//
// SRC: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/poly1305.c#L794
//
// This depends on the infallibility of poly1305_blocks, which we have already showed
// is infallible.
//
// So, this can only fail if the following preconditions are not met:
//
//  ctx != null /\ (bytes > 0 -> bytes != null)
//
// Which again, our types guarantee this is satisfied.
//
// — wc_Poly1305_Pad (invoked in finalize)
//
// SRC: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/poly1305.c#L913
//
// This depends on the success of wc_Poly1305Update, which we have already shown to be
// infallible.
//
// This is only fallible if the provided ctx is null, which again our types are not
// able to represent.
//
// Regarding the wc_Poly1305Update invocation, this is clearly infallible.
//
// We have this:
//   paddingLen = (-(int)lenToPad) & (WC_POLY1305_PAD_SZ - 1);
//
// Where they are just computing the compliment of lenToPad, masking it against 15, which gives
// us the offset to 16 byte alignment.
// For example, let's say our length to pad is 13 (for ease of reading over a single octet):
//   13 to -13     (00001101 to 11110011)
//   -13 & 15 to 3 (11110011 & 00001111 to 00000011)
//
// For all values, this will never exceed 15 bytes, which is what is the amount of padding living
// on the stack. Again, this usage of wc_Poly1305Update is clearly infallible with our
// configuration.
//
// — wc_Poly1305_EncodeSizes (invoked in finalize)
//
// SRC: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/poly1305.c#L941
//
// Similar to wc_Poly1305_Pad, this depends on the infallibility of wc_Poly1305Update. Which again,
// in this circumstance is infallible. The usage within this function is infallible with our
// configuration of wolfcrypt. The only precondition again is ctx being non-null, which again
// is guaranteed via our types.
//
// — wc_Poly1305_MAC
//
// SRC: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/poly1305.c#L995
//
// Building on the above commentary, this is infallible as well.
//
// We have the precondition:
//
//   ctx != null /\ input != null /\ tag != null /\ tagSz >= 16
//     /\ (additionalSz != 0 -> additional != null)
//
// Which again, our types ensure that this is satisfied.
//   #1 ctx must not be null as we would never be able to invoke this function otherwise.
//   #2 input must not be null, this is guaranteed via Rust's type system.
//   #3 Our Tag type is never null, and the size of Tag is always 16/
//   #4 Our Aad trait ensures that if the size is non-zero that the ptr method never returns a
//      null pointer.
//
// END COMMENTARY


/// The `Poly1305` Message Authentication Code (MAC)
///
/// # Example
///
/// ```
/// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
///
/// let key: Key = [7u8; 32].into();
///
/// let tag = Poly1305::new(key.as_ref())
///     .aead_padding_ct()
///     .update_ct(b"hello world")
///     .update_ct(b", how are you")
///     .finalize()
///     .unwrap();
///
/// let o_tag = Poly1305::new(key.as_ref())
///     .mac(b"hello world, how are you", b"")
///     .unwrap();
///
/// assert_eq!(tag, o_tag);
/// ```
#[repr(transparent)]
pub struct Poly1305<State: Poly1305State = Init> {
    inner: wc_Poly1305,
    _state: PhantomData<State>
}

impl<State: Poly1305State> From<Poly1305<State>> for Unspecified {
    #[inline]
    fn from(_value: Poly1305<State>) -> Self {
        Self
    }
}

opaque_dbg! { Poly1305 }

impl Poly1305<Init> {
    /// Creates a new `Poly1305` instance with the provided key.
    ///
    /// # Arguments
    ///
    /// * `key` - The secret key material used for MAC computation.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::mac::{Poly1305, poly1305::Key};
    ///
    /// let key: Key = [42u8; 32].into();
    /// let poly = Poly1305::new(key.as_ref());
    /// ```
    pub fn new<K: GenericKey>(key: K) -> Poly1305<Ready> {
        let mut poly1305 = MaybeUninit::<wc_Poly1305>::uninit();

        unsafe {
            // infallible, see commentary at start of file.
            let _res = wc_Poly1305SetKey(
                poly1305.as_mut_ptr(),
                key.ptr(),
                KEY_SIZE_U32
            );

            debug_assert_eq!(_res, 0);

            Poly1305::<Ready> {
                inner: poly1305.assume_init(),
                _state: PhantomData
            }
        }
    }
}

impl<State: Poly1305State> Poly1305<State> {
    /// Transitions the `Poly1305` instance to a new state.
    ///
    /// # Type Parameters
    ///
    /// * `N` - The new state type.
    ///
    /// # Returns
    ///
    /// A `Poly1305` instance in the new state.
    #[inline]
    const fn with_state<N: Poly1305State>(self) -> Poly1305<N> {
        unsafe { core::mem::transmute(self) }
    }

    /// Updates the `Poly1305` instance with additional input without performing checks.
    ///
    /// # Safety
    ///
    /// The length of the input must not be truncated / overflow a `u32`.
    ///
    /// # Arguments
    ///
    /// * `input` - A byte slice representing the data to include in the MAC computation.
    #[inline]
    unsafe fn update_unchecked(&mut self, input: &[u8]) {
        // infallible, see commentary at beginning of file.
        let _res = wc_Poly1305Update(
            addr_of_mut!(self.inner),
            input.as_ptr(),
            input.len() as u32
        );

        debug_assert_eq!(_res, 0);
    }
}

impl Poly1305<Ready> {
    /// Computes the MAC for the given input and additional data without performing input length checks.
    ///
    /// # Safety
    ///
    /// Both the `input` and `additional` arguments length must be less than `u32::MAX`.
    ///
    /// # Arguments
    ///
    /// * `input` - A byte slice representing the message to authenticate.
    /// * `additional` - A byte slice representing optional additional authenticated data (AAD).
    ///
    /// # Returns
    ///
    /// The associated authentication tag.
    unsafe fn mac_unchecked<A: Aad>(mut self, input: &[u8], aad: A) -> Tag {
        debug_assert!(can_cast_u32(input.len()));
        debug_assert!(aad.is_valid_size());

        let mut tag = Tag::new_zeroed();

        // Infallible, see final section of commentary at beginning of file.
        let _res = wc_Poly1305_MAC(
            addr_of_mut!(self.inner),
            aad.ptr(),
            aad.size(),
            input.as_ptr(),
            input.len() as u32,
            tag.as_mut_ptr(),
            Tag::SIZE
        );

        assert_eq!(_res, 0);

        debug_assert_eq!(_res, 0);

        tag
    }

    /// Computes the MAC for the given input and additional data. This uses the TLS AEAD padding
    /// scheme. If this is undesirable, consider calling `update` followed by `finalize` manually.
    ///
    /// # Arguments
    ///
    /// * `input` - A byte slice representing the message to authenticate.
    /// * `aad` - Any additional authenticated data.
    ///
    /// # Returns
    ///
    /// The associated authentication tag.
    ///
    /// # Errors
    ///
    /// - The length of the `aad` is greater than [`u32::MAX`].
    /// - The length of the `input` is greater than [`u32::MAX`].
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// let key: Key = [42u8; 32].into();
    /// let tag = Poly1305::new(key.as_ref())
    ///     .mac(b"message", b"aad")
    ///     .unwrap();
    /// # assert_ne!(tag, Tag::new_zeroed());
    /// ```
    #[inline]
    pub fn mac<A: Aad>(self, input: &[u8], aad: A) -> Result<Tag, Unspecified> {
        if can_cast_u32(input.len()) && aad.is_valid_size() {
            Ok(unsafe { self.mac_unchecked(input, aad) })
        } else {
            Err(Unspecified)
        }
    }

    /// Transitions the `Poly1305` instance into the streaming state with the TLS AEAD padding
    /// scheme.
    ///
    /// # Returns
    ///
    /// A [`StreamPoly1305Aead`] instance for continued updates.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let key: Key = [42u8; 32].into();
    /// let stream = Poly1305::new(key.as_ref())
    ///     .aead_padding()
    ///     .update(b"chunk1")?
    ///     .update(b"chunk2")?;
    /// # Ok(()) }
    /// ```
    pub const fn aead_padding(self) -> StreamPoly1305Aead {
        StreamPoly1305Aead::from_parts(self.with_state(), 0)
    }

    /// Transitions the `Poly1305` instance into the streaming state.
    ///
    /// # Returns
    ///
    /// A [`StreamPoly1305`] instance for continued updates.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let key: Key = [42u8; 32].into();
    /// let stream = Poly1305::new(key.as_ref()).normal()
    ///     .update(b"chunk1")?
    ///     .update(b"chunk2")?;
    /// # Ok(()) }
    /// ```
    pub const fn normal(self) -> StreamPoly1305 {
        StreamPoly1305::from_parts(self.with_state(), 0)
    }

    /// Transitions the `Poly1305` instance into the streaming state with the TLS AEAD padding
    /// scheme.
    ///
    /// The distinction between this and the standard [`aead_padding`] is that this accumulates
    /// errors up until the point of finalization in constant time.
    ///
    /// # Returns
    ///
    /// A [`CtPoly1305Aead`] instance for continued updates.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let key: Key = [42u8; 32].into();
    /// let stream = Poly1305::new(key.as_ref())
    ///     .aead_padding_ct()
    ///     .update_ct(b"chunk1")
    ///     .update_ct(b"chunk2");
    /// # Ok(()) }
    /// ```
    ///
    /// [`aead_padding`]: Self::aead_padding
    pub const fn aead_padding_ct(self) -> CtPoly1305Aead {
        CtPoly1305Aead::from_parts(self.with_state(), Res::OK, 0)
    }

    /// Transitions the `Poly1305` instance into the streaming state.
    ///
    /// The distinction between this and the standard [`normal`] is that this accumulates
    /// errors up until the point of finalization in constant time.
    ///
    /// # Returns
    ///
    /// A [`CtPoly1305`] instance for continued updates.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let key: Key = [42u8; 32].into();
    /// let stream = Poly1305::new(key.as_ref()).normal_ct()
    ///     .update_ct(b"chunk1")
    ///     .update_ct(b"chunk2");
    /// # Ok(()) }
    /// ```
    ///
    /// [`normal`]: Self::normal
    pub const fn normal_ct(self) -> CtPoly1305 {
        CtPoly1305::from_parts(self.with_state(), Res::OK, 0)
    }

    /// Updates the `Poly1305` instance with additional input, transitioning it to a streaming
    /// state.
    ///
    /// # Arguments
    ///
    /// * `input` - A byte slice representing the data to include in the MAC computation.
    ///
    /// # Returns
    ///
    /// A `StreamPoly1305` instance for continued updates.
    ///
    /// # Errors
    ///
    /// If the length of `input` is greater than [`u32::MAX`].
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let key: Key = [42u8; 32].into();
    /// let stream = Poly1305::new(key.as_ref())
    ///     .update(b"chunk1")?
    ///     .update(b"chunk2")?;
    /// # Ok(()) }
    /// ```
    #[inline]
    pub fn update(mut self, input: &[u8]) -> Result<StreamPoly1305, Unspecified> {
        to_u32(input.len()).map_or(
            Err(Unspecified), 
            |len| unsafe {
                self.update_unchecked(input);
                Ok(StreamPoly1305::from_parts(self.with_state(), len))
            }
        )
    }

    /// Updates the `Poly1305` instance with additional input in a constant-time manner.
    ///
    /// # Arguments
    ///
    /// * `input` - A byte slice representing the data to include in the MAC computation.
    ///
    /// # Returns
    ///
    /// A `CtPoly1305` instance containing the updated state.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// let key: Key = [42u8; 32].into();
    /// let tag = Poly1305::new(key.as_ref())
    ///     .update_ct(b"sensitive ")
    ///     .update_ct(b"chunks")
    ///     .finalize()
    ///     .unwrap();
    ///
    /// let o_tag = Poly1305::new(key.as_ref())
    ///     .update_ct(b"sensitive chunks")
    ///     .finalize().unwrap();
    ///
    /// assert_eq!(tag, o_tag);
    /// ```
    pub fn update_ct(mut self, input: &[u8]) -> CtPoly1305 {
        let (adjusted, res) = adjust_slice(input);
        unsafe { self.update_unchecked(adjusted) };
        // adjusted length will always be below u32::MAX
        CtPoly1305::from_parts(self.with_state(), res, adjusted.len() as u32)
    }
}

/// Finalizes the `Poly1305` MAC computation using the TLS AEAD padding scheme.
///
/// # Arguments
///
/// * `poly` - The `Poly1305` instance.
/// * `accum_len` - The accumulated length of the input data.
///
/// # Returns
///
/// The associated authentication [`Tag`].
#[inline]
fn finalize_aead<S: Poly1305State>(mut poly: Poly1305<S>, accum_len: u32) -> Tag {
    // Regarding fallibility for all functions invoked, and debug_asserted to have succeeded,
    // see the commentary at the beginning of the document.
    unsafe {
        let _res = wc_Poly1305_Pad(
            addr_of_mut!(poly.inner),
            accum_len
        );

        debug_assert_eq!(_res, 0);

        let _res = wc_Poly1305_EncodeSizes(
            addr_of_mut!(poly.inner),
            0u32,
            accum_len
        );

        debug_assert_eq!(_res, 0);

        finalize_no_pad(poly)
    }
}

/// Finalizes the `Poly1305` MAC computation with padding.
///
/// # Arguments
///
/// * `poly` - The `Poly1305` instance.
/// * `to_pad` - Either the length of the input, or the accumulated output of [`update_to_pad`].
///
/// # Returns
///
/// The associated authentication [`Tag`].
#[inline]
fn finalize<S: Poly1305State>(mut poly: Poly1305<S>, to_pad: u32) -> Tag {
    unsafe {
        let _res = wc_Poly1305_Pad(
            addr_of_mut!(poly.inner),
            to_pad
        );

        debug_assert_eq!(_res, 0);

        finalize_no_pad(poly)
    }
}

/// Finalizes the `Poly1305` MAC computation without padding.
///
/// # Arguments
///
/// * `poly` - The `Poly1305` instance.
///
/// # Returns
///
/// The associated authentication [`Tag`].
#[inline]
fn finalize_no_pad<S: Poly1305State>(mut poly: Poly1305<S>) -> Tag {
    unsafe {
        let mut tag = Tag::new_zeroed();

        let _res = wc_Poly1305Final(
            addr_of_mut!(poly.inner),
            tag.as_mut_ptr()
        );

        debug_assert_eq!(_res, 0);

        tag
    }
}

#[inline(always)]
#[must_use]
const fn update_to_pad(to_pad: u8, new_len: u32) -> u8 {
    // this is the same as (num + num) & 15, where num is a number of any possible size, not bound
    // to a concrete type like u32.

    // With wolfcrypt's padding algorithm this will always result in the same output as providing
    // the total length. See kani verification at the bottom of the file.
    to_pad.wrapping_add((new_len & 15) as u8) & 15
}

/// Represents an ongoing streaming MAC computation, allowing incremental updates.
///
/// This uses the TLS AEAD padding scheme.
///
/// # Example
///
/// ```
/// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
///
/// # fn main() -> Result<(), wolf_crypto::Unspecified> {
/// let key: Key = [42u8; 32].into();
/// let tag = Poly1305::new(key.as_ref())
///     .aead_padding()
///     .update(b"chunk1")?
///     .update(b"chunk2")?
///     .update(b"chunk3")?
///     .finalize();
/// # Ok(()) }
/// ```
pub struct StreamPoly1305Aead {
    poly1305: Poly1305<Streaming>,
    accum_len: u32
}

impl From<StreamPoly1305Aead> for Unspecified {
    #[inline]
    fn from(value: StreamPoly1305Aead) -> Self {
        value.poly1305.into()
    }
}

opaque_dbg! { StreamPoly1305Aead }

impl StreamPoly1305Aead {
    /// Creates a new `StreamPoly1305` instance from its parts.
    ///
    /// # Arguments
    ///
    /// * `poly1305` - The `Poly1305` instance in the `Streaming` state.
    /// * `accum_len` - The accumulated length of the input data.
    ///
    /// # Returns
    ///
    /// A new `StreamPoly1305` instance.
    const fn from_parts(poly1305: Poly1305<Streaming>, accum_len: u32) -> Self {
        Self { poly1305, accum_len }
    }

    /// Increments the accumulated length with the provided length.
    ///
    /// # Arguments
    ///
    /// * `len` - The length to add to the accumulator.
    ///
    /// # Returns
    ///
    /// A `Res` indicating the success or failure of the operation.
    #[inline(always)]
    fn incr_accum(&mut self, len: u32) -> Res {
        let (accum_len, res) = ct::add_no_wrap(self.accum_len, len);
        self.accum_len = accum_len;
        res
    }

    /// Updates the streaming MAC computation with additional input.
    ///
    /// # Arguments
    ///
    /// * `input` - A byte slice representing the additional data to include.
    ///
    /// # Errors
    ///
    /// - The length of the `input` was greater than [`u32::MAX`].
    /// - The total length that has been processed is greater than [`u32::MAX`],
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let key: Key = [42u8; 32].into();
    ///
    /// let tag = Poly1305::new(key.as_ref())
    ///     .aead_padding()
    ///     .update(b"chunk1")?
    ///     .update(b"chunk2")?
    ///     .update(b"chunk3")?
    ///     .finalize();
    /// # Ok(()) }
    /// ```
    pub fn update(mut self, input: &[u8]) -> Result<Self, Self> {
        if let Some(input_len) = to_u32(input.len()) {
            into_result!(self.incr_accum(input_len),
                ok => {
                    // We MUST only invoke this AFTER knowing that the incr_accum succeeded.
                    // incr_accum uses the ct_add_no_wrap function, which may sound like it performs
                    // some form of saturating addition, but it does not. If the operation would
                    // overflow, no addition would take place. So, we can return self under the
                    // error case, and the state will not be corrupted.
                    unsafe { self.poly1305.update_unchecked(input) };
                    self
                },
                err => self
            )
        } else {
            Err(self)
        }
    }

    /// Finalizes the streaming MAC computation and returns the resulting `Tag`.
    ///
    /// # Returns
    ///
    /// The associated authentication [`Tag`].
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let key: Key = [42u8; 32].into();
    ///
    /// let tag = Poly1305::new(key.as_ref())
    ///     .aead_padding()
    ///     .update(b"chunk1")?
    ///     .update(b"chunk2")?
    ///     .update(b"chunk3")?
    ///     .finalize();
    /// # Ok(()) }
    /// ```
    pub fn finalize(self) -> Tag {
        finalize_aead(self.poly1305, self.accum_len)
    }
}

/// Represents an ongoing streaming MAC computation, allowing incremental updates.
///
/// # Example
///
/// ```
/// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
///
/// # fn main() -> Result<(), wolf_crypto::Unspecified> {
/// let key: Key = [42u8; 32].into();
/// let tag = Poly1305::new(key.as_ref())
///     .update(b"chunk1")?
///     .update(b"chunk2")?
///     .update(b"chunk3")?
///     .finalize();
/// # Ok(()) }
/// ```
pub struct StreamPoly1305 {
    poly1305: Poly1305<Streaming>,
    to_pad: u8
}

impl From<StreamPoly1305> for Unspecified {
    #[inline]
    fn from(value: StreamPoly1305) -> Self {
        value.poly1305.into()
    }
}

opaque_dbg! { StreamPoly1305 }

impl StreamPoly1305 {
    /// Creates a new `StreamPoly1305` instance from its parts.
    ///
    /// # Arguments
    ///
    /// * `poly1305` - The `Poly1305` instance in the `Streaming` state.
    /// * `accum_len` - The accumulated length of the input data.
    ///
    /// # Returns
    ///
    /// A new `StreamPoly1305` instance.
    const fn from_parts(poly1305: Poly1305<Streaming>, len: u32) -> Self {
        Self { poly1305, to_pad: update_to_pad(0, len) }
    }

    /// Updates the streaming MAC computation with additional input.
    ///
    /// # Arguments
    ///
    /// * `input` - A byte slice representing the additional data to include.
    ///
    /// # Errors
    ///
    /// The length of the `input` was greater than [`u32::MAX`].
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let key: Key = [42u8; 32].into();
    ///
    /// let tag = Poly1305::new(key.as_ref())
    ///     .update(b"chunk1")?
    ///     .update(b"chunk2")?
    ///     .update(b"chunk3")?
    ///     .finalize();
    /// # Ok(()) }
    /// ```
    pub fn update(mut self, input: &[u8]) -> Result<Self, Self> {
        if let Some(len) = to_u32(input.len()) {
            self.to_pad = update_to_pad(self.to_pad, len);
            unsafe { self.poly1305.update_unchecked(input) };
            Ok(self)
        } else {
            Err(self)
        }
    }

    /// Finalizes the streaming MAC computation and returns the resulting `Tag`.
    ///
    /// # Returns
    ///
    /// The associated authentication [`Tag`].
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let key: Key = [42u8; 32].into();
    ///
    /// let tag = Poly1305::new(key.as_ref())
    ///     .update(b"chunk1")?
    ///     .update(b"chunk2")?
    ///     .update(b"chunk3")?
    ///     .finalize();
    /// # Ok(()) }
    /// ```
    #[inline]
    pub fn finalize(self) -> Tag {
        finalize(self.poly1305, self.to_pad as u32)
    }

    /// Finalizes the constant-time streaming MAC computation and returns the resulting `Tag`.
    ///
    /// # Note
    ///
    /// It is far more common in practice to use to pad the [`finalize`] method. This is only here
    /// `XSalsa20Poly1305`.
    ///
    /// # Returns
    ///
    /// The associated authentication [`Tag`] representing all updates and the total length of the
    /// updates.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// let key: Key = [42u8; 32].into();
    /// let tag = Poly1305::new(key.as_ref())
    ///     .update(b"chunk1").unwrap()
    ///     .update(b"chunk2").unwrap()
    ///     .finalize_no_padding();
    /// ```
    ///
    /// [`finalize`]: Self::finalize
    #[inline]
    pub fn finalize_no_padding(self) -> Tag {
        finalize_no_pad(self.poly1305)
    }
}

/// Provides a constant-time interface for updating the MAC computation, enhancing resistance
/// against side-channel attacks.
///
/// This uses the recent TLS AEAD padding scheme on finalization, if this is not desired see
/// [`CtPoly1305`].
///
/// # Example
///
/// ```
/// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
///
/// let key: Key = [42u8; 32].into();
/// let ct_poly = Poly1305::new(key.as_ref())
///     .aead_padding_ct()
///     .update_ct(b"constant time ")
///     .update_ct(b"chunk")
///     .finalize()
///     .unwrap();
/// ```
#[must_use]
pub struct CtPoly1305Aead {
    poly1305: Poly1305<Streaming>,
    result: Res,
    accum_len: u32
}

opaque_dbg! { CtPoly1305Aead }

/// Creates a mask based on the slice length for constant-time adjustments.
///
/// # Arguments
///
/// * `len` - The length of the slice.
///
/// # Returns
///
/// If the length of the slice is greater than [`u32::MAX`] this will return all zeroes,
/// otherwise this will return all ones.
#[inline(always)]
#[must_use]
const fn slice_len_mask(len: usize) -> usize {
    (can_cast_u32(len) as usize).wrapping_neg()
}

/// Adjusts the input slice based on the mask to ensure constant-time operations.
///
/// # Arguments
///
/// * `slice` - The input byte slice to adjust.
///
/// # Returns
///
/// A tuple containing the adjusted slice and the resulting `Res` state.
#[inline(always)]
fn adjust_slice(slice: &[u8]) -> (&[u8], Res) {
    let mask = slice_len_mask(slice.len());

    // So, of course, this isn't pure constant time. It has variable timing for lengths,
    // though so does poly1305, and practically everything. Only way to avoid this is masking
    // the computation which will never be perfect.
    //
    // Though, it does allow us to not need any early exit, the position of this error across
    // multiple updates is not leaked via timing.
    //
    // So, there is variance in timing under this error yes, but this is given as at some point
    // (finalize) there must be some branch to ensure the operation was successful and that
    // the authentication code genuinely corresponds to the provided messages. With this
    // approach there is a **reduction** in timing leakage, not a complete elimination of it.
    (&slice[..(slice.len() & mask)], Res(mask != 0))
}

impl CtPoly1305Aead {
    /// Creates a new `CtPoly1305` instance from its parts.
    ///
    /// # Arguments
    ///
    /// * `poly1305` - The `Poly1305` instance in the `Streaming` state.
    /// * `result` - The current `Res` state.
    /// * `accum_len` - The accumulated length of the input data.
    ///
    /// # Returns
    ///
    /// A new `CtPoly1305` instance.
    const fn from_parts(poly1305: Poly1305<Streaming>, result: Res, accum_len: u32) -> Self {
        Self {
            poly1305,
            result,
            accum_len
        }
    }

    /// Increments the accumulated length with the provided length without wrapping on overflow.
    ///
    /// # Arguments
    ///
    /// * `len` - The length to add to the accumulator.
    ///
    /// # Returns
    ///
    /// `Res` indicating if the operation would have overflowed the internal length.
    #[inline(always)]
    fn incr_accum(&mut self, len: u32) -> Res {
        let (accum_len, res) = ct::add_no_wrap(self.accum_len, len);
        self.accum_len = accum_len;
        res
    }

    /// Adds more data to the constant-time streaming MAC computation.
    ///
    /// # Arguments
    ///
    /// * `input` - A byte slice representing the additional data to include.
    ///
    /// # Returns
    ///
    /// The updated `CtPoly1305` instance.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// let key: Key = [42u8; 32].into();
    /// let ct_poly = Poly1305::new(key.as_ref())
    ///     .aead_padding_ct()
    ///     .update_ct(b"chunk1")
    ///     .update_ct(b"chunk2")
    ///     .finalize()
    ///     .unwrap();
    /// ```
    pub fn update_ct(mut self, input: &[u8]) -> Self {
        let (adjusted, mut res) = adjust_slice(input);
        res.ensure(self.incr_accum(adjusted.len() as u32));

        unsafe { self.poly1305.update_unchecked(adjusted) };

        self.result.ensure(res);
        self
    }

    /// Returns `true` if no errors have been encountered to this point.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.result.is_ok()
    }

    /// Returns `true` if an error has been encountered at some point.
    #[must_use]
    pub const fn is_err(&self) -> bool {
        self.result.is_err()
    }

    /// Finalizes the constant-time streaming MAC computation and returns the resulting `Tag`.
    ///
    /// # Returns
    ///
    /// The associated authentication tag representing all updates and the total length of the
    /// updates.
    ///
    /// # Errors
    ///
    /// The `CtPoly1305` instance accumulates errors throughout the updating process without
    /// branching. There are two ways that this will return an error based on prior updates:
    ///
    /// - One of the provided inputs had a length which was greater than [`u32::MAX`].
    /// - The total length, accumulated from all inputs, is greater than [`u32::MAX`].
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// let key: Key = [42u8; 32].into();
    /// let tag = Poly1305::new(key.as_ref())
    ///     .aead_padding_ct()
    ///     .update_ct(b"chunk1")
    ///     .update_ct(b"chunk2")
    ///     .finalize()
    ///     .unwrap();
    /// ```
    pub fn finalize(self) -> Result<Tag, Unspecified> {
        let tag = finalize_aead(self.poly1305, self.accum_len);
        self.result.unit_err(tag)
    }
}

/// Provides a constant-time interface for updating the MAC computation, enhancing resistance
/// against side-channel attacks.
///
/// # Example
///
/// ```
/// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
///
/// let key: Key = [42u8; 32].into();
/// let ct_poly = Poly1305::new(key.as_ref())
///     .update_ct(b"constant time ")
///     .update_ct(b"chunk")
///     .finalize()
///     .unwrap();
/// ```
#[must_use]
pub struct CtPoly1305 {
    poly1305: Poly1305<Streaming>,
    result: Res,
    to_pad: u8
}

opaque_dbg! { CtPoly1305 }

impl CtPoly1305 {
    /// Creates a new `CtPoly1305` instance from its parts.
    ///
    /// # Arguments
    ///
    /// * `poly1305` - The `Poly1305` instance in the `Streaming` state.
    /// * `result` - The current `Res` state.
    /// * `len` - The length of the input data. Used to compute the amount needed for padding
    ///   overtime.
    ///
    /// # Returns
    ///
    /// A new `CtPoly1305` instance.
    const fn from_parts(poly1305: Poly1305<Streaming>, result: Res, len: u32) -> Self {
        Self {
            poly1305,
            result,
            to_pad: update_to_pad(0, len)
        }
    }

    /// Adds more data to the constant-time streaming MAC computation.
    ///
    /// # Arguments
    ///
    /// * `input` - A byte slice representing the additional data to include.
    ///
    /// # Returns
    ///
    /// The updated `CtPoly1305` instance.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// let key: Key = [42u8; 32].into();
    /// let ct_poly = Poly1305::new(key.as_ref())
    ///     .update_ct(b"chunk1")
    ///     .update_ct(b"chunk2")
    ///     .finalize()
    ///     .unwrap();
    /// ```
    pub fn update_ct(mut self, input: &[u8]) -> Self {
        let (adjusted, res) = adjust_slice(input);

        // adjusted length will always be less than u32::MAX
        self.to_pad = update_to_pad(self.to_pad, adjusted.len() as u32);

        unsafe { self.poly1305.update_unchecked(adjusted) };

        self.result.ensure(res);
        self
    }

    /// Returns `true` if no errors have been encountered to this point.
    #[must_use]
    pub const fn is_ok(&self) -> bool { self.result.is_ok() }

    /// Returns `true` if an error has been encountered at some point.
    #[must_use]
    pub const fn is_err(&self) -> bool {
        self.result.is_err()
    }

    /// Finalizes the constant-time streaming MAC computation and returns the resulting `Tag`.
    ///
    /// # Returns
    ///
    /// The associated authentication [`Tag`] representing all updates and the total length of the
    /// updates.
    ///
    /// # Errors
    ///
    /// The `CtPoly1305` instance accumulates errors throughout the updating process without
    /// branching. The only error which could occur:
    ///
    /// One of the provided inputs had a length which was greater than [`u32::MAX`].
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// let key: Key = [42u8; 32].into();
    /// let tag = Poly1305::new(key.as_ref())
    ///     .update_ct(b"chunk1")
    ///     .update_ct(b"chunk2")
    ///     .finalize()
    ///     .unwrap();
    /// ```
    pub fn finalize(self) -> Result<Tag, Unspecified> {
        let tag = finalize(self.poly1305, self.to_pad as u32);
        self.result.unit_err(tag)
    }

    /// Finalizes the constant-time streaming MAC computation and returns the resulting `Tag`.
    ///
    /// # Note
    ///
    /// It is far more common in practice to use to pad the [`finalize`] method. This is only here
    /// `XSalsa20Poly1305`.
    ///
    /// # Returns
    ///
    /// The associated authentication [`Tag`] representing all updates and the total length of the
    /// updates.
    ///
    /// # Errors
    ///
    /// The `CtPoly1305` instance accumulates errors throughout the updating process without
    /// branching. The only error which could occur:
    ///
    /// One of the provided inputs had a length which was greater than [`u32::MAX`].
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// let key: Key = [42u8; 32].into();
    /// let tag = Poly1305::new(key.as_ref())
    ///     .update_ct(b"chunk1")
    ///     .update_ct(b"chunk2")
    ///     .finalize_no_padding()
    ///     .unwrap();
    /// ```
    ///
    /// [`finalize`]: Self::finalize
    pub fn finalize_no_padding(self) -> Result<Tag, Unspecified> {
        let tag = finalize_no_pad(self.poly1305);
        self.result.unit_err(tag)
    }
}

#[cfg(test)]
use poly1305::universal_hash::generic_array::{GenericArray, ArrayLength};

#[cfg(test)]
const fn rc_to_blocks<T, N: ArrayLength<T>>(data: &[T]) -> (&[GenericArray<T, N>], &[T]) {
    let nb = data.len() / N::USIZE;
    let (left, right) = data.split_at(nb * N::USIZE);
    let p = left.as_ptr().cast::<GenericArray<T, N>>();
    // SAFETY: we guarantee that `blocks` does not point outside `data`
    // and `p` is valid for reads
    #[allow(unsafe_code)]
    let blocks = unsafe { core::slice::from_raw_parts(p, nb) };
    (blocks, right)
}

#[cfg(test)]
use poly1305::{Poly1305 as rc_Poly1305, universal_hash::{KeyInit, UniversalHash}};

#[cfg(test)]
fn construct_polys(key: [u8; 32]) -> (rc_Poly1305, Poly1305<Ready>) {
    let rc_key = poly1305::Key::from_slice(key.as_slice());
    (rc_Poly1305::new(rc_key), Poly1305::new(KeyRef::new(&key)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        let key: Key = [42u8; 32].into();
        let tag = Poly1305::new(key.as_ref())
            .aead_padding_ct()
            .update_ct(b"hello world")
            .update_ct(b"good day to you")
            .update_ct(b"mmm yes mm yes indeed mm")
            .update_ct(b"hmm...")
            .finalize()
            .unwrap();

        let o_tag = Poly1305::new(key.as_ref())
            .mac(b"hello worldgood day to yoummm yes mm yes indeed mmhmm...", b"")
            .unwrap();

        assert_eq!(tag, o_tag);
    }

    #[test]
    fn rust_crypto_aligned() {
        let key = [42u8; 32];
        let (mut rc, wc) = construct_polys(key);
        let data = b"hello world we operate equivalen";

        let (blocks, _rem) = rc_to_blocks(data);

        rc.update(blocks);
        let rc_out = rc.finalize();

        let wc_out = wc.update(data).unwrap().finalize();

        assert_eq!(wc_out, rc_out.as_slice());
    }

    #[test]
    fn rust_crypto_unaligned() {
        let key = [42u8; 32];
        let (mut rc, wc) = construct_polys(key);
        let data = b"hello world we operate equivalently";

        rc.update_padded(data);
        let rc_tag = rc.finalize();
        let tag = wc.update(data).unwrap().finalize();

        assert_eq!(tag, rc_tag.as_slice());
    }
}

#[cfg(kani)]
const fn wc_to_pad(len_to_pad: u32) -> u32 {
    ((-(len_to_pad as isize)) & 15) as u32
}

#[cfg(kani)]
const fn wc_to_pad_64(len_to_pad: u64) -> u32 {
    ((-(len_to_pad as i128)) & 15) as u32
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use crate::aes::test_utils::{BoundList, AnyList};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5_000))]

        #[test]
        fn wc_poly_is_eq_to_rc_poly(
            key in any::<[u8; 32]>(),
            data in any::<BoundList<1024>>()
        ) {
            let (mut rc, wc) = construct_polys(key);

            rc.update_padded(data.as_slice());

            let tag = wc.update(data.as_slice()).unwrap().finalize();
            let rc_tag = rc.finalize();

            prop_assert_eq!(tag, rc_tag.as_slice());
        }

        #[test]
        fn wc_poly_multi_updates_is_eq_to_rc_poly_oneshot(
            key in any::<[u8; 32]>(),
            data in any::<AnyList<32, BoundList<256>>>()
        ) {
            let (mut rc, wc) = construct_polys(key);

            let mut wc = wc.normal();

            for input in data.as_slice() {
                wc = wc.update(input.as_slice()).unwrap();
            }

            let joined = data.join();
            rc.update_padded(joined.as_slice());

            let tag = wc.finalize();
            let rc_tag = rc.finalize();

            prop_assert_eq!(tag, rc_tag.as_slice());
        }

        #[test]
        fn multi_updates_is_eq_to_oneshot_tls_aead_scheme(
            key in any::<Key>(),
            data in any::<AnyList<32, BoundList<256>>>()
        ) {
            let mut updates = Poly1305::new(key.as_ref()).aead_padding();

            for input in data.as_slice() {
                updates = updates.update(input.as_slice()).unwrap();
            }

            let tag = updates.finalize();

            let joined = data.join();
            let m_tag = Poly1305::new(key).mac(joined.as_slice(), ()).unwrap();

            prop_assert_eq!(tag, m_tag);
        }

        #[test]
        fn multi_updates_ct_is_eq_to_normal(
            key in any::<Key>(),
            data in any::<AnyList<32, BoundList<256>>>()
        ) {
            let mut poly = Poly1305::new(key.as_ref()).normal();
            let mut poly_ct = Poly1305::new(key.as_ref()).normal_ct();

            for input in data.as_slice() {
                poly = poly.update(input.as_slice()).unwrap();
                poly_ct = poly_ct.update_ct(input.as_slice());
            }

            let tag = poly.finalize();
            let tag_ct = poly_ct.finalize().unwrap();

            prop_assert_eq!(tag, tag_ct);
        }

        #[test]
        fn multi_updates_is_eq_oneshot(
            key in any::<Key>(),
            data in any::<AnyList<32, BoundList<256>>>()
        ) {
            let mut poly = Poly1305::new(key.as_ref()).normal();

            for input in data.as_slice() {
                poly = poly.update(input.as_slice()).unwrap();
            }

            let tag = poly.finalize();

            let joined = data.join();
            let o_tag = Poly1305::new(key)
                .update(joined.as_slice()).unwrap()
                .finalize();

            prop_assert_eq!(tag, o_tag);
        }

        #[test]
        fn multi_updates_ct_is_eq_oneshot(
            key in any::<Key>(),
            data in any::<AnyList<32, BoundList<256>>>()
        ) {
            let mut poly = Poly1305::new(key.as_ref()).normal_ct();

            for input in data.as_slice() {
                poly = poly.update_ct(input.as_slice());
            }

            let tag = poly.finalize().unwrap();

            let joined = data.join();
            let o_tag = Poly1305::new(key)
                .update(joined.as_slice()).unwrap()
                .finalize();

            prop_assert_eq!(tag, o_tag);
        }
    }
}

#[cfg(kani)]
mod proofs {
    use kani::proof;
    use super::*;

    #[proof]
    fn univ_update_to_pad_is_no_wrap_mask() {
        let existing: u32 = kani::any();
        let to_add: u32 = kani::any();

        let utp = update_to_pad((existing & 15) as u8, to_add) as u64;
        let genuine = ((existing as u64) + (to_add as u64)) & 15;

        kani::assert(
            utp == genuine,
            "The wrapping addition must always be equivalent to non-wrapping output"
        );
    }

    #[proof]
    fn univ_update_to_pad_holds_for_wc_pad_algo() {
        let start: u32 = kani::any();
        let end: u32 = kani::any();

        let utp = update_to_pad((start & 15) as u8, end);

        kani::assert(
            wc_to_pad(utp as u32) == wc_to_pad_64((start as u64) + (end as u64)),
            "update_to_pad must be equivalent to the total length in the eyes of the wolfcrypt \
            padding algorithm."
        );
    }

    #[proof]
    fn univ_mask_is_no_mask_to_wc_pad_algo() {
        let some_num: u64 = kani::any();

        kani::assert(
            wc_to_pad_64(some_num & 15) == wc_to_pad_64(some_num),
            "wolfcrypt's to pad must result in the same output for the input mask 15 and raw input"
        )
    }
}