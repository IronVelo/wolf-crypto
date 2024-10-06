//! The `Poly1305` Message Authentication Code
//!
//! ```
//! use wolf_crypto::mac::{Poly1305, poly1305::Key};
//!
//! # fn main() -> Result<(), wolf_crypto::Unspecified> {
//! let key = Key::new([0u8; 32]);
//!
//! let tag = Poly1305::new(key.as_ref())
//!     .update(b"hello world")?
//!     .finalize();
//!
//! let o_tag = Poly1305::new(key)
//!     .update(b"Different message")?
//!     .finalize();
//!
//! assert_eq!(
//!     tag, o_tag,
//!     "All of our coefficients are zero!"
//! );
//!
//! let key = Key::new([42u8; 32]);
//!
//! let tag = Poly1305::new(key.as_ref())
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

macro_rules! smear {
    ($b:ident) => {{
        $b |= $b >> 1;
        $b |= $b >> 2;
        $b |= $b >> 4;
        $b |= $b >> 8;
        $b |= $b >> 16;
    }};
}

/// Performs a constant-time greater-than comparison.
///
/// # Arguments
///
/// * `left` - The left-hand side operand.
/// * `right` - The right-hand side operand.
///
/// # Returns
///
/// Returns `1` if `left > right`, otherwise `0`.
const fn ct_gt(left: u32, right: u32) -> u32 {
    let gtb = left & !right;
    let mut ltb = !left & right;

    smear!(ltb);

    let mut bit = gtb & !ltb;
    // smear the highest set bit
    smear!(bit);

    bit & 1
}

/// Performs constant-time addition without wrapping on overflow.
///
/// # Arguments
///
/// * `a` - The first operand.
/// * `b` - The second operand.
///
/// # Returns
///
/// A tuple containing the sum and a `Res` indicating if there was no overflow.
#[inline]
const fn ct_add_no_wrap(a: u32, b: u32) -> (u32, Res) {
    let overflow = ct_gt(b, u32::MAX.wrapping_sub(a));
    let sum = a.wrapping_add(b & (!overflow.wrapping_neg()));
    (sum, Res(overflow == 0))
}

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
    fn from(value: Poly1305<State>) -> Self {
        drop(value);
        Unspecified
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

    /// Computes the MAC for the given input and additional data.
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
        if let Some(input_len) = to_u32(input.len()) {
            unsafe { self.update_unchecked(input) };
            Ok(StreamPoly1305::from_parts(self.with_state(), input_len))
        } else {
            Err(Unspecified)
        }
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
    /// let ct_poly = Poly1305::new(key)
    ///     .update_ct(b"sensitive ")
    ///     .update_ct(b"chunks")
    ///     .finalize()
    ///     .unwrap();
    ///
    /// dbg!(ct_poly);
    /// assert_ne!(ct_poly, Tag::new_zeroed());
    /// ```
    pub fn update_ct(mut self, input: &[u8]) -> CtPoly1305 {
        let (adjusted, res) = CtPoly1305::adjust_slice(input);
        unsafe { self.update_unchecked(adjusted) };
        CtPoly1305::from_parts(self.with_state(), res, adjusted.len() as u32)
    }
}

/// Finalizes the `Poly1305` MAC computation.
///
/// # Arguments
///
/// * `res` - The current `Res` state.
/// * `poly` - The `Poly1305` instance.
/// * `accum_len` - The accumulated length of the input data.
///
/// # Returns
///
/// A `Result<Tag, Unspecified>` containing the computed `Tag` on success or an `Unspecified` error
/// on failure.
#[inline]
fn finalize<S: Poly1305State>(mut poly: Poly1305<S>, accum_len: u32) -> Tag {
    // Regarding fallibility for all functions invoked, and debug_asserted to have succeeded,
    // see the commentary at the beginning of the document.
    unsafe {
        let mut tag = Tag::new_zeroed();

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

        let _res = wc_Poly1305Final(
            addr_of_mut!(poly.inner),
            tag.as_mut_ptr()
        );

        debug_assert_eq!(_res, 0);

        tag
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
    accum_len: u32
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
        let (accum_len, res) = ct_add_no_wrap(self.accum_len, len);
        self.accum_len = accum_len;
        res
    }

    /// Updates the streaming MAC computation with additional input.
    ///
    /// # Arguments
    ///
    /// * `input` - A byte slice representing the additional data to include.
    ///
    /// # Returns
    ///
    /// `Self` for chaining updates. If taking ownership is not desired, see [`update_streaming`].
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
    ///     .update(b"chunk1")?
    ///     .update(b"chunk2")?
    ///     .update(b"chunk3")?
    ///     .finalize();
    /// # Ok(()) }
    /// ```
    ///
    /// [`update_streaming`]: Self::update_streaming
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
    /// A `Result<Tag, Unspecified>` containing the computed `Tag` on success or an `Unspecified` error on failure.
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
    pub fn finalize(self) -> Tag {
        finalize(self.poly1305, self.accum_len)
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
    accum_len: u32
}

opaque_dbg! { CtPoly1305 }

impl CtPoly1305 {
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
        let (accum_len, res) = ct_add_no_wrap(self.accum_len, len);
        self.accum_len = accum_len;
        res
    }

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
        let mask = Self::slice_len_mask(slice.len());
        (&slice[..(slice.len() & mask)], Res(mask != 0))
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
        let (adjusted, mut res) = Self::adjust_slice(input);
        res.ensure(self.incr_accum(adjusted.len() as u32));

        unsafe { self.poly1305.update_unchecked(input) };

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
    ///     .update_ct(b"chunk1")
    ///     .update_ct(b"chunk2")
    ///     .finalize()
    ///     .unwrap();
    /// ```
    pub fn finalize(self) -> Result<Tag, Unspecified> {
        let tag = finalize(self.poly1305, self.accum_len);
        self.result.unit_err(tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        let key: Key = [69; 32].into();
        let tag = Poly1305::new(key.as_ref())
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
}

#[cfg(test)]
/// Basic macro just so that I can think more clearly about my assertions with infix notation.
macro_rules! ensure {
    // implications
    (($left:expr) ==> ($right:expr)) => {
        if $left {
            assert!($right, concat!(stringify!($left), " -> ", stringify!($right)));
        }
    };
    (kani ($left:expr) ==> ($right:expr)) => {
        if $left {
            kani::assert($right, concat!(stringify!($left), " -> ", stringify!($right)));
        }
    };
    (($left:expr) <== ($right:expr)) => {
        if $right {
            assert!($left, concat!(stringify!($left), " <- ", stringify!($right)));
        }
    };
    (kani ($left:expr) <== ($right:expr)) => {
        if $right {
            kani::assert($left, concat!(stringify!($left), " <- ", stringify!($right)));
        }
    };
    // biconditional
    (($a:expr) <==> ($b:expr)) => {{
        ensure!(($a) ==> ($b));
        ensure!(($a) <== ($b));
    }};
    (kani ($a:expr) <==> ($b:expr)) => {
        kani::assert(
            kani::implies!($a => $b) && kani::implies!($b => $a),
            concat!(stringify!($a), " <-> ", stringify!($b))
        )
    };
}

#[cfg(test)]
mod ct_arithmetic_property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(300_000))]

        #[test]
        fn enusre_ct_add_no_wrap(a in any::<u32>(), b in any::<u32>()) {
            let (out, res) = ct_add_no_wrap(a, b);

            ensure!(( res.is_err() ) <==> ( a.checked_add(b).is_none() ));
            ensure!(( out == a )     <==> ( res.is_err() || b == 0 ));
            ensure!(( res.is_ok() )  <==> ( out != a || b == 0 ));
        }
    }
}

#[cfg(kani)]
mod ct_arithmetic_checks {
    use super::*;
    use kani::proof;

    #[proof]
    fn check_ct_add_no_wrap() {
        let a = kani::any();
        let b = kani::any();

        let (out, res) = ct_add_no_wrap(a, b);

        ensure!(kani ( res.is_err() ) <==> ( a.checked_add(b).is_none() ));
        ensure!(kani ( out == a )     <==> ( res.is_err() || b == 0 ));
        ensure!(kani ( res.is_ok() )  <==> ( out != a || b == 0 ));
    }
}