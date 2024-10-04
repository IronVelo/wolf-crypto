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
use crate::{can_cast_u32, Unspecified};
use core::marker::PhantomData;
use crate::aead::Tag;

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

/// Performs constant-time addition with overflow detection.
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
const fn ct_add(a: u32, b: u32) -> (u32, Res) {
    // there's certainly more efficient ways of doing this and achieving the same
    // outcome. I just don't want to write that many tests (and probably necessitates formal
    // verification) right now. This is easy to reason about.
    let overflow = ct_gt(b, u32::MAX.wrapping_sub(a));
    let sum = a.wrapping_add(b);
    (sum, Res(overflow == 0))
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
    /// let key: Key = [0u8; 32].into();
    /// let poly = Poly1305::new(key.as_ref());
    /// ```
    pub fn new<K: GenericKey>(key: K) -> Poly1305<Ready> {
        let mut poly1305 = MaybeUninit::<wc_Poly1305>::uninit();

        unsafe {
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
    ///
    /// # Returns
    ///
    /// A `Res` indicating the success or failure of the update operation.
    #[inline]
    unsafe fn update_unchecked(&mut self, input: &[u8]) -> Res {
        let mut res = Res::new();

        res.ensure_0(wc_Poly1305Update(
            addr_of_mut!(self.inner),
            input.as_ptr(),
            input.len() as u32
        ));

        res
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
    /// A `Result<Tag, Unspecified>` containing the computed `Tag` on success or an `Unspecified`
    /// error on failure.
    unsafe fn mac_unchecked(mut self, input: &[u8], additional: &[u8]) -> Result<Tag, Unspecified> {
        let mut res = Res::new();
        let mut tag = Tag::new_zeroed();

        res.ensure_0(wc_Poly1305_MAC(
            addr_of_mut!(self.inner),
            additional.as_ptr(),
            additional.len() as u32,
            input.as_ptr(),
            input.len() as u32,
            tag.as_mut_ptr(),
            Tag::SIZE
        ));

        res.unit_err(tag)
    }

    /// Computes the MAC for the given input and additional data.
    ///
    /// # Arguments
    ///
    /// * `input` - A byte slice representing the message to authenticate.
    /// * `additional` - A byte slice representing optional additional authenticated data (AAD).
    ///
    /// # Returns
    ///
    /// A `Result<Tag, Unspecified>` containing the computed `Tag` on success or an `Unspecified`
    /// error on failure.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// let key: Key = [0u8; 32].into();
    /// let tag = Poly1305::new(key.as_ref())
    ///     .mac(b"message", b"aad")
    ///     .unwrap();
    /// ```
    #[inline]
    pub fn mac(self, input: &[u8], additional: &[u8]) -> Result<Tag, Unspecified> {
        if !(can_cast_u32(input.len()) && can_cast_u32(additional.len())) {
            return Err(Unspecified)
        }

        unsafe { self.mac_unchecked(input, additional) }
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
    /// A `Result<StreamPoly1305, Unspecified>` containing a `StreamPoly1305` instance for continued
    /// updates or an `Unspecified` error on failure.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let key: Key = [0u8; 32].into();
    /// let stream = Poly1305::new(key.as_ref())
    ///     .update(b"chunk1")?
    ///     .update(b"chunk2")?;
    /// # Ok(()) }
    /// ```
    #[inline]
    pub fn update(mut self, input: &[u8]) -> Result<StreamPoly1305, Unspecified> {
        if !can_cast_u32(input.len()) { return Err(Unspecified) }
        unsafe { self.update_unchecked(input) }
            .unit_err(StreamPoly1305::from_parts(self.with_state(), input.len() as u32))
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
    /// let key: Key = [0u8; 32].into();
    /// let ct_poly = Poly1305::new(key.as_ref())
    ///     .update_ct(b"sensitive ")
    ///     .update_ct(b"chunks")
    ///     .finalize()
    ///     .unwrap();
    /// ```
    pub fn update_ct(mut self, input: &[u8]) -> CtPoly1305 {
        let (adjusted, mut res) = CtPoly1305::adjust_slice(input);
        res.ensure(unsafe { self.update_unchecked(adjusted) });
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
fn finalize<S: Poly1305State>(mut res: Res, mut poly: Poly1305<S>, accum_len: u32) -> Result<Tag, Unspecified> {
    unsafe {
        let mut tag = Tag::new_zeroed();

        res.ensure_0(wc_Poly1305_Pad(
            addr_of_mut!(poly.inner),
            accum_len
        ));

        res.ensure_0(wc_Poly1305_EncodeSizes(
            addr_of_mut!(poly.inner),
            0u32,
            accum_len
        ));

        res.ensure_0(wc_Poly1305Final(
            addr_of_mut!(poly.inner),
            tag.as_mut_ptr()
        ));

        res.unit_err(tag)
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
/// let key: Key = [0u8; 32].into();
/// let mut stream = Poly1305::new(key.as_ref())
///     .update(b"chunk1")?
///     .update(b"chunk2")?
///     .update(b"chunk3")?;
///
/// let tag = stream.finalize()?;
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
        let (accum_len, res) = ct_add(self.accum_len, len);
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
    /// A `Result<&mut Self, Unspecified>` containing a mutable reference to `StreamPoly1305` for chaining or an `Unspecified` error on failure.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// # fn main() -> Result<(), wolf_crypto::Unspecified> {
    /// let key: Key = [0u8; 32].into();
    ///
    /// let tag = Poly1305::new(key.as_ref())
    ///     .update(b"chunk1")?
    ///     .update(b"chunk2")?
    ///     .update(b"chunk3")?
    ///     .finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn update(mut self, input: &[u8]) -> Result<Self, Self> {
        if !can_cast_u32(input.len()) { return Err(self) };
        let mut res = unsafe { self.poly1305.update_unchecked(input) };
        res.ensure(self.incr_accum(input.len() as u32));

        into_result!(
            res,
            ok => self,
            err => self
        )
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
    /// let key: Key = [0u8; 32].into();
    ///
    /// let tag = Poly1305::new(key.as_ref())
    ///     .update(b"chunk1")?
    ///     .update(b"chunk2")?
    ///     .update(b"chunk3")?
    ///     .finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn finalize(self) -> Result<Tag, Unspecified> {
        finalize(Res::new(), self.poly1305, self.accum_len)
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
/// let key: Key = [0u8; 32].into();
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
    /// A `Res` indicating the success or failure of the operation.
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
    /// A mask derived from the slice length.
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
    /// let key: Key = [0u8; 32].into();
    /// let ct_poly = Poly1305::new(key.as_ref())
    ///     .update_ct(b"chunk1")
    ///     .update_ct(b"chunk2")
    ///     .finalize()
    ///     .unwrap();
    /// ```
    pub fn update_ct(mut self, input: &[u8]) -> Self {
        let (adjusted, mut res) = Self::adjust_slice(input);
        res.ensure(self.incr_accum(adjusted.len() as u32));
        res.ensure(unsafe { self.poly1305.update_unchecked(input) });

        self.result.ensure(res);
        self
    }

    /// Finalizes the constant-time streaming MAC computation and returns the resulting `Tag`.
    ///
    /// # Returns
    ///
    /// A `Result<Tag, Unspecified>` containing the computed `Tag` on success or an `Unspecified`
    /// error on failure.
    ///
    /// # Errors
    ///
    /// The `CtPoly1305` accumulates errors throughout the process of updating. If there was
    /// an error at any point in said updating, or an error in this function call, that will show up
    /// here.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::{mac::{Poly1305, poly1305::Key}, aead::Tag};
    ///
    /// let key: Key = [0u8; 32].into();
    /// let tag = Poly1305::new(key.as_ref())
    ///     .update_ct(b"chunk1")
    ///     .update_ct(b"chunk2")
    ///     .finalize()
    ///     .unwrap();
    /// ```
    pub fn finalize(self) -> Result<Tag, Unspecified> {
        finalize(self.result, self.poly1305, self.accum_len)
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
