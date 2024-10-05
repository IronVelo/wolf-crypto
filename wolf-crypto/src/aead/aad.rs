use crate::{can_cast_u32, const_can_cast_u32, to_u32};
use crate::sealed::AadSealed as Sealed;
use core::fmt;


/// A generic representation of additional authenticated data (AAD)
pub unsafe trait Aad: Sealed {
    /// Returns the length of the [`ptr`] result, represented as a `u32`.
    ///
    /// # Trait Safety
    ///
    /// - This must return the length as a `u32`, if the length is too large to be represented as
    ///   a `u32` then it should return `None`.
    /// - This returns `None` **if and only if** the length cannot be represented as a `u32`.
    ///   If no AAD is being provided, the returned length should **always** be zero. `None` is
    ///   reserved only for when casting the `usize` to a `u32` would overflow.
    #[doc(hidden)]
    #[must_use]
    fn try_size(&self) -> Option<u32>;

    /// Returns a pointer valid for the length of the [`try_size`] result.
    ///
    /// # Trait Safety
    ///
    /// - This must provide a valid pointer if the result of [`try_size`] is not `Some(0)`. If
    ///   `Some(0)` is returned from [`try_size`] it is acceptable for the result of this to be
    ///   null.
    /// - This must return a pointer which is valid for the result of [`try_size`], any less will
    ///   result in undefined behavior.
    ///
    /// [`try_size`]: Aad::try_size
    #[doc(hidden)]
    #[must_use]
    fn ptr(&self) -> *const u8;

    /// # Trait Safety
    ///
    /// Same invariants as [`try_size`], just this function does not need to check for overflow
    /// as to safely invoke this, the caller must ensure [`is_valid_size`] returns true.
    ///
    /// # Safety
    ///
    /// The caller must ensure the [`is_valid_size`] returns true prior to invoking this.
    ///
    /// [`try_size`]: Aad::try_size
    /// [`is_valid_size`]: Aad::is_valid_size
    #[doc(hidden)]
    #[must_use]
    unsafe fn size(&self) -> u32;

    /// Returns `true` IFF the result of [`try_size`] would be `Some`.
    ///
    /// [`try_size`]: Aad::try_size
    #[doc(hidden)]
    #[must_use]
    fn is_valid_size(&self) -> bool;
}

/// Represents Additional Authenticated Data (AAD) Slice.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct AadSlice<'s> {
    inner: Option<&'s [u8]>
}

impl<'s> fmt::Debug for AadSlice<'s> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AadSlice(")
            .and_then(|()| match self.inner {
                None => f.write_str("EMPTY"),
                Some(inner) => <[u8] as fmt::Debug>::fmt(inner, f)
            })
            .and_then(|()| f.write_str(")"))
    }
}

impl<'a> PartialEq<[u8]> for AadSlice<'a> {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.inner.is_some_and(|inner| inner == other)
    }
}

impl<'s> AadSlice<'s> {
    /// An empty AAD.
    pub const EMPTY: Self = Self { inner: None };

    /// Create a new AAD instance from a byte slice.
    pub const fn new(aad: &'s [u8]) -> Self {
        Self { inner: Some(aad) }
    }

    /// Pointer may be null of the option was None
    #[inline]
    pub(crate) const fn as_ptr(&self) -> *const u8 {
        match self.inner {
            Some(inner) => inner.as_ptr(),
            None => core::ptr::null()
        }
    }

    #[inline(always)]
    #[must_use]
    pub const fn size(&self) -> Option<u32> {
        match self.inner {
            None => Some(0),
            Some(val) => to_u32(val.len())
        }
    }

    #[inline]
    #[must_use]
    pub const fn valid_size(&self) -> bool {
        match self.inner {
            Some(inner) => can_cast_u32(inner.len()),
            None => true
        }
    }
}

impl<'a> From<&'a [u8]> for AadSlice<'a> {
    #[inline]
    fn from(value: &'a [u8]) -> Self {
        Self::new(value)
    }
}

impl<'a> Sealed for AadSlice<'a> {}

unsafe impl<'a> Aad for AadSlice<'a> {
    #[inline]
    fn try_size(&self) -> Option<u32> { self.size() }
    #[inline]
    fn ptr(&self) -> *const u8 { self.as_ptr() }

    #[inline]
    unsafe fn size(&self) -> u32 {
        debug_assert!(self.is_valid_size());
        self.inner.map_or(0, |inner| inner.len() as u32)
    }

    #[inline]
    fn is_valid_size(&self) -> bool { self.valid_size() }
}

impl<T: ?Sized + Sealed> Sealed for &T {}
unsafe impl<T: ?Sized + Aad> Aad for &T {
    #[inline]
    fn try_size(&self) -> Option<u32> {
        T::try_size(self)
    }
    #[inline]
    fn ptr(&self) -> *const u8 {
        T::ptr(self)
    }
    #[inline]
    #[cfg_attr(debug_assertions, track_caller)]
    unsafe fn size(&self) -> u32 {
        T::size(self)
    }
    #[inline]
    fn is_valid_size(&self) -> bool {
        T::is_valid_size(self)
    }
}
impl<T: ?Sized + Sealed> Sealed for &mut T {}
unsafe impl<T: ?Sized + Aad> Aad for &mut T {
    #[inline]
    fn try_size(&self) -> Option<u32> {
        T::try_size(self)
    }
    #[inline]
    fn ptr(&self) -> *const u8 {
        T::ptr(self)
    }
    #[inline]
    #[cfg_attr(debug_assertions, track_caller)]
    unsafe fn size(&self) -> u32 {
        T::size(self)
    }
    #[inline]
    fn is_valid_size(&self) -> bool {
        T::is_valid_size(self)
    }
}

impl Sealed for [u8] {}

unsafe impl Aad for [u8] {
    #[inline]
    fn try_size(&self) -> Option<u32> {
        to_u32(self.len())
    }
    #[inline]
    fn ptr(&self) -> *const u8 {
        self.as_ptr()
    }
    #[inline]
    #[cfg_attr(debug_assertions, track_caller)]
    unsafe fn size(&self) -> u32 {
        debug_assert!(self.is_valid_size());
        self.len() as u32
    }
    #[inline]
    fn is_valid_size(&self) -> bool {
        can_cast_u32(self.len())
    }
}

impl<const C: usize> Sealed for [u8; C] {}

unsafe impl<const C: usize> Aad for [u8; C] {
    #[inline]
    fn try_size(&self) -> Option<u32> {
        if const_can_cast_u32::<C>() {
            Some(C as u32)
        } else {
            None
        }
    }
    #[inline]
    fn ptr(&self) -> *const u8 {
        self.as_ptr()
    }
    #[inline]
    #[cfg_attr(debug_assertions, track_caller)]
    unsafe fn size(&self) -> u32 {
        debug_assert!(const_can_cast_u32::<C>());
        C as u32
    }
    #[inline]
    fn is_valid_size(&self) -> bool {
        const_can_cast_u32::<C>()
    }
}

impl Sealed for str {}

unsafe impl Aad for str {
    #[inline]
    fn try_size(&self) -> Option<u32> {
        to_u32(self.len())
    }
    #[inline]
    fn ptr(&self) -> *const u8 {
        self.as_ptr()
    }
    #[inline]
    #[cfg_attr(debug_assertions, track_caller)]
    unsafe fn size(&self) -> u32 {
        debug_assert!(self.is_valid_size());
        self.len() as u32
    }
    #[inline]
    fn is_valid_size(&self) -> bool {
        can_cast_u32(self.len())
    }
}

impl Sealed for () {}

unsafe impl Aad for () {
    #[inline]
    fn try_size(&self) -> Option<u32> {
        Some(0)
    }
    #[inline]
    fn ptr(&self) -> *const u8 {
        core::ptr::null()
    }
    #[inline]
    unsafe fn size(&self) -> u32 {
        0
    }
    #[inline]
    fn is_valid_size(&self) -> bool {
        true
    }
}

impl<T: Sealed> Sealed for Option<T> {}

unsafe impl<T: Aad> Aad for Option<T> {
    #[inline]
    fn try_size(&self) -> Option<u32> {
        match self {
            None => Some(0),
            Some(inner) => inner.try_size()
        }
    }
    #[inline]
    fn ptr(&self) -> *const u8 {
        match self {
            None => core::ptr::null(),
            Some(inner) => inner.ptr()
        }
    }
    #[inline]
    unsafe fn size(&self) -> u32 {
        match self {
            None => 0,
            Some(inner) => inner.size()
        }
    }
    #[inline]
    fn is_valid_size(&self) -> bool {
        match self {
            None => true,
            Some(inner) => inner.is_valid_size()
        }
    }
}

alloc! {
    impl Sealed for Vec<u8> {}

    unsafe impl Aad for Vec<u8> {
        #[inline]
        fn try_size(&self) -> Option<u32> {
            to_u32(self.len())
        }
        #[inline]
        fn ptr(&self) -> *const u8 {
            self.as_ptr()
        }
        #[inline]
        #[cfg_attr(debug_assertions, track_caller)]
        unsafe fn size(&self) -> u32 {
            debug_assert!(self.is_valid_size());
            self.len() as u32
        }
        #[inline]
        fn is_valid_size(&self) -> bool {
            can_cast_u32(self.len())
        }
    }

    impl Sealed for String {}

    unsafe impl Aad for String {
        #[inline]
        fn try_size(&self) -> Option<u32> {
            to_u32(self.len())
        }
        #[inline]
        fn ptr(&self) -> *const u8 {
            self.as_ptr()
        }
        #[inline]
        #[cfg_attr(debug_assertions, track_caller)]
        unsafe fn size(&self) -> u32 {
            debug_assert!(self.is_valid_size());
            self.len() as u32
        }
        #[inline]
        fn is_valid_size(&self) -> bool {
            can_cast_u32(self.len())
        }
    }
}